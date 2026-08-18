/**
 * CoNET DePIN UDP mailbox relay (zero-trust).
 *
 * B never decrypts UDP payloads and never stores Securitykey.
 * Subscribe (AES key) is a business PGP message to the UDP server **user** PGP.
 * Client listen / server listen / relay commands are encrypted to **B route** PGP
 * and arrive here after checkSign.
 *
 * SSE writes: `socket.write() === false` is backpressure (wait for `drain`), not failure.
 * See `.cursor/rules/conet-depin-udp-forward-protocol.mdc`.
 */
import type { Socket } from 'net'
import type { TLSSocket } from 'tls'
import { ethers } from 'ethers'
import Colors from 'colors/safe'
import { logger } from './logger'
import { distorySocket, response200Html } from './htmlResponse'
import { isMyRoute, isLivenessListenSocketStale } from './util'

const UDP_SESSION_IDLE_MS = 10 * 60 * 1000
const UDP_SWEEP_MS = 60_000
const UDP_MAX_PAYLOAD_B64 = 12_000
const UDP_MAX_SESSIONS_PER_CLIENT = 16
const UDP_MAX_SESSIONS_PER_SERVER = 64
const UDP_MAX_SESSIONS_GLOBAL = 256
const UDP_TIMESTAMP_SKEW_SEC = 600
const SESSION_ID_RE = /^[0-9a-fA-F-]{16,64}$/

/** Per-session outbound SSE queue (UDP may drop oldest under load). */
const UDP_MAX_QUEUED_FRAMES = 64
const UDP_MAX_QUEUED_BYTES = 256 * 1024
const UDP_MAX_QUEUE_AGE_MS = 2_000
/** If highWaterMark never drains, treat the listen socket as dead. */
const UDP_DRAIN_TIMEOUT_MS = 2_000

export type UdpListenKind = 'udp' | 'udp_server'

/** Node write semantics for SSE lines (not “ok / fail”). */
export type UdpSseWriteResult = 'accepted' | 'backpressured' | 'closed' | 'queued'

interface UdpQueuedFrame {
	line: string
	enqueuedAt: number
	bytes: number
}

interface UdpSseWriter {
	res: Socket | TLSSocket
	paused: boolean
	queue: UdpQueuedFrame[]
	queuedBytes: number
	drainBound: boolean
	drainTimer: ReturnType<typeof setTimeout> | undefined
	/** Called when the socket is closed / drain times out. */
	onClosed: (why: string) => void
}

export interface UdpClientSession {
	sessionId: string
	clientWallet: string
	serverWallet: string
	res: Socket | TLSSocket
	ipaddress: string
	connectedAt: number
	lastActivityAt: number
	seqDown: number
	writer: UdpSseWriter
}

export interface UdpServerListen {
	serverWallet: string
	res: Socket | TLSSocket
	ipaddress: string
	connectedAt: number
	lastActivityAt: number
	writer: UdpSseWriter
}

const udpClientPool: Map<string, UdpClientSession> = new Map()
const udpServerPool: Map<string, UdpServerListen> = new Map()

type ChatNotifyFn = (serverWallet: string, frame: Record<string, unknown>) => boolean
let notifyUdpServerChatListen: ChatNotifyFn | null = null

/** Wire from localNodeCommand so uplink / listen-attached can also hit chat SSE. */
export const setUdpServerChatNotify = (fn: ChatNotifyFn | null) => {
	notifyUdpServerChatListen = fn
}

let sweepTimer: ReturnType<typeof setTimeout> | undefined

const scheduleSweep = () => {
	if (sweepTimer !== undefined) return
	sweepTimer = setTimeout(() => {
		sweepTimer = undefined
		try {
			sweepIdleUdpSessions()
		} finally {
			if (udpClientPool.size > 0 || udpServerPool.size > 0) {
				scheduleSweep()
			}
		}
	}, UDP_SWEEP_MS)
}

const nowMs = () => Date.now()

const lowerAddr = (raw: unknown): string => {
	if (typeof raw !== 'string') return ''
	const t = raw.trim()
	if (!t || !ethers.isAddress(t)) return ''
	return t.toLowerCase()
}

export const normalizeUdpSessionId = (raw: unknown): string => {
	if (typeof raw !== 'string') return ''
	const id = raw.trim()
	return SESSION_ID_RE.test(id) ? id : ''
}

const timestampOk = (raw: unknown): boolean => {
	const ts = Number(raw)
	if (!Number.isFinite(ts)) return false
	const now = Math.floor(Date.now() / 1000)
	return Math.abs(now - ts) <= UDP_TIMESTAMP_SKEW_SEC
}

const payloadOk = (raw: unknown): raw is string => {
	return typeof raw === 'string' && raw.length > 0 && raw.length <= UDP_MAX_PAYLOAD_B64
}

const countBy = (pool: Map<string, UdpClientSession>, field: 'clientWallet' | 'serverWallet', wallet: string): number => {
	let n = 0
	pool.forEach((s) => {
		if (s[field] === wallet) n += 1
	})
	return n
}

const sseHeaders = (): string =>
	`HTTP/1.1 200 OK\r\n` +
	`Date: ${new Date().toUTCString()}\r\n` +
	`Content-Type: text/event-stream; charset=utf-8\r\n` +
	`Cache-Control: no-cache, no-transform\r\n` +
	`Connection: keep-alive\r\n` +
	`X-Accel-Buffering: no\r\n` +
	`Access-Control-Allow-Origin: *\r\n` +
	`\r\n`

const formatSseJsonLine = (obj: Record<string, unknown>): string =>
	`data: ${JSON.stringify(obj)}\r\n\r\n`

const clearDrainTimer = (w: UdpSseWriter) => {
	if (w.drainTimer !== undefined) {
		clearTimeout(w.drainTimer)
		w.drainTimer = undefined
	}
}

const resetWriterQueue = (w: UdpSseWriter) => {
	clearDrainTimer(w)
	w.paused = false
	w.drainBound = false
	w.queue = []
	w.queuedBytes = 0
	const s = w.res as Socket
	s.removeAllListeners('drain')
}

/**
 * Attempt one SSE line write.
 * `false` from `socket.write` means the line was accepted into the buffer but
 * highWaterMark was hit — callers must wait for `drain`, not tear down the session.
 */
const tryWriteSseLine = (res: Socket | TLSSocket, line: string): UdpSseWriteResult => {
	const s = res as Socket
	if (isLivenessListenSocketStale(s)) return 'closed'
	try {
		const ok = s.write(line)
		return ok ? 'accepted' : 'backpressured'
	} catch {
		return 'closed'
	}
}

const dropOldestQueued = (w: UdpSseWriter, why: string) => {
	const dropped = w.queue.shift()
	if (!dropped) return
	w.queuedBytes = Math.max(0, w.queuedBytes - dropped.bytes)
	logger(Colors.grey(`udp SSE drop-old ${why} bytes=${dropped.bytes} remain=${w.queue.length}`))
}

const trimQueueLimits = (w: UdpSseWriter) => {
	const now = nowMs()
	while (w.queue.length > 0) {
		const head = w.queue[0]
		if (now - head.enqueuedAt <= UDP_MAX_QUEUE_AGE_MS) break
		dropOldestQueued(w, 'age')
	}
	while (
		w.queue.length > UDP_MAX_QUEUED_FRAMES ||
		w.queuedBytes > UDP_MAX_QUEUED_BYTES
	) {
		dropOldestQueued(w, 'limit')
	}
}

const enqueueFrame = (w: UdpSseWriter, line: string) => {
	const bytes = Buffer.byteLength(line, 'utf8')
	w.queue.push({ line, enqueuedAt: nowMs(), bytes })
	w.queuedBytes += bytes
	trimQueueLimits(w)
}

const bindDrain = (w: UdpSseWriter) => {
	if (w.drainBound) return
	w.drainBound = true
	const s = w.res as Socket
	clearDrainTimer(w)
	w.drainTimer = setTimeout(() => {
		w.drainTimer = undefined
		w.drainBound = false
		logger(Colors.yellow(`udp SSE drain timeout — closing listen`))
		w.onClosed('drain_timeout')
		try {
			if (!s.destroyed) s.destroy()
		} catch {
			/* ignore */
		}
	}, UDP_DRAIN_TIMEOUT_MS)
	s.once('drain', () => {
		clearDrainTimer(w)
		w.drainBound = false
		w.paused = false
		flushWriterQueue(w)
	})
}

const flushWriterQueue = (w: UdpSseWriter) => {
	while (w.queue.length > 0) {
		if (isLivenessListenSocketStale(w.res)) {
			w.onClosed('stale_on_flush')
			return
		}
		trimQueueLimits(w)
		const next = w.queue[0]
		if (!next) break
		const result = tryWriteSseLine(w.res, next.line)
		if (result === 'closed') {
			w.onClosed('write_closed_on_flush')
			return
		}
		// accepted or backpressured: line left the JS queue into the socket buffer
		w.queue.shift()
		w.queuedBytes = Math.max(0, w.queuedBytes - next.bytes)
		if (result === 'backpressured') {
			w.paused = true
			bindDrain(w)
			return
		}
	}
}

/**
 * Deliver one JSON SSE frame. Never treats `write()===false` as hard failure.
 * Under backpressure, further frames queue with drop-oldest UDP semantics.
 */
const deliverSseJson = (w: UdpSseWriter, obj: Record<string, unknown>): UdpSseWriteResult => {
	if (isLivenessListenSocketStale(w.res)) return 'closed'
	const line = formatSseJsonLine(obj)

	if (w.paused) {
		enqueueFrame(w, line)
		return 'queued'
	}

	const result = tryWriteSseLine(w.res, line)
	if (result === 'closed') return 'closed'
	if (result === 'backpressured') {
		w.paused = true
		bindDrain(w)
		return 'backpressured'
	}
	return 'accepted'
}

const makeWriter = (res: Socket | TLSSocket, onClosed: (why: string) => void): UdpSseWriter => ({
	res,
	paused: false,
	queue: [],
	queuedBytes: 0,
	drainBound: false,
	drainTimer: undefined,
	onClosed,
})

const destroyListenSocket = (res: Socket | TLSSocket) => {
	try {
		const s = res as Socket
		if (!s.destroyed) s.destroy()
	} catch {
		/* ignore */
	}
}

const dropClientSession = (sessionId: string, why: string) => {
	const s = udpClientPool.get(sessionId)
	if (!s) return
	udpClientPool.delete(sessionId)
	resetWriterQueue(s.writer)
	logger(Colors.grey(`udp_listen drop session=${sessionId} client=${s.clientWallet} ${why}`))
	destroyListenSocket(s.res)
}

const dropServerListen = (serverWallet: string, why: string) => {
	const s = udpServerPool.get(serverWallet)
	if (!s) return
	udpServerPool.delete(serverWallet)
	resetWriterQueue(s.writer)
	logger(Colors.grey(`udp_server_listen drop server=${serverWallet} ${why}`))
	destroyListenSocket(s.res)
}

const sweepIdleUdpSessions = () => {
	const now = nowMs()
	udpClientPool.forEach((s, id) => {
		if (now - s.lastActivityAt > UDP_SESSION_IDLE_MS || isLivenessListenSocketStale(s.res)) {
			dropClientSession(id, 'idle_or_stale')
		}
	})
	udpServerPool.forEach((s, wallet) => {
		if (now - s.lastActivityAt > UDP_SESSION_IDLE_MS || isLivenessListenSocketStale(s.res)) {
			dropServerListen(wallet, 'idle_or_stale')
		}
	})
}

const bindListenLifecycle = (
	res: Socket | TLSSocket,
	onDead: (why: string) => void,
) => {
	const s = res as Socket
	s.once('error', (err: Error) => onDead(`error:${err.message}`))
	s.once('close', () => onDead('close'))
	s.once('end', () => {
		logger(Colors.grey(`udp listen peer half-close — keep writable`))
	})
}

const notifyServer = (serverWallet: string, frame: Record<string, unknown>) => {
	const dedicated = udpServerPool.get(serverWallet)
	if (dedicated && !isLivenessListenSocketStale(dedicated.res)) {
		dedicated.lastActivityAt = nowMs()
		const wr = deliverSseJson(dedicated.writer, frame)
		if (wr === 'closed') {
			dropServerListen(serverWallet, 'notify_write_closed')
		}
	}
	if (notifyUdpServerChatListen) {
		notifyUdpServerChatListen(serverWallet, frame)
	}
}

/**
 * Client long-lived SSE on the UDP server's mailbox B.
 * Encrypted to B route PGP. Does **not** carry Securitykey.
 */
export const handleUdpListen = async (
	socket: Socket,
	command: minerObj,
	nodeWallet: ethers.Wallet,
) => {
	const clientWallet = lowerAddr(command.walletAddress)
	const serverWallet = lowerAddr((command as any).udpServerWallet)
	const sessionId = normalizeUdpSessionId((command as any).sessionId)
	if (!clientWallet || !serverWallet || !sessionId) {
		logger(Colors.red(`udp_listen missing client/server/sessionId`))
		return distorySocket(socket)
	}
	if (!timestampOk((command as any).timestamp)) {
		logger(Colors.red(`udp_listen timestamp rejected client=${clientWallet}`))
		return distorySocket(socket)
	}
	if (clientWallet === serverWallet) {
		logger(Colors.red(`udp_listen client==server rejected`))
		return distorySocket(socket)
	}
	const mine = await isMyRoute(serverWallet, nodeWallet.address)
	if (!mine) {
		logger(Colors.yellow(`udp_listen not my route server=${serverWallet}`))
		return response200Html(socket, JSON.stringify({ ok: false, error: 'not_my_route', udpServerWallet: serverWallet }))
	}
	if (udpClientPool.size >= UDP_MAX_SESSIONS_GLOBAL) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'pool_full' }))
	}
	if (countBy(udpClientPool, 'clientWallet', clientWallet) >= UDP_MAX_SESSIONS_PER_CLIENT) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'client_session_limit' }))
	}
	if (countBy(udpClientPool, 'serverWallet', serverWallet) >= UDP_MAX_SESSIONS_PER_SERVER) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'server_session_limit' }))
	}

	const existing = udpClientPool.get(sessionId)
	if (existing) {
		if (existing.clientWallet !== clientWallet || existing.serverWallet !== serverWallet) {
			return response200Html(socket, JSON.stringify({ ok: false, error: 'session_conflict' }))
		}
		destroyListenSocket(existing.res)
		resetWriterQueue(existing.writer)
		udpClientPool.delete(sessionId)
	}

	const ipaddress = socket.remoteAddressShow || ''
	const writer = makeWriter(socket, (why) => {
		const cur = udpClientPool.get(sessionId)
		if (cur && cur.res === socket) {
			dropClientSession(sessionId, why)
		}
	})
	const session: UdpClientSession = {
		sessionId,
		clientWallet,
		serverWallet,
		res: socket,
		ipaddress,
		connectedAt: nowMs(),
		lastActivityAt: nowMs(),
		seqDown: 0,
		writer,
	}
	bindListenLifecycle(socket, (why) => {
		const cur = udpClientPool.get(sessionId)
		if (cur && cur.res === socket) {
			resetWriterQueue(cur.writer)
			udpClientPool.delete(sessionId)
			logger(Colors.grey(`udp_listen ${sessionId} ${why}`))
		}
	})

	const handshake = {
		ok: true,
		status: 200,
		kind: 'udp' as const,
		sessionId,
		clientWallet,
		udpServerWallet: serverWallet,
		nodeWallet: nodeWallet.address?.toLowerCase() || '',
	}
	const first = sseHeaders() + `data: ${JSON.stringify(handshake)}\r\n\r\n`
	if (isLivenessListenSocketStale(socket)) {
		return
	}
	socket.write(first, (err) => {
		if (err) {
			logger(Colors.red(`udp_listen handshake write fail ${sessionId}`))
			return
		}
		udpClientPool.set(sessionId, session)
		scheduleSweep()
		logger(Colors.cyan(`udp_listen attached session=${sessionId} client=${clientWallet} server=${serverWallet}`))
		notifyServer(serverWallet, {
			type: 'udp_listen_attached',
			sessionId,
			clientWallet,
			udpServerWallet: serverWallet,
			timestamp: Math.floor(Date.now() / 1000),
		})
	})
}

/**
 * UDP server long-lived SSE on its own mailbox (to receive listen-attached + uplink).
 * Subscribe (AES key) still arrives as user-PGP gossip on chat listen.
 */
export const handleUdpServerListen = async (
	socket: Socket,
	command: minerObj,
	nodeWallet: ethers.Wallet,
) => {
	const serverWallet = lowerAddr(command.walletAddress)
	if (!serverWallet) {
		return distorySocket(socket)
	}
	if (!timestampOk((command as any).timestamp)) {
		return distorySocket(socket)
	}
	const mine = await isMyRoute(serverWallet, nodeWallet.address)
	if (!mine) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'not_my_route', wallet: serverWallet }))
	}
	const prev = udpServerPool.get(serverWallet)
	if (prev) {
		resetWriterQueue(prev.writer)
		destroyListenSocket(prev.res)
		udpServerPool.delete(serverWallet)
	}
	const writer = makeWriter(socket, (why) => {
		const cur = udpServerPool.get(serverWallet)
		if (cur && cur.res === socket) {
			dropServerListen(serverWallet, why)
		}
	})
	const rec: UdpServerListen = {
		serverWallet,
		res: socket,
		ipaddress: socket.remoteAddressShow || '',
		connectedAt: nowMs(),
		lastActivityAt: nowMs(),
		writer,
	}
	bindListenLifecycle(socket, (why) => {
		const cur = udpServerPool.get(serverWallet)
		if (cur && cur.res === socket) {
			resetWriterQueue(cur.writer)
			udpServerPool.delete(serverWallet)
			logger(Colors.grey(`udp_server_listen ${serverWallet} ${why}`))
		}
	})
	const handshake = {
		ok: true,
		status: 200,
		kind: 'udp_server' as const,
		wallet: serverWallet,
		nodeWallet: nodeWallet.address?.toLowerCase() || '',
	}
	const first = sseHeaders() + `data: ${JSON.stringify(handshake)}\r\n\r\n`
	if (isLivenessListenSocketStale(socket)) return
	socket.write(first, (err) => {
		if (err) {
			logger(Colors.red(`udp_server_listen handshake write fail ${serverWallet}`))
			return
		}
		udpServerPool.set(serverWallet, rec)
		scheduleSweep()
		logger(Colors.cyan(`udp_server_listen attached server=${serverWallet}`))
	})
}

/**
 * If mailbox decrypted `udp_subscribe`, the client encrypted to route PGP (wrong).
 * Refuse so Securitykey is never stored on B.
 */
export const handleUdpSubscribeMisrouted = (socket: Socket) => {
	logger(Colors.yellow(`udp_subscribe decrypted on mailbox — encrypt to UDP server user PGP, not route B`))
	return response200Html(
		socket,
		JSON.stringify({
			ok: false,
			error: 'encrypt_to_udp_server_user_pgp',
			hint: 'udp_subscribe is a business message; mailbox only forwards opaque PGP',
		}),
	)
}

/** UDP server → client: AES blob, B cannot decrypt. */
export const handleUdpRelay = async (
	socket: Socket,
	command: minerObj,
	nodeWallet: ethers.Wallet,
) => {
	const serverWallet = lowerAddr(command.walletAddress)
	const sessionId = normalizeUdpSessionId((command as any).sessionId)
	const payload = (command as any).payload
	if (!serverWallet || !sessionId) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'invalid_session' }))
	}
	if (!timestampOk((command as any).timestamp)) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'timestamp' }))
	}
	if (!payloadOk(payload)) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'invalid_payload' }))
	}
	const mine = await isMyRoute(serverWallet, nodeWallet.address)
	if (!mine) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'not_my_route' }))
	}
	const session = udpClientPool.get(sessionId)
	if (!session || session.serverWallet !== serverWallet) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'client_not_listening', sessionId }))
	}
	if (isLivenessListenSocketStale(session.res)) {
		dropClientSession(sessionId, 'stale_on_relay')
		return response200Html(socket, JSON.stringify({ ok: false, error: 'client_not_listening', sessionId }))
	}
	session.seqDown += 1
	session.lastActivityAt = nowMs()
	const frame = {
		type: 'udp_frame',
		dir: 'down',
		sessionId,
		seq: session.seqDown,
		payload,
		timestamp: Math.floor(Date.now() / 1000),
	}
	const wr = deliverSseJson(session.writer, frame)
	if (wr === 'closed') {
		dropClientSession(sessionId, 'relay_write_closed')
		return response200Html(socket, JSON.stringify({ ok: false, error: 'client_not_listening', sessionId }))
	}
	// accepted | backpressured | queued — frame is on the wire buffer or in the session queue
	return response200Html(
		socket,
		JSON.stringify({
			ok: true,
			sessionId,
			seq: session.seqDown,
			delivered: wr === 'accepted' || wr === 'backpressured',
			queued: wr === 'queued' || wr === 'backpressured',
		}),
	)
}

/** Client → UDP server: AES blob, B cannot decrypt. */
export const handleUdpUplink = async (
	socket: Socket,
	command: minerObj,
	nodeWallet: ethers.Wallet,
) => {
	const clientWallet = lowerAddr(command.walletAddress)
	const sessionId = normalizeUdpSessionId((command as any).sessionId)
	const payload = (command as any).payload
	if (!clientWallet || !sessionId) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'invalid_session' }))
	}
	if (!timestampOk((command as any).timestamp)) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'timestamp' }))
	}
	if (!payloadOk(payload)) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'invalid_payload' }))
	}
	const session = udpClientPool.get(sessionId)
	if (!session || session.clientWallet !== clientWallet) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'session_not_found', sessionId }))
	}
	const mine = await isMyRoute(session.serverWallet, nodeWallet.address)
	if (!mine) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'not_my_route' }))
	}
	session.lastActivityAt = nowMs()
	const frame = {
		type: 'udp_frame',
		dir: 'up',
		sessionId,
		clientWallet,
		payload,
		timestamp: Math.floor(Date.now() / 1000),
	}
	const dedicated = udpServerPool.get(session.serverWallet)
	let delivered = false
	let queued = false
	if (dedicated && !isLivenessListenSocketStale(dedicated.res)) {
		dedicated.lastActivityAt = nowMs()
		const wr = deliverSseJson(dedicated.writer, frame)
		if (wr === 'closed') {
			dropServerListen(session.serverWallet, 'uplink_write_closed')
		} else {
			// accepted | backpressured | queued — frame retained
			delivered = true
			queued = wr === 'queued' || wr === 'backpressured'
		}
	}
	if (!delivered && !queued && notifyUdpServerChatListen) {
		delivered = notifyUdpServerChatListen(session.serverWallet, frame)
	}
	if (!delivered && !queued) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'server_not_listening', sessionId }))
	}
	return response200Html(
		socket,
		JSON.stringify({ ok: true, sessionId, delivered: true, queued }),
	)
}

export const handleUdpUnlisten = (
	socket: Socket,
	command: minerObj,
) => {
	const clientWallet = lowerAddr(command.walletAddress)
	const sessionId = normalizeUdpSessionId((command as any).sessionId)
	if (!clientWallet || !sessionId) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'invalid_session' }))
	}
	const session = udpClientPool.get(sessionId)
	if (!session || session.clientWallet !== clientWallet) {
		return response200Html(socket, JSON.stringify({ ok: true, sessionId, closed: false }))
	}
	dropClientSession(sessionId, 'unlisten')
	notifyServer(session.serverWallet, {
		type: 'udp_listen_detached',
		sessionId,
		clientWallet,
		timestamp: Math.floor(Date.now() / 1000),
	})
	return response200Html(socket, JSON.stringify({ ok: true, sessionId, closed: true }))
}

export const udpForwardPoolStats = () => ({
	clients: udpClientPool.size,
	servers: udpServerPool.size,
})
