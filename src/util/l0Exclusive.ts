/**
 * CoNET L0 exclusive occupancy pipe.
 *
 * Idle `l0_listen` SSE may still receive user-PGP gossip (application offers).
 * The first `l0_connect` (route-PGP signed command) occupies the SSE: SI pipes
 * remaining inbound TCP bytes onto that SSE, then relinquishes control.
 * A second `l0_connect` to the occupied wallet is 409. User-PGP Chat /
 * mining gossip on the same node must continue (do not 409 those).
 *
 * Overlay AES keys must never appear in these B-decryptable commands.
 */
import type { Socket } from 'net'
import type { TLSSocket } from 'tls'
import { ethers } from 'ethers'
import Colors from 'colors/safe'
import { logger } from './logger'
import { distorySocket, response200Html } from './htmlResponse'
import { isMyRoute, isLivenessListenSocketStale, getWalletFromKeyID } from './util'

const L0_TIMESTAMP_SKEW_SEC = 600
const L0_MAX_LISTEN = 256
/** Idle L0 has no mining epoch heartbeat. Comment ticks keep Entry/mailbox 60s socket timeout from killing the SSE. */
const L0_IDLE_KEEPALIVE_MS = 15_000

export interface L0Listen {
	wallet: string
	res: Socket | TLSSocket
	ipaddress: string
	connectedAt: number
	pgpKeyId?: string
	occupied: boolean
	occupiedBy?: string
	inbound?: Socket | TLSSocket
	keepaliveTimer?: ReturnType<typeof setTimeout>
}

const l0ListenPool: Map<string, L0Listen> = new Map()
const l0ListenByPgp: Map<string, L0Listen> = new Map()

const nowMs = () => Date.now()

const lowerAddr = (raw: unknown): string => {
	if (typeof raw !== 'string') return ''
	const t = raw.trim()
	if (!t || !ethers.isAddress(t)) return ''
	return t.toLowerCase()
}

const timestampOk = (raw: unknown): boolean => {
	const ts = Number(raw)
	if (!Number.isFinite(ts)) return false
	const now = Math.floor(Date.now() / 1000)
	return Math.abs(now - ts) <= L0_TIMESTAMP_SKEW_SEC
}

const normalizePgp = (id: string): string =>
	String(id || '').replace(/[^a-zA-Z0-9]/g, '').toUpperCase()

const sseHeaders = (): string =>
	`HTTP/1.1 200 OK\r\n` +
	`Date: ${new Date().toUTCString()}\r\n` +
	`Content-Type: text/event-stream; charset=utf-8\r\n` +
	`Cache-Control: no-cache, no-transform\r\n` +
	`Connection: keep-alive\r\n` +
	`X-Accel-Buffering: no\r\n` +
	`Access-Control-Allow-Origin: *\r\n` +
	`\r\n`

/** `write()===false` is backpressure, not failure. */
type L0SseWriteResult = 'accepted' | 'backpressured' | 'closed'

const tryWriteSse = (res: Socket | TLSSocket, payload: string): L0SseWriteResult => {
	const s = res as Socket
	if (isLivenessListenSocketStale(s)) return 'closed'
	try {
		return s.write(payload) ? 'accepted' : 'backpressured'
	} catch {
		return 'closed'
	}
}

const writeSseJson = (res: Socket | TLSSocket, obj: Record<string, unknown>): L0SseWriteResult =>
	tryWriteSse(res, `data: ${JSON.stringify(obj)}\r\n\r\n`)

const writeSseLine = (res: Socket | TLSSocket, line: string): L0SseWriteResult =>
	tryWriteSse(res, `data: ${line}\r\n\r\n`)

const disableSocketIdleTimeout = (sock?: Socket | TLSSocket) => {
	if (!sock) return
	try {
		;(sock as Socket).setTimeout(0)
	} catch {
		/* ignore */
	}
}

const clearKeepalive = (listen: L0Listen) => {
	if (listen.keepaliveTimer === undefined) return
	clearTimeout(listen.keepaliveTimer)
	listen.keepaliveTimer = undefined
}

const armListenKeepalive = (listen: L0Listen) => {
	clearKeepalive(listen)
	const tick = () => {
		listen.keepaliveTimer = undefined
		const live = l0ListenPool.get(listen.wallet)
		if (live !== listen) return
		if (isLivenessListenSocketStale(listen.res)) {
			dropL0Listen(listen.wallet, 'stale_keepalive')
			return
		}
		const wr = tryWriteSse(listen.res, ': keepalive\n\n')
		if (wr === 'closed') {
			dropL0Listen(listen.wallet, 'keepalive_closed')
			return
		}
		listen.keepaliveTimer = setTimeout(tick, L0_IDLE_KEEPALIVE_MS)
	}
	listen.keepaliveTimer = setTimeout(tick, L0_IDLE_KEEPALIVE_MS)
}

const occupyHttpOkHeaders = (): string =>
	`HTTP/1.1 200 OK\r\n` +
	`Date: ${new Date().toUTCString()}\r\n` +
	`Content-Type: application/octet-stream\r\n` +
	`Cache-Control: no-cache, no-transform\r\n` +
	`Connection: keep-alive\r\n` +
	`X-Accel-Buffering: no\r\n` +
	`Access-Control-Allow-Origin: *\r\n` +
	`\r\n`

const destroySock = (res?: Socket | TLSSocket) => {
	if (!res) return
	try {
		const s = res as Socket
		if (!s.destroyed) s.destroy()
	} catch {
		/* ignore */
	}
}

/** Best-effort JSON line on occupied inbound TCP so connector knows SI released the pipe. */
const emitL0PipeEnd = (listen: L0Listen, reason: string) => {
	if (!listen.occupied || !listen.inbound) return
	const payload =
		JSON.stringify({
			type: 'l0_pipe_end',
			wallet: listen.wallet,
			connector: listen.occupiedBy,
			reason,
		}) + '\n'
	try {
		const inbound = listen.inbound as Socket
		if (!inbound.destroyed) inbound.write(payload)
	} catch {
		/* best-effort */
	}
}

const dropL0Listen = (wallet: string, why: string) => {
	const obj = l0ListenPool.get(wallet)
	if (!obj) return
	clearKeepalive(obj)
	if (obj.occupied) {
		emitL0PipeEnd(obj, why)
		writeSseJson(obj.res, {
			type: 'l0_listen_released',
			wallet: obj.wallet,
			reason: why,
		})
	}
	l0ListenPool.delete(wallet)
	if (obj.pgpKeyId) {
		l0ListenByPgp.delete(obj.pgpKeyId)
		l0ListenByPgp.delete(normalizePgp(obj.pgpKeyId))
	}
	logger(Colors.grey(`l0_listen drop wallet=${wallet} occupied=${obj.occupied} ${why}`))
	destroySock(obj.inbound)
	destroySock(obj.res)
}

const findByPgp = (gpgPublicKeyID: string): L0Listen | undefined => {
	const want = normalizePgp(gpgPublicKeyID)
	if (!want) return undefined
	const direct = l0ListenByPgp.get(want) ?? l0ListenByPgp.get(gpgPublicKeyID)
	if (direct) return direct
	for (const [stored, obj] of l0ListenByPgp) {
		if (normalizePgp(stored) === want) return obj
	}
	for (const obj of l0ListenPool.values()) {
		if (obj.pgpKeyId && normalizePgp(obj.pgpKeyId) === want) return obj
	}
	return undefined
}

export const l0ListenOccupiedByPgp = (gpgPublicKeyID: string): boolean => {
	const obj = findByPgp(gpgPublicKeyID)
	return !!(obj && obj.occupied)
}

export const findIdleL0ListenByPgp = (gpgPublicKeyID: string): L0Listen | undefined => {
	const obj = findByPgp(gpgPublicKeyID)
	if (!obj || obj.occupied) return undefined
	if (isLivenessListenSocketStale(obj.res)) {
		dropL0Listen(obj.wallet, 'stale_idle')
		return undefined
	}
	return obj
}

/** Idle L0 SSE may receive user-PGP gossip (offers). Does not occupy. */
export const writeGossipToIdleL0 = (listen: L0Listen, armor: string): boolean => {
	if (listen.occupied) return false
	const data = JSON.stringify({ data: armor })
	const wr = writeSseLine(listen.res, data)
	// backpressured = line accepted into socket buffer; only closed is hard fail
	return wr === 'accepted' || wr === 'backpressured'
}

export const rejectOccupiedInflow = (socket: Socket) => {
	distorySocket(socket, '409 Conflict')
}

/**
 * Exclusive long SSE. Encrypt to B route PGP. Never put overlay Securitykey here.
 */
export const handleL0Listen = async (
	socket: Socket,
	command: minerObj,
	nodeWallet: ethers.Wallet,
) => {
	const wallet = lowerAddr(command.walletAddress)
	if (!wallet) {
		logger(Colors.red(`l0_listen missing walletAddress`))
		return distorySocket(socket)
	}
	if ((command as any).Securitykey) {
		logger(Colors.red(`l0_listen refused Securitykey (B would decrypt overlay key)`))
		return distorySocket(socket)
	}
	if (!timestampOk((command as any).timestamp)) {
		logger(Colors.red(`l0_listen timestamp rejected wallet=${wallet}`))
		return distorySocket(socket)
	}
	const mine = await isMyRoute(wallet, nodeWallet.address)
	if (!mine) {
		logger(Colors.yellow(`l0_listen not my route wallet=${wallet}`))
		return response200Html(socket, JSON.stringify({ ok: false, error: 'not_my_route', wallet }))
	}
	if (l0ListenPool.size >= L0_MAX_LISTEN && !l0ListenPool.has(wallet)) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'pool_full' }))
	}

	const existing = l0ListenPool.get(wallet)
	if (existing?.occupied) {
		logger(Colors.yellow(`l0_listen refuse replace while occupied wallet=${wallet} by=${existing.occupiedBy}`))
		return rejectOccupiedInflow(socket)
	}
	if (existing) {
		dropL0Listen(wallet, 'replaced')
	}

	const keyIDRaw = await getWalletFromKeyID(wallet)
	const keyID = keyIDRaw ? normalizePgp(keyIDRaw) : undefined
	const obj: L0Listen = {
		wallet,
		res: socket,
		ipaddress: socket.remoteAddressShow || socket.remoteAddress || '',
		connectedAt: nowMs(),
		pgpKeyId: keyID,
		occupied: false,
	}

	const s = socket as Socket
	disableSocketIdleTimeout(s)
	s.once('error', (err: Error) => dropL0Listen(wallet, `error:${err.message}`))
	s.once('close', () => dropL0Listen(wallet, 'close'))
	s.once('end', () => {
		logger(Colors.grey(`l0_listen peer half-close wallet=${wallet} — keep writable`))
	})

	const handshake =
		sseHeaders() +
		`data: ${JSON.stringify({
			ok: true,
			kind: 'l0',
			wallet,
			nodeWallet: nodeWallet.address?.toLowerCase(),
		})}\r\n\r\n`

	if (!s.write(handshake)) {
		logger(Colors.red(`l0_listen handshake write fail wallet=${wallet}`))
		return dropL0Listen(wallet, 'handshake_write')
	}

	l0ListenPool.set(wallet, obj)
	if (keyID) {
		l0ListenByPgp.set(keyID, obj)
	}
	armListenKeepalive(obj)
	logger(Colors.cyan(`l0_listen idle wallet=${wallet} pgp=${keyID || 'none'}`))
}

/**
 * First route-PGP connect to an idle l0_listen. Occupies, pipes remaining TCP, SI stops parsing.
 */
export const handleL0Connect = async (
	socket: Socket,
	command: minerObj,
	nodeWallet: ethers.Wallet,
) => {
	const connector = lowerAddr(command.walletAddress)
	const target = lowerAddr((command as any).targetWallet)
	if (!connector || !target) {
		logger(Colors.red(`l0_connect missing walletAddress/targetWallet`))
		return distorySocket(socket)
	}
	if ((command as any).Securitykey) {
		logger(Colors.red(`l0_connect refused Securitykey`))
		return distorySocket(socket)
	}
	if (!timestampOk((command as any).timestamp)) {
		logger(Colors.red(`l0_connect timestamp rejected connector=${connector}`))
		return distorySocket(socket)
	}
	const mine = await isMyRoute(target, nodeWallet.address)
	if (!mine) {
		logger(Colors.yellow(`l0_connect not my route target=${target}`))
		return response200Html(socket, JSON.stringify({ ok: false, error: 'not_my_route', targetWallet: target }))
	}

	const listen = l0ListenPool.get(target)
	if (!listen || isLivenessListenSocketStale(listen.res)) {
		if (listen) dropL0Listen(target, 'stale_before_connect')
		logger(Colors.yellow(`l0_connect no idle listen target=${target}`))
		return distorySocket(socket)
	}
	if (listen.occupied) {
		logger(Colors.yellow(`l0_connect occupied target=${target} by=${listen.occupiedBy}`))
		return rejectOccupiedInflow(socket)
	}

	listen.occupied = true
	listen.occupiedBy = connector
	listen.inbound = socket
	logger(Colors.cyan(`l0_connect occupy target=${target} connector=${connector} — SI relinquishes`))

	const occupyWr = writeSseJson(listen.res, {
		type: 'l0_occupied',
		wallet: target,
		connector,
	})
	if (occupyWr === 'closed') {
		dropL0Listen(target, 'occupy_write_closed')
		return distorySocket(socket)
	}

	const inbound = socket as Socket
	const sse = listen.res as Socket
	disableSocketIdleTimeout(inbound)
	disableSocketIdleTimeout(sse)
	let carry = ''
	let ssePaused = occupyWr === 'backpressured'
	let drainBound = false

	const bindSseDrain = () => {
		if (drainBound) return
		drainBound = true
		sse.once('drain', () => {
			drainBound = false
			ssePaused = false
			if (typeof inbound.resume === 'function') inbound.resume()
			flushCarry()
		})
	}

	const flushCarry = (): boolean => {
		const parts = carry.split(/\r?\n/)
		carry = parts.pop() || ''
		for (const line of parts) {
			const trimmed = line.trim()
			if (!trimmed) continue
			if (ssePaused) {
				carry = `${trimmed}\n${carry}`
				return true
			}
			const wr = writeSseLine(sse, trimmed)
			if (wr === 'closed') {
				dropL0Listen(target, 'pipe_write_closed')
				return false
			}
			if (wr === 'backpressured') {
				ssePaused = true
				if (typeof inbound.pause === 'function') inbound.pause()
				bindSseDrain()
			}
		}
		return true
	}

	if (ssePaused) {
		if (typeof inbound.pause === 'function') inbound.pause()
		bindSseDrain()
	}

	inbound.on('data', (buf: Buffer) => {
		carry += buf.toString('utf8')
		if (!flushCarry()) {
			destroySock(inbound)
		}
	})
	inbound.once('error', (err: Error) => dropL0Listen(target, `inbound_error:${err.message}`))
	inbound.once('close', () => dropL0Listen(target, 'inbound_close'))
	sse.once('close', () => destroySock(inbound))
	// Connector waits for HTTP 2xx before the first AES blob. Must write headers
	// without socket.end() — response200Html would close the occupy TCP.
	try {
		inbound.write(occupyHttpOkHeaders())
	} catch {
		dropL0Listen(target, 'occupy_http_write')
		return
	}
	logger(Colors.cyan(`l0_connect occupy HTTP 200 keep-alive target=${target}`))
	// getDataPOST unshifts bytes after Content-Length; emit them now that we listen.
	if (!ssePaused && typeof inbound.resume === 'function') inbound.resume()
}
