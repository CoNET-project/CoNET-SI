/**
 * Temporary CoNET Chat voice relay.
 *
 * A voice session is deliberately separate from `mailbox_listen`: the normal
 * mailbox SSE remains available for messages, receipts and offline delivery.
 * Each participant opens a random voice SSE on its own mailbox. Encrypted voice
 * frames are short route commands sent to the peer mailbox and written to the
 * peer's temporary SSE. The mailbox never decrypts the audio payload.
 */
import type { Socket } from 'net'
import type { TLSSocket } from 'tls'
import { createHmac, timingSafeEqual } from 'crypto'
import { ethers } from 'ethers'
import Colors from 'colors/safe'
import { logger } from './logger'
import { distorySocket, response200Html } from './htmlResponse'
import { isLivenessListenSocketStale, notifyVoiceCallPush } from './util'

const VOICE_IDLE_MS = 2 * 60 * 1000
const VOICE_SWEEP_MS = 30_000
const VOICE_MAX_GLOBAL = 256
const VOICE_MAX_PAYLOAD_B64 = 12_000
const VOICE_TIMESTAMP_SKEW_SEC = 10 * 60
const VOICE_SESSION_RE = /^[0-9a-fA-F-]{16,64}$/

/**
 * Voice channel v2 (CoNET Chat rule 23). The listener registers a 16-byte
 * channel locator (its 32-hex sessionId) and a 32-byte write key once. Every
 * later chunk is a binary OpenPGP literal `CVC2 ‖ locator(16) ‖ mac(16) ‖ blob`
 * with no per-frame metadata; the node checks the MAC and forwards the blob.
 */
export const VOICE_CHUNK_MAGIC = Buffer.from('CVC2', 'ascii')
const VOICE_V2_SESSION_RE = /^[0-9a-f]{32}$/
const VOICE_CHUNK_HEADER = 4 + 16 + 16
const VOICE_CHUNK_MAX_BLOB = 9_000
const VOICE_CHUNK_MAX_PER_SEC = 100
const VOICE_CHUNK_MAX_BYTES_PER_SEC = 600_000

type VoiceSession = {
	sessionId: string
	res: Socket | TLSSocket
	lastActivityAt: number
	paused: boolean
	queue: string[]
	drainTimer?: ReturnType<typeof setTimeout>
	/** v2: HMAC key for chunks written to this channel. */
	writeKey?: Buffer
	rateWindowAt: number
	rateChunks: number
	rateBytes: number
}

const sessions = new Map<string, VoiceSession>()
let sweepTimer: ReturnType<typeof setTimeout> | undefined

const lowerAddress = (value: unknown): string => {
	if (typeof value !== 'string' || !ethers.isAddress(value)) return ''
	return value.toLowerCase()
}

const validSessionId = (value: unknown): value is string =>
	typeof value === 'string' && VOICE_SESSION_RE.test(value.trim())

const validTimestamp = (value: unknown): boolean => {
	const timestamp = Number(value)
	if (!Number.isFinite(timestamp)) return false
	return Math.abs(Math.floor(Date.now() / 1000) - timestamp) <= VOICE_TIMESTAMP_SKEW_SEC
}

const validPayload = (value: unknown): value is string =>
	typeof value === 'string' && value.length > 0 && value.length <= VOICE_MAX_PAYLOAD_B64

const removeSession = (sessionId: string, reason: string): void => {
	const session = sessions.get(sessionId)
	if (!session) return
	sessions.delete(sessionId)
	if (session.drainTimer) clearTimeout(session.drainTimer)
	logger(Colors.grey(`voice session=${sessionId} ${reason}`))
	try {
		const stream = session.res as Socket
		if (!stream.destroyed) stream.destroy()
	} catch {
		/* ignore */
	}
}

const scheduleSweep = (): void => {
	if (sweepTimer !== undefined) return
	sweepTimer = setTimeout(() => {
		sweepTimer = undefined
		const now = Date.now()
		for (const [sessionId, session] of sessions) {
			if (now - session.lastActivityAt > VOICE_IDLE_MS || isLivenessListenSocketStale(session.res)) {
				removeSession(sessionId, 'idle_or_stale')
			}
		}
		if (sessions.size) scheduleSweep()
	}, VOICE_SWEEP_MS)
}

const writeFrame = (session: VoiceSession, line: string): boolean => {
	if (isLivenessListenSocketStale(session.res)) return false
	if (session.paused) {
		if (session.queue.length >= 32) session.queue.shift()
		session.queue.push(line)
		return true
	}
	try {
		const accepted = (session.res as Socket).write(line)
		if (!accepted) {
			session.paused = true
			session.drainTimer = setTimeout(() => removeSession(session.sessionId, 'drain_timeout'), 2_000)
			session.res.once('drain', () => {
				if (session.drainTimer) clearTimeout(session.drainTimer)
				session.drainTimer = undefined
				session.paused = false
				while (session.queue.length && !session.paused) {
					const queued = session.queue.shift()
					if (queued) writeFrame(session, queued)
				}
			})
		}
		return true
	} catch {
		return false
	}
}

const frameLine = (frame: Record<string, unknown>): string =>
	`data: ${JSON.stringify(frame)}\r\n\r\n`

export const handleVoiceListen = async (
	socket: Socket,
	command: Record<string, unknown>,
	nodeWallet: ethers.Wallet,
): Promise<void> => {
	const sessionId = validSessionId(command.sessionId) ? command.sessionId.trim() : ''
	if (!sessionId || !validTimestamp(command.timestamp)) return distorySocket(socket)
	// v2 opt-in: lowercase 32-hex locator plus a 32-byte write key. A bad v2
	// request falls back to a v1 session; the client reads `v` in voice_ready.
	let writeKey: Buffer | undefined
	if (Number(command.v) === 2 && VOICE_V2_SESSION_RE.test(sessionId) && typeof command.wk === 'string') {
		try {
			const key = Buffer.from(command.wk, 'base64')
			if (key.length === 32) writeKey = key
		} catch { /* ignore */ }
	}
	try { socket.setTimeout(0) } catch { /* ignore */ }
	if (sessions.size >= VOICE_MAX_GLOBAL) return response200Html(socket, JSON.stringify({ ok: false, error: 'pool_full' }))
	if (sessions.has(sessionId)) return response200Html(socket, JSON.stringify({ ok: false, error: 'session_conflict' }))

	const session: VoiceSession = {
		sessionId,
		res: socket,
		lastActivityAt: Date.now(),
		paused: false,
		queue: [],
		writeKey,
		rateWindowAt: Date.now(),
		rateChunks: 0,
		rateBytes: 0,
	}
	const remove = (reason: string) => {
		if (sessions.get(sessionId)?.res === socket) removeSession(sessionId, reason)
	}
	socket.once('error', () => remove('error'))
	socket.once('close', () => remove('close'))
	socket.once('end', () => logger(Colors.grey(`voice session=${sessionId} half-close; keep writable`)))

	const headers =
		`HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\n` +
		`Cache-Control: no-cache, no-transform\r\nConnection: keep-alive\r\n` +
		`X-Accel-Buffering: no\r\nAccess-Control-Allow-Origin: *\r\n\r\n`
	const handshake = {
		type: 'voice_ready',
		ok: true,
		sessionId,
		nodeWallet: nodeWallet.address.toLowerCase(),
		...(writeKey ? { v: 2 } : {}),
	}
	if (!writeFrame({ ...session, paused: false, queue: [] }, headers + frameLine(handshake))) {
		return remove('handshake_failed')
	}
	sessions.set(sessionId, session)
	scheduleSweep()
	logger(Colors.cyan(`voice listen attached session=${sessionId}${writeKey ? ' v2' : ''}`))

	// The caller's mailbox is the only component that wakes native devices.
	// The PWA never calls /api/voiceCallPush directly, so the API sees the
	// mailbox node as the network source rather than the caller's IP.
	// relayVoiceOfferArmor already stored the attached user-PGP offer on the
	// callee mailbox before this push.
	const callId = typeof command.callId === 'string' ? command.callId.trim() : ''
	const calleeEoa = lowerAddress(command.targetWallet)
	const expiresAt = Number(command.expiresAt)
	const pushTimestamp = Number(command.pushTimestamp)
	if (
		callId &&
		calleeEoa &&
		Number.isFinite(expiresAt) &&
		expiresAt > Date.now() &&
		expiresAt <= Date.now() + 10 * 60_000 &&
		validTimestamp(pushTimestamp)
	) {
		notifyVoiceCallPush({
			callId,
			sessionId,
			calleeEoa,
			expiresAt,
			timestamp: pushTimestamp,
		})
	} else if (callId || calleeEoa) {
		logger(Colors.yellow(
			`voiceCallPush skipped callId=${callId ? 'yes' : 'no'} callee=${calleeEoa ? 'yes' : 'no'} expiresOk=${Number.isFinite(expiresAt) && expiresAt > Date.now() && expiresAt <= Date.now() + 10 * 60_000} tsOk=${validTimestamp(pushTimestamp)}`
		))
	}
}

export const handleVoiceUnlisten = (
	socket: Socket,
	command: Record<string, unknown>,
): void => {
	const sessionId = validSessionId(command.sessionId) ? command.sessionId.trim() : ''
	const session = sessions.get(sessionId)
	if (session) removeSession(sessionId, 'unlisten')
	return response200Html(socket, JSON.stringify({ ok: true, sessionId }))
}

export const handleVoiceFrame = async (
	socket: Socket,
	command: Record<string, unknown>,
	nodeWallet: ethers.Wallet,
): Promise<void> => {
	const targetSessionId = validSessionId(command.targetSessionId) ? command.targetSessionId.trim() : ''
	const callId = typeof command.callId === 'string' ? command.callId.trim() : ''
	const sessionId = validSessionId(command.sessionId) ? command.sessionId.trim() : ''
	const payload = command.payload
	const seq = Number(command.seq)
	if (!targetSessionId || !sessionId || !callId || !validPayload(payload) ||
		!Number.isSafeInteger(seq) || seq < 0 || !validTimestamp(command.timestamp)) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'invalid_voice_frame' }))
	}
	const target = sessions.get(targetSessionId)
	if (!target || isLivenessListenSocketStale(target.res)) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'target_voice_session_not_found' }))
	}
	target.lastActivityAt = Date.now()
	const frame = frameLine({
		type: 'voice_frame_v1',
		callId,
		sessionId,
		seq,
		timestamp: Math.floor(Date.now() / 1000),
		payload,
	})
	if (!writeFrame(target, frame)) {
		removeSession(targetSessionId, 'frame_write_failed')
		return response200Html(socket, JSON.stringify({ ok: false, error: 'target_voice_session_closed' }))
	}
	return response200Html(socket, JSON.stringify({ ok: true, sessionId, seq }))
}

/** True when the decrypted route literal is a v2 voice chunk. */
export const isVoiceChunk = (data: Uint8Array): boolean =>
	data instanceof Uint8Array &&
	data.length > VOICE_CHUNK_HEADER &&
	Buffer.from(data.buffer, data.byteOffset, 4).equals(VOICE_CHUNK_MAGIC)

const chunkMac = (key: Buffer, locator: Buffer, blob: Buffer): Buffer =>
	createHmac('sha256', key).update(locator).update(blob).digest().subarray(0, 16)

const overRate = (session: VoiceSession, bytes: number): boolean => {
	const now = Date.now()
	if (now - session.rateWindowAt >= 1_000) {
		session.rateWindowAt = now
		session.rateChunks = 0
		session.rateBytes = 0
	}
	session.rateChunks += 1
	session.rateBytes += bytes
	return session.rateChunks > VOICE_CHUNK_MAX_PER_SEC || session.rateBytes > VOICE_CHUNK_MAX_BYTES_PER_SEC
}

/**
 * v2 chunk: `CVC2 ‖ locator(16) ‖ mac(16) ‖ blob`. The node reads only the
 * locator, checks the MAC with the channel's write key, and writes the opaque
 * blob to that channel's SSE. No seq, time, call id or media kind.
 */
export const handleVoiceChunk = (socket: Socket, data: Uint8Array): void => {
	const buf = Buffer.from(data.buffer, data.byteOffset, data.byteLength)
	const locator = buf.subarray(4, 20)
	const mac = buf.subarray(20, VOICE_CHUNK_HEADER)
	const blob = buf.subarray(VOICE_CHUNK_HEADER)
	if (!blob.length || blob.length > VOICE_CHUNK_MAX_BLOB) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'invalid_voice_chunk' }))
	}
	const target = sessions.get(locator.toString('hex'))
	if (!target || !target.writeKey || isLivenessListenSocketStale(target.res)) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'target_voice_session_not_found' }))
	}
	if (!timingSafeEqual(mac, chunkMac(target.writeKey, locator, blob))) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'voice_chunk_auth' }))
	}
	if (overRate(target, blob.length)) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'voice_chunk_rate' }))
	}
	target.lastActivityAt = Date.now()
	if (!writeFrame(target, frameLine({ t: 'c', d: blob.toString('base64') }))) {
		removeSession(target.sessionId, 'chunk_write_failed')
		return response200Html(socket, JSON.stringify({ ok: false, error: 'target_voice_session_closed' }))
	}
	return response200Html(socket, JSON.stringify({ ok: true }))
}

export const voiceForwardPoolStats = (): { sessions: number } => ({
	sessions: sessions.size,
})
