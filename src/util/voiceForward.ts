/**
 * Temporary CoNET Chat voice relay.
 *
 * A voice session is deliberately separate from `mailbox_listen`: the normal
 * mailbox SSE remains available for messages, receipts and offline delivery.
 * Voice protocol v3: each call has four paid channels (voice and video, one
 * per direction). Each side opens its two on relays it picks (never a
 * mailbox). A listen is accepted only with the temporary wallet's signature
 * bound to this relay and the payer wallet's signature over that wallet.
 * Chunks are opaque blobs plus a channel locator; the node checks the write
 * key MAC and forwards them. It never decrypts the media. Older listens and
 * v1 `voice_uplink` frames are not accepted.
 */
import type { Socket } from 'net'
import type { TLSSocket } from 'tls'
import { createHmac, timingSafeEqual } from 'crypto'
import { ethers } from 'ethers'
import Colors from 'colors/safe'
import { logger } from './logger'
import { distorySocket, response200Html } from './htmlResponse'
import { isLivenessListenSocketStale } from './util'

const VOICE_IDLE_MS = 2 * 60 * 1000
const VOICE_SWEEP_MS = 30_000
const VOICE_MAX_GLOBAL = 256
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

/**
 * Voice listen v3: every voice SSE is paid. The payer wallet signs the
 * channel's temporary wallet T (`voicePayText`); T signs this listen
 * (`voiceListenText`), bound to this relay's route key ID. The node only
 * checks the two signatures and `notAfter`. Settlement and the `maxBytes` /
 * `maxSeconds` limits are reserved for later; nothing is metered here.
 */
const VOICE_PAY_MAX_VALID_MS = 48 * 60 * 60 * 1000
const VOICE_TEMP_WALLET_MAX = 50_000
/** T → the one session it opened. A T is single-use; a reconnect reopens the same sessionId. */
const tempWallets = new Map<string, { sessionId: string; notAfter: number }>()

export type VoicePayAuth = {
	payer: string
	notAfter: number
	maxBytes: number
	maxSeconds: number
	sig: string
}

export const voicePayText = (temp: string, notAfter: number, maxBytes: number, maxSeconds: number): string =>
	[
		'conet.voice.sse.pay.v3',
		`temp=${temp.toLowerCase()}`,
		`notAfter=${notAfter}`,
		`maxBytes=${maxBytes}`,
		`maxSeconds=${maxSeconds}`,
	].join('\n')

export const voiceListenText = (sessionId: string, wk: string, relayKeyId: string, timestamp: number): string =>
	['conet.voice.sse.listen.v3', sessionId, wk, relayKeyId.toUpperCase(), String(timestamp)].join('|')

const nonNegativeInt = (value: unknown): number | null => {
	const n = Number(value)
	return Number.isSafeInteger(n) && n >= 0 ? n : null
}

const recoverSigner = (text: string, sig: unknown): string => {
	if (typeof sig !== 'string' || !sig) return ''
	try {
		return ethers.verifyMessage(text, sig).toLowerCase()
	} catch {
		return ''
	}
}

/**
 * Checks a v3 listen. Returns the write key and the temporary wallet, or the
 * error the client gets. `relayKeyId` is this node's route key ID (its domain).
 */
export const verifyVoiceListenV3 = (
	command: Record<string, unknown>,
	relayKeyId: string,
	nowMs = Date.now(),
): { ok: true; sessionId: string; writeKey: Buffer; temp: string; notAfter: number } | { ok: false; error: string } => {
	if (Number(command.v) !== 3) return { ok: false, error: 'voice_listen_v3_required' }
	const sessionId = typeof command.sessionId === 'string' ? command.sessionId.trim() : ''
	if (!VOICE_V2_SESSION_RE.test(sessionId)) return { ok: false, error: 'invalid_voice_session' }
	const wk = typeof command.wk === 'string' ? command.wk.trim() : ''
	let writeKey: Buffer
	try {
		writeKey = Buffer.from(wk, 'base64')
	} catch {
		return { ok: false, error: 'invalid_voice_session' }
	}
	if (writeKey.length !== 32) return { ok: false, error: 'invalid_voice_session' }
	const timestamp = Number(command.timestamp)
	if (!Number.isSafeInteger(timestamp) || Math.abs(Math.floor(nowMs / 1000) - timestamp) > VOICE_TIMESTAMP_SKEW_SEC) {
		return { ok: false, error: 'invalid_voice_timestamp' }
	}
	const temp = typeof command.temp === 'string' && ethers.isAddress(command.temp) ? command.temp.toLowerCase() : ''
	if (!temp || !relayKeyId) return { ok: false, error: 'voice_temp_auth' }
	if (recoverSigner(voiceListenText(sessionId, wk, relayKeyId, timestamp), command.tempSig) !== temp) {
		return { ok: false, error: 'voice_temp_auth' }
	}
	const pay = (command.pay && typeof command.pay === 'object' ? command.pay : {}) as Record<string, unknown>
	const payer = typeof pay.payer === 'string' && ethers.isAddress(pay.payer) ? pay.payer.toLowerCase() : ''
	const notAfter = nonNegativeInt(pay.notAfter)
	const maxBytes = nonNegativeInt(pay.maxBytes)
	const maxSeconds = nonNegativeInt(pay.maxSeconds)
	if (!payer || notAfter === null || maxBytes === null || maxSeconds === null) {
		return { ok: false, error: 'voice_pay_auth' }
	}
	if (notAfter * 1000 <= nowMs || notAfter * 1000 > nowMs + VOICE_PAY_MAX_VALID_MS) {
		return { ok: false, error: 'voice_pay_expired' }
	}
	if (recoverSigner(voicePayText(temp, notAfter, maxBytes, maxSeconds), pay.sig) !== payer) {
		return { ok: false, error: 'voice_pay_auth' }
	}
	const used = tempWallets.get(temp)
	if (used && used.notAfter * 1000 > nowMs && used.sessionId !== sessionId) {
		return { ok: false, error: 'voice_temp_reused' }
	}
	return { ok: true, sessionId, writeKey, temp, notAfter }
}

const sweepTempWallets = (nowMs: number): void => {
	for (const [temp, used] of tempWallets) {
		if (used.notAfter * 1000 <= nowMs) tempWallets.delete(temp)
	}
}

const validSessionId = (value: unknown): value is string =>
	typeof value === 'string' && VOICE_SESSION_RE.test(value.trim())

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
		sweepTempWallets(now)
		for (const [sessionId, session] of sessions) {
			if (now - session.lastActivityAt > VOICE_IDLE_MS || isLivenessListenSocketStale(session.res)) {
				removeSession(sessionId, 'idle_or_stale')
			}
		}
		if (sessions.size || tempWallets.size) scheduleSweep()
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
	relayKeyId = '',
): Promise<void> => {
	// v3 only: a listen without a valid payment signature is refused.
	const auth = verifyVoiceListenV3(command, relayKeyId)
	if (!auth.ok) {
		logger(Colors.yellow(`voice listen refused ${auth.error}`))
		return response200Html(socket, JSON.stringify({ ok: false, error: auth.error }))
	}
	const { sessionId, writeKey } = auth
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
		// `v: 2` = chunk format; `listen: 3` = paid listen accepted.
		v: 2,
		listen: 3,
	}
	if (!writeFrame({ ...session, paused: false, queue: [] }, headers + frameLine(handshake))) {
		return remove('handshake_failed')
	}
	sessions.set(sessionId, session)
	tempWallets.set(auth.temp, { sessionId, notAfter: auth.notAfter })
	// Bound memory: drop the oldest records first (Map keeps insertion order).
	while (tempWallets.size > VOICE_TEMP_WALLET_MAX) {
		const oldest = tempWallets.keys().next().value
		if (oldest === undefined) break
		tempWallets.delete(oldest)
	}
	scheduleSweep()
	logger(Colors.cyan(`voice listen attached session=${sessionId} v3`))
	// Only the callee's own mailbox rings the callee (`voice_offer_store` with
	// push: 1). Legacy wake fields (`targetWallet`, `offerArmor`, `callId`) are
	// ignored here: the session node must not learn who is being called.
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
