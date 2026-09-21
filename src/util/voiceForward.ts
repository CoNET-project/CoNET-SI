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
import { ethers } from 'ethers'
import Colors from 'colors/safe'
import { logger } from './logger'
import { distorySocket, response200Html } from './htmlResponse'
import { isLivenessListenSocketStale, isMyRoute, notifyVoiceCallPush } from './util'

const VOICE_IDLE_MS = 2 * 60 * 1000
const VOICE_SWEEP_MS = 30_000
const VOICE_MAX_GLOBAL = 256
const VOICE_MAX_PER_WALLET = 4
const VOICE_MAX_PAYLOAD_B64 = 12_000
const VOICE_TIMESTAMP_SKEW_SEC = 60
const VOICE_SESSION_RE = /^[0-9a-fA-F-]{16,64}$/

type VoiceSession = {
	sessionId: string
	wallet: string
	res: Socket | TLSSocket
	lastActivityAt: number
	paused: boolean
	queue: string[]
	drainTimer?: ReturnType<typeof setTimeout>
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
	logger(Colors.grey(`voice session=${sessionId} wallet=${session.wallet} ${reason}`))
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
	const wallet = lowerAddress(command.walletAddress)
	const sessionId = validSessionId(command.sessionId) ? command.sessionId.trim() : ''
	if (!wallet || !sessionId || !validTimestamp(command.timestamp)) return distorySocket(socket)
	if (!(await isMyRoute(wallet, nodeWallet.address))) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'not_my_route' }))
	}
	if (sessions.size >= VOICE_MAX_GLOBAL) return response200Html(socket, JSON.stringify({ ok: false, error: 'pool_full' }))
	const walletSessions = [...sessions.values()].filter((session) => session.wallet === wallet)
	if (walletSessions.length >= VOICE_MAX_PER_WALLET) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'wallet_session_limit' }))
	}
	if (sessions.has(sessionId)) return response200Html(socket, JSON.stringify({ ok: false, error: 'session_conflict' }))

	const session: VoiceSession = {
		sessionId,
		wallet,
		res: socket,
		lastActivityAt: Date.now(),
		paused: false,
		queue: [],
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
		wallet,
		nodeWallet: nodeWallet.address.toLowerCase(),
	}
	if (!writeFrame({ ...session, paused: false, queue: [] }, headers + frameLine(handshake))) {
		return remove('handshake_failed')
	}
	sessions.set(sessionId, session)
	scheduleSweep()
	logger(Colors.cyan(`voice listen attached session=${sessionId} wallet=${wallet}`))

	// The caller's mailbox is the only component that wakes native devices.
	// The PWA never calls /api/voiceCallPush directly, so the API sees the
	// mailbox node as the network source rather than the caller's IP.
	const callId = typeof command.callId === 'string' ? command.callId.trim() : ''
	const calleeEoa = lowerAddress(command.targetWallet)
	const expiresAt = Number(command.expiresAt)
	const pushTimestamp = Number(command.pushTimestamp)
	const pushSignature = typeof command.pushSignature === 'string' ? command.pushSignature.trim() : ''
	if (
		callId &&
		calleeEoa &&
		Number.isFinite(expiresAt) &&
		expiresAt > Date.now() &&
		expiresAt <= Date.now() + 10 * 60_000 &&
		validTimestamp(pushTimestamp) &&
		pushSignature
	) {
		notifyVoiceCallPush({
			callId,
			sessionId,
			callerEoa: wallet,
			calleeEoa,
			expiresAt,
			timestamp: pushTimestamp,
			signature: pushSignature,
		})
	}
}

export const handleVoiceUnlisten = (
	socket: Socket,
	command: Record<string, unknown>,
): void => {
	const sessionId = validSessionId(command.sessionId) ? command.sessionId.trim() : ''
	const wallet = lowerAddress(command.walletAddress)
	const session = sessions.get(sessionId)
	if (session && session.wallet === wallet) removeSession(sessionId, 'unlisten')
	return response200Html(socket, JSON.stringify({ ok: true, sessionId }))
}

export const handleVoiceFrame = async (
	socket: Socket,
	command: Record<string, unknown>,
	nodeWallet: ethers.Wallet,
): Promise<void> => {
	const from = lowerAddress(command.walletAddress)
	const targetWallet = lowerAddress(command.targetWallet)
	const targetSessionId = validSessionId(command.targetSessionId) ? command.targetSessionId.trim() : ''
	const callId = typeof command.callId === 'string' ? command.callId.trim() : ''
	const sessionId = validSessionId(command.sessionId) ? command.sessionId.trim() : ''
	const payload = command.payload
	const seq = Number(command.seq)
	if (!from || !targetWallet || !targetSessionId || !sessionId || !callId || !validPayload(payload) ||
		!Number.isSafeInteger(seq) || seq < 0 || !validTimestamp(command.timestamp)) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'invalid_voice_frame' }))
	}
	if (!(await isMyRoute(targetWallet, nodeWallet.address))) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'not_my_route' }))
	}
	const target = sessions.get(targetSessionId)
	if (!target || target.wallet !== targetWallet || isLivenessListenSocketStale(target.res)) {
		return response200Html(socket, JSON.stringify({ ok: false, error: 'target_voice_session_not_found' }))
	}
	target.lastActivityAt = Date.now()
	const frame = frameLine({
		type: 'voice_frame_v1',
		callId,
		sessionId,
		from,
		to: targetWallet,
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

export const voiceForwardPoolStats = (): { sessions: number } => ({
	sessions: sessions.size,
})
