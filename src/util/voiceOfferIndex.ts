/**
 * CallId-indexed store for callee user-PGP voice offer armor.
 *
 * Mailbox never decrypts offerArmor. Native shells (killed PWA) fetch by the
 * opaque callId + sessionId from the VoIP push, then decrypt locally with the
 * injected recipient user PGP private key.
 */
import Colors from 'colors/safe'
import type { logger as LoggerFn } from './logger'
import * as Fs from 'node:fs'
import * as Path from 'node:path'
import * as Os from 'node:os'

const logger: typeof LoggerFn = require('./logger').logger

const MAX_ENTRIES = 256
const DEFAULT_TTL_MS = 5 * 60_000
const STORE_DIR = Path.join(Os.homedir(), '.data', 'voice-offers')

export type VoiceOfferRecord = {
	callId: string
	sessionId: string
	offerArmor: string
	expiresAt: number
	storedAt: number
}

const memory = new Map<string, VoiceOfferRecord>()

const normalizeId = (raw: unknown): string => {
	if (typeof raw !== 'string') return ''
	return raw.trim()
}

const recordKey = (callId: string, sessionId: string): string =>
	`${callId.toLowerCase()}|${sessionId.toLowerCase()}`

const ensureDir = (): void => {
	try {
		if (!Fs.existsSync(STORE_DIR)) Fs.mkdirSync(STORE_DIR, { recursive: true })
	} catch {
		/* ignore */
	}
}

const diskPath = (callId: string, sessionId: string): string => {
	const safe = recordKey(callId, sessionId).replace(/[^a-zA-Z0-9._|-]/g, '_')
	return Path.join(STORE_DIR, `${safe}.json`)
}

const pruneExpired = (now = Date.now()): void => {
	for (const [key, rec] of memory) {
		if (rec.expiresAt <= now) memory.delete(key)
	}
	while (memory.size > MAX_ENTRIES) {
		const oldest = memory.keys().next().value
		if (!oldest) break
		memory.delete(oldest)
	}
}

export const storeVoiceOffer = (
	callIdRaw: unknown,
	sessionIdRaw: unknown,
	offerArmorRaw: unknown,
	expiresAtRaw?: unknown,
): boolean => {
	const callId = normalizeId(callIdRaw)
	const sessionId = normalizeId(sessionIdRaw)
	const offerArmor = typeof offerArmorRaw === 'string' ? offerArmorRaw.trim() : ''
	if (!callId || callId.length < 8 || callId.length > 128) return false
	if (!sessionId || sessionId.length < 16 || sessionId.length > 128) return false
	if (!offerArmor || offerArmor.length > 48_000) return false
	if (!offerArmor.includes('-----BEGIN PGP MESSAGE-----')) return false

	const now = Date.now()
	let expiresAt = Number(expiresAtRaw)
	if (!Number.isFinite(expiresAt) || expiresAt <= now) {
		expiresAt = now + DEFAULT_TTL_MS
	}
	if (expiresAt > now + 24 * 60 * 60_000) {
		expiresAt = now + DEFAULT_TTL_MS
	}

	pruneExpired(now)
	const rec: VoiceOfferRecord = {
		callId,
		sessionId,
		offerArmor,
		expiresAt,
		storedAt: now,
	}
	memory.set(recordKey(callId, sessionId), rec)
	try {
		ensureDir()
		Fs.writeFileSync(diskPath(callId, sessionId), JSON.stringify(rec), 'utf8')
	} catch (ex) {
		logger(Colors.yellow(`voiceOfferIndex disk write failed: ${(ex as Error)?.message || ex}`))
	}
	logger(Colors.cyan(`voiceOfferIndex store callId=${callId.slice(0, 12)}… session=${sessionId.slice(0, 12)}…`))
	return true
}

export const fetchVoiceOffer = (
	callIdRaw: unknown,
	sessionIdRaw: unknown,
): VoiceOfferRecord | null => {
	const callId = normalizeId(callIdRaw)
	const sessionId = normalizeId(sessionIdRaw)
	if (!callId || !sessionId) return null
	const now = Date.now()
	pruneExpired(now)
	const key = recordKey(callId, sessionId)
	let rec = memory.get(key) || null
	if (!rec) {
		try {
			const p = diskPath(callId, sessionId)
			if (Fs.existsSync(p)) {
				const parsed = JSON.parse(Fs.readFileSync(p, 'utf8')) as VoiceOfferRecord
				if (
					parsed &&
					typeof parsed.offerArmor === 'string' &&
					normalizeId(parsed.callId).toLowerCase() === callId.toLowerCase() &&
					normalizeId(parsed.sessionId).toLowerCase() === sessionId.toLowerCase()
				) {
					rec = parsed
					memory.set(key, parsed)
				}
			}
		} catch {
			/* ignore */
		}
	}
	if (!rec) return null
	if (rec.expiresAt <= now) {
		memory.delete(key)
		try { Fs.unlinkSync(diskPath(callId, sessionId)) } catch { /* ignore */ }
		return null
	}
	return rec
}

export const removeVoiceOffer = (callIdRaw: unknown, sessionIdRaw: unknown): void => {
	const callId = normalizeId(callIdRaw)
	const sessionId = normalizeId(sessionIdRaw)
	if (!callId || !sessionId) return
	memory.delete(recordKey(callId, sessionId))
	try { Fs.unlinkSync(diskPath(callId, sessionId)) } catch { /* ignore */ }
}
