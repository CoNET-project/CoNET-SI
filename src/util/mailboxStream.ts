/**
 * Mailbox listen stream sealing.
 *
 * `mailbox_listen` carries a per-listen `streamKey` (32 random bytes, base64)
 * inside the command, which only this mailbox can decrypt. Every frame this
 * mailbox writes on that SSE (handshake, offline flush, live message,
 * keepalive) is sealed with it, so the entry relaying the stream sees only
 * opaque, length-bucketed data: no recipient key ID, no wallet, no frame type.
 *
 * Frame: `data: base64(iv[12] ‖ AES-256-GCM ciphertext ‖ tag[16])\r\n\r\n`.
 * Plaintext: the frame JSON, right-padded with spaces to a multiple of 256
 * bytes (JSON parsers ignore trailing whitespace). Random IV per frame: a
 * client may reuse the same command (and key) when it reconnects.
 * The key is held in memory for the life of the SSE only and never logged.
 */
import { createCipheriv, randomBytes } from 'crypto'

export const MAILBOX_STREAM_PAD = 256

/** 32-byte key from the command field, or null. */
export const parseMailboxStreamKey = (value: unknown): Buffer | null => {
	if (typeof value !== 'string' || value.length < 40 || value.length > 64) return null
	if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return null
	const key = Buffer.from(value, 'base64')
	return key.length === 32 ? key : null
}

export const sealMailboxStreamPayload = (obj: Record<string, unknown>, key: Buffer): string => {
	const json = Buffer.from(JSON.stringify(obj), 'utf8')
	const padded = Buffer.alloc(Math.ceil((json.length + 1) / MAILBOX_STREAM_PAD) * MAILBOX_STREAM_PAD, 0x20)
	json.copy(padded)
	const iv = randomBytes(12)
	const cipher = createCipheriv('aes-256-gcm', key, iv)
	const body = Buffer.concat([cipher.update(padded), cipher.final()])
	return Buffer.concat([iv, body, cipher.getAuthTag()]).toString('base64')
}

/** One SSE event: sealed when the session has a key, plain JSON otherwise. */
export const mailboxSseFrame = (obj: Record<string, unknown>, key?: Buffer): string =>
	`data: ${key ? sealMailboxStreamPayload(obj, key) : JSON.stringify(obj)}\r\n\r\n`
