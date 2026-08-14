/**
 * End-to-end AES-256-GCM for CoNET DePIN UDP frames.
 * Mailbox B only relays the ciphertext — it never holds Securitykey.
 *
 * Wire format (base64): nonce(12) || ciphertext || tag(16)
 * Key: 32 raw bytes, transported as base64 in `udp_subscribe.Securitykey`
 * (encrypted to the UDP server **user** PGP, never to route B).
 */
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto'

export const UDP_AES_ALGORITHM = 'aes-256-gcm' as const
export const UDP_AES_KEY_BYTES = 32
export const UDP_AES_NONCE_BYTES = 12
export const UDP_AES_TAG_BYTES = 16

export const generateUdpSymmetricKey = (): { raw: Buffer; securityKeyB64: string } => {
	const raw = randomBytes(UDP_AES_KEY_BYTES)
	return { raw, securityKeyB64: raw.toString('base64') }
}

export const decodeUdpSecurityKey = (securityKeyB64: string): Buffer | null => {
	if (typeof securityKeyB64 !== 'string' || !securityKeyB64.trim()) return null
	try {
		const raw = Buffer.from(securityKeyB64.trim(), 'base64')
		if (raw.length !== UDP_AES_KEY_BYTES) return null
		return raw
	} catch {
		return null
	}
}

export const encryptUdpPayload = (key: Buffer, plaintext: Buffer): string => {
	if (key.length !== UDP_AES_KEY_BYTES) {
		throw new Error('udp_aes_key_len')
	}
	const nonce = randomBytes(UDP_AES_NONCE_BYTES)
	const cipher = createCipheriv(UDP_AES_ALGORITHM, key, nonce)
	const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
	const tag = cipher.getAuthTag()
	return Buffer.concat([nonce, ciphertext, tag]).toString('base64')
}

export const decryptUdpPayload = (key: Buffer, payloadB64: string): Buffer | null => {
	if (key.length !== UDP_AES_KEY_BYTES) return null
	let packed: Buffer
	try {
		packed = Buffer.from(payloadB64, 'base64')
	} catch {
		return null
	}
	if (packed.length < UDP_AES_NONCE_BYTES + UDP_AES_TAG_BYTES) return null
	const nonce = packed.subarray(0, UDP_AES_NONCE_BYTES)
	const tag = packed.subarray(packed.length - UDP_AES_TAG_BYTES)
	const ciphertext = packed.subarray(UDP_AES_NONCE_BYTES, packed.length - UDP_AES_TAG_BYTES)
	try {
		const decipher = createDecipheriv(UDP_AES_ALGORITHM, key, nonce)
		decipher.setAuthTag(tag)
		return Buffer.concat([decipher.update(ciphertext), decipher.final()])
	} catch {
		return null
	}
}
