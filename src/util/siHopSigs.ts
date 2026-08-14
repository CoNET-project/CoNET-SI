import { ethers } from 'ethers'

/** Max SI-to-SI hop signatures. A further forward is treated as an all-node flood. */
export const MAX_SI_HOP_SIGS = 3
export const SI_HOP_SIG_HEADER = 'X-CoNET-Hop-Sigs'
const HOP_SIG_DOMAIN = 'conet.l0.hop.v1'
const HOP_SIG_TS_WINDOW_SEC = 600

export type SiHopSig = {
	w: string
	t: number
	n: number
	h: string
	k: string
	s: string
}

export const hopArmorHash = (armor: string): string => {
	return ethers.keccak256(ethers.toUtf8Bytes(armor))
}

export const hopSigPayload = (hop: Omit<SiHopSig, 's'>): string => {
	return [
		HOP_SIG_DOMAIN,
		hop.w.toLowerCase(),
		String(hop.t),
		String(hop.n),
		hop.h.toLowerCase(),
		hop.k.toUpperCase(),
	].join('|')
}

const headerNameOf = (line: string): string => {
	const i = line.indexOf(':')
	return i < 0 ? '' : line.slice(0, i).trim().toLowerCase()
}

const headerValueOf = (line: string): string => {
	const i = line.indexOf(':')
	return i < 0 ? '' : line.slice(i + 1).trim()
}

export const parseHopSigsFromHeaders = (headers: string[]): SiHopSig[] | 'invalid' => {
	const line = headers.find(h => headerNameOf(h) === SI_HOP_SIG_HEADER.toLowerCase())
	if (!line) {
		return []
	}
	const raw = headerValueOf(line)
	if (!raw) {
		return []
	}
	try {
		const jsonText = raw.startsWith('[')
			? raw
			: Buffer.from(raw, 'base64').toString('utf8')
		const parsed = JSON.parse(jsonText)
		if (!Array.isArray(parsed)) {
			return 'invalid'
		}
		if (parsed.length > MAX_SI_HOP_SIGS) {
			return parsed as SiHopSig[]
		}
		const hops: SiHopSig[] = []
		for (const row of parsed) {
			if (!row || typeof row !== 'object') {
				return 'invalid'
			}
			const w = String(row.w || '')
			const t = Number(row.t)
			const n = Number(row.n)
			const h = String(row.h || '')
			const k = String(row.k || '')
			const s = String(row.s || '')
			if (!ethers.isAddress(w) || !Number.isFinite(t) || !Number.isFinite(n) || n < 0 || !h || !k || !s) {
				return 'invalid'
			}
			hops.push({ w, t, n, h, k, s })
		}
		return hops
	} catch {
		return 'invalid'
	}
}

export const serializeHopSigsHeaderValue = (hops: SiHopSig[]): string => {
	return Buffer.from(JSON.stringify(hops), 'utf8').toString('base64')
}

export const hopSigsHeaderLine = (hops: SiHopSig[]): string => {
	return `${SI_HOP_SIG_HEADER}: ${serializeHopSigsHeaderValue(hops)}`
}

export const verifyHopSig = (hop: SiHopSig, nowSec = Math.floor(Date.now() / 1000)): boolean => {
	if (Math.abs(nowSec - hop.t) > HOP_SIG_TS_WINDOW_SEC) {
		return false
	}
	try {
		const recovered = ethers.verifyMessage(hopSigPayload(hop), hop.s)
		return recovered.toLowerCase() === hop.w.toLowerCase()
	} catch {
		return false
	}
}

export const verifyHopSigs = (hops: SiHopSig[]): SiHopSig[] => {
	return hops.filter(h => verifyHopSig(h))
}

export const hopSigCountExceedsLimit = (count: number): boolean => {
	return count > MAX_SI_HOP_SIGS
}

export const cannotAppendAnotherHop = (count: number): boolean => {
	return count >= MAX_SI_HOP_SIGS
}

export const hopChainIncludesWallet = (hops: SiHopSig[], wallet: string): boolean => {
	const lower = wallet.toLowerCase()
	return hops.some(h => h.w.toLowerCase() === lower)
}

export const signAndAppendHop = async (
	incoming: SiHopSig[],
	nodeWallet: ethers.Wallet,
	nextKeyID: string,
	armor: string,
): Promise<SiHopSig[] | null> => {
	if (cannotAppendAnotherHop(incoming.length) || hopSigCountExceedsLimit(incoming.length)) {
		return null
	}
	if (hopChainIncludesWallet(incoming, nodeWallet.address)) {
		return null
	}
	const unsigned: Omit<SiHopSig, 's'> = {
		w: nodeWallet.address,
		t: Math.floor(Date.now() / 1000),
		n: Buffer.byteLength(armor, 'utf8'),
		h: hopArmorHash(armor),
		k: nextKeyID.toUpperCase(),
	}
	const hop: SiHopSig = {
		...unsigned,
		s: await nodeWallet.signMessage(hopSigPayload(unsigned)),
	}
	return [...incoming, hop]
}
