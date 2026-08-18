/**
 * CoNET L0 exclusive occupancy pipe.
 *
 * Idle `l0_listen` SSE may still receive user-PGP gossip (application offers).
 * The first `l0_connect` (route-PGP signed command) occupies the SSE: SI pipes
 * remaining inbound TCP bytes onto that SSE, then relinquishes control.
 * Later inflows to the occupied wallet / PGP key ID are 409.
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

export interface L0Listen {
	wallet: string
	res: Socket | TLSSocket
	ipaddress: string
	connectedAt: number
	pgpKeyId?: string
	occupied: boolean
	occupiedBy?: string
	inbound?: Socket | TLSSocket
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

const writeSseJson = (res: Socket | TLSSocket, obj: Record<string, unknown>): boolean => {
	const s = res as Socket
	if (isLivenessListenSocketStale(s)) return false
	try {
		return s.write(`data: ${JSON.stringify(obj)}\r\n\r\n`)
	} catch {
		return false
	}
}

const writeSseLine = (res: Socket | TLSSocket, line: string): boolean => {
	const s = res as Socket
	if (isLivenessListenSocketStale(s)) return false
	try {
		return s.write(`data: ${line}\r\n\r\n`)
	} catch {
		return false
	}
}

const destroySock = (res?: Socket | TLSSocket) => {
	if (!res) return
	try {
		const s = res as Socket
		if (!s.destroyed) s.destroy()
	} catch {
		/* ignore */
	}
}

const dropL0Listen = (wallet: string, why: string) => {
	const obj = l0ListenPool.get(wallet)
	if (!obj) return
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
	return writeSseLine(listen.res, data)
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

	if (!writeSseJson(listen.res, {
		type: 'l0_occupied',
		wallet: target,
		connector,
	})) {
		dropL0Listen(target, 'occupy_write_fail')
		return distorySocket(socket)
	}

	const inbound = socket as Socket
	const sse = listen.res as Socket
	let carry = ''
	const flushCarry = () => {
		const parts = carry.split(/\r?\n/)
		carry = parts.pop() || ''
		for (const line of parts) {
			const trimmed = line.trim()
			if (!trimmed) continue
			if (!writeSseLine(sse, trimmed)) {
				dropL0Listen(target, 'pipe_write_fail')
				return false
			}
		}
		return true
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
	// getDataPOST unshifts bytes after Content-Length; emit them now that we listen.
	if (typeof inbound.resume === 'function') inbound.resume()
}
