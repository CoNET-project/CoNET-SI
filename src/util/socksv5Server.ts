// socks5.ts

import * as net from 'node:net'
type SockState = 'handshake' | 'request' | 'proxy'

const SOCKS_VERSION = 0x05

// Reply codes (RFC 1928)
const REP = {
	SUCCEEDED: 0x00,
	GEN_FAIL: 0x01,
	NET_UNREACH: 0x03,
	HOST_UNREACH: 0x04,
	CONN_REFUSED: 0x05,
	TTL_EXPIRED: 0x06,
	CMD_NOT_SUP: 0x07,
	ADDR_NOT_SUP: 0x08
} as const

// Utilities
const u16be = (b: Buffer, o: number) => (b[o] << 8) | b[o + 1]
const portToBuf = (p: number) => Buffer.from([ (p >> 8) & 0xff, p & 0xff ])

function ipv4ToBuf(addr: string): Buffer {
	return Buffer.from(addr.split('.').map(n => Number(n) & 0xff));
}

function ipv6ToBuf(addr: string): Buffer {
	// Node 可返回简写 IPv6，需要正规化
	const sec = addr.split(':');
	// 处理 :: 压缩
	let expand: string[] = [];
	let skip = sec.indexOf('');
	if (skip !== -1) {
		// 左右段
		let left = sec.slice(0, skip);
		let right = sec.slice(skip + 1);
		const fill = new Array(8 - (left.length + right.length)).fill('0');
		expand = [...left, ...fill, ...right];
	} else {
		expand = sec;
	}
	expand = expand.map(x => x === '' ? '0' : x.padStart(4, '0'));
	const bytes: number[] = [];
	for (const h of expand) {
		const v = parseInt(h, 16);
		bytes.push((v >> 8) & 0xff, v & 0xff);
	}
	return Buffer.from(bytes);
}

function buildReply(rep: number, addr: string | null, port: number | null): Buffer {
	// 默认 0.0.0.0:0
	let atyp = 0x01
	let addrBuf: Buffer = Buffer.from([0, 0, 0, 0])
	let portBuf: Buffer = Buffer.from([0, 0])

	if (addr && port != null) {
		const ipVer = net.isIP(addr)
		if (ipVer === 4) {
			atyp = 0x01
			addrBuf = ipv4ToBuf(addr)
		} else if (ipVer === 6) {
			atyp = 0x04
			addrBuf = ipv6ToBuf(addr)
		} else {
			// 不建议回域名，这里仍回 0.0.0.0
		}
		portBuf = portToBuf(port)
	}

	return Buffer.concat([
		Buffer.from([SOCKS_VERSION, rep, 0x00, atyp]),
		addrBuf,
		portBuf
	])
}

class BufCursor {
	private buf = Buffer.alloc(0)

	append(data: Buffer) {
		this.buf = this.buf.length === 0 ? Buffer.from(data) : Buffer.concat([this.buf, Buffer.from(data)])
	}

	need(n: number): boolean {
		return this.buf.length >= n
	}

	read(n: number): Buffer | null {
		if (!this.need(n)) return null
		const out = this.buf.subarray(0, n)
		this.buf = this.buf.subarray(n)
		return out
	}
}

class ClientSession {
	private state: SockState = 'handshake'
	private cur = new BufCursor()
	private upstream: net.Socket | null = null
	private closed = false
	private id: number

	constructor(private client: net.Socket, idSeed: number) {
		this.id = idSeed
		this.client.setNoDelay(true)
		this.client.setKeepAlive(true)
		this.client.setTimeout(90_000)

		this.client.on('data', d => this.onData(d))
		this.client.on('error', err => this.endBoth(`client_error ${err.message}`))
		this.client.on('timeout', () => this.endBoth('client_timeout'))
		this.client.on('close', () => this.endBoth('client_close'))
	}

	private log(msg: string) {
		console.log(`[${this.id}] ${msg}`)
	}

	private endBoth(reason: string) {
		if (this.closed) return
		this.closed = true
		this.log(`close ${reason}`)
		this.client.destroy()
		if (this.upstream) this.upstream.destroy()
	}

	private onData(chunk: Buffer) {
		if (this.closed) return
		this.cur.append(chunk)
		try {
			if (this.state === 'handshake') this.tryHandshake()
			if (this.state === 'request') this.tryRequest()
			// proxy 状态下由 pipe 管
		} catch (e: any) {
			this.log(`parse_error ${e?.message || e}`)
			this.safeFail(REP.GEN_FAIL)
		}
	}

	private tryHandshake() {
		// VER | NMETHODS | METHODS...
		if (!this.cur.need(2)) return
		const head = this.cur.read(2)!
		const ver = head[0]
		const nMethods = head[1]
		if (ver !== SOCKS_VERSION) {
			this.log(`bad_version ${ver}`)
			this.client.end()
			this.closed = true
			return
		}
		if (!this.cur.need(nMethods)) {
			// 等更多方法字节
			this.cur.append(head) // 放回？——我们已经 read 了，只需等后续 methods；更简洁：再读 methods 就好
			// 但上面已经移除了 head，这里需要处理：简单做法是缓存 head 并合并，下方重写实现
		}
		// 为简洁：重新读取（把 head 拼回去）
		this.cur = this.rewind([head, this.cur.read(nMethods) ?? Buffer.alloc(0)])
		if (!this.cur.need(2 + nMethods)) return
		const all = this.cur.read(2 + nMethods)!
		const methods = [...all.subarray(2)]
		const noAuthOffered = methods.includes(0x00)
		this.client.write(Buffer.from([SOCKS_VERSION, noAuthOffered ? 0x00 : 0xff]))
		if (!noAuthOffered) {
			this.log('no acceptable auth method')
			this.client.end()
			this.closed = true
			return
		}
		this.state = 'request'
	}

	private tryRequest() {
		// VER CMD RSV ATYP ...
		if (!this.cur.need(4)) return
		const head = this.cur.read(4)!
		const ver = head[0]
		const cmd = head[1]
		const atyp = head[3]
		if (ver !== SOCKS_VERSION) {
			this.safeFail(REP.GEN_FAIL)
			return
		}
		let host = ''
		if (atyp === 0x01) {
			// IPv4 + port
			if (!this.cur.need(4 + 2)) {
				this.cur = this.rewind([head, this.cur.read(0) ?? Buffer.alloc(0)])
				return
			}
			const addr = this.cur.read(4)!
			const port = u16be(this.cur.read(2)!, 0)
			host = [...addr].join('.')
			this.handleConnect(cmd, host, port)
			return
		} else if (atyp === 0x03) {
			// domain len + domain + port
			if (!this.cur.need(1)) {
				this.cur = this.rewind([head, this.cur.read(0) ?? Buffer.alloc(0)])
				return
			}
			const len = this.cur.read(1)![0]
			if (!this.cur.need(len + 2)) {
				this.cur = this.rewind([head, Buffer.from([len]), this.cur.read(0) ?? Buffer.alloc(0)])
				return
			}
			const name = this.cur.read(len)!.toString('utf8')
			const port = u16be(this.cur.read(2)!, 0)
			host = name
			this.handleConnect(cmd, host, port)
			return
		} else if (atyp === 0x04) {
			// IPv6 + port
			if (!this.cur.need(16 + 2)) {
				this.cur = this.rewind([head, this.cur.read(0) ?? Buffer.alloc(0)])
				return
			}
			const addr = this.cur.read(16)!
			const port = u16be(this.cur.read(2)!, 0)
			const parts: string[] = []
			for (let i = 0; i < 16; i += 2) {
				parts.push(((addr[i] << 8) | addr[i + 1]).toString(16))
			}
			host = parts.join(':')
			this.handleConnect(cmd, host, port)
			return
		} else {
			this.safeFail(REP.ADDR_NOT_SUP)
			return
		}
	}

	private handleConnect(cmd: number, host: string, port: number) {
		if (cmd !== 0x01) {
			this.safeFail(REP.CMD_NOT_SUP)
			return
		}
		this.log(`CONNECT ${host}:${port}`)
		const upstream = net.connect({ host, port }, () => {
			const bndAddr = upstream.localAddress || '0.0.0.0'
			const bndPort = upstream.localPort || 0
			this.client.write(buildReply(REP.SUCCEEDED, bndAddr, bndPort))
			this.state = 'proxy'
			this.bridge(upstream)
		})
		this.upstream = upstream
		upstream.setNoDelay(true)
		upstream.setKeepAlive(true)
		upstream.setTimeout(90_000)
		upstream.on('error', err => {
			this.log(`up_error ${err.message}`)
			this.safeFail(mapErrToRep(err))
		})
		upstream.on('timeout', () => this.endBoth('up_timeout'))
	}

	private bridge(up: net.Socket) {
		// 背压与半关闭
		this.client.pipe(up)
		up.pipe(this.client)

		this.client.on('end', () => up.end())
		up.on('end', () => this.client.end())

		this.client.on('close', () => up.destroy())
		up.on('close', () => this.client.destroy())
	}

	private safeFail(rep: number) {
		try {
			this.client.write(buildReply(rep, null, null))
		} catch {}
		this.client.end()
		this.closed = true
	}

	private rewind(parts: (Buffer | null)[]): BufCursor {
		const c = new BufCursor()
		for (const p of parts) if (p && p.length) c.append(p)
		return c
	}
}

function mapErrToRep(err: any): number {
	const code = (err?.code || '').toString()
	if (code === 'ECONNREFUSED') return REP.CONN_REFUSED
	if (code === 'ENETUNREACH') return REP.NET_UNREACH
	if (code === 'EHOSTUNREACH') return REP.HOST_UNREACH
	if (code === 'ETIMEDOUT') return REP.TTL_EXPIRED
	return REP.GEN_FAIL
}

// ---- Server bootstrap ----
const port = parseInt(process.env.PORT || process.argv[2] || '1080', 10)
let nextId = 1

const server = net.createServer( sock => {
	const id = nextId++
	console.log(`[${id}] client connected from ${sock.remoteAddress}:${sock.remotePort}`)
	new ClientSession(sock, id)
})

server.on('error', err => {
	console.error(`server_error ${err.message}`)
})

server.listen(port, () => {
	console.log(`SOCKS5 server listening on 0.0.0.0:${port}`)
})
