// globalDnsCache.ts
import { promises as fs } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { once } from 'node:events'
import { randomBytes } from 'node:crypto'
import IP from 'ip'
import dns from 'node:dns'

type CacheEntry = {
	address: string
	expiresAt: number   // epoch ms
	usedAt: number      // LRU hint
}

type CacheFile = Record<string, CacheEntry>

const CACHE_FILE = join(process.env.CONET_DNS_CACHE_DIR || tmpdir(), 'conet_dns_cache.json')
const MAX_FILE_BYTES = 1 * 1024 * 1024   // 1MB 上限
const GC_KEEP = 1000                     // GC 时保留最近 1000 个
const READ_OPTS: any = { encoding: 'utf8' }


async function readCache(): Promise<CacheFile> {
	try {
        const txt: string = await fs.readFile(CACHE_FILE, READ_OPTS) as unknown as string
        if (!txt.trim()) return {}
        return JSON.parse(txt) as CacheFile
    } catch {
        return {}
    }
}

async function atomicWrite(obj: CacheFile) {
	const tmp = CACHE_FILE + '.' + randomBytes(4).toString('hex') + '.tmp'
	await fs.writeFile(tmp, JSON.stringify(obj), 'utf8')
	await fs.rename(tmp, CACHE_FILE)
}

function gcIfTooLarge(obj: CacheFile) {
	const encoded = Buffer.from(JSON.stringify(obj), 'utf8')
	if (encoded.byteLength <= MAX_FILE_BYTES) return obj
	const entries = Object.entries(obj).sort((a,b) => b[1].usedAt - a[1].usedAt)
	const trimmed = Object.fromEntries(entries.slice(0, GC_KEEP))
	return trimmed
}

const resolver = new dns.Resolver()

export async function getHostIPv4Cached(host: string): Promise<string> {
	const now = Date.now()
	let cache = await readCache()
	const hit = cache[host]
	if (hit && hit.expiresAt > now && IP.isPublic(hit.address)) {
		hit.usedAt = now
		// 异步写回 usedAt（不阻塞主流程）
		atomicWrite(cache).catch(() => {})
		return hit.address
	}

	// 失效：实际解析（带 TTL）
	const records = await new Promise<Array<{address: string, ttl: number}>>((resolve) => {
		// Node >= 18 支持 { ttl: true }
		// 若不支持/失败，降级到无 TTL
		try {
			(resolver as any).resolve4(host, { ttl: true }, (err: any, ans: Array<{address: string, ttl: number}>) => {
				if (err || !Array.isArray(ans) || !ans.length) return resolve([])
				resolve(ans)
			})
		} catch {
			resolver.resolve4(host, (err, ans: string[]) => {
				if (err || !Array.isArray(ans) || !ans.length) return resolve([])
				resolve(ans.map(a => ({ address: a, ttl: 60 }))) // 无 TTL 则给默认 60s
			})
		}
	})

	if (!records.length) return ''

	// 选择第一个公网 IPv4；并找到最小 TTL（更安全）
	const publicAddrs = records.filter(r => IP.isPublic(r.address))
	if (!publicAddrs.length) return ''
	const chosen = publicAddrs[0]
	const minTTL = Math.max(5, Math.min(...publicAddrs.map(r => (r.ttl || 60)))) // 最少 5s

	cache[host] = {
		address: chosen.address,
		expiresAt: now + minTTL * 1000,
		usedAt: now
	}

	cache = gcIfTooLarge(cache)
	await atomicWrite(cache)
	return chosen.address
}