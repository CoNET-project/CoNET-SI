/**
 * Guardian node table sync: strict chain read, change watcher, refresh scheduler.
 *
 * The node table comes from GuardianNodesInfoV6 on CoNET mainnet. That contract emits one
 * event, `deleteIPAddr`, and only from removeNode. addNode / pgpUpdate / id2node change
 * storage without any event, so an event subscription alone misses new nodes and IP/PGP
 * changes (an IP change is done on chain as removeNode + addNode).
 *
 * How changes are detected:
 * - Every poll reads the contract's storage root (eth_getProof storageHash). Any write changes
 *   it, including writes made through another contract. Comparing two roots covers every block
 *   in between, so blocks missed while the RPC was down are covered as soon as it answers again.
 * - When the root changed, eth_getLogs (deleteIPAddr) and a short block scan (decoded calls to
 *   the contract) say what changed, for the log. If the RPC stops serving eth_getProof, the
 *   watcher falls back to those two as the detector.
 * - A change schedules a full table read after a debounce plus random jitter, so the fleet does
 *   not hit the RPC at the same moment. Reads are pinned to one block and must finish completely.
 * - A low-frequency reconcile compares the root with the one the table was built from, and does
 *   a full read anyway at least once a day.
 *
 * A failed or suspicious read never replaces the current table (see ShrinkGuard).
 */
import { ethers } from 'ethers'
import Colors from 'colors/safe'
import { logger } from './logger'
import GuardianNodesInfoV6ABI from './newNodeInfoABI.json'

/** GuardianNodesInfoV6 on CoNET mainnet (explorer-verified, not a proxy). */
export const GUARDIAN_NODES_INFO_ADDRESS = '0xBC6b53065b5647261396d002bDBA0d3396E0722f'
export const CONET_MAINNET_CHAIN_ID = 224422

const TAG = Colors.cyan('[guardian-nodes]')
const log = (...args: any[]) => logger(TAG, ...args)

export const SYNC_DEFAULTS = {
	/** Blocks behind head treated as final. CoNET blocks are ~6s apart. */
	confirmations: 2,
	pollMs: 30_000,
	rpcTimeoutMs: 20_000,
	pageSize: 100,
	/** eth_getLogs on publicrpc rejects ranges over 5000 blocks. */
	logsChunk: 4_000,
	/** Gaps longer than this are not described with getLogs (refresh still happens). */
	maxDescribeBlocks: 100_000,
	/** Block-by-block tx scan only for short ranges. */
	maxTxScanBlocks: 30,
	debounceMs: 5_000,
	/** Random spread so 472 nodes do not read the full table at the same moment. */
	jitterMs: 120_000,
	minIntervalMs: 60_000,
	failBackoffBaseMs: 30_000,
	failBackoffMaxMs: 15 * 60_000,
	reconcileMs: 6 * 60 * 60_000,
	reconcileJitterMs: 60 * 60_000,
	forceFullReadMs: 24 * 60 * 60_000,
}

export interface GuardianChainNode {
	id: number
	pgpArmored: string
	pgpKey: string
	ip: string
	region: string
}

export type NodeWallet = { ipAddr: string, wallet: string }

export type RefreshOutcome = { ok: boolean, retryInMs?: number }

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms))

export const withTimeout = <T>(p: Promise<T>, ms: number, label: string): Promise<T> =>
	new Promise<T>((resolve, reject) => {
		const t = setTimeout(() => reject(new Error(`${label} timeout after ${ms}ms`)), ms)
		p.then(v => { clearTimeout(t); resolve(v) }, e => { clearTimeout(t); reject(e) })
	})

const errText = (e: any) => String(e?.shortMessage ?? e?.message ?? e).slice(0, 300)

const normalizeIp = (ip: string) => (ip || '').trim().replace(/^::ffff:/i, '').toLowerCase()

export const createGuardianProvider = (rpcUrl: string) =>
	new ethers.JsonRpcProvider(rpcUrl, ethers.Network.from(CONET_MAINNET_CHAIN_ID), { staticNetwork: true })

export const createGuardianContract = (provider: ethers.Provider) =>
	new ethers.Contract(GUARDIAN_NODES_INFO_ADDRESS, GuardianNodesInfoV6ABI, provider)

/**
 * Read every node at one block. Throws if any page fails after retries: a partial list must
 * never reach the table.
 */
export const readGuardianNodesAt = async (
	contract: ethers.Contract,
	blockTag: number,
	opts: { pageSize?: number, timeoutMs?: number } = {},
): Promise<GuardianChainNode[]> => {
	const pageSize = opts.pageSize ?? SYNC_DEFAULTS.pageSize
	const timeoutMs = opts.timeoutMs ?? SYNC_DEFAULTS.rpcTimeoutMs
	const out: GuardianChainNode[] = []
	const seen = new Set<string>()
	let start = 0

	for (let pageNo = 0; pageNo < 1000; pageNo++) {
		let page: any[] = []
		for (let attempt = 1; ; attempt++) {
			try {
				page = await withTimeout(
					contract.getAllNodes(start, pageSize, { blockTag }),
					timeoutMs,
					`getAllNodes(${start},${pageSize})@${blockTag}`,
				)
				break
			} catch (e: any) {
				if (attempt >= 3) {
					throw new Error(`getAllNodes page start=${start} failed: ${errText(e)}`)
				}
				await sleep(2_000 * attempt)
			}
		}
		if (!page.length) return out

		for (const n of page) {
			const ip = String(n?.[3] ?? '').trim()
			if (!ip) continue
			const key = normalizeIp(ip)
			if (seen.has(key)) continue
			seen.add(key)
			out.push({
				id: Number(n[0]?.toString() ?? 0),
				pgpArmored: Buffer.from(String(n[1] ?? ''), 'base64').toString(),
				pgpKey: String(n[2] ?? '').trim(),
				ip,
				region: String(n[4] ?? ''),
			})
		}
		start += page.length
	}
	throw new Error('getAllNodes did not reach the end after 1000 pages')
}

/**
 * Turn chain rows into nodeInfo. Wallets come from apiv4 miningRate; if that list is missing
 * or lacks a node, keep the wallet the previous table had for the same IP and key.
 */
export const toNodeInfos = (
	chain: GuardianChainNode[],
	wallets: NodeWallet[] | null,
	previous: nodeInfo[],
): nodeInfo[] => {
	const walletByIp = new Map<string, string>()
	for (const w of wallets ?? []) {
		if (w?.ipAddr && w?.wallet) walletByIp.set(normalizeIp(w.ipAddr), w.wallet)
	}
	const prevByIp = new Map<string, nodeInfo>()
	for (const p of previous) prevByIp.set(normalizeIp(p.ipaddress), p)

	return chain.map(n => {
		const prev = prevByIp.get(normalizeIp(n.ip))
		const carried = prev && prev.domain === n.pgpKey ? prev.wallet : ''
		return {
			ipaddress: n.ip,
			pgpArmored: n.pgpArmored,
			domain: n.pgpKey,
			nftNumber: n.id,
			regionName: n.region,
			pgpKeyID: n.pgpKey,
			wallet: walletByIp.get(normalizeIp(n.ip)) || carried || '',
		}
	})
}

export const diffNodeTables = (before: nodeInfo[], after: nodeInfo[]) => {
	const b = new Map(before.map(n => [normalizeIp(n.ipaddress), n]))
	const a = new Map(after.map(n => [normalizeIp(n.ipaddress), n]))
	const added: string[] = []
	const removed: string[] = []
	const changed: string[] = []
	for (const [ip, n] of a) {
		const o = b.get(ip)
		if (!o) { added.push(ip); continue }
		if (o.domain !== n.domain || o.pgpArmored !== n.pgpArmored || o.regionName !== n.regionName || o.nftNumber !== n.nftNumber) {
			changed.push(ip)
		}
	}
	for (const ip of b.keys()) if (!a.has(ip)) removed.push(ip)
	return { added, removed, changed }
}

/**
 * Refuses tables that look broken. An empty table is always refused. A drop below half of a
 * table of 20+ nodes is accepted only when a second read at least `confirmMs` later returns the
 * same count, so a real mass removal still lands without a restart.
 */
export class ShrinkGuard {
	private pending: { count: number, firstSeen: number } | null = null
	constructor(
		private ratio = 0.5,
		private minBefore = 20,
		private confirmMs = 20 * 60_000,
	) {}

	check(before: number, after: number, now = Date.now()): { accept: boolean, reason?: string, retryInMs?: number } {
		if (after === 0) {
			return { accept: false, reason: `new table is empty (current ${before})` }
		}
		if (before < this.minBefore || after >= before * this.ratio) {
			this.pending = null
			return { accept: true }
		}
		if (this.pending && this.pending.count === after) {
			const waited = now - this.pending.firstSeen
			if (waited >= this.confirmMs) {
				this.pending = null
				return { accept: true, reason: `shrink ${before}→${after} confirmed by a second read ${Math.round(waited / 60_000)} min later` }
			}
			return { accept: false, reason: `shrink ${before}→${after} awaiting confirmation`, retryInMs: this.confirmMs - waited }
		}
		this.pending = { count: after, firstSeen: now }
		return { accept: false, reason: `node count fell ${before}→${after} (<${this.ratio * 100}%); will accept only if a read in ${Math.round(this.confirmMs / 60_000)} min confirms it`, retryInMs: this.confirmMs }
	}
}

/**
 * Coalesces refresh requests. Requests made while one is pending are merged; a request made
 * during a run causes one more run afterwards. Each run waits debounce + random jitter, at least
 * `minIntervalMs` after the previous run, and backs off exponentially after failures.
 */
export class RefreshScheduler {
	private reasons = new Set<string>()
	private timer: NodeJS.Timeout | null = null
	private running = false
	private failures = 0
	private notBefore = 0

	constructor(
		private run: (reason: string) => Promise<RefreshOutcome>,
		private opts = SYNC_DEFAULTS,
		private random = Math.random,
	) {}

	request(reason: string) {
		this.reasons.add(reason)
		if (this.running || this.timer) return
		this.schedule(0)
	}

	get isPending() {
		return this.running || this.timer !== null
	}

	stop() {
		if (this.timer) clearTimeout(this.timer)
		this.timer = null
	}

	private schedule(extraDelayMs: number) {
		const now = Date.now()
		const jitter = Math.floor(this.random() * this.opts.jitterMs)
		const delay = Math.max(this.opts.debounceMs + jitter, this.notBefore - now, extraDelayMs)
		log(`refresh scheduled in ${Math.round(delay / 1000)}s (reasons: ${this.summary()})`)
		this.timer = setTimeout(() => void this.fire(), delay)
	}

	private summary() {
		const all = [...this.reasons]
		const text = all.slice(0, 5).join(' | ')
		return all.length > 5 ? `${text} | +${all.length - 5} more` : text
	}

	private async fire() {
		this.timer = null
		const reason = this.summary()
		const batch = [...this.reasons]
		this.reasons.clear()
		this.running = true
		let outcome: RefreshOutcome = { ok: false }
		try {
			outcome = await this.run(reason)
		} catch (e: any) {
			log(Colors.red(`refresh threw: ${errText(e)}`))
		} finally {
			this.running = false
		}
		if (outcome.ok) {
			this.failures = 0
			this.notBefore = Date.now() + this.opts.minIntervalMs
		} else {
			this.failures++
			const backoff = Math.min(this.opts.failBackoffMaxMs, this.opts.failBackoffBaseMs * 2 ** (this.failures - 1))
			this.notBefore = Date.now() + Math.max(backoff, outcome.retryInMs ?? 0)
			for (const r of batch) this.reasons.add(r)
		}
		if (this.reasons.size && !this.timer) this.schedule(0)
	}
}

/** Contract storage root at a block. Every write to the contract changes it. */
export const storageHashAt = async (provider: ethers.JsonRpcProvider, block: number, timeoutMs = SYNC_DEFAULTS.rpcTimeoutMs): Promise<string> => {
	const proof = await withTimeout(
		provider.send('eth_getProof', [GUARDIAN_NODES_INFO_ADDRESS, [], ethers.toQuantity(block)]),
		timeoutMs,
		`eth_getProof@${block}`,
	)
	const h = proof?.storageHash
	if (typeof h !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(h)) {
		throw new Error(`eth_getProof@${block} returned no storageHash`)
	}
	return h.toLowerCase()
}

const isUnsupportedMethod = (e: any) => {
	const code = e?.error?.code ?? e?.info?.error?.code ?? e?.code
	return code === -32601 || /method .*(not found|not supported|does not exist|not available)|unsupported method/i.test(errText(e))
}

export interface ChangeDescription {
	/** One line per event or contract call found. */
	items: string[]
	/** False when the range was too long to scan for calls, or a lookup failed. */
	complete: boolean
}

/**
 * Explain what happened in blocks (from, to]: deleteIPAddr logs and, for short ranges, the
 * decoded calls to the contract. `knownIps` resolves the hashed IP in deleteIPAddr.
 */
export const describeChanges = async (
	provider: ethers.JsonRpcProvider,
	from: number,
	to: number,
	knownIps: string[],
	opts = SYNC_DEFAULTS,
	strict = false,
): Promise<ChangeDescription> => {
	const iface = new ethers.Interface(GuardianNodesInfoV6ABI)
	const items: string[] = []
	let complete = true
	const address = GUARDIAN_NODES_INFO_ADDRESS.toLowerCase()
	const ipByHash = new Map(knownIps.map(ip => [ethers.keccak256(ethers.toUtf8Bytes(ip)).toLowerCase(), ip]))

	const span = to - from
	if (span > opts.maxDescribeBlocks) {
		return { items: [`${span} blocks since last check; too long to list events`], complete: false }
	}

	try {
		for (let a = from + 1; a <= to; a += opts.logsChunk) {
			const b = Math.min(to, a + opts.logsChunk - 1)
			const logs = await withTimeout(provider.getLogs({ address, fromBlock: a, toBlock: b }), opts.rpcTimeoutMs, `getLogs ${a}-${b}`)
			for (const l of logs) {
				let parsed: ethers.LogDescription | null = null
				try { parsed = iface.parseLog(l) } catch {}
				if (parsed?.name === 'deleteIPAddr') {
					const ipHash = String(l.topics[1] ?? '').toLowerCase()
					items.push(`event deleteIPAddr block=${l.blockNumber} tx=${l.transactionHash} ip=${ipByHash.get(ipHash) ?? `hash:${ipHash.slice(0, 18)}…`}`)
				} else {
					items.push(`event ${parsed?.name ?? l.topics[0]?.slice(0, 10) ?? '?'} block=${l.blockNumber} tx=${l.transactionHash}`)
				}
			}
		}
	} catch (e: any) {
		if (strict) throw e
		complete = false
		items.push(`getLogs failed: ${errText(e)}`)
	}

	if (span > opts.maxTxScanBlocks) {
		return { items, complete: false }
	}
	try {
		for (let n = from + 1; n <= to; n++) {
			const blk = await withTimeout(provider.getBlock(n, true), opts.rpcTimeoutMs, `getBlock ${n}`)
			for (const tx of blk?.prefetchedTransactions ?? []) {
				if (tx.to?.toLowerCase() !== address) continue
				let desc = `call ${tx.data.slice(0, 10)}`
				try {
					const p = iface.parseTransaction({ data: tx.data })
					if (p) {
						const args = p.fragment.inputs.map((input, i) => {
							const v = p.args[i]
							if (input.name === 'pgp') return `pgp=<${String(v).length} chars>`
							return `${input.name}=${String(v)}`
						})
						desc = `call ${p.name}(${args.join(', ')})`
					}
				} catch {}
				let status = '?'
				try {
					const r = await withTimeout(provider.getTransactionReceipt(tx.hash), opts.rpcTimeoutMs, `receipt ${tx.hash}`)
					status = r?.status === 1 ? 'ok' : r?.status === 0 ? 'reverted' : '?'
				} catch {}
				items.push(`${desc} block=${n} tx=${tx.hash} status=${status}`)
			}
		}
	} catch (e: any) {
		if (strict) throw e
		complete = false
		items.push(`block scan failed: ${errText(e)}`)
	}
	return { items, complete }
}

export interface GuardianNodeSyncDeps {
	rpcUrl: string
	/** Current table (read-only use). */
	getTable: () => nodeInfo[]
	/** Replace the table. Must be synchronous so no request sees a half-applied table. */
	applyTable: (nodes: nodeInfo[]) => { clientRoutesDropped: number, clientRoutesRepointed: number }
	fetchWallets: () => Promise<NodeWallet[] | null>
	opts?: Partial<typeof SYNC_DEFAULTS>
	/** Replay/testing: never look past this block. */
	maxBlock?: number
}

export const createGuardianNodeSync = (deps: GuardianNodeSyncDeps) => {
	const opts = { ...SYNC_DEFAULTS, ...(deps.opts ?? {}) }
	const provider = createGuardianProvider(deps.rpcUrl)
	const contract = createGuardianContract(provider)
	const guard = new ShrinkGuard()

	/** Block and storage root the current table was read at. */
	let tableVersion: { block: number, storageHash: string | null } | null = null
	let lastFullReadAt = 0
	let inflight: Promise<RefreshOutcome> | null = null

	const finalizedHead = async () => {
		const head = await withTimeout(provider.getBlockNumber(), opts.rpcTimeoutMs, 'getBlockNumber')
		const target = Math.max(0, head - opts.confirmations)
		return deps.maxBlock !== undefined ? Math.min(target, deps.maxBlock) : target
	}

	const doRefresh = async (reason: string): Promise<RefreshOutcome> => {
		const t0 = Date.now()
		const before = deps.getTable()
		let block = -1
		try {
			block = await finalizedHead()
			const [chainNodes, wallets, storageHash] = await Promise.all([
				readGuardianNodesAt(contract, block, { pageSize: opts.pageSize, timeoutMs: opts.rpcTimeoutMs }),
				deps.fetchWallets().catch(() => null),
				storageHashAt(provider, block, opts.rpcTimeoutMs).catch(() => null),
			])
			if (!wallets) {
				log(Colors.yellow(`wallet list (apiv4 miningRate) unavailable; keeping wallets from the previous table`))
			}
			const next = toNodeInfos(chainNodes, wallets, before)
			const verdict = guard.check(before.length, next.length)
			if (!verdict.accept) {
				log(Colors.red(`refresh REJECTED, keeping current table (${before.length} nodes): ${verdict.reason}; block=${block} reason=[${reason}] ms=${Date.now() - t0}`))
				return { ok: false, retryInMs: verdict.retryInMs }
			}
			const d = diffNodeTables(before, next)
			const routes = deps.applyTable(next)
			tableVersion = { block, storageHash }
			lastFullReadAt = Date.now()
			const sample = (label: string, ips: string[]) => ips.length ? ` ${label}=[${ips.slice(0, 5).join(', ')}${ips.length > 5 ? ', …' : ''}]` : ''
			log(Colors.green(
				`refresh OK nodes ${before.length}→${next.length} (+${d.added.length} -${d.removed.length} ~${d.changed.length})` +
				` block=${block} ms=${Date.now() - t0} clientRoute dropped=${routes.clientRoutesDropped} repointed=${routes.clientRoutesRepointed}` +
				` reason=[${reason}]${verdict.reason ? ` note=[${verdict.reason}]` : ''}` +
				sample('added', d.added) + sample('removed', d.removed) + sample('changed', d.changed),
			))
			return { ok: true }
		} catch (e: any) {
			log(Colors.red(`refresh FAILED, keeping current table (${before.length} nodes): ${errText(e)}; block=${block} reason=[${reason}] ms=${Date.now() - t0}`))
			return { ok: false }
		}
	}

	/** Read and apply now (single-flight). Used at boot and by the scheduler. */
	const refreshNow = (reason: string): Promise<RefreshOutcome> => {
		if (inflight) return inflight
		inflight = doRefresh(reason).finally(() => { inflight = null })
		return inflight
	}

	const scheduler = new RefreshScheduler(refreshNow, opts)

	// ---- watcher ----
	let proofSupported = true
	let cursor: number | null = null
	let seenHash: string | null = null
	let pollTimer: NodeJS.Timeout | null = null
	let reconcileTimer: NodeJS.Timeout | null = null
	let rpcFailures = 0
	let started = false

	const knownIps = () => deps.getTable().map(n => n.ipaddress)

	const reportChange = async (from: number, to: number, how: string) => {
		const desc = await describeChanges(provider, from, to, knownIps(), opts)
		for (const item of desc.items) log(Colors.magenta(`chain change: ${item}`))
		if (!desc.complete || !desc.items.length) {
			log(Colors.magenta(`chain change in blocks ${from + 1}..${to} (${how})${desc.items.length ? '; list above may be partial' : '; no event or direct call found (internal call?)'}`))
		}
		const first = desc.items.find(i => !/failed|too long/.test(i))
		const summary = first ? first.replace(/ tx=0x[0-9a-f]+/i, '').slice(0, 120) : how
		scheduler.request(`blocks ${from + 1}..${to}: ${summary}${desc.items.length > 1 ? ` (+${desc.items.length - 1})` : ''}`)
	}

	const tick = async (): Promise<void> => {
		const target = await finalizedHead()
		if (cursor === null) {
			cursor = tableVersion?.block ?? target
			seenHash = tableVersion?.storageHash ?? null
			log(`watching ${GUARDIAN_NODES_INFO_ADDRESS} from block ${cursor} (mode: ${proofSupported ? 'storage root + logs' : 'logs + block scan'})`)
		}
		if (target <= cursor) return

		if (proofSupported) {
			let h: string
			try {
				h = await storageHashAt(provider, target, opts.rpcTimeoutMs)
			} catch (e: any) {
				if (!isUnsupportedMethod(e)) throw e
				proofSupported = false
				log(Colors.yellow(`eth_getProof not served by RPC; falling back to logs + block scan (${errText(e)})`))
				return tick()
			}
			if (seenHash && h !== seenHash) {
				await reportChange(cursor, target, 'storage root changed')
			} else if (!seenHash) {
				// Root unknown from the table read: compare against the table's block once.
				const tv = tableVersion
				if (tv && !tv.storageHash) {
					try {
						const base = await storageHashAt(provider, tv.block, opts.rpcTimeoutMs)
						tableVersion = { block: tv.block, storageHash: base }
						if (base !== h) await reportChange(Math.max(cursor, tv.block), target, 'storage root differs from table')
					} catch {}
				}
			}
			// Table is older than chain (failed or rejected refresh): keep asking, scheduler backs off.
			const tv = tableVersion
			if (tv?.storageHash && target >= tv.block && h !== tv.storageHash && !scheduler.isPending) {
				scheduler.request(`table built at block ${tv.block} is behind chain`)
			}
			seenHash = h
			cursor = target
			return
		}

		// Fallback: no storage root. Logs catch removals; addNode/pgpUpdate need the block scan.
		const span = target - cursor
		if (span > opts.maxTxScanBlocks) {
			await reportChange(cursor, target, `${span} blocks without storage root`)
		} else {
			const desc = await describeChanges(provider, cursor, target, knownIps(), opts, true)
			if (desc.items.length) {
				for (const item of desc.items) log(Colors.magenta(`chain change: ${item}`))
				scheduler.request(`blocks ${cursor + 1}..${target}: ${desc.items[0].replace(/ tx=0x[0-9a-f]+/i, '').slice(0, 120)}`)
			}
		}
		cursor = target
	}

	const schedulePoll = (delayMs: number) => {
		if (pollTimer) clearTimeout(pollTimer)
		pollTimer = setTimeout(async () => {
			pollTimer = null
			const from = cursor
			try {
				await tick()
				if (rpcFailures) {
					log(Colors.green(`RPC recovered after ${rpcFailures} failed polls; checked blocks ${from === null ? '?' : from + 1}..${cursor}`))
				}
				rpcFailures = 0
				schedulePoll(opts.pollMs)
			} catch (e: any) {
				rpcFailures++
				if (rpcFailures === 1 || rpcFailures % 10 === 0) {
					log(Colors.yellow(`poll failed (${rpcFailures} in a row), last checked block ${cursor ?? '?'}; missed blocks are checked after recovery: ${errText(e)}`))
				}
				schedulePoll(Math.min(5 * 60_000, opts.pollMs * 2 ** Math.min(rpcFailures, 4)))
			}
		}, delayMs)
	}

	const reconcile = async () => {
		const tv = tableVersion
		const stale = Date.now() - lastFullReadAt > opts.forceFullReadMs
		let why = ''
		if (stale) {
			why = `last full read over ${Math.round(opts.forceFullReadMs / 3_600_000)}h ago`
		} else if (!tv?.storageHash) {
			why = 'table storage root unknown'
		} else {
			try {
				const target = await finalizedHead()
				const h = await storageHashAt(provider, target, opts.rpcTimeoutMs)
				if (!proofSupported) {
					proofSupported = true
					log(`eth_getProof served again; back to storage-root mode`)
				}
				if (h !== tv.storageHash) why = `storage root at ${target} differs from table (block ${tv.block})`
				else log(`reconcile: table matches chain at block ${target} (${deps.getTable().length} nodes)`)
			} catch (e: any) {
				why = `could not read storage root (${errText(e)})`
			}
		}
		if (why) scheduler.request(`reconcile: ${why}`)
	}

	const scheduleReconcile = () => {
		if (reconcileTimer) clearTimeout(reconcileTimer)
		const delay = opts.reconcileMs + Math.floor(Math.random() * opts.reconcileJitterMs)
		reconcileTimer = setTimeout(() => {
			void reconcile().finally(scheduleReconcile)
		}, delay)
	}

	/** Start watching; safe to call more than once. Call after the first successful refresh. */
	const startWatching = () => {
		if (started) return
		started = true
		const firstPoll = Math.floor(Math.random() * opts.pollMs)
		log(`watcher starting (first poll in ${Math.round(firstPoll / 1000)}s, every ${opts.pollMs / 1000}s; reconcile every ${opts.reconcileMs / 3_600_000}h)`)
		schedulePoll(firstPoll)
		scheduleReconcile()
	}

	const stop = () => {
		if (pollTimer) clearTimeout(pollTimer)
		if (reconcileTimer) clearTimeout(reconcileTimer)
		pollTimer = reconcileTimer = null
		scheduler.stop()
		started = false
	}

	return {
		refreshNow,
		requestRefresh: (reason: string) => scheduler.request(reason),
		startWatching,
		stop,
		/** For tests and diagnostics. */
		_tick: tick,
		_state: () => ({ cursor, seenHash, tableVersion, proofSupported, rpcFailures }),
	}
}
