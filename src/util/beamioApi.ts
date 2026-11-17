import P from 'phin'
import Colors from 'colors/safe'
import { logger } from './logger'

/**
 * Beamio API 的唯一允许基址。旧域 beamio.app 已退役，节点只能调用 beamio.ca。
 * 节点环境变量 BEAMIO_API_BASE 只作为存量配置的审计入口：只有严格等于 https://beamio.ca
 * （允许末尾一个 `/`）才被接受；其他任何取值（旧域、*.beamio.app、http、相似域名、带账号信息、
 * 带端口或路径等）都不会用于出站请求，统一改用本常量并打一次告警。
 */
export const BEAMIO_API_BASE = 'https://beamio.ca'
const BEAMIO_API_HOST = 'beamio.ca'

export type BeamioApiPath =
	| '/api/notifyOfflineChat'
	| '/api/voiceCallPush'
	| '/api/nativeWakeable'
	| '/api/registerPushDevice'

export type BeamioApiBaseRejectReason =
	| 'unparseable'
	| 'retired-domain'
	| 'not-https'
	| 'credentials'
	| 'not-allowed-host'
	| 'port'
	| 'path'

/** 返回 null 表示该值可接受（即严格等于 https://beamio.ca，允许末尾单个 `/`）。 */
export const classifyBeamioApiBase = (raw: string): BeamioApiBaseRejectReason | null => {
	let url: URL
	try {
		url = new URL(raw)
	} catch {
		return 'unparseable'
	}
	const host = url.hostname.toLowerCase()
	if (host === 'beamio.app' || host.endsWith('.beamio.app')) return 'retired-domain'
	if (url.protocol !== 'https:') return 'not-https'
	if (url.username || url.password) return 'credentials'
	if (host !== BEAMIO_API_HOST) return 'not-allowed-host'
	if (url.port) return 'port'
	if ((url.pathname !== '/' && url.pathname !== '') || url.search || url.hash) return 'path'
	return null
}

const warnedReasons = new Set<BeamioApiBaseRejectReason>()

/** 解析出站基址。只返回 BEAMIO_API_BASE；不合规的环境值只记录原因，不记录其内容。 */
export const resolveBeamioApiBase = (): string => {
	const raw = (process.env.BEAMIO_API_BASE ?? '').trim()
	if (!raw) return BEAMIO_API_BASE
	const reason = classifyBeamioApiBase(raw)
	if (reason && !warnedReasons.has(reason)) {
		warnedReasons.add(reason)
		logger(Colors.yellow(`BEAMIO_API_BASE rejected (${reason}); using ${BEAMIO_API_BASE}. Update the node environment config.`))
	}
	return BEAMIO_API_BASE
}

/**
 * POST JSON 到 Beamio API。
 * - 基址固定为 BEAMIO_API_BASE（beamio.ca），路径、请求体、超时保持调用方原样；
 * - 不跟随重定向（followRedirects: false；phin/centra 默认也不跟随），任何 3xx 直接抛出显式错误，
 *   不会再向 Location 指向的任何主机发起请求。
 */
export const postBeamioApi = async (apiPath: BeamioApiPath, body: Record<string, unknown>, timeoutMs: number) => {
	const res = await P({
		url: `${resolveBeamioApiBase()}${apiPath}`,
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		data: JSON.stringify(body),
		parse: 'json',
		timeout: timeoutMs,
		followRedirects: false,
	})
	const status = res.statusCode || 0
	if (status >= 300 && status < 400) {
		throw new Error(`Beamio API redirect refused (HTTP ${status})`)
	}
	return res
}
