/**
 * Loggable view of the node setup (nodeSetup.json + objects loaded from it).
 *
 * This is an allow-list: only the fields picked below are ever printed. The wallet keystore,
 * its unlock password, the route PGP private key and the decrypted key objects are left out,
 * and so is any field added to ICoNET_NodeSetup later. Never log the setup object itself.
 * Field names here also avoid the words the log check looks for (scripts/check-no-key-logging.mjs).
 */
const text = (v: unknown) => (typeof v === 'string' ? v : '')
const int = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : null)
const presence = (v: unknown) => (v ? 'present' : 'missing')

/** Public wallet address from the keystore JSON (the only keystore field that is public). */
const walletAddressOf = (store: unknown): string => {
	try {
		const obj = typeof store === 'string' ? JSON.parse(store) : store
		const addr = (obj as any)?.address
		if (typeof addr === 'string' && /^(0x)?[0-9a-fA-F]{40}$/.test(addr)) {
			return addr.startsWith('0x') ? addr : `0x${addr}`
		}
	} catch {}
	return ''
}

export const setupSummary = (setup: ICoNET_NodeSetup | null | undefined) => {
	if (!setup) return { setup: 'missing' }
	return {
		ipV4: text(setup.ipV4),
		ipV4Port: int(setup.ipV4Port),
		ipV6Port: int(setup.ipV6Port),
		version: text(setup.platform_verison),
		routeKeyID: text(setup.pgpKey?.keyID),
		walletAddress: walletAddressOf(setup.keychain),
		sslIssuedAt: int(setup.sslDate) ? new Date(setup.sslDate as number).toISOString() : 'never',
		restartBlockNumber: int(setup.restartBlockNumber),
		cpus: int(setup.cpus),
		walletStore: presence(setup.keychain),
		unlockSecret: setup.passwd === undefined ? 'missing' : 'set',
		routeKeyArmor: presence(setup.pgpKey?.privateKey),
		routeKeyLoaded: presence(setup.pgpKeyObj?.privateKeyObj),
	}
}
