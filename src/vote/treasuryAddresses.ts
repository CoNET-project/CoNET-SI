/** Treasury V3 UUPS proxy，Base 与 CoNET 使用同一 canonical 地址。 */
export const TREASURY_V3_CREATE2 =
  process.env.TREASURY_V3_ADDRESS?.trim() || '0xa208982212978550594A7FEEB70a61665d129003'

/** @deprecated 旧国库地址，仅保留给历史兼容代码，不得用于新投票监听。 */
export const CONET_TREASURY_CREATE2 = TREASURY_V3_CREATE2
export const CONET_TREASURY_PEER_CREATE2 = TREASURY_V3_CREATE2

export const BASE_CHAIN_ID = 8453n
export const CONET_CHAIN_ID = 224422n

export const BASE_CIRCLE_USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'
