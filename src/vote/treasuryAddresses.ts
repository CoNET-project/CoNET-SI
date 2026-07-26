/**
 * 统一国库 + Peer 跨链桥 CREATE2 同址（Base 8453 + CoNET 224422）。
 * 与 x402sdk `chainAddresses.ts` / deployments/conet-treasury-cross-chain-stack.json 对齐。
 */

/** ConetTreasury（miner 治理、BUnitPurchased、Factory mint） */
export const CONET_TREASURY_CREATE2 = '0xa311c8fBE7CafC611603Ee925465A62493B73B30'

/** ConetTreasuryPeer（跨链 burn / StableSwap → 目标链 voteMint*） */
export const CONET_TREASURY_PEER_CREATE2 = '0x025eC62F801B2f63d5C5b3eB066bab21B12Bbeb5'

export const BASE_CHAIN_ID = 8453n
export const CONET_CHAIN_ID = 224422n

export const BASE_CIRCLE_USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'
