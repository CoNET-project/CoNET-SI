/**
 * ERC20Deposited 事件发生后，使用本机钱包连接 CoNET 的 ConetTreasury 合约，
 * 调用 vote 进行 mint 投票（2/3 miner 通过后自动 mint）。
 * 支持 miner 直接投票 voteAirdropBUnit（B-Unit airdrop）。
 */
import { ethers, Wallet, JsonRpcProvider, Contract } from 'ethers'
import { onBaseVoteEvent, ERC20DepositedPayload, BUnitPurchasedPayload } from './baseVote'
import { logger } from '../util/logger'
import Colors from 'colors/safe'

const CONET_RPC = process.env.CONET_RPC ?? 'https://mainnet-rpc1.conet.network'

const ConetTreasuryABI = [
  'function vote(bytes32 txHash, address token, address recipient, uint256 amount) external',
  'function voteAirdropBUnit(address claimant, uint256 nonce, uint256 deadline, bytes calldata signature) external',
  'function voteAirdropBUnitFromBase(bytes32 txHash, address user, uint256 usdcAmount) external',
  'function getCreatedTokens() external view returns (address[])',
  'function baseTokenOf(address token) external view returns (address)',
  'function isMiner(address account) external view returns (bool)',
]

/**
 * 根据 Base 链 ERC20 地址查找对应的 CoNET 链 token 地址
 */
async function findConetTokenForBaseToken(
  conetTreasury: Contract,
  baseToken: string
): Promise<string | null> {
  const tokens = await conetTreasury.getCreatedTokens()
  const baseLower = baseToken.toLowerCase()
  for (const t of tokens) {
    const bt = await conetTreasury.baseTokenOf(t)
    if (bt?.toLowerCase() === baseLower) return t
  }
  return null
}

/**
 * 处理 ERC20Deposited 事件：向 ConetTreasury 发起 vote
 */
async function handleERC20Deposited(
  wallet: Wallet,
  conetTreasuryAddress: string,
  conetRpcUrl: string,
  payload: ERC20DepositedPayload
): Promise<void> {
  const provider = new JsonRpcProvider(conetRpcUrl)
  const signer = wallet.connect(provider)
  const contract = new Contract(conetTreasuryAddress, ConetTreasuryABI, signer)

  const isMiner = await contract.isMiner(wallet.address)
  if (!isMiner) {
    logger(Colors.yellow(`conetVote: ${wallet.address} 不是 ConetTreasury miner，跳过 vote`))
    return
  }

  const conetToken = await findConetTokenForBaseToken(contract, payload.token)
  if (!conetToken) {
    logger(Colors.yellow(`conetVote: 未找到 Base token ${payload.token} 对应的 CoNET token，跳过`))
    return
  }

  // txHash 已是 32 字节 hex，直接传入
  const txHashBytes32 = payload.txHash.startsWith('0x') ? payload.txHash : '0x' + payload.txHash
  try {
    const tx = await contract.vote(
      txHashBytes32,
      conetToken,
      payload.to,
      payload.amount
    )
    logger(Colors.green(`conetVote: vote 已提交 tx=${tx.hash} txHash=${payload.txHash} to=${payload.to} amount=${payload.amount}`))
    await tx.wait()
    logger(Colors.green(`conetVote: vote 已确认 tx=${tx.hash}`))
  } catch (ex: any) {
    if (ex?.message?.includes('AlreadyVoted')) {
      logger(Colors.grey(`conetVote: 已投过票 txHash=${payload.txHash}，跳过`))
      return
    }
    logger(Colors.red(`conetVote: vote 失败 txHash=${payload.txHash} ${ex?.message ?? ex}`))
  }
}

/**
 * Miner 直接调用 ConetTreasury.voteAirdropBUnit 投票
 * @param wallet 本机钱包（需为 ConetTreasury 的 miner）
 * @param conetTreasuryAddress CoNET 链上 ConetTreasury 合约地址
 * @param claimant 申领人地址
 * @param nonce BUnitAirdrop.claimNonces(claimant) 的当前值
 * @param deadline 用户签名的 deadline
 * @param signature 用户 ClaimAirdrop(claimant, nonce, deadline) 的 EIP-712 签名
 * @param conetRpcUrl CoNET RPC（可选）
 */
export async function voteAirdropBUnitDirect(
  wallet: Wallet,
  conetTreasuryAddress: string,
  claimant: string,
  nonce: bigint | number,
  deadline: bigint | number,
  signature: string,
  conetRpcUrl?: string
): Promise<{ txHash: string } | null> {
  const url = conetRpcUrl ?? CONET_RPC
  const provider = new JsonRpcProvider(url)
  const signer = wallet.connect(provider)
  const contract = new Contract(conetTreasuryAddress, ConetTreasuryABI, signer)

  const isMiner = await contract.isMiner(wallet.address)
  if (!isMiner) {
    logger(Colors.yellow(`conetVote: ${wallet.address} 不是 ConetTreasury miner，跳过 voteAirdropBUnit`))
    return null
  }

  try {
    const tx = await contract.voteAirdropBUnit(claimant, nonce, deadline, signature)
    logger(Colors.green(`conetVote: voteAirdropBUnit 已提交 tx=${tx.hash} claimant=${claimant}`))
    await tx.wait()
    logger(Colors.green(`conetVote: voteAirdropBUnit 已确认 tx=${tx.hash}`))
    return { txHash: tx.hash }
  } catch (ex: any) {
    if (ex?.message?.includes('AlreadyVoted')) {
      logger(Colors.grey(`conetVote: voteAirdropBUnit 已投过票 claimant=${claimant}，跳过`))
      return null
    }
    logger(Colors.red(`conetVote: voteAirdropBUnit 失败 claimant=${claimant} ${ex?.message ?? ex}`))
    return null
  }
}

/**
 * 处理 BUnitPurchased 事件：用 txHash + to 证明用户已支付 USDC，直接 voteAirdropBUnitFromBase
 * 按 1 USDC = 100 B-Units 铸造到用户付费池
 */
async function handleBUnitPurchased(
  wallet: Wallet,
  conetTreasuryAddress: string,
  conetRpcUrl: string,
  payload: BUnitPurchasedPayload
): Promise<void> {
  await voteAirdropBUnitFromBaseDirect(
    wallet,
    conetTreasuryAddress,
    payload.txHash,
    payload.to,
    payload.amount,
    conetRpcUrl
  )
}

/**
 * Miner 直接调用 ConetTreasury.voteAirdropBUnitFromBase
 * 用 Base 链 txHash + user 证明 USDC 支付，按 1 USDC = 100 B-Units 铸造
 */
export async function voteAirdropBUnitFromBaseDirect(
  wallet: Wallet,
  conetTreasuryAddress: string,
  txHash: string,
  user: string,
  usdcAmount: bigint | number,
  conetRpcUrl?: string
): Promise<{ txHash: string } | null> {
  const url = conetRpcUrl ?? CONET_RPC
  const provider = new JsonRpcProvider(url)
  const signer = wallet.connect(provider)
  const contract = new Contract(conetTreasuryAddress, ConetTreasuryABI, signer)

  const isMiner = await contract.isMiner(wallet.address)
  if (!isMiner) {
    logger(Colors.yellow(`conetVote: ${wallet.address} 不是 ConetTreasury miner，跳过 voteAirdropBUnitFromBase`))
    return null
  }

  const txHashBytes32 = txHash.startsWith('0x') ? txHash : '0x' + txHash
  const amount = BigInt(usdcAmount)
  try {
    const tx = await contract.voteAirdropBUnitFromBase(txHashBytes32, user, amount)
    logger(Colors.green(`conetVote: voteAirdropBUnitFromBase 已提交 tx=${tx.hash} user=${user} usdc=${amount}`))
    await tx.wait()
    logger(Colors.green(`conetVote: voteAirdropBUnitFromBase 已确认 tx=${tx.hash}`))
    return { txHash: tx.hash }
  } catch (ex: any) {
    if (ex?.message?.includes('AlreadyVoted')) {
      logger(Colors.grey(`conetVote: voteAirdropBUnitFromBase 已投过票 txHash=${txHash}，跳过`))
      return null
    }
    logger(Colors.red(`conetVote: voteAirdropBUnitFromBase 失败 txHash=${txHash} ${ex?.message ?? ex}`))
    return null
  }
}

/**
 * 启动 ERC20Deposited 监听并自动向 ConetTreasury 投票
 * @param wallet 本机钱包（需为 ConetTreasury 的 miner）
 * @param conetTreasuryAddress CoNET 链上 ConetTreasury 合约地址
 * @param conetRpcUrl CoNET RPC（可选）
 */
export function startConetVoteForERC20Deposited(
  wallet: Wallet,
  conetTreasuryAddress: string,
  conetRpcUrl?: string
): () => void {
  const url = conetRpcUrl ?? CONET_RPC
  const unsub = onBaseVoteEvent(async (ev) => {
    if (ev.type !== 'ERC20Deposited') return
    await handleERC20Deposited(wallet, conetTreasuryAddress, url, ev.payload)
  })
  logger(Colors.blue(`conetVote: 已启动 ERC20Deposited -> ConetTreasury.vote 监听 wallet=${wallet.address} treasury=${conetTreasuryAddress}`))
  return unsub
}

/**
 * 启动 BUnitPurchased 监听：用 txHash + to 证明 USDC 支付，自动 voteAirdropBUnitFromBase（1 USDC = 100 B-Units）
 */
export function startConetVoteForBUnitPurchased(
  wallet: Wallet,
  conetTreasuryAddress: string,
  conetRpcUrl?: string
): () => void {
  const url = conetRpcUrl ?? CONET_RPC
  const unsub = onBaseVoteEvent(async (ev) => {
    if (ev.type !== 'BUnitPurchased') return
    await handleBUnitPurchased(wallet, conetTreasuryAddress, url, ev.payload)
  })
  logger(Colors.blue(`conetVote: 已启动 BUnitPurchased -> ConetTreasury.voteAirdropBUnitFromBase 监听 wallet=${wallet.address}`))
  return unsub
}