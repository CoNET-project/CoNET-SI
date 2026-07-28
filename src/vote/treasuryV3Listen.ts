import { ethers, Wallet } from 'ethers'
import * as fs from 'fs/promises'
import * as path from 'path'
import { BASE_CHAIN_ID, CONET_CHAIN_ID, TREASURY_V3_CREATE2 } from './treasuryAddresses'

const TREASURY_V3_ABI = [
  'event BridgeOperation(bytes32 indexed operationId,uint256 indexed sourceChainId,uint256 indexed destinationChainId,uint8 phase,uint8 mode,address sourceTreasury,address sourceAsset,address destinationAsset,address sender,address[] beneficiaries,uint256[] amounts,uint256 grossAmount,uint256 feeAmount,uint256 netAmount,bytes32 sourceTxHash,uint256 nonce)',
  'function isMiner(address account) view returns (bool)',
  'function voteBridgeOperation(bytes32 operationId,uint256 sourceChainId,uint256 destinationChainId,address sourceTreasury,address sourceAsset,address destinationAsset,address[] beneficiaries,uint256[] amounts,uint8 mode,uint256 grossAmount,uint256 feeAmount,bytes32 sourceTxHash,uint256 nonce)',
] as const

const BRIDGE_OPERATION_TOPIC = ethers.id(
  'BridgeOperation(bytes32,uint256,uint256,uint8,uint8,address,address,address,address,address[],uint256[],uint256,uint256,uint256,bytes32,uint256)',
)
const VOTE_TAG = 'vote-v3'
const CHUNK_BLOCKS = BigInt(process.env.TREASURY_V3_LOGS_CHUNK_BLOCKS || '400')
const CHUNKS_PER_TICK = Math.max(1, Number(process.env.TREASURY_V3_CHUNKS_PER_TICK || '4'))
const POLL_DELAY_MS = Number(process.env.TREASURY_V3_POLL_DELAY_MS || 12_000)
const MAX_BACKFILL_BLOCKS = BigInt(process.env.TREASURY_V3_BACKFILL_BLOCKS || '0')
const DEPLOY_BLOCK_BASE = BigInt(process.env.TREASURY_V3_DEPLOY_BLOCK_BASE || process.env.TREASURY_V3_DEPLOY_BLOCK || '0')
const DEPLOY_BLOCK_CONET = BigInt(process.env.TREASURY_V3_DEPLOY_BLOCK_CONET || process.env.TREASURY_V3_DEPLOY_BLOCK || '0')
type BridgeOperation = {
  operationId: string
  sourceChainId: bigint
  destinationChainId: bigint
  mode: number
  sourceTreasury: string
  sourceAsset: string
  destinationAsset: string
  beneficiaries: string[]
  amounts: bigint[]
  grossAmount: bigint
  feeAmount: bigint
  sourceTxHash: string
  nonce: bigint
  sourceTransactionHash: string
  sourceBlockNumber: number
}

type VoteState = {
  version: 1
  lastProcessedBlock: string
  scanTargetBlock: string
  updatedAt: string
}

function debug(message: string, data?: Record<string, unknown>): void {
  const suffix = data ? ` ${JSON.stringify(data)}` : ''
  console.log(`[${VOTE_TAG}] [${new Date().toISOString()}] ${message}${suffix}`)
}

function rpcHttpUrl(raw: string): string {
  if (/^https?:\/\//i.test(raw)) return raw
  if (/^wss?:\/\//i.test(raw)) return raw.replace(/^ws/i, 'http')
  return `https://${raw}`
}

function statePath(chainId: bigint): string {
  const suffix = chainId === BASE_CHAIN_ID ? 'base' : 'conet'
  return process.env.TREASURY_V3_VOTE_STATE_FILE
    ? `${process.env.TREASURY_V3_VOTE_STATE_FILE}.${suffix}`
    : path.join(process.cwd(), `.treasury-v3-vote-${suffix}.json`)
}

async function loadState(file: string): Promise<VoteState | null> {
  try {
    const value = JSON.parse(await fs.readFile(file, 'utf8')) as VoteState
    if (
      value.version === 1 &&
      typeof value.lastProcessedBlock === 'string' &&
      typeof value.scanTargetBlock === 'string'
    ) return value
  } catch {
    /* first start */
  }
  return null
}

async function saveState(file: string, lastProcessedBlock: bigint, scanTargetBlock: bigint): Promise<void> {
  await fs.mkdir(path.dirname(file), { recursive: true })
  const temp = `${file}.${process.pid}.tmp`
  await fs.writeFile(
    temp,
    JSON.stringify({
      version: 1,
      lastProcessedBlock: lastProcessedBlock.toString(),
      scanTargetBlock: scanTargetBlock.toString(),
      updatedAt: new Date().toISOString(),
    }, null, 2),
  )
  await fs.rename(temp, file)
}

async function getLogsChunked(
  provider: ethers.Provider,
  fromBlock: bigint,
  toBlock: bigint,
): Promise<ethers.Log[]> {
  const logs: ethers.Log[] = []
  for (let start = fromBlock; start <= toBlock; start += CHUNK_BLOCKS) {
    const end = start + CHUNK_BLOCKS - 1n <= toBlock ? start + CHUNK_BLOCKS - 1n : toBlock
    logs.push(
      ...(await provider.getLogs({
        address: TREASURY_V3_CREATE2,
        topics: [BRIDGE_OPERATION_TOPIC],
        fromBlock: start,
        toBlock: end,
      })),
    )
  }
  return logs
}

function parseBridgeOperation(log: ethers.Log): BridgeOperation | null {
  const parsed = new ethers.Interface(TREASURY_V3_ABI).parseLog({
    topics: log.topics as string[],
    data: log.data,
  })
  if (!parsed || Number(parsed.args.phase) !== 0) return null
  return {
    operationId: parsed.args.operationId,
    sourceChainId: BigInt(parsed.args.sourceChainId),
    destinationChainId: BigInt(parsed.args.destinationChainId),
    mode: Number(parsed.args.mode),
    sourceTreasury: parsed.args.sourceTreasury,
    sourceAsset: parsed.args.sourceAsset,
    destinationAsset: parsed.args.destinationAsset,
    beneficiaries: [...(parsed.args.beneficiaries as string[])],
    amounts: (parsed.args.amounts as readonly bigint[]).map((v) => BigInt(v)),
    grossAmount: BigInt(parsed.args.grossAmount),
    feeAmount: BigInt(parsed.args.feeAmount),
    sourceTxHash: parsed.args.sourceTxHash,
    nonce: BigInt(parsed.args.nonce),
    sourceTransactionHash: log.transactionHash,
    sourceBlockNumber: log.blockNumber,
  }
}

/** Errors that mean this miner can skip the op without blocking the cursor. */
function isSkippableVoteError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error)
  return /AlreadyVoted|OperationAlreadyUsed|already voted|already (used|executed)/i.test(message)
}

async function voteOnDestination(
  wallet: Wallet,
  operation: BridgeOperation,
  sourceChainId: bigint,
  destinationRpc: string,
): Promise<void> {
  if (operation.destinationChainId !== (sourceChainId === BASE_CHAIN_ID ? CONET_CHAIN_ID : BASE_CHAIN_ID)) return
  const destinationProvider = new ethers.JsonRpcProvider(rpcHttpUrl(destinationRpc))
  const destinationWallet = wallet.connect(destinationProvider)
  const treasury = new ethers.Contract(TREASURY_V3_CREATE2, TREASURY_V3_ABI, destinationWallet)
  if (!(await treasury.isMiner(destinationWallet.address))) {
    throw new Error(`destination wallet ${destinationWallet.address} is not a Treasury V3 miner`)
  }
  debug('submitting direct Treasury V3 miner vote', {
    operationId: operation.operationId,
    sourceChainId: operation.sourceChainId.toString(),
    destinationChainId: operation.destinationChainId.toString(),
    signer: destinationWallet.address,
  })
  // Quorum-final votes execute mint/release in the same tx. estimateGas often
  // prices only the vote branch (~90k) when local tip still shows voteCount <
  // required, then the mined tx becomes the executor and OOGs. Multi-beneficiary
  // mint/transfer needs headroom — pin a higher ceiling.
  const VOTE_GAS_LIMIT = BigInt(process.env.TREASURY_V3_VOTE_GAS_LIMIT || '900000')
  const tx = await treasury.voteBridgeOperation(
    operation.operationId,
    operation.sourceChainId,
    operation.destinationChainId,
    operation.sourceTreasury,
    operation.sourceAsset,
    operation.destinationAsset,
    operation.beneficiaries,
    operation.amounts,
    operation.mode,
    operation.grossAmount,
    operation.feeAmount,
    operation.sourceTxHash,
    operation.nonce,
    { gasLimit: VOTE_GAS_LIMIT },
  )
  const receipt = await tx.wait()
  if (!receipt) throw new Error(`missing receipt for Treasury V3 vote ${tx.hash}`)
  debug('Treasury V3 miner vote confirmed', {
    operationId: operation.operationId,
    txHash: tx.hash,
    blockNumber: receipt.blockNumber,
  })
}

/**
 * Vote each Initiated log. Returns retryable failure count.
 * Skippable on-chain states (already voted / executed) do not count as failures.
 */
async function processLogs(
  wallet: Wallet,
  sourceChainId: bigint,
  destinationRpc: string,
  logs: ethers.Log[],
): Promise<number> {
  let retryableFailures = 0
  for (const log of logs) {
    const operation = parseBridgeOperation(log)
    if (!operation) continue
    try {
      await voteOnDestination(wallet, operation, sourceChainId, destinationRpc)
    } catch (error) {
      if (isSkippableVoteError(error)) {
        debug('Treasury V3 vote skipped', {
          operationId: operation.operationId,
          sourceChainId: sourceChainId.toString(),
          error: error instanceof Error ? error.message : String(error),
        })
        continue
      }
      retryableFailures++
      debug('Treasury V3 vote failed; chunk will be retried', {
        operationId: operation.operationId,
        sourceChainId: sourceChainId.toString(),
        sourceBlockNumber: operation.sourceBlockNumber,
        error: error instanceof Error ? error.message : String(error),
      })
    }
  }
  return retryableFailures
}

async function runChain(wallet: Wallet, sourceChainId: bigint, sourceRpc: string, destinationRpc: string): Promise<void> {
  const provider = new ethers.JsonRpcProvider(rpcHttpUrl(sourceRpc))
  const treasury = new ethers.Contract(TREASURY_V3_CREATE2, TREASURY_V3_ABI, provider)
  const miner = await treasury.isMiner(wallet.address)
  debug('Treasury V3 miner check', { sourceChainId: sourceChainId.toString(), wallet: wallet.address, miner })
  if (!miner) return

  const stateFile = statePath(sourceChainId)
  const deployBlock = sourceChainId === BASE_CHAIN_ID ? DEPLOY_BLOCK_BASE : DEPLOY_BLOCK_CONET
  const currentHead = BigInt(await provider.getBlockNumber())
  const floor = deployBlock
  const initialLast = floor > 0n ? floor - 1n : currentHead
  const state = await loadState(stateFile)
  let lastProcessed = state ? BigInt(state.lastProcessedBlock) : initialLast
  let scanTarget = state ? BigInt(state.scanTargetBlock) : currentHead
  if (lastProcessed < initialLast) lastProcessed = initialLast
  if (scanTarget < lastProcessed) scanTarget = lastProcessed
  if (!state && MAX_BACKFILL_BLOCKS > 0n) {
    lastProcessed = currentHead > MAX_BACKFILL_BLOCKS ? currentHead - MAX_BACKFILL_BLOCKS : initialLast
    if (lastProcessed < initialLast) lastProcessed = initialLast
  }
  await saveState(stateFile, lastProcessed, scanTarget)

  // Serial setTimeout chain: always reschedule in finally so a thrown vote/RPC
  // error cannot kill the poll loop (previous bug: setTimeout only ran after success).
  const scheduleNext = (): void => {
    setTimeout(() => {
      void tick()
    }, POLL_DELAY_MS)
  }

  const tick = async (): Promise<void> => {
    try {
      if (lastProcessed >= scanTarget) {
        scanTarget = BigInt(await provider.getBlockNumber())
      }
      const maxBlocks = CHUNK_BLOCKS * BigInt(CHUNKS_PER_TICK)
      const toBlock = lastProcessed + maxBlocks < scanTarget ? lastProcessed + maxBlocks : scanTarget
      if (lastProcessed < toBlock) {
        const failures = await processLogs(
          wallet,
          sourceChainId,
          destinationRpc,
          await getLogsChunked(provider, lastProcessed + 1n, toBlock),
        )
        if (failures === 0) {
          lastProcessed = toBlock
        } else {
          debug('Treasury V3 cursor not advanced', {
            sourceChainId: sourceChainId.toString(),
            lastProcessedBlock: lastProcessed.toString(),
            attemptedToBlock: toBlock.toString(),
            retryableFailures: failures,
          })
        }
      }
      await saveState(stateFile, lastProcessed, scanTarget)
    } catch (error) {
      debug('Treasury V3 poll failed', {
        sourceChainId: sourceChainId.toString(),
        error: error instanceof Error ? error.message : String(error),
      })
    } finally {
      scheduleNext()
    }
  }
  scheduleNext()
  debug('Treasury V3 listener ready', {
    sourceChainId: sourceChainId.toString(),
    lastProcessedBlock: lastProcessed.toString(),
    scanTargetBlock: scanTarget.toString(),
    deployBlock: deployBlock.toString(),
  })
}

export async function startTreasuryV3VoteListen(
  wallet: Wallet,
  baseRpc?: string,
  conetRpc?: string,
): Promise<void> {
  const base = baseRpc || process.env.BASE_RPC || process.env.BASE_RPC_HTTP || 'https://base-rpc.conet.network'
  const conet = conetRpc || process.env.CONET_RPC || 'https://rpc1.conet.network'
  await Promise.all([
    runChain(wallet, BASE_CHAIN_ID, base, conet),
    runChain(wallet, CONET_CHAIN_ID, conet, base),
  ])
}
