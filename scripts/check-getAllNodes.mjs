#!/usr/bin/env node
/**
 * 使用 curl 测试链上 getAllNodes 合约调用是否正常
 * 用法: node scripts/check-getAllNodes.mjs
 */

import { execSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const __dirname = dirname(fileURLToPath(import.meta.url))
const require = createRequire(import.meta.url)
const { ethers } = require(join(__dirname, '../node_modules/ethers'))
const newNodeInfoABI = require(join(__dirname, '../src/util/newNodeInfoABI.json'))

const RPC = 'https://mainnet-rpc1.conet.network'
const CONTRACT = '0xCd68C3FFFE403f9F26081807c77aB29a4DF6940D'

function curlRpc(payload) {
  return execSync(
    `curl -s -X POST "${RPC}" -H "Content-Type: application/json" -d '${payload}'`,
    { encoding: 'utf-8', maxBuffer: 10 * 1024 * 1024 }
  )
}

const iface = new ethers.Interface(newNodeInfoABI)
const data = iface.encodeFunctionData('getAllNodes', [0, 100])

const payload = JSON.stringify({
  jsonrpc: '2.0',
  method: 'eth_call',
  params: [
    { to: CONTRACT, data },
    'latest'
  ],
  id: 1
})

// 1. 先检查 chainId 和合约是否存在
const chainIdPayload = JSON.stringify({ jsonrpc: '2.0', method: 'eth_chainId', params: [], id: 0 })
const chainIdRes = JSON.parse(curlRpc(chainIdPayload))
console.log('--- 1. RPC 链信息 ---\n')
console.log('chainId:', chainIdRes.result ? parseInt(chainIdRes.result, 16) : chainIdRes)

const getCodePayload = JSON.stringify({
  jsonrpc: '2.0',
  method: 'eth_getCode',
  params: [CONTRACT, 'latest'],
  id: 2
})
console.log('\n--- 2. 检查合约是否存在 (eth_getCode) ---\n')
const getCodeResult = JSON.parse(curlRpc(getCodePayload))
const code = getCodeResult.result
console.log('合约代码长度:', code === '0x' ? 0 : (code?.length ?? 0) - 2, 'bytes')
console.log(code === '0x' || !code ? '⚠️ 该地址无合约代码' : '✓ 有合约代码')
console.log('')

console.log('--- 3. 测试 getAllNodes(0, 100) ---\n')
console.log('RPC:', RPC)
console.log('合约:', CONTRACT)
console.log('calldata:', data.slice(0, 20) + '...\n')
console.log('curl 命令:\ncurl -s -X POST "' + RPC + '" -H "Content-Type: application/json" -d \'' + payload + '\'\n')
console.log('--- 返回结果 ---')

try {
  const result = curlRpc(payload)
  const json = JSON.parse(result)
  if (json.error) {
    console.log('RPC 错误:', json.error)
  } else {
    const hex = json.result
    console.log('原始返回 (前 200 字符):', (hex || 'null').slice(0, 200))
    console.log('返回长度:', hex ? hex.length : 0, '字符')
    if (hex === '0x' || !hex) {
      console.log('\n⚠️  返回 0x 或空，说明合约可能:')
      console.log('   - 该地址无合约或未部署 getAllNodes')
      console.log('   - RPC 链与合约部署链不一致')
      console.log('   - 合约 revert')
    } else if (hex.length > 10) {
      console.log('\n✓ 链上有有效返回，尝试解码...')
      try {
        const decoded = iface.decodeFunctionResult('getAllNodes', hex)
        const nodes = decoded[0] || []
        console.log('解码成功，节点数:', nodes.length)
        if (nodes.length > 0) {
          console.log('首条:', JSON.stringify(nodes[0], (_, v) => typeof v === 'bigint' ? v.toString() : v).slice(0, 150) + '...')
        }
      } catch (e) {
        console.log('解码失败:', e.message)
      }
    }
  }
} catch (e) {
  console.error('执行失败:', e.message)
}
