#!/usr/bin/env node
/**
 * 测试 Base RPC 转发可用性
 * 用法: node scripts/test-base-rpc.mjs [--proxy PORT]
 * 不加 --proxy 时只测试直连 upstream；加 --proxy 4000 时测试经代理转发
 */

import Https from 'node:https'
import Http from 'node:http'
import Net from 'node:net'

const UPSTREAM_HOST = '1rpc.io'
const UPSTREAM_PATH = '/base'
const RPC_BODY = JSON.stringify({
  jsonrpc: '2.0',
  method: 'eth_chainId',
  params: [],
  id: 1
})

async function testDirectUpstream() {
  return new Promise((resolve, reject) => {
    const req = Https.request(
      {
        hostname: UPSTREAM_HOST,
        port: 443,
        path: UPSTREAM_PATH,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(RPC_BODY, 'utf8').toString(),
          Accept: '*/*'
        }
      },
      res => {
        let body = ''
        res.on('data', chunk => (body += chunk))
        res.on('end', () => {
          try {
            const json = JSON.parse(body)
            resolve({ ok: !json.error, statusCode: res.statusCode, body: json })
          } catch (e) {
            resolve({ ok: false, statusCode: res.statusCode, body, parseError: e.message })
          }
        })
      }
    )
    req.on('error', reject)
    req.write(RPC_BODY)
    req.end()
  })
}

async function testViaProxy(port) {
  return new Promise((resolve, reject) => {
    const headers = [
      'POST /base-rpc HTTP/1.1',
      `Host: 127.0.0.1:${port}`,
      'Content-Type: application/json',
      `Content-Length: ${Buffer.byteLength(RPC_BODY, 'utf8')}`,
      '\r\n'
    ].join('\r\n')
    const rawRequest = headers + RPC_BODY

    const socket = Net.connect({ host: '127.0.0.1', port }, () => {
      socket.write(rawRequest)
    })

    let buffer = ''
    socket.on('data', chunk => {
      buffer += chunk.toString()
      const sep = buffer.indexOf('\r\n\r\n')
      if (sep >= 0) {
        const bodyStart = sep + 4
        const m = /Content-Length:\s*(\d+)/i.exec(buffer)
        const contentLength = m ? parseInt(m[1], 10) : 0
        const bodyEnd = bodyStart + contentLength
        if (buffer.length >= bodyEnd) {
          socket.destroy()
          const statusMatch = buffer.match(/HTTP\/[\d.]+\s+(\d+)\s/)
          const body = buffer.slice(bodyStart, bodyEnd)
          try {
            const json = JSON.parse(body)
            resolve({ ok: !json.error, statusCode: parseInt(statusMatch?.[1] || 0), body: json, viaProxy: true })
          } catch (e) {
            resolve({ ok: false, statusCode: parseInt(statusMatch?.[1] || 0), body, parseError: e.message, viaProxy: true })
          }
        }
      }
    })
    socket.on('error', reject)
    socket.setTimeout(10000, () => {
      socket.destroy()
      reject(new Error('Proxy test timeout'))
    })
  })
}

async function main() {
  const proxyPort = process.argv.includes('--proxy') 
    ? parseInt(process.argv[process.argv.indexOf('--proxy') + 1], 10) 
    : null

  console.log('--- Base RPC 转发测试 ---\n')

  // 1. 直连 upstream
  console.log('1. 直连 upstream (1rpc.io/base)...')
  try {
    const direct = await testDirectUpstream()
    console.log('   状态:', direct.statusCode, direct.ok ? '✓' : '✗')
    console.log('   返回:', JSON.stringify(direct.body).slice(0, 120) + '...')
    if (direct.body?.result) {
      console.log('   chainId:', direct.body.result, '(Base = 0x2105)')
    }
  } catch (e) {
    console.log('   ✗ 失败:', e.message)
  }

  if (proxyPort) {
    console.log('\n2. 经代理 localhost:' + proxyPort + ' /base-rpc ...')
    try {
      const proxy = await testViaProxy(proxyPort)
      console.log('   状态:', proxy.statusCode, proxy.ok ? '✓' : '✗')
      console.log('   返回:', JSON.stringify(proxy.body).slice(0, 120) + '...')
    } catch (e) {
      console.log('   ✗ 失败:', e.message)
      console.log('   请先启动服务: npm run start 或 conet-mvp-si')
    }
  } else {
    console.log('\n(加 --proxy 4000 可测试经代理转发)')
  }
  console.log('')
}

main().catch(console.error)
