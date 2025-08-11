import Express from 'express'
import {createServer, Server, IncomingMessage, ServerResponse} from 'http'
import { logger } from '../util/logger'
import path from 'node:path'
import fs from 'node:fs'

let server: Server<typeof IncomingMessage, typeof ServerResponse> | null = null

export const stopServer = () => new Promise(resolve => {
  if (!server) {
    logger(`startExpressServer server is NULL error!`)
    return resolve(false)
  }
  server.close(() => resolve(true))
})

function ensureDirRecursive(p: string) {
  try {
    fs.mkdirSync(p, { recursive: true })       // 等同于 shell: mkdir -p
    // 确保任何人可“走到”该目录链（对静态文件服务器重要）
    try { fs.chmodSync(p, 0o755) } catch {}
  } catch (e) {
    logger(`ensureDirRecursive failed for ${p}: ${(e as Error).message}`)
    throw e
  }
}

export const startExpressServer = () => {
  const app = Express()

  // dist/endpoint（就是之前 certbot -w 指向的 webroot）
  const webroot = __dirname
  const wellKnown = path.join(webroot, '.well-known')
  const acmeRoot = path.join(wellKnown, 'acme-challenge')

  // 1) 像 shell 的 `mkdir -p` 一样，把路径准备好
  ensureDirRecursive(webroot)
  ensureDirRecursive(wellKnown)
  ensureDirRecursive(acmeRoot)

  // 2) 专门给 ACME 的静态路由：允许 dotfiles
  app.use(
    '/.well-known/acme-challenge',
    Express.static(acmeRoot, {
      dotfiles: 'allow',
      etag: false,
      maxAge: 0,
      setHeaders: (res) => {
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate')
        res.setHeader('Pragma', 'no-cache')
        res.setHeader('Expires', '0')
        res.type('text/plain')
      },
    })
  )

  // 3) 其他静态资源
  app.use('/', Express.static(webroot))

  logger(`ACME webroot prepared at: ${acmeRoot}`)
  server = createServer(app)
  server.listen(80, () => {
    logger(`startExpressServer server started at 80 port!`)
  })
}
