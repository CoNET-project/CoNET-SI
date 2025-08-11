import Express from 'express'
import {createServer, Server, IncomingMessage, ServerResponse} from 'http'
import { logger } from '../util/logger'
import path from 'node:path'

let server: Server<typeof IncomingMessage, typeof ServerResponse> | null = null

export const stopServer = () => new Promise(resolve => {
	if (!server) {
		resolve(false)
		return logger(`startExpressServer server is NULL error!`)
	}

	server.close(err => {
		return resolve(true)
	})
})


export const startExpressServer = () => {
  const app = Express()
  const webroot = __dirname        // 这里就是 dist/endpoint
  const acmeRoot = path.join(webroot, '.well-known', 'acme-challenge')

  // 1) 专门为 ACME 开通 .well-known 路由，允许 dotfiles
  app.use(
    '/.well-known/acme-challenge',
    Express.static(acmeRoot, {
      dotfiles: 'allow',
      etag: false,
      maxAge: 0,                  // 不缓存
      setHeaders: (res) => {
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate')
        res.setHeader('Pragma', 'no-cache')
        res.setHeader('Expires', '0')
        res.type('text/plain')
      },
    })
  )

  // 2) 其他静态资源（不必允许 dotfiles）
  app.use('/', Express.static(webroot))

  logger(`ACME webroot: ${acmeRoot}`)
  server = createServer(app)
  server.listen(80, () => {
    logger(`startExpressServer server started at 80 port!`)
  })
}

startExpressServer()