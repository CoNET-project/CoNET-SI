import Express from 'express'
import {createServer, Server, IncomingMessage, ServerResponse} from 'http'
import { logger } from '../util/logger'

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
	app.use( '/', Express.static(__dirname))
	logger(__dirname)
	server = createServer(app)
	server.listen(80, () => {
		logger(`startExpressServer server started at 80 port!`)
	})
	
}

