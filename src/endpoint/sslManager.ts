import Express from 'express'
import { logger } from '../util/logger'

export const startExpressServer = () => {
	const app = Express()
	app.use( '/', Express.static(__dirname))
	app.listen(80)
	logger(__dirname)
}

