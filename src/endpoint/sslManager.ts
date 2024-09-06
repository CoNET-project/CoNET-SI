import Express from 'express'

export const startExpressServer = () => {
	const app = Express()
	app.use( '/', Express.static(__dirname))
	app.listen(80)
	
}

