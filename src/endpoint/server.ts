import Express from 'express'
import { join } from 'node:path'
import { inspect } from 'node:util'
import { logger, getSetup, loadWalletAddress, waitKeyInput, return404, returnHome, register_to_DL } from '../util/util'



class conet_si_server {
	// @ts-ignore
    private localserver: Server
	private appsPath =''
	private PORT=0
	private keyChain = null
	private initData: ICoNET_NodeSetup|any

	private initSetupData = async () => {
		// @ts-ignore: Unreachable code error
		this.initData = await getSetup ( this.debug )

		if ( !this.initData?.keychain ) {
			throw new Error (`Error: have no setup data!\nPlease restart CoNET-SI`)
		}
		// @ts-ignore: Unreachable code error
		const password = await waitKeyInput (`Please enter the wallet password: `, true )

		this.initData.keyObj = await loadWalletAddress ( this.initData.keychain, password )

		this.debug? logger ('Load initData success', inspect (this.initData, false, 3, true )): null

		this.debug? logger ('this.keyChain\n', inspect (this.keyChain, false, 3, true )): null

		this.appsPath = this.initData.setupPath

		this.PORT = this.initData.ipV4Port

		if ( !this.initData.DL_registeredData ) {
			this.debug ? logger (`This SI node has not registered`): null
			register_to_DL (this.initData)
		}
		
		//this.startServer ()
	}

	constructor ( private debug: boolean ) {
        this.initSetupData ()
    }

	private startServer = () => {
		const staticFolder = join ( this.appsPath, 'workers' )
		const launcherFolder = join ( this.appsPath, '../launcher' )
		const app = Express()
		const Cors = require('cors')
		app.use( Cors ())
		app.use ( Express.static ( staticFolder ))
        app.use ( Express.static ( launcherFolder ))
        app.use ( Express.json() )

		app.once ( 'error', ( err: any ) => {
            logger (err)
            logger (`Si node on ERROR!`)
        })

		app.once ('end', () => {
			this.debug ? logger ('server net once END event'): null
		})

		app.get ('/', (req, res) => {
			res.end (returnHome())
		})

		app.get('*', (req, res) => {
			return res.end (return404 ())
		})

		app.post('*', (req, res) => {
			return res.end (return404 ())
		})

		this.localserver = app.listen ( this.PORT, 'localhost', () => {
            return console.table([
                { 'CoNET SI node': `http://localhost:${ this.PORT }, local-path = [${ staticFolder }]` }
            ])
        })
	}

	public end () {
        this.localserver.close ()
    }
}

export default conet_si_server