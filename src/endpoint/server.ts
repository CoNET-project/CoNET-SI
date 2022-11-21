import Express from 'express'
import { join } from 'node:path'
import { inspect } from 'node:util'
import { logger, getSetup, loadWalletAddress, waitKeyInput, return404, returnHome, register_to_DL, saveSetup, si_health, makeOpenpgpObj } from '../util/util'
import Colors from 'colors/safe'

const healthTimeout = 1000 * 60 * 5

class conet_si_server {
	// @ts-ignore
    private localserver: Server
	private appsPath =''
	private PORT=0
	private keyChain = null
	private initData: ICoNET_NodeSetup|null = null
	private s3Pass: null|s3pass = null

	private initSetupData = async () => {
		// @ts-ignore: Unreachable code error
		this.initData = await getSetup ( this.debug )

		if ( !this.initData?.keychain ) {
			throw new Error (`Error: have no setup data!\nPlease restart CoNET-SI`)
		}

		if ( !this.password ) {
			// @ts-ignore: Unreachable code error
			this.password = await waitKeyInput (`Please enter the wallet password: `, true )
		}
		
		this.initData.pgpKeyObj = await makeOpenpgpObj(this.initData.pgpKey.privateKey, this.initData.pgpKey.publicKey, this.password)
	
		this.initData.keyObj = await loadWalletAddress ( this.initData.keychain, this.password )

		this.PORT = this.initData.ipV4Port

		if ( !this.initData.DL_registeredData ) {
			this.debug ? logger (`This SI node has not registered`): null
			const kkk = await register_to_DL (this.initData)
			if ( kkk?.nft_tokenid ) {
				logger (`register_to_DL success!`, inspect(kkk, false, 3, true))
				this.initData.DL_registeredData = kkk.nft_tokenid
				const setupInfo: ICoNET_NodeSetup = {
					keychain: this.initData.keychain,
					ipV4: this.initData.ipV4,
					ipV6: '',
					ipV4Port: this.initData.ipV4Port,
					ipV6Port: this.initData.ipV6Port,
					storage_price: this.initData.storage_price,
					outbound_price: this.initData.outbound_price,
					pgpKey: this.initData.pgpKey,
					DL_registeredData: kkk.nft_tokenid
				}

				return saveSetup ( setupInfo, this.debug ).then (() => {
					this.startServer ()
					setTimeout (()=> {
						if ( !this.initData ) {
							return logger ( Colors.red(`setTimeout STOP si_health Error! `))
						}
						si_health (this.initData)
					}, healthTimeout)
				})
			}
			
		}
		si_health (this.initData)
		this.startServer ()
	}

	constructor ( private debug: boolean, private password: string ) {
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

		app.post ('/post', (req, res) => {
			
			return res.end (return404 ())
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