
import { join } from 'node:path'
import { inspect } from 'node:util'
import Cluster from 'node:cluster'
import type { Server } from 'node:http'
import { logger, getSetup, loadWalletAddress, return404, register_to_DL, saveSetup, si_healthLoop, makeOpenpgpObj, postOpenpgpRoute, proxyRequest,splitIpAddr, getPublicKeyArmoredKeyID } from '../util/util'
import type {IclientPool} from '../util/util'
import Colors from 'colors/safe'
import Express from 'express'


const healthTimeout = 1000 * 60 * 5
const projectMain = 'https://kloak.io/'

const packageFile = join (__dirname, '..', '..','package.json')
const packageJson = require ( packageFile )
const version = packageJson.version

let initData:ICoNET_NodeSetup|null

class conet_si_server {

    private localserver: Server| undefined
	private appsPath =''
	private PORT=0
	private password = ''
	private debug = true
	private onlineClientPool: IclientPool[] = []
	private workerNumber = 0
	private finishRegister = () => {

		if (!initData ) {
			return logger (Colors.red(`conet_si_server finishRegister have no initData Error!`))
		}

		return saveSetup ( initData, this.debug )
		.then (() => {
			this.startServer ()
			if (!initData ) {
				return logger (Colors.red(`conet_si_server finishRegister have no initData Error!`))
			}
			si_healthLoop ( initData )
		})
	}

	private DL_registeredData: () => any = async () => {

		if (! initData ) {
			return logger (Colors.red(`conet_si_server DL_registeredData have no initData Error!`))
		}
		const kkk = await register_to_DL (initData)
		if ( kkk?.nft_tokenid ) {
			return this.finishRegister ()
		}
		
		logger (Colors.red(`register_to_DL response null\n Try Again After 30s`))

		return setTimeout (() => {
			return this.DL_registeredData ()
		}, 1000 * 30 )
	}	

	private initSetupData = async () => {
		
		initData = await getSetup ()
		if ( Cluster.isWorker && Cluster?.worker?.id ) {
			this.workerNumber = Cluster?.worker?.id
		}

		logger (inspect(initData, false, 3, true))

		if ( !initData?.keychain || !initData.passwd ) {
			throw new Error (`Error: have no setup data!\nPlease restart CoNET-SI !`)
		}

		this.password = initData.passwd

		initData.pgpKeyObj = await makeOpenpgpObj(initData.pgpKey.privateKey, initData.pgpKey.publicKey, this.password)
		initData.keyObj = await loadWalletAddress ( initData.keychain, this.password )

		this.PORT = initData.ipV4Port
		
		if ( !initData.DL_registeredData ) {
			logger (`This SI node has not registered`)
			return this.DL_registeredData()
		}

		const newID = await getPublicKeyArmoredKeyID(initData.pgpKey.publicKey)
		
		logger (`this.initData.pgpKey.keyID [${initData.pgpKey.keyID}] <= newID [${newID}]`)
		initData.pgpKey.keyID = newID
		initData.platform_verison = version
		saveSetup ( initData, true )
		si_healthLoop ( initData )

		this.startServer ()
	}

	constructor () {
        this.initSetupData ()
    }

	private startServer = () => {
		const staticFolder = join ( this.appsPath, 'workers' )
		const launcherFolder = join ( this.appsPath, '../launcher' )
		const app = Express()
		const Cors = require('cors')
		app.disable('x-powered-by')
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
	//				Support MVP Application *********************************************************************************** */
			app.get (/^\/$|^\/index.html$|^\/index.htm$/, (req, res) => {
				logger (Colors.red(`Get HOME url [${ splitIpAddr (req.ip) }] => [http://${ req.headers.host }${ req.url }]`))
				return proxyRequest (req, res, projectMain)
			})

			app.get ('/favicon.ico', (req, res) => {
				return proxyRequest (req, res, `${projectMain}favicon.ico` )
			})

			app.get ('/static/*', (req, res) => {
				const staticUrl = req.url.split ('/static/')[1]
				return proxyRequest (req, res, `${projectMain}static/${staticUrl}` )
			})

			app.get ('/utilities/*', (req, res) => {
				const staticUrl = req.url.split ('/utilities/')[1]
				return proxyRequest (req, res, `${projectMain}utilities/${staticUrl}` )
			})

			app.get ('/encrypt.js', (req, res) => {
				return proxyRequest (req, res, `${projectMain}encrypt.js` )
			})
	//**************************************************************************************************************************** */

		app.post ('/post', (req, res) => {
			const data = req.body.data
			if (!data || typeof data !== 'string') {
				logger (Colors.red(`/post have no body ERROR! \n`), inspect(req.body, false, 3, true), '\n')
				return res.status(400).end ()
			}
			if (!initData?.pgpKeyObj?.privateKeyObj) {
				logger (Colors.red(`this.initData?.pgpKeyObj?.privateKeyObj NULL ERROR \n`), inspect(initData, false, 3, true), '\n')
				return res.status(503).end ()
			}
			logger (Colors.blue(`app.post ('/post') [${splitIpAddr( req.ip )}] goto postOpenpgpRoute`))
			return postOpenpgpRoute (req, res, req.body.data, initData.pgpKey.privateKey, initData.passwd? initData.passwd: '', initData.outbound_price, initData.storage_price, initData.ipV4, this.onlineClientPool, null, '')
		})

		app.get ('/publicGpgKey', (req, res ) => {

		})

		app.all ('*', (req, res) => {
			logger (Colors.red(`Get unknow url Error! [${ splitIpAddr (req.ip) }] => ${ req.method }[http://${ req.headers.host }${ req.url }]`))
			return res.status(404).end (return404 ())
		})

		this.localserver = app.listen ( this.PORT, () => {
            return console.table([
                { 'CoNET SI node': `version ${version} startup success Url http://localhost:${ this.PORT }, local-path = [${ staticFolder }]` }
            ])
        })
	}

	public end () {
		if ( typeof this.localserver?.close === 'function') {
			this.localserver.close ()
		}
        
    }
}

export default conet_si_server