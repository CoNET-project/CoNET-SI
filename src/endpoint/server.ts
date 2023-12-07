
import { join } from 'node:path'
import { inspect, } from 'node:util'
import Cluster from 'node:cluster'
import Net from 'node:net'
import { Transform } from 'node:stream'
import type { Server } from 'node:http'
import {logger} from '../util/logger'
import {postOpenpgpRouteSocket, IclientPool, generateWalletAddress, getPublicKeyArmoredKeyID, getSetup, loadWalletAddress, makeOpenpgpObj, saveSetup, si_healthLoop, register_to_DL} from '../util/localNodeCommand'
import Colors from 'colors/safe'
import type { HDNodeWallet } from 'ethers'
import Express from 'express'
import  { distorySocket } from '../util/htmlResponse'
import dgram from 'node:dgram'
//@ts-ignore
import hexdump from 'hexdump-nodejs'

const healthTimeout = 1000 * 60 * 5
const projectMain = 'https://app.conet.network/'

const packageFile = join (__dirname, '..', '..','package.json')
const packageJson = require ( packageFile )
const version = packageJson.version
const onlineClientPool: IclientPool[] = []
let initData:ICoNET_NodeSetup|null

const packagePGP = (data:string) => {
	return `-----BEGIN PGP MESSAGE-----\n\n${data}-----END PGP MESSAGE-----\n`
}


export const hexDebug = ( buffer: Buffer, length: number= 256 ) => {
    console.log(Colors.underline(Colors.green(`TOTAL LENGTH [${ buffer.length }]`)))
    console.log(Colors.grey( hexdump( buffer.slice( 0, length ))))
}

// const udpListening = () => {
// 	const server = dgram.createSocket('udp4')
// 	server.on('error', (err) => {
// 		console.error(`server error:\n${err.stack}`)
// 		server.close()
// 		udpListening()
// 	})
	
// 	server.on('message', (msg, rinfo) => {
		
// 		console.log(Colors.red(`UDP server got Message [${ msg.length }] from ${rinfo.address}:${rinfo.port}`))
// 		if (!initData) {
// 			return 
// 		}
		
// 		postFromUDP (msg.toString(), initData.pgpKey.privateKey, initData.passwd? initData.passwd: '', initData.outbound_price, initData.storage_price, initData.ipV4, onlineClientPool, null, '')
// 	})
	
// 	server.on('listening', () => {
// 		const address = server.address()
// 		console.log(Colors.blue(`UDP server listening ${address.address}:${address.port}`))
		
// 	})
	
// 	server.bind(41234)
// }

const getLengthHander = (headers: string[]) => {
	const index = headers.findIndex( n => /^Content-Length\:/i.test(n))
	if (index < 0) {
		logger (inspect(headers, false, 3, true))
		return -1
	}
	const length = headers[index].split(/^Content-Length\: /i)[1]
	const ret = parseInt(length)
	return isNaN(ret) ? -1 : ret
}

class conet_si_server {

    private localserver: Server| undefined
	private appsPath =''
	private PORT=0
	private password = ''
	private debug = true
	private workerNumber = 0
	public nodePool = []
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
			si_healthLoop ( initData, this )
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

		if ( !initData?.keychain || initData?.passwd === undefined) {
            logger ('initData?.keychain = ',initData?.keychain,'initData.passwd = ', initData?.passwd)
			throw new Error (`Error: have no setup data!\nPlease restart CoNET-SI !`)
		}

        logger (`initSetupData initData.passwd = [${initData.passwd}]`)

		this.password = initData.passwd

		initData.pgpKeyObj = await makeOpenpgpObj(initData.pgpKey.privateKey, initData.pgpKey.publicKey, this.password)
		try {
			initData.keyObj = await loadWalletAddress ( initData.keychain, this.password )
		} catch (ex) {
			initData.keychain = await generateWalletAddress (this.password)
			initData.keyObj = await loadWalletAddress ( initData.keychain, this.password )
		}
		
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
		si_healthLoop(initData, this)
		this.startServer ()
	}

	constructor () {
        this.initSetupData ()
		// udpListening()
    }

	private startServer = () => {
		
		const server = new Net.Server( socket => {

			socket.once('data', data => {

				const request = data.toString()
				
				const request_line = request.split('\r\n\r\n')
				
				if (request_line.length < 2) {
					return distorySocket(socket)
				}

				const htmlHeaders = request_line[0].split('\r\n')
				const requestProtocol = htmlHeaders[0]

				if (/^POST \/post HTTP\/1.1/.test(requestProtocol)) {
					logger (Colors.blue(`/post access! from ${socket.remoteAddress}`))
					const bodyLength = getLengthHander (htmlHeaders)

					if (bodyLength < 0) {
						logger (Colors.red(`startServer get header has no bodyLength [${bodyLength}] destory CONNECT!`))
						return distorySocket(socket)
					}

					const getData = () => {

						if (!initData || !initData?.pgpKeyObj?.privateKeyObj) {
							logger (Colors.red(`this.initData?.pgpKeyObj?.privateKeyObj NULL ERROR \n`), inspect(initData, false, 3, true), '\n')
							return distorySocket(socket)
						}
						logger (Colors.magenta(`startServer getData request_line.length [${request_line[1].length}] bodyLength = [${bodyLength}]`))
						let body
						try {
							body = JSON.parse(request_line[1])
						} catch (ex) {
							logger (Colors.magenta(`startServer HTML body JSON parse ERROR!`))
							return distorySocket(socket)
						}
						if (!body.data || typeof body.data !== 'string') {
							logger (Colors.magenta(`startServer HTML body format error!`))
							return distorySocket(socket)
						}
						logger (Colors.magenta(`SERVER call postOpenpgpRouteSocket nodePool = [${ this.nodePool }]`))
						return postOpenpgpRouteSocket (socket, htmlHeaders, body.data, initData.pgpKey.privateKey, initData.passwd? initData.passwd: '', initData.outbound_price, initData.storage_price, initData.ipV4, onlineClientPool, null, '', this)
					}

					const readMore = () => {
						logger (Colors.magenta(`startServer readMore request_line.length [${request_line[1].length}] bodyLength = [${bodyLength}]`))
						socket.once('data', _data => {
							
							request_line[1] += _data
							if (request_line[1].length < bodyLength) {
								logger (Colors.magenta(`startServer readMore request_line.length [${request_line[1].length}] bodyLength = [${bodyLength}]`))
								return readMore ()
							}
							
							getData ()
						})
					}

					if (request_line[1].length < bodyLength) {

						return readMore ()
					}

					return getData ()
					
				}
				
				return distorySocket(socket)
			})

		})

		server.on('error', err => {
			logger(Colors.red(`conet_si_server server on Error! ${err.message}`))
		})

		server.listen(80, () => {
			return console.table([
                { 'CoNET SI node': `version ${version} startup success Url http://localhost:${ this.PORT }` }
            ])
		})

	}
}

export default conet_si_server