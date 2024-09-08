
import { join } from 'node:path'
import { inspect, } from 'node:util'
import Cluster from 'node:cluster'
import {Socket, createServer} from 'node:net'
import {logger} from '../util/logger'
import {postOpenpgpRouteSocket, IclientPool, generateWalletAddress, getPublicKeyArmoredKeyID, getSetup, loadWalletAddress, makeOpenpgpObj, saveSetup, testCertificateFiles, CertificatePATH, checkSign} from '../util/localNodeCommand'
import {startEventListening, CONETProvider} from '../util/util'
import Colors from 'colors/safe'
import { readFileSync} from 'fs'
import {createServer as createServerSSL, TLSSocket} from 'node:tls'
import  { distorySocket } from '../util/htmlResponse'
import {Wallet} from 'ethers'
//@ts-ignore
import hexdump from 'hexdump-nodejs'

const healthTimeout = 1000 * 60 * 5

const packageFile = join (__dirname, '..', '..','package.json')
const packageJson = require ( packageFile )
const version = packageJson.version
const onlineClientPool: IclientPool[] = []

export const hexDebug = ( buffer: Buffer, length: number= 256 ) => {
    console.log(Colors.underline(Colors.green(`TOTAL LENGTH [${ buffer.length }]`)))
    console.log(Colors.grey( hexdump( buffer.slice( 0, length ))))
}

const countAccessPool: Map<string, number[]> = new Map()

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

const indexHtmlFileName = join(`${__dirname}`, 'index.html')

const responseRootHomePage = (socket: Socket|TLSSocket) => {
	const homepage = readFileSync(indexHtmlFileName, 'utf-8') + '\r\n\r\n'
	//	@ts-ignore
	const ret = `HTTP/1.1 200 OK\r\n` +
	`Server: nginx/1.24.0 (Ubuntu)\r\n` +
	//@ts-ignore
	`Date: ${new Date().toGMTString()}\r\n` +
	`Content-Type: text/html\r\n` +
	`Content-Length: ${homepage.length}\r\n`+
	`Connection: keep-alive\r\n` +
	'access-control-allow-origin: *\r\n' +
	`Accept-Ranges: bytes\r\n\r\n` + homepage
	
	if (socket.writable) {
		socket.write(ret, err => {
			socket.end(() => {
				logger(Colors.blue(`responseRootHomePage PIPE on End() ${socket?.remoteAddress} socket.writable = ${socket.writable} homepage length =${homepage.length}`))
			})
			
		})
	}
	
}


interface livenessListeningPoolObj {
	res: Socket|TLSSocket
	ipaddress: string
	wallet: string
}
//			getIpAddressFromForwardHeader(req.header(''))

const livenessListeningPool: Map <string, livenessListeningPoolObj> = new Map()

const addIpaddressToLivenessListeningPool = (ipaddress: string, wallet: string, res: Socket|TLSSocket) => {
	const _obj = livenessListeningPool.get (wallet)
	if (_obj) {
		if (_obj.res.writable && typeof _obj.res.end === 'function') {
			_obj.res.end()
		}
		
	}
	const obj: livenessListeningPoolObj = {
		ipaddress, wallet, res
	}
	
	livenessListeningPool.set (wallet, obj)
	const returnData = {
		ipaddress,
		status: 200
	}

	res.once('error', err => {
		logger(Colors.grey(`Clisnt ${wallet}:${ipaddress} on error! delete from Pool`), err.message)
		livenessListeningPool.delete(wallet)
	})
	res.once('close', () => {
		logger(Colors.grey(`Clisnt ${wallet}:${ipaddress} on close! delete from Pool`))
		livenessListeningPool.delete(wallet)
	})

	logger (Colors.cyan(` [${ipaddress}:${wallet}] Added to livenessListeningPool [${livenessListeningPool.size}]!`))
	return returnData
}


const testMinerCOnnecting = (res: Socket|TLSSocket, returnData: any, wallet: string, ipaddress: string) => new Promise (resolve=> {
	returnData['wallet'] = wallet
	if (res.writable && !res.closed) {
		return res.write( JSON.stringify(returnData)+'\r\n\r\n', async err => {
			if (err) {
				logger(Colors.grey (`stratliveness write Error! delete ${wallet}`))
				livenessListeningPool.delete(wallet)
			}
			return resolve (true)
		})
		
	}
	livenessListeningPool.delete(wallet)
	logger(Colors.grey (`stratliveness write Error! delete ${wallet}`))
	return resolve (true)
})


const stratlivenessV2 = async (block: number, nodeWallet: string) => {
	
	
	logger(Colors.magenta(`stratliveness EPOCH ${block} starting! ${nodeWallet} Pool length = [${livenessListeningPool.size}]`))

	// clusterNodes = await getApiNodes()
	const processPool: any[] = []
	
	livenessListeningPool.forEach(async (n, key) => {
		const res = n.res
		const returnData = {
			status: 200,
			epoch: block
		}
		processPool.push(testMinerCOnnecting(res, returnData, key, n.ipaddress))

	})

	await Promise.all(processPool)

	const wallets: string[] = []

	livenessListeningPool.forEach((value: livenessListeningPoolObj, key: string) => {
		wallets.push (key)
	})

}

class conet_si_server {

	private PORT=0
	private password = ''
	private debug = true
	private workerNumber = 0
	private nodeWallet: string = ''
	public nodePool = []
	private publicKeyID = ''
	public initData:ICoNET_NodeSetup|null = null

	private initSetupData = async () => {
		
		this.initData = await getSetup ()
		if ( Cluster.isWorker && Cluster?.worker?.id ) {
			this.workerNumber = Cluster?.worker?.id
		}

		logger (inspect(this.initData, false, 3, true))

		if ( !this.initData?.keychain || this.initData?.passwd === undefined) {
            logger ('initData?.keychain = ',this.initData?.keychain,'initData.passwd = ', this.initData?.passwd)
			throw new Error (`Error: have no setup data!\nPlease restart CoNET-SI with node dist/cli start!`)
		}

        logger (`initSetupData initData.passwd = [${this.initData.passwd}]`)

		this.password = this.initData.passwd

		this.initData.pgpKeyObj = await makeOpenpgpObj(this.initData.pgpKey.privateKey, this.initData.pgpKey.publicKey, this.password)
		try {
			this.initData.keyObj = await loadWalletAddress ( this.initData.keychain, this.password )
		} catch (ex) {
			this.initData.keychain = await generateWalletAddress (this.password)
			this.initData.keyObj = await loadWalletAddress ( this.initData.keychain, this.password )
		}
		
		this.publicKeyID = this.initData.pgpKeyObj.publicKeyObj.getKeyIDs()[1].toHex().toUpperCase()

		this.PORT = this.initData.ipV4Port

		const newID = await getPublicKeyArmoredKeyID(this.initData.pgpKey.publicKey)
		
		logger (`this.initData.pgpKey.keyID [${this.initData.pgpKey.keyID}] <= newID [${newID}]`)
		logger(Colors.blue(`pgpKey base64 \n`), Buffer.from(this.initData.pgpKey.publicKey).toString('base64'))
		this.initData.pgpKey.keyID = newID
		this.initData.platform_verison = version
		saveSetup ( this.initData, true )
		const wallet:Wallet = this.initData.keyObj
		this.nodeWallet = wallet.address.toLowerCase()
		const ssl = await testCertificateFiles ()
		if (ssl) {
			this.startSslServer ()
		}

		// this.startServer ()
		//startEventListening()
	}

	constructor () {
        this.initSetupData ()
    }



	private sockerdata = (socket: Socket|TLSSocket) => {
		logger(Colors.gray(`sockerdata has new connect ${socket.remoteAddress}`))
		let first = true

		const getData = (bodyLength: number, request_line: string[], htmlHeaders: string[]) => {

			if (!this.initData || !this.initData?.pgpKeyObj?.privateKeyObj) {
				logger (Colors.red(`this.initData?.pgpKeyObj?.privateKeyObj NULL ERROR \n`), inspect(this.initData, false, 3, true), '\n')
				return distorySocket(socket)
			}

			logger (Colors.magenta(`startServer getData request_line.length [${request_line[1].length}] bodyLength = [${bodyLength}]`))
			let body
			try {
				body = JSON.parse(request_line[1])
			} catch (ex) {
				logger (Colors.magenta(`startServer HTML body JSON parse ERROR!`))
				logger(request_line[1])
				return distorySocket(socket)
			}
			
			if (!body.data || typeof body.data !== 'string') {
				logger (Colors.magenta(`startServer HTML body is ont string error!`))
				logger(request_line[1])
				distorySocket(socket)
				
			}
			//logger (Colors.magenta(`SERVER call postOpenpgpRouteSocket nodePool = [${ this.nodePool }]`))
			return postOpenpgpRouteSocket (socket, htmlHeaders, body.data, this.initData.pgpKeyObj.privateKeyObj, this.publicKeyID)
		}

		const readMore = (data: Buffer) => {
			logger(Colors.blue(`readMore listen more data!`))
			
			socket.on('data', _data => {
				data+= _data
			})
			socket.on('end', ()=> {
				logger(`readMore on end`)
				
				const request = data.toString()
				logger(inspect(data))
				const request_line = request.toString().split('\r\n\r\n')
				const htmlHeaders = request_line[0].split('\r\n')
				const bodyLength = getLengthHander (htmlHeaders)
				
				getData (bodyLength, request_line, htmlHeaders)
			})
		}



		socket.once('data', (data: Buffer) => {
			
			const request = data.toString()
			logger(Colors.gray(`sockerdata connect ${socket.remoteAddress} on request [${request}]`))
			const request_line = request.split('\r\n\r\n')
			
			if (request_line.length < 2) {
				return distorySocket(socket)
			}

			const htmlHeaders = request_line[0].split('\r\n')
			const requestProtocol = htmlHeaders[0]

			const responseHeader = () => {
				logger(`responseHeader send response headers to ${socket.remoteAddress}`)
				const ret = `HTTP/1.1 200 OK\r\n` +
							//	@ts-ignore
							`Date: ${new Date().toGMTString()}\r\n` +
							`Server: nginx/1.24.0 (Ubuntu)\r\n` +
							`access-control-allow-origin: *\r\n` +
							`content-type: text/event-stream\r\n` +
							`Cache-Control: no-cache\r\n` +
							`Connection: close\r\n\r\n`
	
				readMore(data)
					
				if (socket.writable) {
					return socket.write(ret)
				}
			}

			if (/^(POST |OPTIONS )\/post HTTP\/1.1/.test(requestProtocol)) {
				
				const bodyLength = getLengthHander (htmlHeaders)

				logger (Colors.blue(`/post access! from ${socket.remoteAddress} bodyLength=${bodyLength}`))

				if ( bodyLength < 1) {
					first = false
					logger (Colors.red(`startServer get header has no bodyLength [${ bodyLength }]`))
					return responseHeader()
				}
				
				if (request_line[1].length < bodyLength) {
					logger(Colors.blue(`request_line[1].length [${request_line[1].length}]< bodyLength ${bodyLength} goto readMore (data)`))
					return readMore (data)
				}

				return getData (bodyLength, request_line, htmlHeaders)
				
			}

			if (/^GET \/ HTTP\//.test(requestProtocol)) {
				logger (inspect(htmlHeaders, false, 3, true))
				return responseRootHomePage(socket)
			}

			

			return distorySocket(socket)
		})

		socket.once('end', () => {
			logger(Colors.gray(`sockerdata ${socket.remoteAddress} on end()`))
		})
	}

	private startServer = () => {
		
		const server = createServer( socket => {

			return this.sockerdata(socket)

		})

		server.on('error', err => {
			logger(Colors.red(`conet_si_server server on Error! ${err.message}`))
		})

		server.listen ( this.initData?.ipV4Port, () => {
			logger(Colors.blue(`__dirname = ${__dirname}`))
			return console.table([
                { 'CoNET SI node': `version ${version} startup success Url http://localhost:${ this.PORT } doamin name = ${this.publicKeyID}.conet.network` }
				
            ])
		})
	}

	private startSslServer = () => {
		const key = readFileSync(CertificatePATH[1])
		const cert = readFileSync(CertificatePATH[0])
		const options = {
			key,
			cert
		}
		
		const server = createServerSSL (options, socket => {
			this.sockerdata (socket)
		})

		server.listen(443, () => {
			// startEPOCH_EventListeningForMining(this.nodeWallet)
			return console.table([
                { 'CoNET SI SSL server started': `version ${version} startup success Url http://localhost:443 doamin name = ${this.publicKeyID}.conet.network wallet = ${this.nodeWallet}` }
            ])
		})

	}
}

const startEPOCH_EventListeningForMining = (nodeWallet: string) => {
	CONETProvider.on('block', block => {
		stratlivenessV2(block, nodeWallet)
	})
}

export default conet_si_server