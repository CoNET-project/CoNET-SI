import Net from 'node:net'
import { inspect, } from 'node:util'
import {logger} from '../util/logger'
import Tls from 'node:tls'
import Colors from 'colors/safe'
import  { distorySocket } from '../util/htmlResponse'
import Http2 from 'node:http2'
import {readFileSync} from 'node:fs'
import { join } from 'node:path'

//		curl -v -H -s -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0","id": 1,"method": "getBalance","params": ["mDisFS7gA9Ro8QZ9tmHhKa961Z48hHRv2jXqc231uTF"]}' https://api.mainnet-beta.solana.com
//		curl -v --http0.9 -H -s -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0","id": 1,"method": "getBalance","params": ["mDisFS7gA9Ro8QZ9tmHhKa961Z48hHRv2jXqc231uTF"]}' http://9977e9a45187dd80.conet.network/solana-rpc
//		curl -v --http0.9 -H -s -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0","id": 1,"method": "getBalance","params": ["mDisFS7gA9Ro8QZ9tmHhKa961Z48hHRv2jXqc231uTF"]}' http://127.0.0.1:4000/solana-rpc
//		curl -v -i -X OPTIONS https://api.mainnet-beta.solana.com


const solanaRPC_host = 'api.mainnet-beta.solana.com'
const solanaRPCURL = `https://${solanaRPC_host}`

const indexHtmlFileName = join(`${__dirname}`, 'index.html')

//		curl -v -i -X OPTIONS https://solana-rpc.conet.network/
const responseOPTIONS = (socket: Net.Socket) => {
	let response = `HTTP/2 204 No Content\r\n`
		response += `Server: nginx/1.24.0 (Ubuntu)\r\n`
		//	@ts-ignore
		response += `Date: ${new Date().toGMTString()}\r\n`
		response += `Connection: keep-alive\r\n`
		response += `Access-Control-Allow-Origin: *\r\n`
		response += `Access-Control-Allow-Credentials: true\r\n`
		response += `Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n`
		response += `Access-Control-Allow-Headers: solana-client,DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type\r\n`
		response += `Content-Length\r\n\r\n`
	socket.end(response)
}

const responseRootHomePage = (socket: Net.Socket| Tls.TLSSocket) => {
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
				logger(Colors.blue(`responseRootHomePage PIPE End() ${socket?.remoteAddress} socket.writable = ${socket.writable} homepage length =${homepage.length}`))
			})
			
		})
	}
	
}

const getData = (socket: Net.Socket, request: string, requestProtocol: string) => {

	let body
	const request_line = request.split('\r\n\r\n')
	try {
		body = JSON.parse(request_line[1])
	} catch (ex) {
		return distorySocket(socket)
	}

	const htmlHeaders = request_line[0].split('\r\n')
	//logger (Colors.magenta(`startServer getData request_line.length [${request_line[1].length}] bodyLength = [${bodyLength}]`))

	
	if (!body.data || typeof body.data !== 'string') {
		logger (Colors.magenta(`startServer HTML body is ont string error!`))
		logger(request_line[1])
		distorySocket(socket)
	}

}

/**
curl --include \
     --no-buffer \
     --header "Connection: Upgrade" \
     --header "Upgrade: websocket" \
     "https://api.mainnet-beta.solana.com"
 */

	//logger (Colors.magenta(`SERVER call postOpenpgpRouteSocket nodePool = [${ this.nodePool }]`))
	
let headers = `HTTP/2 200\r\n`
	headers += `content-type: application/json; charset=utf-8\r\n`
	headers += `Access-Control-Allow-Origin: *\r\n`
	headers += `Access-Control-Allow-Credentials: true\r\n`
	headers += `Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n`
	headers += `Access-Control-Allow-Headers: solana-client,DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type\r\n`

	
export const forwardToSolana = (socket: Net.Socket, body: string, requestHanders: string[]) => {
	logger (Colors.magenta(`forwardToSolana from ${socket.remoteAddress} ${body}`))
	if (/^OPTIONS/i.test(requestHanders[0].split(' ')[0]) ) {
		logger(inspect(requestHanders, false, 3, true))
		return responseOPTIONS(socket)
	}

	const solanaClient = Http2.connect(solanaRPCURL)
	solanaClient.on('error', (err) => console.error(err))
	const method = requestHanders[0].split(' ')[0]
	const option: Http2.OutgoingHttpHeaders = {
		':path': '/',
		host: solanaRPC_host,
		'User-Agent': 'curl/8.7.1',
		Accept: '*/*',
		'Content-Type': 'application/json',
		'Content-Length': body.length,
		':method': method
	}

	requestHanders.forEach(n => {
		if (/^Upgrade\:/i.test(n)) {
			return option.upgrade = n.split(':')[0]
		}
	})
	logger(inspect(requestHanders, false, 3, true))

	const req = solanaClient.request(option)

	req.once('response', (_headers, _flags) => {
		const length = _headers['content-length']
		let responseHeader = headers + `content-length: ${length}\r\n`
		responseHeader += `date: ${new Date().toUTCString()}\r\n`
		responseHeader += `Connection: ${_headers['connection']}\r\n`
		responseHeader += `${_headers['upgrade'] ? 'Upgrade: '+ _headers['upgrade']+ '\r\n\r\n' : '\r\n'}`
		socket.write(responseHeader)
		req.pipe(socket).pipe(req)
	})
	
	req.on('data', chunk => {
		console.log(`on data chunk = ${chunk.toString()}`)
	})

	req.on('end', () => {
		socket.end()
	})

	req.end(body)
	
}

const getLengthHander = (headers: string[]) => {
	const index = headers.findIndex( n => /^Content-Length\:/i.test(n))
	if (index < 0) {
		//logger (inspect(headers, false, 3, true))
		return -1
	}
	const length = headers[index].split(/^Content-Length\: /i)[1]
	const ret = parseInt(length)
	return isNaN(ret) ? -1 : ret
}


const startServer = (port: number, publicKey: string) => {
		
	const server = Net.createServer( socket => {

		socket.once('data', data => {

			const request = data.toString()
			
			const request_line = request.split('\r\n\r\n')
			
			if (request_line.length < 2) {
				return distorySocket(socket)
			}
			const htmlHeaders = request_line[0].split('\r\n')
			const requestProtocol = htmlHeaders[0]
			const requestPath = requestProtocol.split(' ')[1]

			if (/^POST \/post HTTP\/1.1/.test(requestProtocol)) {
				//logger (Colors.blue(`/post access! from ${socket.remoteAddress}`))
				const bodyLength = getLengthHander (htmlHeaders)

				const readMore = () => {
					//logger (Colors.magenta(`startServer readMore request_line.length [${request_line[1].length}] bodyLength = [${bodyLength}]`))
					socket.once('data', _data => {
						
						request_line[1] += _data
						if (request_line[1].length < bodyLength) {
							//logger (Colors.magenta(`startServer readMore request_line.length [${request_line[1].length}] bodyLength = [${bodyLength}]`))
							return readMore ()
						}
						
						return getData (socket, request, requestProtocol)
					})
				}

				if (request_line[1].length < bodyLength) {
					return readMore ()
				}

				return getData (socket, request, requestProtocol)
				
			}

			if (/^GET \/ HTTP\//.test(requestProtocol)) {
				logger (inspect(htmlHeaders, false, 3, true))
				return responseRootHomePage(socket)
			}

			if (/^OPTIONS \/ HTTP\//.test(requestProtocol)) {
				logger (inspect(htmlHeaders, false, 3, true))
				return responseOPTIONS(socket)
			}
			const path = requestProtocol.split(' ')[1]
			if (/\/solana\-rpc/i.test(path)) {
				return forwardToSolana (socket, request_line[1], htmlHeaders)
			}
			return distorySocket(socket)
		})

	})

	server.on('error', err => {
		logger(Colors.red(`conet_si_server server on Error! ${err.message}`))
	})

	server.listen ( port, () => {
		logger(Colors.blue(`__dirname = ${__dirname}`))
		
		return console.table([
			{ 'CoNET SI node': `Layer Minus Node start success! Url https://${publicKey}.conet.network` }
			
		])
	})
}

startServer(4000, 'pppp')