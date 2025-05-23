import type {Socket} from 'node:net'
import { logger } from './logger'

export const distorySocketPayment = (socket: Socket) => {
	const contentTitle = `402 Payment Required`
	const contectBody = `CoNET Passport has expired Please purchase a new certificate\r\nCoNETパスポートの有効期限が切れています。新しいを購入してください。\r\nCoNET通证已过期请购买新证书`
	const responseHtml = `<html>\r\n<head><title>${contentTitle}</title></head>\r\n<body>\r\n<center><h1>${contectBody}</h1></center>\r\n<hr><center>nginx/1.18.0</center>\r\n</body>\r\n</html>\r\n`
	socket.end(responseHtml).destroy()
}
export const distorySocket = (socket: Socket, header = '404 Not Found') => {
	const responseHtml = `<html>\r\n<head><title>${header}</title></head>\r\n<body>\r\n<center><h1>${header}</h1></center>\r\n<hr><center>nginx/1.18.0</center>\r\n</body>\r\n</html>\r\n`
	//	@ts-ignore
	const time = new Date().toGMTString()
	const response = `HTTP/1.1 ${header}\r\nServer: nginx/1.18.0\r\nDate: ${time}\r\nContent-Type: text/html\r\nContent-Length: ${responseHtml.length}\r\nConnection: keep-alive\r\n\r\n${responseHtml}\r\n`
	socket.end(response).destroy()
}

export const response200Html = (socket: Socket, responseData: string) => {
    //	@ts-ignore
	const time = new Date().toGMTString()
    const response = `HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nDate: ${time}\r\nContent-Type: text/html\r\nContent-Length: ${responseData.length}\r\nConnection: keep-alive\r\n\r\n${responseData}\r\n`

    socket.end(response).destroy()
}