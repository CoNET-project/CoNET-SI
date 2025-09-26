import { createConnection, Socket } from 'net'
import IP from 'ip'
import nodeJs_DNS from 'node:dns'
import { logger } from './logger'
import { inspect } from 'util'
import { distorySocket } from './htmlResponse'
import { Transform, TransformCallback } from 'stream'
import { getHostIPv4Cached } from './globalDnsCache'

class BandwidthCount extends Transform {
    private count = 0
    private startTime = 0
    private endTime = 0
    private printed = false

    constructor(private tab: string){
        super({
            readableHighWaterMark: 64 * 1024,
            writableHighWaterMark: 64 * 1024
        })
    }

    public _transform(chunk: Buffer, encoding: BufferEncoding, callback: TransformCallback): void {
        if (!this.startTime) {
            this.startTime = Date.now()
        }
        this.count += chunk.length
        //logger(`${this.tab} start at ${this.startTime} BandwidthCount ${this.count} bytes`)
        callback(null,chunk)
    }

    public _final(callback: (error?: Error | null | undefined) => void): void {
        this.endTime = Date.now()
        this.finishIfNeeded('normal')
        callback()
    }

    public _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
        this.endTime = Date.now()
        // error 可能为 null（例如主动 destroy()），也可能包含错误信息
        const reason = error ? `error: ${error.message}` : 'destroyed'
        this.finishIfNeeded('abnormal', reason)
        callback(error || undefined)
    }

    public getTotalBytes() {
        return this.count
    }

    private finishIfNeeded(kind: 'normal' | 'abnormal', reason?: string) {
        if (this.printed) return
        this.printed = true

        if (!this.startTime) this.startTime = this.endTime || Date.now()

        const endTs = this.endTime || Date.now()
        const durationMs = Math.max(0, endTs - this.startTime)
        const durationSec = durationMs > 0 ? durationMs / 1000 : 0.000001
        const avgBytesPerSec = this.count / durationSec
        const avgBitsPerSec = avgBytesPerSec * 8

        const totalHuman = BandwidthCount.formatBytes(this.count)
        const avgHumanBytes = BandwidthCount.formatBytes(avgBytesPerSec)
        const avgMbps = (avgBitsPerSec / 1e6).toFixed(3)

        const head = `${this.tab} ${kind === 'normal' ? 'end' : 'end(abnormal)'} at ${endTs}` +
            (reason ? ` reason=${reason}` : '')

        if (!this.count) {
            logger(`${head} BandwidthCount ${this.count} bytes (no data)`)
            return
        }

        logger(
            `${head} BandwidthCount ${this.count} bytes (${totalHuman}), ` +
            `duration ${durationSec.toFixed(3)}s, ` +
            `avg ${avgHumanBytes}/s (${avgMbps} Mbps)`
        )
    }

    private static formatBytes(n: number): string {
        const units = ['B', 'KB', 'MB', 'GB', 'TB']
        let v = n
        let i = 0
        while (v >= 1024 && i < units.length - 1) {
            v /= 1024
            i++
        }
        return i === 0 ? `${Math.round(v)} ${units[i]}` : `${v.toFixed(2)} ${units[i]}`
    }
}

const getHostIpv4 = (host: string) => getHostIPv4Cached(host)

export class socks5Connect_v2 {
    private targetSocket: Socket | null = null
    private resSocket: Socket| null = null
    private uploadCount: BandwidthCount
    private downloadCount: BandwidthCount
    private info = ''
    private resIpaddress = ''
    public ready = false
    private disdestroyed = false
    private resCallListen: () => void = () => {}

    private cleanup = (err: Error|null) => {
        logger(`socks5Connect_v2 ==========> ${this.info} cleanup with Error xxxxxxxxxxxxxxxxxxx ${err?.message}`)
        this.uploadCount.end()
        this.downloadCount.end()
        
        // 第一阶段：优雅 end()
        this.reqSocket.end()
        this.resSocket?.end()
        this.targetSocket?.end()

        // 第二阶段：超时强制 destroy()，防止长尾悬挂
        const force = () => {
            this.reqSocket.destroy()
            this.resSocket?.destroy()
            this.targetSocket?.destroy()
        }

        setTimeout(force, 2000).unref()

        this.disdestroyed = true
        this.ready = false
        
    }

    constructor(private uuid: string, private prosyData: VE_IPptpStream, private reqSocket: Socket, private wallet: string) {
        this.info = `[${uuid}:${wallet}]:req=[${reqSocket.remoteAddressShow}] res=[${this.resIpaddress}] ===> ${prosyData.host}:${prosyData.port}`
        logger(`socks5Connect_v2 ==========> ${this.info} CONNECT Start.....`)
        this.uploadCount = new BandwidthCount(`[${this.uuid}] ==> UPLOAD`)
        this.downloadCount = new BandwidthCount(`[${uuid}] <== DOWNLOAD`)
        this.socks5ConnectFirstConnect(prosyData, reqSocket, wallet, uuid)

    }
     

    public resConnect = async (resSocket: Socket) => {

        if (this.disdestroyed) {
            logger(`socks5Connect_v2 ==========> ${this.info} RES disdestroyed, return`)
            distorySocket(resSocket)
            return
        }

        
        const connecting = () => {
            if (this.disdestroyed||!this.targetSocket) {
                logger(`socks5Connect_v2 resConnect ==========> ${this.info} TARGET disdestroyed, return`)
                distorySocket(resSocket)
                return
            }

            resSocket.on('error', err => { 
                this.cleanup(err)
            })

            resSocket.setKeepAlive?.(true, 30_000)
            resSocket.setNoDelay?.(true)

            this.targetSocket.pipe(this.downloadCount).pipe(resSocket, { end: false }).on('error', err => {
                this.cleanup(err)
            }).on('end', () => {
                this.cleanup(new Error(`downStreem on END!`))
            })
            this.targetSocket.resume()
            this.resSocket = resSocket
            resSocket.resume()
            logger(`socks5Connect_v2 ==========> ${this.info} RES connected! !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!`)
        }

        if (!this.ready||!this.targetSocket) {
            this.resCallListen = connecting
            logger(`socks5Connect_v2 ==========> ${this.info} RES not ready, wait...`)
            return
        }

        connecting()
        
    }


    private socks5ConnectFirstConnect = async (prosyData: VE_IPptpStream, reqSocket: Socket, wallet: string, uuid: string) => {

        let host: string, port: number, ipStyle: boolean

        
       try {
            port = prosyData.port
            host = prosyData.host || ''
            ipStyle = IP.isV4Format(host)
            this.info = `[${uuid}:${wallet}]:req=[${reqSocket.remoteAddressShow}] res=[${this.resIpaddress}] ===> ${host}:${port}`
            
            host = ipStyle ? (IP.isPublic(host) ? host : '') : await getHostIpv4(host)
            

            if ( port < 1 || port > 65535 || ! host) {
                logger(`socks5Connect_v2 ==========> ${this.info} CONNECT Start... Error Invalid host${host} or port ${port}`)
                throw new Error(` ${prosyData.host}:${prosyData.port} Error!`)
            }
            
            
        } catch (ex: any) {
            logger(inspect(prosyData, false, 3, true))
            logger(`socks5Connect_v2 req = ${reqSocket.remoteAddressShow} Error! ${ex.message}`)
            distorySocket(reqSocket)
            this.disdestroyed = true
            return
        }

        try {
        
            const socket = createConnection ( port, host, () => {
                socket.setNoDelay(true)
                reqSocket.setNoDelay?.(true)
                socket.setKeepAlive(true, 30_000)
                reqSocket.setKeepAlive?.(true, 30_000)
                this.reqSocket = reqSocket
                this.ready = true

                reqSocket.pipe(this.uploadCount).pipe(socket, { end: false }).on('error', err => { 
                    logger(`socks5Connect_v2 ==========> ${this.info} reqSocket.pipe(uploadCount).pipe(socket) on error `, err)
                    this.cleanup(err)
                }).on('end', () => {
                    this.cleanup(new Error(`upStreem on END!`))
                })

                const data = Buffer.from(prosyData.buffer, 'base64')
                if (data && data.length) {
                    if (!socket.write(data)) {
                        // 发生背压：暂停入口到上游的泵，待 drain 再恢复
                        reqSocket.pause()
                        socket.once('drain', () => reqSocket.resume())
                    }
                }
                reqSocket.resume()
                this.resCallListen()
            })
        
            

            socket.on('error', err => {
                this.cleanup(new Error(`target Error ${err.message}`))
            })

            this.targetSocket = socket
            
            reqSocket.on('error', err => {
               this.cleanup(new Error(`reqSocket Error ${err.message}`))
            })


            reqSocket.once('close', () => {
                this.cleanup(new Error(`reqSocket on CLOSE!`))
            })
            
        } catch (ex: any) {
            this.cleanup(new Error(`catch EX ${ex.message}`))
        }

    }
    
}