import Cluster from 'node:cluster'
import colors from 'colors/safe'
const workerNumber = Cluster?.worker?.id ? colors.grey(`worker : ${Cluster.worker.id} `) : `${ Cluster?.isPrimary ? colors.grey('Cluster Master'): colors.bgCyan('Cluster unknow')}`
//@ts-ignore
import hexdump from 'hexdump-nodejs'

export const logger = (...argv: any ) => {
    const date = new Date ()
    let dateStrang = `${ workerNumber } [${ date.getHours() }:${ date.getMinutes() }:${ date.getSeconds() }:${ date.getMilliseconds ()}]`
    return console.log ( colors.yellow(dateStrang), ...argv )
}

export const hexDebug = ( buffer: Buffer, length: number= 256 ) => {
    console.log(colors.underline(colors.green(`TOTAL LENGTH [${ buffer.length }]`)))
    console.log(colors.grey( hexdump( buffer.slice( 0, length ))))
}