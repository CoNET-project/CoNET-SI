import colors from 'colors/safe'
//@ts-ignore
import hexdump from 'hexdump-nodejs'

export  const logger = (...argv: any ) => {
    const date = new Date ()
    const dateStrang = `%c [CONET-worker INFO ${ date.getHours() }:${ date.getMinutes() }:${ date.getSeconds() }:${ date.getMilliseconds ()}]`
    return console.log ( colors.yellow(`${dateStrang}`),...argv)
}

export const hexDebug = ( buffer: Buffer, length: number= 256 ) => {
    console.log(colors.underline(colors.green(`TOTAL LENGTH [${ buffer.length }]`)))
    console.log(colors.grey( hexdump( buffer.slice( 0, length ))))
}