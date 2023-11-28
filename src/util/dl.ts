import type { RequestOptions } from 'https'
import {logger, } from './logger'
import {requestHttpsUrl} from './localNodeCommand'
import {readPrivateKey, decryptKey} from 'openpgp'
const conetDLServer = 'openpgp.online'
const conetDLServerPOST = 443

export const getCoNETCashBalance = async (id: string) => {

	const postJSON = JSON.stringify({id})

	const option: RequestOptions = {
		hostname: conetDLServer,
		port: conetDLServerPOST,
		path: '/api/conetcash_balance',
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Content-Length': Buffer.byteLength( postJSON )
		},
		rejectUnauthorized: false
	}
	const response = await requestHttpsUrl (option, postJSON)
	return response
}

const regiestCustomsProfileRoute = async (profileObj: ICoNET_Router) => {

	const sendData = JSON.stringify (profileObj)
	
	const option: RequestOptions = {
		hostname: conetDLServer,
		port: conetDLServerPOST,
		path: '/api/regiestProfileRoute',
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Content-Length': Buffer.byteLength( sendData )
		},
		rejectUnauthorized: false
	}

	const response: any = await requestHttpsUrl (option, sendData)

	logger (`regiestCustomsProfileRoute response is\n`, response)

	return response
}

export const regiestNewCustomer = (profile: any, walletAddr: string, clientKeyID: string, publicGPGKeyArmored: string ) => {
	
}

/**
 * 
 * 				TEST
 * 
 */
/*
const privateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----\n' +
'\n' +
'xVgEZWPenRYJKwYBBAHaRw8BAQdA5TGUigPLcUcG/k+kaAIZfu2zhD0tb1xL\n' +
'GHtOni5o4bUAAP433mZCdV2KBtn9ekAdaEJYvm3x1+7crLCS6IYdckNO2RHe\n' +
'zSoweEIzNEQwNjVCMEQ3ZGYxYWZkZUEzNDRGQzhiM2JhMkIwNENjMWQzODPC\n' +
'jAQQFgoAPgWCZWPenQQLCQcICZD47yaVqEQstgMVCAoEFgACAQIZAQKbAwIe\n' +
'ARYhBJjGbP4bqOB+k1Gc8/jvJpWoRCy2AABoWgEA/B7t4/30DOmShKIZy4qf\n' +
'ODGxWnRNYtqmWrDjn9fRUtgA/RiZW7ksd6fS8JdY8blKSae1oqRpLM6U/GuA\n' +
'yKnVZJUPx10EZWPenRIKKwYBBAGXVQEFAQEHQKQFXg09WAaJCoxciFv/CKq+\n' +
'C4eo6ZlVbDExqTv4Qh0iAwEIBwAA/24TZwTIOzzuhH5Pk5rZKnHJLUGOFj6Y\n' +
'p1Ovo6Mxw/8oD8XCeAQYFgoAKgWCZWPenQmQ+O8mlahELLYCmwwWIQSYxmz+\n' +
'G6jgfpNRnPP47yaVqEQstgAABa4A/1PJEWWbvi/+B7DHEkkfj21LEaqOMNGh\n' +
'CuhgwwY5ceb9AQDk9PWIiLlFny9d9DaAeilUHbNZ8cs6ZgQuiT3WI4ZNCg==\n' +
'=KCne\n' +
'-----END PGP PRIVATE KEY BLOCK-----\n'

const uuu = async () => {
    let obj = await readPrivateKey ({armoredKey: privateKey})
    if (!obj.isDecrypted()) {
        obj = await decryptKey ({privateKey: obj, passphrase: ''})
    }
    
    logger (obj.getKeyIDs())
}

uuu()
/*
const id = 'EA9E3C47-C90F-4D72-BE24-E531762D7A8F'
const uu = async () => {
	
	const kk = await getCoNETCashBalance (id)
	const balance = <CoNETCashBalanceResponse> kk
	logger (balance)
}

uu()
/** */