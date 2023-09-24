import type { RequestOptions } from 'https'
import {logger, requestHttpsUrl} from './util'

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
const id = 'EA9E3C47-C90F-4D72-BE24-E531762D7A8F'
const uu = async () => {
	
	const kk = await getCoNETCashBalance (id)
	const balance = <CoNETCashBalanceResponse> kk
	logger (balance)
}

uu()
/** */