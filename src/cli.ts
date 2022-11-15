#!/usr/bin/env node
import conet_si_server from './endpoint/server'
import Cluster from 'node:cluster'
import { cpus } from 'node:os'
import { join } from 'node:path'
import { inspect } from 'node:util'

import { logger, getServerIPV4Address, getSetup, waitKeyInput, GenerateWalletAddress, saveSetup } from './util/util'

const [,,...args] = process.argv

let debug = false
let version = false
let help = false
let passwd = ''
args.forEach ((n, index ) => {
    if (/\-d/.test(n)) {
        debug = true
    } else if ( /\-v|\--version/.test (n)) {
		version = true
	} else if (/\-h|\--help/.test (n)) {
		help = true
	} else if (/\-p/.test(n)) {
		passwd = args[index + 1]
	}
})

if ( Cluster.isPrimary ) {
	const packageFile = join (__dirname, '..', 'package.json')
	debug ? logger (`packageFile = ${ packageFile }`): null

	const setup = require (packageFile)

	const printVersion = () => {
		logger (`CoNET-SI node version ${ setup.version }\n` )
		process.exit (0)
	}

	const DL_key = setup.DL_Public

	const printInfo = () => {
		logger (
			`CoNET-SI CLI ${ setup.version } is a command line tool that gives CoNET-SI participant who provides network and storage to earn stablecoin\n` +
			`Usage:\n`+
			`	conet-mvp-si [command]\n\n` +
			`CoNET-SI CLI Commands:\n` +
			`	node start|stop			Manage node \n` +
			`\n` +
			`Flags:\n` +
			`-v, --version            version for CoNET-SI CLI` +
			``
		)

		process.exit (0)
	}

	if ( version ) {
		printVersion ()
	}

	if ( !args[0] || help ) {
		printInfo ()
	}

	const GlobalIpAddress = getServerIPV4Address ( false )

	debug? logger (inspect (GlobalIpAddress, false, 3, true )) : null

	if ( GlobalIpAddress.length === 0 ) {
		logger ('WARING: Your node looks have no Global IP address!')
	}
	
	let numCPUs = cpus ().length

	debug ? logger (`Cluster.isPrimary node have ${ numCPUs } cpus\n`): null

	numCPUs = 1							//			not support multi-cpus

	// for (let i = 0; i < numCPUs; i++) {
	// 	Cluster.fork()
	// }

	const getSetupInfo = async () => {
		// @ts-ignore: Unreachable code error
		let setupInfo: ICoNET_NodeSetup|undefined = await getSetup ( debug )

		if ( !setupInfo ) {
			
			// @ts-ignore: Unreachable code error
			const password = await waitKeyInput (`Please enter the password for protected wallet address: `, true )

			// @ts-ignore: Unreachable code error
			const port: number = parseInt(await waitKeyInput (`Please enter the node listening PORT number [default is 80]: `, false))|| 80

			// @ts-ignore: Unreachable code error
			const storage: number =  parseInt(await waitKeyInput (`Please enter the price of storage price USDC/MB every month [default is 0.01]: `)) || 0.01
			// @ts-ignore: Unreachable code error
			const outbound: number = parseInt(await waitKeyInput (`Please enter the price of outbound of data price USDC/MB every month [default is 0.00001]: `)) || 0.00001
			const keychain = GenerateWalletAddress ( password )
			logger (inspect (keychain, false, 3, true ))
			setupInfo = {
				keychain: keychain,
				ipV4: GlobalIpAddress[0]||'',
				ipV6: '',
				ipV4Port: port,
				ipV6Port: port,
				storage_price: storage,
				outbound_price: outbound,
				DL_nodes: setup.DL_nodes,
				setupPath: '',
				DL_registeredData: null,
				keyObj: null
			}
			// @ts-ignore: Unreachable code error
			await saveSetup ( setupInfo, debug )
			return new conet_si_server( debug, passwd )
		}
		
		// debug ? logger (`getSetupInfo has data:\n`, inspect ( setupInfo, false, 4, true )): null
		return new conet_si_server( debug, passwd )
	}

	getSetupInfo ()
} else {
	logger (`Cluster fock running!`)
	// new conet_si_server( debug )
}
