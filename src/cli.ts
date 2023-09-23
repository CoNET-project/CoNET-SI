#!/usr/bin/env node

import { cpus } from 'node:os'
import { join } from 'node:path'
import { inspect } from 'node:util'
import Cluster from 'node:cluster'
import type { Worker } from 'node:cluster'
import {exec} from 'node:child_process'

import colors from 'colors/safe'
import { logger, getServerIPV4Address, getSetup, waitKeyInput, generateWalletAddress, saveSetup, generatePgpKey, loadWalletAddress, startPackageSelfVersionCheckAndUpgrade, regiestPrivateKey } from './util/util'
import conet_si_server from './endpoint/server'

import type {HDNodeWallet} from 'ethers'

if ( Cluster.isPrimary ) {

	const startCommand = `cd; conet-mvp-si start -d > system.log &`

	const killAllWorker = () => {
		if ( workerPool.length > 0) {
			for (let i = 0; i < workerPool.length; i ++) {
				const worker = workerPool[i]
				worker.kill ()
			}
		}
	}
	
	const [,,...args] = process.argv

	let debug = false
	let version = false
	let help = false
	let passwd = ''
	let singleCPU = false
	let workerPool: Worker[] = []


	args.forEach ((n, index ) => {
		if (/\-d/.test(n)) {
			debug = true
		} else if ( /\-v|\--version/.test (n)) {
			version = true
		} else if (/\-h|\--help/.test (n)) {
			help = true
		} else if (/\-p/.test(n)) {
			passwd = args[index + 1]
		} else if (/\-s/.test(n)) {
			singleCPU = true
		}
	})
	const packageFile = join (__dirname, '..', 'package.json')
	debug ? logger (`packageFile = ${ packageFile }`): null

	const setup = require (packageFile)

	const printVersion = () => {
		logger (`CoNET-SI node version ${ setup.version }\n` )
		process.exit (0)
	}

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

	if ( !GlobalIpAddress?.length ) {
		logger ('WARING: Your node looks have no Global IP address!')
	}
	
	let numCPUs = cpus ().length

	debug ? logger (`Cluster.isPrimary node have ${ numCPUs } cpus\n`): null

	numCPUs = 1							//			not support multi-cpus

	// for (let i = 0; i < numCPUs; i++) {
	// 	Cluster.fork()
	// }
	const forkWorker = () => {
		
		let numCPUs = cpus ().length
		
		debug ? logger (`Cluster.isPrimary node have ${ numCPUs } cpus\n`): null
	
		const _forkWorker = () => {
			const fork = Cluster.fork ()
			fork.once ('exit', (code: number, signal: string) => {
				logger (colors.red(`Worker [${ fork.id }] Exit with code[${ code }] signal[${ signal }]!\n Restart after 30 seconds!`))
				if ( !signal ) {
					return logger (`Worker [${ fork.id }] signal = NEW_VERSION do not restart!`)
				}
				return setTimeout (() => {
					return _forkWorker ()
				}, 1000 * 10 )
			})
			return (fork)
		}
		
		for (let i = 0; i < numCPUs; i ++) {
			const woeker = _forkWorker ()
			workerPool.push (woeker)
		}
		
	}

	const startPackageSelfVersionCheckAndUpgrade_IntervalTime = 1000 * 60 * 10				//			10 mins

	const checkNewVer = async () => {
		const haveNewVersion = await startPackageSelfVersionCheckAndUpgrade('@conet.project/mvp-si')
		if ( haveNewVersion === null ) {
			return logger (colors.red(`startPackageSelfVersionCheckAndUpgrade responsed null! Interval exec STOP!`))
		}
		if ( haveNewVersion === true ) {
			logger (colors.red (`@conet.project/mvp-si had UPGRADE new!, restart all!`))
			killAllWorker()
			return process.exit()
		}

		setTimeout (() => {
			checkNewVer ()
		}, startPackageSelfVersionCheckAndUpgrade_IntervalTime)
	}

	const getSetupInfo = async () => {
		
		let setupInfo = await getSetup ()

		process.once ('exit', () => {
			logger (colors.red (`@conet.project/mvp-si main process on EXIT, restart again!, ${startCommand}`))
			const uuu = exec (startCommand)

			uuu.once ('spawn', () => {
				return logger (colors.red (`@conet.project/mvp-si main process now to exit!, ${startCommand} Start!`))
			})
		})

		if ( !setupInfo ) {
			

			const password = await waitKeyInput (`Please enter the password for protected wallet address: `, true )

			const port: number = parseInt( await waitKeyInput (`Please enter the node listening PORT number [default is 80]: `, false) ) || 80


			const storage: number =  parseInt(await waitKeyInput (`Please enter the price of storage price USDC/MB every month [default is 0.01]: `, false )) || 0.01

			const outbound: number = parseInt(await waitKeyInput (`Please enter the price of outbound of data price USDC/MB every month [default is 0.00001]: `, false )) || 0.00001
			const keychain =  await generateWalletAddress ( password )
			
			const keyObj = await loadWalletAddress ( keychain, password )
			const pgpKey = await generatePgpKey (keyObj.address, password)
			logger (inspect (keychain, false, 3, true ))
			setupInfo = {
				keychain: keychain,
				ipV4: GlobalIpAddress?.length ? GlobalIpAddress[0]:'',
				ipV6: '',
				ipV4Port: port,
				ipV6Port: port,
				storage_price: storage,
				outbound_price: outbound,
				DL_registeredData: '',
				pgpKey,
				cpus: cpus().length,
				passwd: password, 
				platform_verison: setup.version,
				dl_publicKeyArmored: ''
			}


			await regiestPrivateKey (setupInfo.pgpKey.privateKey, password)
			await saveSetup ( setupInfo, debug )
			return process.exit ()
		}

		checkNewVer()
		if (!singleCPU) {
			return forkWorker()
		}
		new conet_si_server ()
	}


	getSetupInfo ()
} else {
	new conet_si_server ()
}
