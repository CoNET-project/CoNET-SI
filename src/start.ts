import Cluster from 'node:cluster'
import {cpus} from 'node:os'
import conet_si_server from './endpoint/server'

if (Cluster.isPrimary) {
	const worker = Math.floor(cpus().length/2)
	if (worker<2) {
		new conet_si_server()
	} else {
		for (let i = 0; i < worker; i ++) {
			Cluster.fork()
		}
	}

} else {
	new conet_si_server()
}
