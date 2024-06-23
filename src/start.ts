import Cluster from 'node:cluster'
import {cpus} from 'node:os'
import conet_si_server from './endpoint/server'

if (Cluster.isPrimary) {
	for (let i = 0; i < cpus().length; i ++) {
		Cluster.fork()
	}
	
} else {
	new conet_si_server()
}
