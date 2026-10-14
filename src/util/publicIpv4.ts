import {isIP} from 'net'
import ipaddr from 'ipaddr.js'

/**
 * Accept only globally routable IPv4 unicast addresses.
 * This deliberately does not use the deprecated/vulnerable `ip` package.
 */
export const isPublicIpv4 = (address: string): boolean =>
	isIP(address) === 4 && ipaddr.parse(address).range() === 'unicast'
