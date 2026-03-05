/**
 * Extend net.Socket with custom remoteAddressShow used in CoNET-SI.
 * TLSSocket extends net.Socket at runtime; type assertions used where TS resolution fails.
 */
import type { Socket } from 'net';

declare module 'net' {
  interface Socket {
    remoteAddressShow?: string;
  }
}
