# L0 pipe teardown — `l0_pipe_end` / `l0_listen_released`

**Status:** MVP (2026-08) · **Code:** `src/util/l0Exclusive.ts`

## Problem

When an occupied `l0_listen` drops (inbound TCP error, listen SSE close, replaced session, stale idle), SI used to `destroy()` sockets without telling the **connector** (`l0_connect` client). Mailbox B could stay logically occupied while the connector still believed a pipe existed → repeated **HTTP 409** on re-occupy and ghost SYN-SENT on overlay `:4200`.

## Fix (SI)

On `dropL0Listen(wallet, reason)` while `occupied === true`:

1. **`emitL0PipeEnd`** — write one line on the occupied **inbound** TCP (the `l0_connect` POST socket):

   ```json
   {"type":"l0_pipe_end","wallet":"<listen>","connector":"<connector>","reason":"<why>"}\n
   ```

2. **`writeSseJson`** — optional notice on the listen SSE:

   ```json
   {"type":"l0_listen_released","wallet":"<listen>","reason":"<why>"}
   ```

3. Remove from `l0ListenPool` / `l0ListenByPgp`, then `destroy` inbound + SSE sockets.

Reason strings are opaque but stable: `inbound_close`, `inbound_error`, `pipe_write_closed`, `close`, `replaced`, `stale_idle`, etc.

## Consumer (conet-l0d)

- `pipe.rs` reads inbound lines while forwarding AES blobs; `l0_pipe_end` → `L0dError::L0PipeEnd`.
- `client.rs` clears `pipe_tx` for sessions whose `peer_listen_wallet` matches; retries occupy with **1s** backoff after pipe end.
- Listen SSE may deliver `l0_listen_released` → same release path.

## PR checklist

- [ ] `dropL0Listen` calls `emitL0PipeEnd` before destroy when occupied
- [ ] GitBook [duplex-forward](https://gitbook.conet.network/l0/duplex-forward.html) documents both JSON shapes
- [ ] Lab: after hub/spoke listen bounce, overlay `:4200` ESTAB + beacon `connected≥1` without manual SI `pkill` on B only

## Occupy HTTP 200 + idle keepalive (2026-08-19)

Lab `:8400` never reached duplex AES because:

1. Idle `l0_listen` has no mining epoch. Entry `socketData` + `sourceSocket` 60s idle destroyed the listen ~every 64s. Hub reconnect `l0_listen` used to **replace** the pool entry and tear a live occupy → spoke **404** / **409**.
2. Occupy did not write HTTP 200 keep-alive on the `l0_connect` TCP (`response200Html` would `end()`). Crate `read_http_ok` never returned, so `pipe_tx` never became a live AES pipe.
3. Occupied inflow used to **409 all** packets, including user-PGP Chat `duplex_offer` / `duplex_accept`.
4. Idle L0 **stole** gossip and returned before the Chat pool, so the initiator Chat SSE never saw accept if L0 later died.

SI now: SSE comment keepalive (~15s, `\r\n\r\n`) **only while idle**; occupy **clears** that timer and never writes comments (AES `data:` keeps the socket); `setTimeout(0)` on listen / occupy / client→C; occupy writes HTTP 200 keep-alive then AES; 409 only on a second `l0_connect` or replace-while-occupied; Chat pool always gets user-PGP gossip (idle L0 may get a copy). Crate installs `pipe_tx` only after that 200. Occupied-pipe AES `duplex_accept` omits bulky `listenUserPgp`.

## Occupied-pipe ghost cleanup (2026-08-20)

An occupied TCP can remain half-open after an entry or socket-forward process
dies: the socket may still report `writable=true`, so a close-only cleanup never
runs and every new `l0_connect` receives `409`. SI now arms a transport-only
180-second inactivity watchdog on both the occupied inbound TCP and the mailbox
SSE. The interval is above the conet-l0d application ping cadence, so a live
pipe remains active; a ghost occupy is dropped and both sockets are destroyed
when the watchdog fires.

An `end` event on the occupied inbound TCP is also an immediate teardown signal.
This rule applies only to the exclusive L0 pool. Chat and mining SSE keep their
normal half-close semantics and are not evicted by this watchdog.

If the peer SSE disappears before the occupy response is committed, SI returns
HTTP `410 Gone` with `error: "l0_peer_disconnected"` to the `l0_connect` POST
sender, then closes the pipe. If HTTP `200` keep-alive was already committed,
SI cannot send a second HTTP response; it closes the occupied TCP instead. The
client must treat either the `410` response head or EOF as terminal for that
pipe incarnation. Bytes arriving after release are discarded and are never
passed to `saveLocal` or a gossip SSE.

## Not in scope

- Automatic conntrack flush (ops scripts)
- Changing 409 semantics for a genuinely live second `l0_connect`
- Putting teardown fields in HTTP `{ "data" }` POST bodies (wire is occupied TCP + SSE only)
