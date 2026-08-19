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

## Not in scope

- Automatic conntrack flush (ops scripts)
- Changing 409 semantics for genuinely live occupies
- Putting teardown fields in HTTP `{ "data" }` POST bodies (wire is occupied TCP + SSE only)
