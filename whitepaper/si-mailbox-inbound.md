# CoNET-SI inbound: commands vs mailbox work

Revision: 2026-10-31 (L0 exclusive occupancy removed). Pair: [si-mailbox-sse-lifecycle.zh-CN.md](./si-mailbox-sse-lifecycle.zh-CN.md).

## Temporary voice SSE

Chat real-time voice is an application-level temporary stream. It does not
reuse or occupy `mailbox_listen`. A signed `voice_listen` command creates a
random per-call SSE session on the wallet's own route. A signed
`voice_uplink` or `voice_downlink` command addressed to the peer mailbox
locates that peer session and writes an opaque AES-GCM frame. The node checks
route ownership, session ownership, timestamp, sequence and size only. It
never decrypts, persists, pushes, or indexes the audio payload.

Decrypting this node’s **route PGP** does not open an SSE. `postOpenpgpRouteSocket` then takes **one** branch:

| Order | Plaintext | Action |
|---|---|---|
| 1 | Inner OpenPGP for another key | Forward that armor (onion). Not a command. |
| 2 | Mailbox work `{ "data": "<user-PGP armor>" }` | `getRoute` by the inner user-PGP key ID and forward (local: store and deliver to Chat SSE). **Not** a command. |
| 3 | `base64({ message, signMessage })` | EIP-191 `command` (mining, `mailbox_listen`, UDP, voice, …). |

## L0 exclusive occupancy (removed)

`l0_listen`, `l0_connect`, `mining` with `listenKind: "l0"`, and idle-L0 delivery of mailbox work were removed on 2026-10-31. `l0_listen` / `l0_connect` now fall to the default branch and close the connection.

## Forbidden confusions

- `NoPush` in mailbox work only skips the Chat / APNs push.
- HTTP `{ "data" }` never carries `NoPush` as a sibling field.

Implementation: `src/util/localNodeCommand.ts`. Programming rules: [`RULES.md`](../RULES.md). GitBook: [mailbox routing](../../docs/gitbook/l0/mailbox-routing.md), [SI guide](../../docs/gitbook/l0/si-developer-guide.md).
