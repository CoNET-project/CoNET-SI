# CoNET-SI inbound: commands vs mailbox work vs idle L0

Revision: 2026-08-25. Pair: [si-mailbox-sse-lifecycle.zh-CN.md](./si-mailbox-sse-lifecycle.zh-CN.md) §7.

Decrypting this node’s **route PGP** does not open an SSE. `postOpenpgpRouteSocket` then takes **one** branch:

| Order | Plaintext | Action |
|---|---|---|
| 1 | Inner OpenPGP for another key | Forward that armor (onion). Not a command. |
| 2 | Mailbox work `{ "data": "<user-PGP armor>" }` | Match **idle `l0_listen`** by inner user-PGP key ID (`l0ListenByPgp`). Hit: gossip copy on that SSE, HTTP 200, stop. Miss: then Chat / `getRoute`. **Not** a command. |
| 3 | `base64({ message, signMessage })` | EIP-191 `command` (`l0_listen`, `l0_connect`, mining, UDP, …). |

## Idle L0 index

`l0_listen` must store `userPgpKeyId` (encryption subkey, 16-hex) in `l0ListenByPgp`. Temporary wallets are not on AddressPGP; `getWalletFromKeyID` alone leaves `pgp=none` and mailbox work cannot match.

## Forbidden confusions

- Inner duplex user PGP is **not** a Guardian route key. Do not `getRoute` it first.
- Do not send `NoPush` on L0 duplex mailbox work. That field is Chat/APNs skip-push, not “deliver to L0 pool.”
- `duplex_accept` is branch 2. `l0_connect` is branch 3. Occupying the same idle SSE before branch 2 is processed drops the accept.
- HTTP `{ "data" }` never carries `NoPush` as a sibling field.

Implementation: `src/util/localNodeCommand.ts`, `src/util/l0Exclusive.ts`. Programming rules: [`RULES.md`](../RULES.md). GitBook: [mailbox routing](../../docs/gitbook/l0/mailbox-routing.md), [duplex](../../docs/gitbook/l0/duplex-forward.md), [SI guide](../../docs/gitbook/l0/si-developer-guide.md).
