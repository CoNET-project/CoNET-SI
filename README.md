# CoNET "Layer Minus protocol" node

## Description

The New Era of the Internet
with a new generation of Transmission Protocols

## INSTALL
1. Install NodeJS

https://nodejs.org/en/

2. Install CoNET-SI node
```bash
npm i @conet.project/mvp-si -g
```

## SETUP

### start CoNET "Layer Minus protocol" node

```bash
conet-mvp-si
```

## Notice

Mailbox 入站与可执行 `command` 清单（含 `l0_listen` / mailbox work → idle L0 pool）：见 [`RULES.md`](RULES.md) 与 [`whitepaper/si-mailbox-inbound.md`](whitepaper/si-mailbox-inbound.md)。

### Temporary voice relay

CoNET-SI supports an experimental Chat voice relay separate from the normal
`mailbox_listen` SSE. Each participant opens a random `voice_listen` session
on its own mailbox. The peer sends opaque AES-GCM frames using
`voice_uplink`/`voice_downlink`; the node writes them only to the matching
temporary voice SSE. Voice frames are never decrypted, saved to offline
mailbox storage, pushed through APNs, or included in Chat history. This is an
application-level duplex relay, not raw UDP and not WebRTC.

## License

Copyright (c) Kloak Information Technologies Inc. All rights reserved.

Licensed under the [MIT](LICENSE) License.

The MIT License (MIT)
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
