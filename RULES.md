# CoNET-SI mailbox 协议与 command 一览

权威远程：[https://github.com/CoNET-project/CoNET-SI](https://github.com/CoNET-project/CoNET-SI)。  
改 mailbox 入站、`localNodeCommandSocket`、`l0Exclusive`、`udpForward`、gossip 投递前先读本文。  
实现入口：`src/util/localNodeCommand.ts`（`postOpenpgpRouteSocket` → `localNodeCommandSocket`）。  
类型：`src/define.d.ts` `SICommandObj.command` / `minerObj.listenKind`。

## 一、能解开 mailbox PGP ≠ 一定是 SSE

HTTP `POST /post` 的 `{ "data": "<OpenPGP armor>" }` 若 PKESK 指向**本节点 route PGP**，本机解密。解密成功只说明「这包是给本 mailbox 的」，**不**自动开 SSE。

解密后按顺序分流（只走一条）：

| 顺序 | 明文形态 | mailbox 行为 |
| --- | --- | --- |
| 1 | 内层仍是另一把 key 的 PGP（洋葱） | **转发**到该 key 的节点 / 本机用户 SSE；不再当 command |
| 2 | mailbox work `{ "data": "<user-PGP armor>" }` | 先按内层 user PGP 匹配本机 **`l0ListenPool` / `l0ListenByPgp`** 空闲 SSE；没有再 `getRoute` 转发。不进 command。不要带 `NoPush`（那会走 Chat/APNs 语义，不是 L0 pool） |
| 3 | `base64({ message, signMessage })` 且 EIP-191 通过 | 解析 JSON 的 **`command`**，进 `localNodeCommandSocket` |
| 其他 | 无法解析 | 关连接 |

因此：L0 占用、UDP relay、支付隧道、在线查询等都会用 mailbox PGP 包一层，但它们**不是** `l0_listen` SSE。必须读 `command`（以及 `mining` 的 `listenKind`）再执行。

Entry 角色：PKESK **不是**本节点 route key 时，`getRoute(keyID)` 后 `socketForward` 到目标 mailbox，本机不解密、不执行 command。

## 二、`l0_listen` 在可执行 command 内

是。两条入口，同一实现 `handleL0Listen`（`src/util/l0Exclusive.ts`）：

1. **`command: "l0_listen"`**（L0d 现行）
2. **`command: "mining"` + `listenKind: "l0"`**（兼容别名）

都是：校验时间戳 / 禁止 overlay `Securitykey` → 入 **`l0ListenPool`**，并用 command 的 **`userPgpKeyId`** 写入 **`l0ListenByPgp`**（临时钱包不在 AddressPGP，禁止只靠 `getWalletFromKeyID`）→ 写 SSE 握手 `{ ok, kind:'l0', wallet, nodeWallet }` → 空闲 keepalive。

对接占用是另一条 command：**`l0_connect`**（不是 SSE）。mailbox 用 `targetWallet` 找 pool 内空闲 listen；未占用则 occupy 并 **pipe** 剩余 TCP 到该 SSE；已占用且插座仍活则 **409**。

`l0_listen` / `l0_connect` 密文必须包给 **mailbox route PGP**。entry 只负责转到该 SI。拆线只关插座（对端见 EOF/FIN/RST）。现役代码**不**再发应用层 `l0_pipe_end` / `l0_listen_released`。

## 三、mailbox 可执行 command 清单

未知 `command` → `default` 关连接。`mining_gossip` 仅残留在类型里，**switch 已注释，不执行**。

### 3.1 开长 SSE（入某个 pool）

| `command` | 附加字段 | Pool | 作用 |
| --- | --- | --- | --- |
| `l0_listen` | `walletAddress`, `timestamp`, **`userPgpKeyId`**（加密子钥 16 hex）；勿带 `Securitykey` | `l0ListenPool` + `l0ListenByPgp` | L0 独占空闲 SSE；gossip 用 user PGP 匹配此索引 |
| `mining` + `listenKind: "l0"` | 同上 | 同上 | 上一条的别名 |
| `mining`（无 listenKind 或非下表） | `walletAddress` | `livenessListeningPool` kind=`mining` | LayerMinus 挖矿 gossip |
| `mining` + `listenKind: "chat"` | `walletAddress` | 同上 kind=`chat` | PWA / 应用 Chat 在线 |
| `mining` + `listenKind: "udp"` | 见 UDP | UDP client pool | 兼容别名 → `udp_listen` |
| `mining` + `listenKind: "udp_server"` | 见 UDP | UDP server pool | 兼容别名 → `udp_server_listen` |
| `udp_listen` | `walletAddress`, `udpServerWallet`, `sessionId`, `timestamp` | UDP client | 客户端 UDP mailbox SSE |
| `udp_server_listen` | server 钱包 / session | UDP server | 服务端 UDP mailbox SSE |

Chat / mining 与 L0 **分池**。Idle L0 可抄一份用户 PGP gossip（offer），**不占用**。真正占用只认 `l0_connect`。

### 3.2 对接 / 中继（不是新开 listen SSE）

| `command` | 作用 |
| --- | --- |
| `l0_connect` | `targetWallet` 对 `l0ListenPool` 空闲 SSE occupy + byte pipe |
| `udp_relay` | 把 AES blob 转到对端 UDP listen（mailbox **不解密** payload） |
| `udp_uplink` | 上行 UDP 帧到 server listen |
| `udp_unlisten` | 拆指定 UDP session |
| `udp_subscribe` | 若误用 route PGP 加密会打到 mailbox；正确目标是 UDP **用户 PGP**。mailbox 解密到此视为误路由 |

### 3.3 短请求（JSON 回包，不开 L0 SSE）

| `command` | 作用 |
| --- | --- |
| `wallet_online_query` | 查本 mailbox **chat/mining** pool 里 `targetWallet` 是否在听 |
| `gossip_delivery_ack` | 客户端确认 gossip，按 `armorHash` 删离线缓存 |
| `mining_validator` | 验证人矿工上报（验签 epoch/hash） |

### 3.4 支付隧道（本机代连，不是 mailbox SSE）

| `command` | 作用 |
| --- | --- |
| `SilentPass` | 付费校验后 SOCKS/HTTP 代连 |
| `SaaS_Sock5` | 同上（含 HTTP type → V3） |
| `SaaS_Sock5_v2` | 用 `Securitykey` 配对双腿再 `resConnect` |

这三条会读 `Securitykey` / `requestData`。L0 / UDP mailbox **命令**禁止带 overlay `Securitykey`（B 能解开）。

## 四、改 mailbox 时的硬约束

1. **先看 `command`，再决定 SSE / pipe / JSON / 代连。** 不要「本机 PGP 解开 ⇒ 当 L0 SSE」。
2. 新能力优先**新 `command` 字符串**，不要往 `l0_listen` 里塞无关语义。`mining` 的 `listenKind` 只用于已存在的兼容别名。
3. 独占 L0：空闲 `l0_listen` + 一次 `l0_connect` occupy；二占 409。Chat/mining gossip 不得 409。
4. L0 / UDP listen、`l0_connect`、UDP relay：**禁止**在 B 可解的 JSON 里放 overlay `Securitykey`。
5. 拆 L0 线：关插座即可；不要恢复应用层 teardown 命令当放大原语。
6. Entry 只转发；command 只在 **PKESK = 本节点 route PGP** 且验签通过后执行。
7. `SICommandObj.command` 联合类型与 `localNodeCommandSocket` 的 `switch` 必须同步；未实现的不要只改类型。

## 五、对照代码

| 步骤 | 位置 |
| --- | --- |
| 解密 / 洋葱 / mailbox work / 验签 | `postOpenpgpRouteSocket` |
| command 分发 | `localNodeCommandSocket` |
| L0 listen / connect / pool | `src/util/l0Exclusive.ts` |
| UDP | `src/util/udpForward.ts` |
| Chat/mining SSE | `addIpaddressToLivenessListeningPool` |
| 类型 | `src/define.d.ts` |

L0 客户端（conet-l0d）如何包 mailbox PGP、offer 里带 SI 身份：见该仓库 `RULES.md`，不要在本仓库改 L0d。

## 六、L0 SSE 心跳与废弃合同

完整生命周期说明见 [`whitepaper/si-mailbox-sse-lifecycle.zh-CN.md`](whitepaper/si-mailbox-sse-lifecycle.zh-CN.md)。

- `l0ListenPool` 是每个 SI 进程独立的内存池，上限 256，不是 472 台 SI 的全局池。
- 空闲 `l0_listen` SSE 由 SI 每 15 秒发送 `: keepalive`；L0d 连续 180 秒没有收到任何心跳或合法 SSE 数据，必须关闭并重建。
- occupied L0 pipe 由 L0d 每 60 秒发送加密 `duplex_ping`；SI 两端 socket 连续 180 秒没有输入时释放 entry 并关闭两端。
- `error`、`close`、不可写和 keepalive 写失败立即清理；pool 满检查前只回收明确已关闭的 socket，不以空闲时间删除合法 idle SSE。
- `pool_full` 是当前 SI 的局部容量错误；L0d 应冷却该 SI 并选择其它 SI，不应持续重试同一入口。
