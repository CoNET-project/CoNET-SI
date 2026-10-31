# CoNET-SI mailbox 协议与 command 一览

权威远程：[https://github.com/CoNET-project/CoNET-SI](https://github.com/CoNET-project/CoNET-SI)。  
改 mailbox 入站、`localNodeCommandSocket`、`udpForward`、gossip 投递前先读本文。  
实现入口：`src/util/localNodeCommand.ts`（`postOpenpgpRouteSocket` → `localNodeCommandSocket`）。  
类型：`src/define.d.ts` `SICommandObj.command` / `minerObj.listenKind`。

实时语音 MVP 使用独立的 `voice_listen` 临时 SSE 池，不得占用普通
`mailbox_listen` Chat SSE。`voice_uplink` / `voice_downlink` 只转发
AES-GCM 密文帧；SI 不保存会话密钥、不解密音频、不写 offline mailbox、
不触发 APNs。会话由随机 `sessionId` 标识，并受 route ownership、时间窗、
帧大小、序号和 idle timeout 限制。

### 杀进程原生壳来电身份（`voice_offer_store` / `voice_offer_fetch`）

VoIP / FCM 唤醒包**只有**不透明 `callId` + `sessionId`（无主叫钱包 / tag）。
被叫用户 PGP 密文 `offerArmor` 过大，不能塞进 APNs。因此：

1. 主叫 mailbox 在 `relayVoiceOfferArmor` 转发 user-PGP armor 时，若本机是被叫
   mailbox：除 `saveLocal` 外，按 `callId|sessionId` **索引**密文
   （`src/util/voiceOfferIndex.ts`，内存 + `~/.data/voice-offers/`）。
2. 若被叫 mailbox 在远程：armor 一跳转发成功后，**best-effort** 再向该 IP
   发 route-PGP 命令 `voice_offer_store`（加密目标 = 对端 **route PGP**；
   capability = `sessionId` ≥ 16，与 `voice_listen` 相同，**无** EIP-191 业务钱包）。
3. 原生壳（PWA 已退出）用推送里的 `callId`/`sessionId` 经 entry 发
   `voice_offer_fetch`（同样加密给本机 mailbox route PGP）取回 `offerArmor`，
   **本地**用已注入的**收件人 user PGP 私钥**解密；SI **永不**解密 offer。

| `command` | 加密目标 | 作用 |
| --- | --- | --- |
| `voice_offer_store` | 被叫 mailbox **route PGP** | 按 callId+sessionId 索引 user-PGP `offerArmor` |
| `voice_offer_fetch` | 被叫 mailbox **route PGP** | 按 callId+sessionId 取回密文（JSON 含 `offerArmor`） |

禁止：mailbox 解密 `offerArmor`；把主叫 EOA / tag 写进推送；把 EOA 助记词注入壳
（壳只需 **收件人 user PGP 私钥** + 可选 route 材料以便经 entry 取 armor）。

## 一、能解开 mailbox PGP ≠ 一定是 SSE

HTTP `POST /post` 的 `{ "data": "<OpenPGP armor>" }` 若 PKESK 指向**本节点 route PGP**，本机解密。解密成功只说明「这包是给本 mailbox 的」，**不**自动开 SSE。

解密后按顺序分流（只走一条）：

| 顺序 | 明文形态 | mailbox 行为 |
| --- | --- | --- |
| 1 | 内层仍是另一把 key 的 PGP（洋葱） | **转发**到该 key 的节点 / 本机用户 SSE；不再当 command |
| 2 | mailbox work `{ "data": "<user-PGP armor>" }` | 按内层 user PGP `getRoute` 转发到收件人 mailbox（本机则存储并投递 Chat SSE）。不进 command。`NoPush` 只表示跳过 Chat / APNs 推送 |
| 3 | `base64({ message, signMessage })` 且 EIP-191 通过 | 解析 JSON 的 **`command`**，进 `localNodeCommandSocket` |
| 其他 | 无法解析 | 关连接 |

因此：UDP relay、支付隧道、在线查询等都会用 mailbox PGP 包一层，但它们**不是** SSE。必须读 `command`（以及 `mining` 的 `listenKind`）再执行。

Entry 角色：PKESK **不是**本节点 route key 时，`getRoute(keyID)` 后 `socketForward` 到目标 mailbox，本机不解密、不执行 command。

## 二、L0 独占管道已移除（2026-10-31）

`l0_listen`、`l0_connect`、`mining` + `listenKind: "l0"` 以及 mailbox work 的空闲 L0 投递，已按用户决定从 SI 删除（原实现 `src/util/l0Exclusive.ts` 已删）。现在 `l0_listen` / `l0_connect` 落入 `default` 关连接，`listenKind: "l0"` 直接关连接，mailbox work 只按内层 user PGP `getRoute` 转发。不要重新引入；确有需要，先征得用户同意，并同步 GitBook。

## 三、mailbox 可执行 command 清单

未知 `command` → `default` 关连接。`mining_gossip` 仅残留在类型里，**switch 已注释，不执行**。

### 3.1 开长 SSE（入某个 pool）

| `command` | 附加字段 | Pool | 作用 |
| --- | --- | --- | --- |
| `mining`（无 listenKind 或非下表） | `walletAddress` | `livenessListeningPool` kind=`mining` | LayerMinus 挖矿 gossip |
| `mining` + `listenKind: "chat"` | `walletAddress` | 同上 kind=`chat` | PWA / 应用 Chat 在线 |
| `mining` + `listenKind: "udp"` | 见 UDP | UDP client pool | 兼容别名 → `udp_listen` |
| `mining` + `listenKind: "udp_server"` | 见 UDP | UDP server pool | 兼容别名 → `udp_server_listen` |
| `udp_listen` | `walletAddress`, `udpServerWallet`, `sessionId`, `timestamp` | UDP client | 客户端 UDP mailbox SSE |
| `udp_server_listen` | server 钱包 / session | UDP server | 服务端 UDP mailbox SSE |

### 3.2 对接 / 中继（不是新开 listen SSE）

| `command` | 作用 |
| --- | --- |
| `udp_relay` | 把 AES blob 转到对端 UDP listen（mailbox **不解密** payload） |
| `udp_uplink` | 上行 UDP 帧到 server listen |
| `udp_unlisten` | 拆指定 UDP session |
| `udp_subscribe` | 若误用 route PGP 加密会打到 mailbox；正确目标是 UDP **用户 PGP**。mailbox 解密到此视为误路由 |

### 3.3 短请求（JSON 回包，不开 SSE）

| `command` | 作用 |
| --- | --- |
| `wallet_online_query` | 查本 mailbox **chat/mining** pool 里 `targetWallet` 是否在听 |
| `wallet_native_wake_query` | 查本 mailbox 登记钱包是否有可唤醒原生壳 |
| `gossip_delivery_ack` | 客户端确认 gossip，按 `armorHash` 删离线缓存 |
| `mining_validator` | 验证人矿工上报（验签 epoch/hash） |
| `voice_offer_store` | 按 `callId`+`sessionId` 索引 user-PGP `offerArmor`（不解密） |
| `voice_offer_fetch` | 按 `callId`+`sessionId` 取回索引密文供原生壳本地解密 |

### 3.4 支付隧道（本机代连，不是 mailbox SSE）

| `command` | 作用 |
| --- | --- |
| `SilentPass` | 付费校验后 SOCKS/HTTP 代连 |
| `SaaS_Sock5` | 同上（含 HTTP type → V3） |
| `SaaS_Sock5_v2` | 用 `Securitykey` 配对双腿再 `resConnect` |

这三条会读 `Securitykey` / `requestData`。UDP mailbox **命令**禁止带 overlay `Securitykey`（B 能解开）。

## 四、改 mailbox 时的硬约束

1. **先看 `command`，再决定 SSE / pipe / JSON / 代连。** 不要「本机 PGP 解开 ⇒ 当 SSE」。
2. 新能力优先**新 `command` 字符串**。`mining` 的 `listenKind` 只用于已存在的兼容别名（`chat` / `udp` / `udp_server`）。
3. L0 独占管道已移除：不要重新引入 `l0_listen` / `l0_connect` 或 mailbox work 的空闲 L0 投递（见第二节）。
4. UDP listen、UDP relay：**禁止**在 B 可解的 JSON 里放 overlay `Securitykey`。
5. Entry 只转发；command 只在 **PKESK = 本节点 route PGP** 且验签通过后执行。
6. `SICommandObj.command` 联合类型与 `localNodeCommandSocket` 的 `switch` 必须同步；未实现的不要只改类型。

## 五、对照代码

| 步骤 | 位置 |
| --- | --- |
| 解密 / 洋葱 / mailbox work / 验签 | `postOpenpgpRouteSocket` |
| command 分发 | `localNodeCommandSocket` |
| UDP | `src/util/udpForward.ts` |
| Chat/mining SSE | `addIpaddressToLivenessListeningPool` |
| 类型 | `src/define.d.ts` |

## 六、L0 SSE 心跳（已随 L0 移除）

L0 独占管道已于 2026-10-31 移除，`l0ListenPool`、空闲 `l0_listen` keepalive、occupied pipe 的 `duplex_ping` 合同一并作废。

