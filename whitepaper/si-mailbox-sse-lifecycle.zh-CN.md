# CoNET-SI Mailbox SSE 生命周期白皮书

修订：2026-10-31（L0 独占管道已移除）

## 0. Chat 实时语音临时通道

Chat 实时语音不占用普通 `mailbox_listen`。每次通话生成随机
`sessionId`，双方分别在自己的 mailbox 上建立独立的 `voice_listen` SSE。
音频帧通过签名的 `voice_uplink` / `voice_downlink` 命令送往对方 mailbox，
再写入对方的临时 voice SSE，从而形成两条单向路径的双工通道。

SI 只校验 route ownership、session ownership、时间戳、序号和帧大小；语音
帧是 AES-GCM 密文，SI 不解密、不写离线 mailbox、不触发 APNs，也不进入
Chat 历史。该通道是应用层密文 relay，不是原生 UDP，也不是 WebRTC。

## 1. L0 独占管道（已移除）

本文原先第 1–7 节定义的 `l0_listen` SSE、occupied L0 pipe、`l0ListenPool`
心跳 / 清理 / `pool_full` 合同，以及 mailbox work 优先投递空闲 L0 pool 的规则，
已于 2026-10-31 随 L0 独占管道一起从 SI 删除。现在 `l0_listen` / `l0_connect`
落入默认分支关连接；mailbox work 只按内层 user PGP `getRoute` 转发。
