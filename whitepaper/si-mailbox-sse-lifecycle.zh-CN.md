# CoNET-SI Mailbox SSE 生命周期白皮书

修订：2026-08-24

## 1. 目的

本文定义 mailbox SI 对 `l0_listen` SSE、occupied L0 pipe 和远端异常退出的
生命周期合同。它解决的不是应用层身份授权；`l0_listen` 仍必须经过 mailbox
PGP、command 签名和时间戳校验。

`l0ListenPool` 是**每个 SI 进程独立**的内存池，当前上限为 256。472 个 SI
并不共享一个全局池，也不保证每个临时 L0 身份平均落到不同的 SI。

## 2. 心跳方向与合同

### 2.1 空闲 `l0_listen`

建立 SSE 后，SI 是发送方，周期发送：

```text
: keepalive\r\n\r\n
```

周期目标为 15 秒，必须显著小于废弃阈值 180 秒。L0d 是接收方；L0d 以最后
收到的 SSE comment、握手、gossip 或其它合法 SSE frame 为活动时间。

L0d 连续 180 秒没有收到任何 SSE 输入，必须关闭该 SSE、释放本地 session，
并重新从 SI 池选择 mailbox。SI 不得因为空闲 SSE 没有反向业务数据而删除它，
因为空闲 L0 的心跳方向是 SI → L0d。

### 2.2 occupied L0 pipe

`l0_connect` 成功后，SSE 不再发送 comment；L0d 使用当前 pipe key 每 60 秒
发送加密 `duplex_ping`。SI 对 occupied pipe 的 inbound TCP 和 SSE 两端均使用
180 秒 receive-idle 安全阈值。任一方向 180 秒没有输入，SI 必须释放该
occupied entry 并关闭两端 socket。

业务数据可以刷新活动状态，但不能代替另一方向的心跳合同。

## 3. 废弃与清理

SI 按以下优先级清理：

1. `error`、`close`、明确 EOF 或不可写：立即 `dropL0Listen`；
2. idle keepalive 写入失败：立即删除 pool entry；
3. occupied inbound/SSE 180 秒无输入：删除 entry 并销毁两端；
4. 新请求触发 pool 检查时，先删除已经由 Node socket 明确判定为
   `destroyed`、`closed`、`writableEnded` 或不可写的条目；
5. `l0_connect` 访问到 stale target 时，只删除该 target，不声称完成全池清理。

TCP 半开连接可能暂时仍报告 writable，`socket.write()` 成功也不证明远端
应用仍然存活。单向 SSE 没有接收确认，因此 SI 不能仅凭自己的 keepalive
写入确认远端已经收到。接收端的 180 秒无输入规则、TCP keepalive、close/error
事件共同构成最终回收边界。

## 4. `pool_full` 与客户端行为

池满表示该 SI 进程的 256 个 Map entry 尚未被上述机制回收；它不表示链上
Guardian 名册丢失，也不表示其它 SI 都不可用。

收到 `pool_full` 后：

- mailbox 返回有限的协议错误，不创建半成品 SSE；
- L0d 将该 SI entry 放入 180 秒失败冷却；
- L0d 重新随机选择其它已通过 TCP 资格检查的 SI；
- L0d 必须释放本地临时 identity、暂停的 TCP 和旧 pump，避免重试本身
  制造重复 listen；
- SI 日志必须区分 `pool_full`、正常关闭、keepalive 失败和 occupied 超时。

## 5. 安全边界

清理只关闭该 pool entry 绑定的 socket，不发送应用层释放命令，不把
`Securitykey` 放进 mailbox 可解密的 `l0_listen` 或 `l0_connect` command。
临时 L0 wallet 不要求登记在 AddressPGP；授权边界仍是 mailbox route PGP、
command 签名、时间戳和后续 target wallet 匹配。

## 6. 非目标

本文不把 L0 声明为公开 L1 共识加入路径，也不授权通过重启 geth、beacon 或
validator 来修复 SSE。L0d 的重连只影响自己的 mailbox/session 和本地 TCP。
