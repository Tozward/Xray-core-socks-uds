# 面向 Go/Caddy 目标站点的 REALITY 构建分支

为便于在 GitHub 分别审核，改动分布在两个公开 fork 的分支中：

| 仓库与分支 | 内容 |
| --- | --- |
| [Tozward/REALITY `codex/caddy-records-16-official-base`](https://github.com/Tozward/REALITY/tree/codex/caddy-records-16-official-base) | 2026-10-15 同步 XTLS/REALITY main `83f6217`，固定提交 `19a3b88`；[PR #40](https://github.com/XTLS/REALITY/pull/40) 已由官方合入，保留 Caddy 目标站点补丁。 |
| [Tozward/Xray-core-socks-uds `codex/caddy-reality`](https://github.com/Tozward/Xray-core-socks-uds/tree/codex/caddy-reality) | 基于 XTLS/Xray-core main，适配 PR #40 的私钥接口，并在 `go.mod` 中固定引用上述 REALITY 分支的具体提交。 |

Xray-core 的 `go.mod` 使用远端 `replace`。编译时无需手动克隆 REALITY；`.local/reality-official-base` 是当前机器上用于维护这个分支的独立工作副本，不属于 Xray-core 提交。

## 定制内容

- REALITY 的 `maxUselessRecords` 固定为 16。这是连续未推进 TLS 记录的容忍上限，不是单条记录的长度，也不是正常握手会发送的记录数。2026-10-11 核对的目标 Caddy v2.11.4 二进制由 Go 1.27.0 构建，其标准 `crypto/tls` 使用同一上限。这样可避免此项异常输入行为与目标不同，但没有证据表明将 32 改为 16 会改善正常流量吞吐。移除按目标探测 CCS 容量的额外连接、探测报文和动态上限；握手后记录长度探测仍保留。升级 Caddy 或 Go 时需要重新核对。
- PR #40 将 REALITY 的 `Config.PrivateKey` 改为 `*ecdh.PrivateKey`。Xray-core 在启动监听时解析一次；无效私钥会报错。
- 这些修改针对由 Go `crypto/tls` 提供 TLS 的 Caddy 目标。若目标站点实际使用另一种 TLS 栈，先核实其记录行为再复用此分支。

保留握手后记录长度探测，是为了匹配目标站点在 TLS 握手后立即发出的加密记录长度，例如会话票据，以及协商 HTTP/2 后可能发出的 SETTINGS。REALITY 启动时按 SNI 和三种 ALPN 情况探测 Caddy；后续握手读取探测结果并发送相同长度的伪装记录。这与上面的 CCS 容量探测是两项独立机制。它会增加启动时到目标站点的连接；若探测尚未结束，最初的客户端握手也可能等待。若实际探测结果为空，保留它不会发送额外的伪装记录，但仍有启动探测开销。

目前没有你的 Caddy 配置或实测记录，不能断定这项探测对你的站点多余。只有确认使用中的 SNI、ALPN 组合在握手后都不发送这类记录，才适合移除；仅凭 Caddy 使用 Go TLS 或站点由自己管理，无法得出这个结论。

## 在 macOS 手动编译

前提：已检出 Xray-core 的 `codex/caddy-reality` 分支，使用 Go 1.27 或更新版本，并能下载 `go.mod` 所列依赖。以下命令**现在执行**，工作目录为 Xray-core 仓库根目录：

```sh
go version
go mod download
go test ./transport/internet/reality ./transport/internet/tcp ./transport/internet/splithttp ./transport/internet/grpc
go build -trimpath -buildvcs=false -pgo=off -ldflags='-s -w -buildid=' -o build_assets/xray-caddy ./main
./build_assets/xray-caddy version
```

生成的 `build_assets/xray-caddy` 是本机架构的可执行文件，已被 `.gitignore` 忽略。`go list -m github.com/xtls/reality` 应显示 `=> github.com/Tozward/REALITY` 和固定的伪版本号，用于确认编译没有误用官方模块缓存。

## 同步上游与审核

**仅作说明**：将来更新时，先查看 `XTLS/Xray-core:main` 锁定的 REALITY 提交，再把这个分支同步到该提交；同步时检查 Vision 读取的 `input` 和 `rawInput` 字段布局，确认 16 条记录上限及无 CCS 探测仍成立，再推送 `codex/caddy-records-16-official-base`。然后将 Xray-core 分支与 `XTLS/Xray-core:main` 同步，把 `go.mod` 的 REALITY 伪版本更新为新提交对应的版本，运行 `go mod tidy`、测试和编译，最后推送 Xray-core 分支。两个仓库的 GitHub 比较页会分别显示各自的改动。

若上游合入 PR #40，检查 REALITY 分支和 Xray-core 私钥转换仍与上游接口兼容。更新 REALITY 版本时使用具体提交生成的伪版本，不要改为浮动分支，以保证审核结果和编译产物可复现。

Vision 通过反射偏移和 `unsafe` 读取 REALITY `Conn` 的私有 `input`、`rawInput` 字段。旧依赖 `246bd8a` 的 `rawInput` 是 `bytes.Buffer` 值；本次同步包含的上游提交 `3c98159` 将它改为可空、会在 TLS 读取时替换的 `*bytes.Buffer`。`proxy/vision_buffers.go` 同时支持值和指针布局，并在实际切换到直通时读取当前指针，避免持有已归还缓冲池的旧缓冲区。`transport/internet/reality/vision_layout_test.go` 检查固定依赖的字段类型，`proxy/vision_buffers_test.go` 验证实际 Vision 切换；测试通过也不能替代真实客户端流量与内存验证。

2026-10-15 的服务器候选使用 Go 1.27.2、`GOOS=linux`、`GOARCH=amd64`、`GOAMD64=v3`、`CGO_ENABLED=0`、默认内联和 `-pgo=off`。现有 `/Users/arthur/Downloads/default.pgo` 的内部采样时间为 2025-07-20，不能视为针对本次依赖和 Vision 路径的性能证明；旧 PGO 版本仅作实验对照。没有代表性服务器基准前，不将任何候选称为绝对最快版本。

本地 `origin` 指向各自的 Tozward fork，`upstream` 指向各自的 XTLS 仓库。Xray-core fork 原有的 `main` 未改动。

## 2026-10-17 当前策略：保持官方实现

本节替代上文关于自定义 VisionBuffers、密钥错误传播及相关测试的历史实现说明。按部署要求，当前 Xray-core 的全部 Go 源文件与 XTLS/Xray-core main `0f127f934c6d7c10e4bb6acbe98033db9e5fd922` 一致；没有额外的 Vision、SOCKS UDS 或密钥解析实现。官方已经合入私钥预解析接口和 Vision 值/指针缓冲兼容，本分支直接使用这些官方代码，不另加防护路径。

XTLS/REALITY main 当前仍为 `83f621788ca88b83179810b12baa7ae518aacb83`。定制提交 `19a3b88e5b2a38c15e7bb8dde7aa2b3defe33a38` 已包含该提交，因此固定模块版本无需改变。Tozward/REALITY 的默认 `main` 原停留在 `3c98159`，本次已快进至官方 `83f6217`；Caddy 补丁继续维护在 `codex/caddy-records-16-official-base`。

当前相对官方保留的差异仅有：

- REALITY 的连续未推进 TLS 记录上限固定为 16，移除 CCS 容量探测及动态上限，保留握手后记录长度探测。该部分涉及 `common.go`、`conn.go`、`record_detect.go`、`tls.go`。
- Xray-core 的 `go.mod` 固定引用上述 REALITY fork，`go.sum` 记录该模块校验值。
- 本文以及忽略本地工作副本的 `.gitignore` 规则；它们不改变程序运行行为。

服务器构建沿用 Go 1.27.2、`GOOS=linux`、`GOARCH=amd64`、`GOAMD64=v3`、`CGO_ENABLED=0`、`-trimpath`、`-buildvcs=false` 和官方发布使用的 `-gcflags="all=-l=4"`，PGO 输入固定为 2026-10-17 采集的 CPU profile，SHA256 为 `0beddc0d1c1bbab3ff2f60ba955a9a24ebe488bec36c3b51ef6bcf4abb326358`。该样本来自前一生产版本，属于 Go 支持的跨版本 PGO 使用方式；没有相同负载下的性能对照，不能据此断言吞吐提升或绝对最优。

质量检查采用官方格式检查、相关传输测试和 VPS 独立回环 HTTPS 传输验证。保留官方代码也会继承其限制：Vision 仍读取 TLS 私有字段，REALITY 仍有目标探测等待和畸形输入处理风险。本次不额外重写这些实现。
