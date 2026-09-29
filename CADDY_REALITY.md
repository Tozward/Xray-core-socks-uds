# 面向 Go/Caddy 目标站点的 REALITY 构建分支

为便于在 GitHub 分别审核，改动分布在两个公开 fork 的分支中：

| 仓库与分支 | 内容 |
| --- | --- |
| [Tozward/REALITY `codex/caddy-records-16`](https://github.com/Tozward/REALITY/tree/codex/caddy-records-16) | 基于 XTLS/REALITY main，合入 [PR #40](https://github.com/XTLS/REALITY/pull/40)，并应用 Caddy 目标站点补丁。 |
| [Tozward/Xray-core-socks-uds `codex/caddy-reality`](https://github.com/Tozward/Xray-core-socks-uds/tree/codex/caddy-reality) | 基于 XTLS/Xray-core main，适配 PR #40 的私钥接口，并在 `go.mod` 中固定引用上述 REALITY 分支的具体提交。 |

Xray-core 的 `go.mod` 使用远端 `replace`。编译时无需手动克隆 REALITY；`.local/reality` 是当前机器上用于维护库补丁的独立工作副本，不属于 Xray-core 提交。

## 定制内容

- REALITY 的 `maxUselessRecords` 固定为 16，与本机 Go 1.27.1 的 `crypto/tls` 一致；移除按目标探测 CCS 容量的额外连接、探测报文和动态上限。握手后记录长度探测仍保留。
- PR #40 将 REALITY 的 `Config.PrivateKey` 改为 `*ecdh.PrivateKey`。Xray-core 在启动监听时解析一次；无效私钥会报错。
- 这些修改针对由 Go `crypto/tls` 提供 TLS 的 Caddy 目标。若目标站点实际使用另一种 TLS 栈，先核实其记录行为再复用此分支。

## 在 macOS 手动编译

前提：已检出 Xray-core 的 `codex/caddy-reality` 分支，使用 Go 1.27 或更新版本，并能下载 `go.mod` 所列依赖。以下命令**现在执行**，工作目录为 Xray-core 仓库根目录：

```sh
go version
go mod download
go test ./transport/internet/reality ./transport/internet/tcp ./transport/internet/splithttp ./transport/internet/grpc
go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o build_assets/xray-caddy ./main
./build_assets/xray-caddy version
```

生成的 `build_assets/xray-caddy` 是本机架构的可执行文件，已被 `.gitignore` 忽略。`go list -m github.com/xtls/reality` 应显示 `=> github.com/Tozward/REALITY` 和固定的伪版本号，用于确认编译没有误用官方模块缓存。

## 同步上游与审核

**仅作说明**：将来更新时，先在 REALITY 工作副本中同步 `XTLS/REALITY:main`，解决冲突并确认 16 条记录上限及无 CCS 探测仍成立，再推送 `codex/caddy-records-16`。然后将 Xray-core 分支与 `XTLS/Xray-core:main` 同步，把 `go.mod` 的 REALITY 伪版本更新为新提交对应的版本，运行 `go mod tidy`、测试和编译，最后推送 Xray-core 分支。两个仓库的 GitHub 比较页会分别显示各自的改动。

若上游合入 PR #40，检查 REALITY 分支和 Xray-core 私钥转换仍与上游接口兼容。更新 REALITY 版本时使用具体提交生成的伪版本，不要改为浮动分支，以保证审核结果和编译产物可复现。

本地 `origin` 指向各自的 Tozward fork，`upstream` 指向各自的 XTLS 仓库。Xray-core fork 原有的 `main` 未改动。
