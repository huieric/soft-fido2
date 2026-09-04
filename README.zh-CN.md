# soft-fido2-headless

[English](README.md) · [中文](README.zh-CN.md)

> **Fork 自** [`lachlan-ibm/soft-fido2`](https://github.com/lachlan-ibm/soft-fido2)（MIT 协议）。
> `upstream` 远程指向该官方项目；本 fork 保留了官方的 CTAP2/U2F 引擎，但将其重新打包为无头 Docker + USB/IP 形态。

一个**无头**的软件 FIDO2 passkey 认证器，基于官方
[`lachlan-ibm/soft-fido2`](https://github.com/lachlan-ibm/soft-fido2)（MIT）代码库，
打包为在 Docker 中以**真实 USB 设备（USB/IP）** 形式运行。

它为 IB Gateway 内嵌的 Chromium（JxBrowser）服务，使 passkey 登录无需 GUI、
无需指纹扫描器、无需实体安全密钥即可完成。

## 为什么用 USB/IP 而不是 UHID？

UHID（`/dev/uhid`）在 `/sys/devices/virtual/` 下创建一个**虚拟 HID 设备**，
**不在** USB 总线上。Chromium（以及 IB Gateway 内嵌的 Chromium）通过 libusb
在 **USB 总线**上枚举 FIDO 密钥，因此 UHID 设备对它不可见。USB/IP 把认证器
呈现为一个真实 USB 设备（`vendor/product 0x3713`），libusb 可以正常枚举。

官方项目默认使用 UHID + Qt 系统托盘 GUI。本仓库保留了官方的
CTAP2/U2F/resident-key 引擎，但以**无头 USB/IP 模式**
（`--transport usbip --no-systray`）在精简容器中运行，并打了两个小补丁，
避免在 import 时引入 PyQt6。

## 工作原理（架构）

```
┌─────────────────────────────── AWS 宿主机 ──────────────────────────────┐
│                                                                        │
│  ┌───────────────────────┐       ┌──────────────────────────────────┐  │
│  │ soft-fido2 容器        │       │ IB Gateway 容器                  │  │
│  │ (network_mode: host)  │       │ (挂载 /dev/bus/usb + hidraw)      │  │
│  │ TCP :3240 USB/IP      │       │ 内嵌 Chromium → libusb            │  │
│  └──────────┬────────────┘       └────────────────▲─────────────────┘  │
│             │  usbip attach -r 127.0.0.1 -b 1-1.1   │                 │
│             ▼               (systemd watchdog)       │                 │
│     vhci-hcd 内核模块 ────────────────────────────────┘                 │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

1. 认证器在 TCP `3240` 上作为 USB/IP *服务端* 监听。
2. 一个 systemd watchdog 单元运行 `usbip attach -r 127.0.0.1 -b 1-1.1`，
   使宿主机内核看到一个真实 USB 设备（通过 `vhci-hcd` 模块）。
3. 宿主机的 `/dev/bus/usb` 和 `/dev/hidraw*` 被 bind-mount 进 IB Gateway 容器，
   其 Chromium 就能正常枚举到虚拟密钥。

## 镜像构建（CI）

GitHub Actions 在每次 push 到 `master`/`main` 以及每个 `v*` tag 时构建并发布镜像
（`.github/workflows/docker.yml`）：

```
ghcr.io/huieric/soft-fido2:latest
```

本地构建：

```bash
docker build -t ghcr.io/huieric/soft-fido2:latest .
```

## 部署（AWS，通过 compose）

创建 `compose.yml`（示例见 `compose.yml.example`）：

```yaml
services:
  soft-fido2:
    image: ghcr.io/huieric/soft-fido2:latest
    container_name: soft-fido2
    network_mode: host          # usbip 客户端在宿主机上连接 127.0.0.1:3240
    restart: unless-stopped
    volumes:
      - soft-fido2-data:/run/fido
    environment:
      SOFT_FIDO2_PORT: "3240"

volumes:
  soft-fido2-data:
```

```bash
docker compose up -d
docker compose logs -f soft-fido2
# 期望输出："Starting the AyeBeKey Passkey USB/IP Service on port 3240"
```

> `FIDO_HOME` 目录在 entrypoint 里默认是 `/run/fido`，无需额外 env。持久化卷跨重启保留：
> - `platform.key` — 首次启动自动生成（仍被 platform-assertion 兜底使用）
> - 导入的 passkey 文件（`ibkr_passkey.txt`）

## 以宿主机 USB 设备形式自动挂载（systemd）

仓库只附带 `usbip-watchdog.service`（及其脚本 `usbip-watchdog.sh`）。它持续检查
`vhci-hcd` 挂载状态，并在重启、容器重启、USB/IP 断连或宿主机设备重置后重新挂载
——这是生产环境推荐（也是唯一）的配置。

它每 10 秒检查一次 `usbip port`，等待 Docker USB/IP 服务，执行
`usbip attach -r 127.0.0.1 -b 1-1.1`，并在每次挂载后修复 `/dev/bus/usb` 和
`/dev/hidraw*` 的权限。

> 之前的一次性 `usbip-attach.service` 和上游桌面 UHID 单元（`passkey.service`、
> `setup_uhid.sh`、`passkey.env`）已移除。只用 watchdog。

### 安装 watchdog

```bash
sudo install -m 0755 systemd/usbip-watchdog.sh /usr/local/bin/usbip-watchdog.sh
sudo install -m 0644 systemd/usbip-watchdog.service /etc/systemd/system/usbip-watchdog.service
sudo systemctl daemon-reload
sudo systemctl enable --now usbip-watchdog.service
sudo systemctl status usbip-watchdog.service
```

可选的 watchdog 环境变量：

| 变量 | 默认值 | 含义 |
|----------|---------|---------|
| `USBIP_SERVER_HOST` | `127.0.0.1` | USB/IP 服务端主机 |
| `USBIP_PORT` | `3240` | USB/IP 服务端端口 |
| `USBIP_BUSID` | `1-1.1` | 导出设备的 bus ID |
| `USBIP_CHECK_INTERVAL` | `10` | 轮询间隔（秒） |

watchdog 日志：

```bash
journalctl -u usbip-watchdog -f
```

期望消息示例：

```text
[usbip-watchdog] ... started (...)
[usbip-watchdog] ... attached 1-1.1
```

验证：

```bash
usbip port          # 应显示 "Port 00: <Port in Use>"，vendor 3713
lsusb -v -d 3713:3713
```

## 把设备暴露给 IB Gateway

虚拟密钥出现在宿主机的 `/dev/bus/usb` 和 `/dev/hidraw*`。把它们 bind-mount 进
IB Gateway 容器并允许对应的设备主设备号：

```yaml
# 在 ibga 的 compose.yml 里
services:
  my-ibga:
    volumes:
      - /dev/bus/usb:/dev/bus/usb
    device_cgroup_rules:
      - 'c 189:* rwm'          # USB 主设备号
      # - 'c 239:* rwm'        # hidraw 主设备号（内核相关；AWS 6.8 上是 239）
```

## 首次 passkey 配置（导入 Bitwarden 凭据）

IBKR 对 `getAssertion` 强制执行严格的 `allowList`：认证器只能返回列表中的凭据 ID。
该列表由**浏览器在本地**检查（服务端还会再查一次），无法绕过——你无法用 IBKR 未
发给该账户的凭据登录。

因此可靠路径是：

1. 在 Bitwarden 里为你的 IBKR 账户注册一个**新 passkey**（浏览器扩展拦截
   WebAuthn 调用并以 `none` attestation 注册，IBKR 接受软件/同步 passkey 的这种方式）。
2. 用 `bwu fido2 get "<entry>"` 导出该 passkey，保留原始的 `key: value` 文本输出
   （无需转 JSON）。
3. 把导出的文件（可多个）挂载进容器，将 `SOFT_FIDO2_IMPORT_DIR` 指向目录
   （或用 `SOFT_FIDO2_IMPORT_FILE` 指向单文件 / 逗号分隔列表）。见下文。

认证器的 `_parse_import_file` 读取每个 `key: value` 块（含内嵌 PEM 私钥），把带连字符
的 `credentialId` 解码为 16 字节，并仅当凭据出现在 IBKR 的 `allowList` 中时才签名
`getAssertion`。

**多 passkey / 多账户**：soft-fido2 可以用一个认证器服务多个 IBKR 账户。为每个账户
放一个 `bwu fido2 get` 导出文件到某个目录，并把 `SOFT_FIDO2_IMPORT_DIR` 指向该目录。
每次 `getAssertion` 时，它会选取 `rpId` 匹配且 id 在该账户 `allowList` 中的那个导入凭据。

```yaml
services:
  soft-fido2:
    image: ghcr.io/huieric/soft-fido2:latest
    volumes:
      - ./passkeys:/run/fido/passkeys:ro   # 每个 IBKR 账户一个文件
    environment:
      SOFT_FIDO2_IMPORT_DIR: /run/fido/passkeys
```

导入文件格式是 `bwu fido2 get` 的原文：

```
name: example-ibkr
credentialId: 01234567-89ab-cdef-0123-456789abcdef
rpId: interactivebrokers.com.hk
userHandle: <redacted>
keyType: public-key
keyCurve: P-256
privateKey (base64url): <redacted>
-----BEGIN PRIVATE KEY-----
<redacted>
-----END PRIVATE KEY-----
```

旧的 JSON 形式（`credentialId`、`rpId`、`userHandle`、`privateKeyPem`）仍被接受。
完整的端到端部署记录和走过的弯路见 [`docs/IBKR-UNATTENDED.md`](docs/IBKR-UNATTENDED.md)。

## 配置

| 环境变量 | 默认值 | 用途 |
|---------|---------|---------|
| `SOFT_FIDO2_PORT` | `3240` | USB/IP 服务端端口 |
| `SOFT_FIDO2_SKIP_UP` | `true` | 跳过 user-presence 检查（无头） |
| `SOFT_FIDO2_IMPORT_DIR` | *(未设置)* | 导入的 `bwu fido2 get` passkey 文件目录（每个账户一个文件） |
| `SOFT_FIDO2_IMPORT_FILE` | *(未设置)* | 单个导入 passkey 文件，或逗号分隔的文件列表 |
| `SOFT_FIDO2_DEBUG_LEVEL` | `INFO` | 日志级别 |
| `SOFT_FIDO2_LOG_FILE` | *(stdout)* | 相对 `FIDO_HOME` 的日志文件路径 |

## 分支

- `master` — 唯一维护的分支；本文档描述的 headless USB/IP 构建。

## 许可证

MIT，遵循上游 `lachlan-ibm/soft-fido2` 项目。
