# IBKR 无人值守 Passkey 登录 — 完整旅程与结论

本文档记录在 AWS 上打通 **IB Gateway 无人值守 passkey 登录** 的完整过程、
踩过的坑、以及最终的工程结论。目标读者是后续维护这套系统的人。

## 1. 最终架构（已跑通）

```
┌─────────────────────────────── AWS host ───────────────────────────────┐
│                                                                        │
│  soft-fido2 容器                IB Gateway 容器 (ibga)                  │
│  (network_mode: host)           (挂载 /dev/bus/usb + /dev/hidraw*)      │
│  软件认证器 + 导入的私钥         内嵌 Chromium (JxBrowser)               │
│  TCP :3240 USB/IP server ─────▶ libusb 枚举到真实 USB 设备              │
│                                      │                                  │
│                                自动点击 Authenticate (xdotool/JAuto)     │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

- **认证器**：`huieric/soft-fido2`，导入 Bitwarden 导出的 passkey 私钥，
  经 USB/IP 呈现为宿主机上的真实 USB 设备（`vendor/product 0x3713`）。
- **点击器**：`huieric/ibga-docker`，`PASSKEY_ENABLED=1` 时自动点击
  Authenticate 按钮。
- **为什么 USB/IP 而非 UHID**：IB Gateway 的 passkey 界面跑在内嵌 Chromium
  里，用 libusb 枚举 **USB 总线** 上的 FIDO 密钥；`/dev/uhid` 造出的虚拟 HID
  设备不在 USB 总线上，Chromium 看不到。

## 2. 核心结论：allowList 是浏览器强制执行的

这是整条路上最重要的一条结论，直接决定了方案走向。

IBKR 下发的 `getAssertion` 请求里带一个 `allowList`（允许的凭据 ID 列表）。
**这个列表是被浏览器（Chromium/Firefox/JxBrowser）在本地强制校验的**，而
不只是服务端验签：

- 认证器返回的凭据 ID **必须在 allowList 里**，否则浏览器直接丢弃响应、
  抛 `SecurityError`，请求**根本到不了服务端**。
- 想用 `IGNORE_ALLOWLIST` 之类的环境变量让认证器"强行返回列表外凭据"是
  **无效的**——浏览器那一关过不去。

这意味着：**不能用别处注册的凭据来登录**。凭据必须是 IBKR 账户名下注册的
那个，且其 credential ID 会出现在 allowList 里。

## 3. 走过的弯路（按时间序）

1. **传输层 bug 连环修**：字节序、单帧判定（exact-fit）、U2F 跨帧重组
   （`bcnt=73`）、多帧响应饿死（`response_ready` 缺失）、`colour_print`
   只输出 DEBUG 导致盲排。教训：**诊断日志必须 INFO 级别**，否则 headless
   环境完全无法定位问题。

2. **PIN 对话框无法驱动**：JxBrowser 内嵌的 Chromium PIN 输入框不接收
   X11 键盘事件（noVNC 手动输入也失败，抓屏 OCR 确认对话框超时死掉）。
   教训：**不要试图自动化驱动 Chromium 的 PIN 弹窗**。

3. **切换到内置 UV 模式**：`getInfo` 广告 `{'rk': True, 'up': True,
   'uv': True, 'plat': False}`（无 `clientPin`），`SOFT_FIDO2_SKIP_UP=true`
   缓存 "verified" 状态，绕过 PIN。UV 协商成功，`getAssertion` 到达。

4. **凭据不匹配（关键卡点）**：IBKR 下发的 allowList 只含 Windows Hello 凭据
   `1024xxxx...`，而本地的 Bitwarden 凭据 `b09axxxx...` 不在列表里 →
   `NO_CREDENTIALS` → "Try a different security key"。

5. **试图强行返回 Bitwarden 凭据**：加了 `SOFT_FIDO2_IMPORT_IGNORE_ALLOWLIST`
   让认证器无视 allowList 签名。结果：同一 challenge 被重试 3 次（浏览器
   本地拒绝），登录仍失败。确认了结论 2。

6. **尝试用 Firefox/Chromium 直接在 soft-fido2 上注册新凭据**：
   - Firefox 严格 enforce `transports:["internal"]`，不把请求路由到 USB 设备
   - Marionette 自动化模式下 WebAuthn 被禁用（`SecurityError: insecure`）
   - rpId `interactivebrokers.com.hk` 与页面 origin `ndcdyn.interactivebrokers.com`
     不匹配 → 域名后缀校验失败

## 4. 最终解决方案（跑通）

**在 Bitwarden 里为 IBKR 账户注册一个新 passkey，导出，导入 soft-fido2。**

1. 在 Client Portal 用 Bitwarden 浏览器扩展注册新 passkey。IBKR 接受
   `none` attestation（软件/同步 passkey 的合法路径）。
2. 用 `bwu fido2 get "<entry>"` 导出，**保留原始 `key: value` 文本格式**
   （不用转 JSON）。
3. 挂载该文件到 soft-fido2，设置 `SOFT_FIDO2_IMPORT_FILE`。认证器解析
   `key: value` 文本（含内嵌 PEM 私钥），把带连字符的 `credentialId` 解码为
   16 字节，凭据出现在 allowList 里时签名 `getAssertion`。
4. 新凭据 `01234567-89ab-cdef-0123-456789abcdef` 现在出现在 allowList 里 →
   严格匹配 → 签名 → 登录成功。

验证标志（IB Gateway 日志）：
```
Passed session token authentication
Authenticated via ccp conman
Connected to cdc1.ibllc.com:4000
```

## 5. 关键教训清单

| 教训 | 说明 |
|------|------|
| allowList 浏览器强制执行 | 返回列表外凭据必失败，无法绕过 |
| 凭据必须账户绑定 | 只有 IBKR 账户名下注册的凭据才在 allowList 里 |
| Bitwarden 用 `none` attestation | 软件 passkey 合法，IBKR 接受 |
| rpId 必须匹配页面 origin | `.com.hk` 的 rpId 只能在 `.com.hk` 域上验证 |
| Marionette 禁用 WebAuthn | 自动化协议下 Firefox 拒绝凭据操作 |
| Firefox enforce `transports` | 只接受平台认证器时不路由到 USB |
| 诊断日志 INFO 级别 | headless 环境唯一排障手段 |
| 不要自动化 PIN 弹窗 | X11 键盘事件进不了 Chromium HTML 输入框 |

## 6. 凭据文件格式（`bwu fido2 get` 原文）

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

`soft_fido2/ctap_interface.py` 的 `_parse_import_file` 同时兼容此格式和旧
JSON 格式（`credentialId`/`rpId`/`userHandle`/`privateKeyPem` 字段）。
