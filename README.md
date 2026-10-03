# dsh-destinywind-computer-user

一个 [DSH](https://github.com/deepseek-ai/dsh)（DeepSeek Harness）插件：让 AI
直接操作你的电脑桌面 —— 截屏、移动鼠标、点击、打字、管理窗口等
**56 个桌面工具**，底层是原生 [Cua Driver SDK](https://github.com/trycua/cua)。

同时在 Web 设置页提供「Computer Use」栏目：**一个总开关**，决定 AI 能不能用
这些能力。设计的核心目标：

> **开关关 = AI 在任何情况下都不能操控电脑；开关开 = 也只有你能打开它。**

---

## ✨ 功能一览

- **56 个桌面操作工具**（全部带 `computer_use__` 前缀）：截屏、获取桌面状态
  （可访问性树）、列出应用与窗口、鼠标移动/单击/双击/右键/拖拽、键盘输入、
  快捷键、滚动、等待、剪贴板等；
- **设置页单总开关**「允许 AI 控制电脑」，一个按钮，无需配置任何权限组；
- **会话权限分级门禁**：同一开关下，AI 在不同权限等级的会话里获得不同的
  放行策略（见下表）；
- **只有你能打开开关**（v2.1）：开启操作被浏览器登录凭证把守，AI 无法自行
  开启 —— 这是本插件与一般「开关」最大的区别；
- **持久化**：开关状态 HMAC-SHA256 签名落盘，重启保留；篡改一律回落「关」。

---

## 📦 安装

在 DSH 中通过 GitHub 链接安装（请勿本地直接安装）：

```
dsh install https://github.com/rickwindman/dsh-destinywind-computer-user
```

安装后重启 DSH，打开 Web 设置页 → 「Computer Use」栏目即可看到开关。

**要求**：Node.js ≥ 22.5；Windows / macOS（Cua Driver 支持的平台）。

---

## 🔐 权限模型（v2.1）

### 一张表看懂

| 总开关 | 会话权限等级 | AI 能否操控电脑 | 说明 |
| :---: | :---: | :---: | --- |
| 关 | 任何 | ❌ 绝对不能 | 56 个工具**全部卸载**（模型根本看不见）；竞态兜底调用也直接拒绝 |
| 开 | 完全权限（danger-full-access） | ✅ 直接执行 | 你授予该会话全权，不再逐次打扰 |
| 开 | 工作区读写（workspace-write） | ⚠️ 每次弹审批卡 | 每次控制电脑都经 DSH 原生审批通道向你请求；「允许」**仅放行这一次**，不落任何持久状态 |
| 开 | 只读（read-only） | ⚠️ 每次弹审批卡 | 同上 |
| 开 | 无审批通道 | ❌ 拒绝 | fail closed：审批服务不可用 / 请求不来自 agent 会话时，一律拒绝而非放行 |

### 为什么「关」是绝对的？

关闭开关时，插件不只是「拒绝调用」，而是把全部工具从 AI 的工具列表里
**卸载**——AI 连这些工具的存在都感知不到，自然也无法调用。即便 AI 手里还
握着卸载前抓到的旧工具引用（极端竞态），工具执行入口的门禁仍会兜底拒绝。
这一层在插件进程内强制，改内存、改文件都绕不过。

### 开 / 关不对称：只有你能打开（v2.1 核心特性）

普通插件的「开关」AI 也能改——本插件明确禁止这一点：

| 操作 | 谁可以 | 怎么做到的 |
| --- | --- | --- |
| **打开开关**（放权） | **只有你**，在浏览器设置页点击 | 浏览器访问 DSH Web GUI 时自动携带宿主签发的 **HttpOnly + SameSite=Strict 登录 cookie**；插件的「开启」接口强制校验该 cookie。AI 发起的 HTTP 请求没有这个 cookie（它不是浏览器），一律 **403** |
| **关闭开关**（收权） | 你 **或 AI** 都可以 | 关闭不产生任何新能力，反而立即收回全部桌面权限——所以保持自由，AI 也可以在你要求时帮你「紧急止损」 |

**为什么 AI 伪造不出有效 cookie？** 签名密钥由 DSH 宿主的凭证服务管理并经
操作系统 **DPAPI** 加密落盘，只有宿主进程能解密。AI 要伪造 cookie，就得先
读出宿主进程运行时解密后的密钥——这不是改个文件能做到的。

**旁路也堵死了**：开关关闭时 AI 没有任何桌面控制能力，所以不存在
「AI 操控鼠标替自己点开设置页」的循环旁路；而开关开启后 AI 能点「关闭」，
关闭只是收权，不构成新风险。

这套「agent 没有 UI 凭证就进不了特权通道」的设计，与 agentgate（写操作必须
真人批准）、Aegis（审批队列只有人类 UI 能操作）等业界项目的思路一致。

### 状态持久化与防篡改

- 开关状态保存在 `<DSH home>/destinywind-computer-user/permissions.json`，
  内容为 `{ version, enabled, mac }`，其中 `mac` 是整包内容的 HMAC-SHA256
  签名（密钥持久化于同目录 `secret.key`，0600 权限）；
- 重启后你的设置保留；
- 文件被手工篡改（改 `enabled` 不重算 `mac`）→ 验签失败 → **回落默认「关」**
  ——出错时永远偏向更安全的一侧。

---

## 🖥️ 使用

1. 安装并重启 DSH；
2. 打开 Web 设置页 → 「Computer Use」→ 打开「允许 AI 控制电脑」
   （**这一步必须由你在浏览器里完成**）；
3. 按你给的会话权限等级工作：
   - 完全权限会话里，AI 可直接调用 `computer_use__*` 工具；
   - 受限会话里，AI 每次要操作桌面都会弹出审批卡，你点「允许」放行这一次；
4. 想立即收回全部权限 → 关闭开关（或让 AI 帮你关）。

> 提示：AI 操作桌面时建议让它「先观察再行动」——用
> `computer_use__get_desktop_state` / `computer_use__list_windows` 拿最新
> 快照定位元素，操作后重新观察核验。插件已把这条规则写进系统提示。

---

## 🔌 HTTP API（设置页数据源，也可脚本调用）

| 接口 | 方法 | 说明 |
| --- | --- | --- |
| `/dsh-destinywind-computer-user/state` | GET | 开关状态、驱动状态（是否就绪/工具数/错误）、`humanGate` 本次请求浏览器凭证诊断 |
| `/dsh-destinywind-computer-user/permissions` | POST | 请求体 `{"enabled": true|false}`。`true` 必须携带有效浏览器 cookie（否则 403）；`false` 自由 |

`humanGate` 字段示例（AI 请求）：

```json
{
  "ok": true,
  "enabled": false,
  "humanGate": {
    "active": false,
    "message": "浏览器凭证校验失败（AI 或未认证请求；开启总开关将被拒绝）"
  },
  "driver": { "ready": true, "toolCount": 56, "error": null }
}
```

---

## 🧱 技术实现要点（给想读源码的人）

- **完全自包含**：唯一外部依赖是 npm registry 上的
  `@trycua/cua-driver@0.28.0`；不 import 任何未发布的 `@deepseek-ai/*`
  宿主包（宿主服务一律通过 cordis `ctx.get()` 动态访问）。
  这是有教训的：旧插件（dsh-cua-native-enable）把官方包复制进 `vendor/`
  以相对路径加载，而 DSH 的 link-projection 模块解析只对「按包名加载的
  插件」生效，相对路径回退 Node 原生解析时 `@deepseek-ai/cordis` 只存在于
  asar 内部 → `MODULE_NOT_FOUND`（独立进程与宿主进程双向实测后放弃）。
- **provider 槽**：向宿主 `computerUse` 服务注册
  `destinywind-computer-user` provider，独占该槽。
- **注入的服务**：`tools` / `webServer` / `systemPrompt` / `sandboxPolicy`
  / `credentials`（v2.1 新增，读取浏览器会话签名密钥）。
- **门禁位置**：每个工具的 `execute` 入口（进程内强制）→ 检查总开关 →
  `sandboxPolicy.resolve()` 判会话权限 → 受限时走
  `ctx.get('approval').request()` 弹 DSH 原生审批卡，仅
  `allowed-once` 放行。
- **浏览器 cookie 校验**：在插件内复刻宿主 `client-connection` 的验签算法
  （cookie 名 `dsh-auth-` + base64url(sha256(authority))，值
  `v1.<payload>.<HMAC-SHA256>`），密钥经宿主 `credentials` 服务读取
  （`client-connection/browser-session` 记录）。不 import 宿主包，只复刻
  算法 + 共享密钥，因此宿主升级签名算法时本插件需要跟随更新。
- **懒加载**：Cua Driver 在首次访问设置页/首次开启时才在后台加载
  （8 秒延迟定时器合并冷启动流量），加载失败可重试，不阻塞 DSH 启动。

---

## ⚠️ 已知边界（诚实声明）

本插件做的是**工程防护**，不是密码学对抗：

- 拥有本机管理员权限的进程可以绕过一切（改文件、读内存、调试宿主进程）；
- 完全权限的 AI 理论上可以读插件密钥重签状态文件、可以**关闭**总开关
  （关闭是允许的）；
- 但「**打开**」这条路由由宿主 DPAPI 保护的密钥签发的 HttpOnly cookie
  把守，AI 伪造不出有效 cookie；
- cookie 验签算法是复刻的：若未来 DSH 宿主变更签名算法，本插件需要
  跟随更新（状态字段 `humanGate` 会在浏览器请求也校验失败时如实呈现，
  方便发现）；
- Windows 更新、杀毒软件或系统策略变化可能影响 Cua Driver 的可用性，
  驱动状态可在设置页查看（就绪/工具数/错误信息）。

**设计目标一句话**：关 = 绝对禁止；开 = 只能由真人浏览器打开；开 + 完全
权限 = 你授予的全权；开 + 受限 = 逐次弹窗。超出这个目标的对抗（内核级
rootkit、有管理员权限的恶意进程）不在防护范围内。

---

## 📜 版本历史

| 版本 | 要点 |
| --- | --- |
| v2.1.0 | 「不允许 AI 自行打开开关」：开启需浏览器登录凭证（HttpOnly cookie），AI 一律 403；关闭保持自由；`humanGate` 诊断字段；79 项离线契约测试 |
| v2.0.0 | 废除 11 权限组，改单总开关 + 会话权限分级门禁（完全权限直通 / 受限逐次弹审批卡 / 关=绝对禁止）；59 项测试 |
| v1.x | 11 组权限表 + 设置页确认弹窗（已废弃） |

## 📄 许可

MIT
