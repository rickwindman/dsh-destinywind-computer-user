# dsh-destinywind-computer-user

让 DSH 直接操作本机桌面（原生 [Cua Driver SDK](https://github.com/trycua/cua)），
并在 Web 设置页提供「Computer Use」栏目 —— 单一总开关「允许 AI 控制电脑」，
结合会话权限分级门禁。

## 为什么重写（dsh-cua-native-enable 之死）

旧插件把官方 `@deepseek-ai/dsh-computer-use` 与
`@deepseek-ai/dsh-experimental-computer-use-cua-driver-native` 复制进 `vendor/`，
再在 `cordis.patch.yml` 里以**相对路径**加载。但 DSH 的 link-projection 模块
解析只对「按包名加载的插件」生效；相对路径加载的文件回退到 Node 原生解析，
而 `@deepseek-ai/cordis` 等宿主包只存在于 asar 内部，磁盘上不可解析 →
`MODULE_NOT_FOUND`（独立进程与宿主进程双向实测）。

本插件改为**完全自包含**：

- 唯一外部依赖是 registry 真依赖 `@trycua/cua-driver@0.28.0`（56 个桌面工具）；
- 不 import 任何未发布的 `@deepseek-ai/*` 官方包；
- 直接向宿主 `tools` 服务注册工具，占 `computerUse` 独占 provider 槽。

## 权限模型 v2.1（单总开关 + 会话权限分级 + 真人开权）

| 场景 | 行为 |
| --- | --- |
| 总开关关 | 全部 56 个工具卸载（模型不可见）；竞态兜底调用直接拒绝 —— **任何情况下都不能操控电脑** |
| 总开关开 + 完全权限会话（danger-full-access） | 直接放行，不弹窗 |
| 总开关开 + 受限会话（workspace-write / read-only） | 每次控制电脑经 DSH 原生审批通道（`ctx.approval.request`）弹审批卡；「允许」仅放行这一次调用；无审批通道 fail closed 拒绝 |

**开/关不对称（v2.1 新增，用户要求「不允许 AI 自行打开开关」）**：

- **开（放权）**：`POST {enabled:true}` 必须携带 DSH Web GUI 的浏览器签名
  cookie（HttpOnly + SameSite=Strict，宿主 `client-connection` 签发，密钥经
  DPAPI 加密落盘）——AI 的 HTTP 调用没有该 cookie，一律 403。业界同款：
  agentgate 的「agent 无 UI 凭证进不了特权通道」、Aegis 的「审批队列只有
  人类 UI 能操作」。
- **关（收权）**：保持自由，AI 可随时帮用户关闭（关闭不产生新能力）。
- 闭环：开关关时所有桌面工具已卸载，AI 没有任何桌面控制能力，不存在
  「AI 操控鼠标替自己点开关」的旁路。

- 防绕过：门禁在工具 execute 进程内强制；权限文件带 HMAC-SHA256 签名
  （密钥持久化于 `<DSH home>/destinywind-computer-user/secret.key`，重启后
  用户设置保留；验签失败一律回落默认「关」）。

## HTTP API（设置页数据源）

- `GET  /dsh-destinywind-computer-user/state` — 总开关 + 驱动状态 +
  `humanGate`（本次请求浏览器凭证诊断）
- `POST /dsh-destinywind-computer-user/permissions` — `{ enabled: true|false }`；
  `true` 需有效浏览器 cookie（否则 403），`false` 自由

## 已知边界（诚实声明）

HMAC 签名防「篡改内容」，不防拥有本机管理员权限的进程；完全权限的 AI 理论上
可读插件密钥重签状态文件、可关闭总开关。「开启」路由由宿主 DPAPI 保护的
密钥所签发的 HttpOnly cookie 把守：AI 伪造不出有效 cookie（伪造就得读取
宿主进程运行时解密后的凭证）；受限会话拿不到免弹窗能力。本设计的目标是：
关=绝对禁止、开只能由真人浏览器操作、开+完全权限=用户既有授权、开+受限=
逐次弹窗，不是密码学对抗。

## 安装

通过 GitHub 链接安装（禁止本地直接安装）：

```
dsh install <github repo url>
```
