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

## 权限模型 v2（单总开关 + 会话权限分级）

| 场景 | 行为 |
| --- | --- |
| 总开关关 | 全部 56 个工具卸载（模型不可见）；竞态兜底调用直接拒绝 —— **任何情况下都不能操控电脑** |
| 总开关开 + 完全权限会话（danger-full-access） | 直接放行，不弹窗 |
| 总开关开 + 受限会话（workspace-write / read-only） | 每次控制电脑经 DSH 原生审批通道（`ctx.approval.request`）弹审批卡；「允许」仅放行这一次调用；无审批通道 fail closed 拒绝 |

- 总开关 AI 也可以改（HTTP 直接落盘，不弹窗）：因为它不构成提权 —— AI 打开
  开关后受限会话依然逐次弹审批，改开关拿不到任何额外能力。
- 防绕过：门禁在工具 execute 进程内强制；权限文件带 HMAC-SHA256 签名
  （密钥持久化于 `<DSH home>/destinywind-computer-user/secret.key`，重启后
  用户设置保留；验签失败一律回落默认「关」）。

## HTTP API（设置页数据源）

- `GET  /dsh-destinywind-computer-user/state` — 总开关 + 驱动状态
- `POST /dsh-destinywind-computer-user/permissions` — `{ enabled: true|false }`，
  直接落盘（无需反向确认，见上）

## 已知边界（诚实声明）

HMAC 签名防「篡改内容」，不防拥有本机管理员权限的进程；完全权限的 AI 理论上
可读密钥重签、也可直接改总开关 —— 但完全权限本身即用户授予的全权，且改开关
在受限会话拿不到免弹窗能力。本设计的目标是：关=绝对禁止、开=受限会话逐次
弹窗、完全权限=用户既有授权，不是密码学对抗。

## 安装

通过 GitHub 链接安装（禁止本地直接安装）：

```
dsh install <github repo url>
```
