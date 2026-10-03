# dsh-destinywind-computer-user

让 DSH 直接操作本机桌面（原生 [Cua Driver SDK](https://github.com/trycua/cua)），
并在 Web 设置页提供「Computer Use」权限栏目 —— 每组权限一个开关，
**永久开启只有用户在设置页操作这一条路**。

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

## 权限模型（硬性设计）

| 规则 | 说明 |
| --- | --- |
| 永久开关唯一入口 | Web 设置页「Computer Use」栏目，持久化到 `<DSH home>/destinywind-computer-user/permissions.json` |
| AI 请求未开启权限 | 当场弹窗，只有「允许（仅本次）/ 拒绝」两个选项；允许不落任何状态，下次再问 |
| 一次性允许 | 仅放行当前这一次调用，进程重启或再次调用都需要重新询问 |
| 防绕过 · 进程内门禁 | 每次工具执行前强制检查权限（模型无法伪造弹窗结果） |
| 防绕过 · 反向确认 | 修改权限的 HTTP POST 一律弹窗「是否本人操作」，AI 冒充设置页调用同样被拦 |
| 防绕过 · HMAC 签名 | 权限文件带 HMAC-SHA256 签名，密钥只在 DSH 进程内存、每次启动随机；AI 篡改文件在本进程内不生效，重启后验签失败回落默认（观察开、其余全关） |

默认仅「观察（只读）」开启；鼠标键盘、剪贴板、窗口管理、浏览器、录制回放、
会话提权、光标外观、配置写入全部默认关闭。

SDK 未来新增的未归类工具自动落入「未归类」组，默认关闭 —— 新能力默认不可用。

## HTTP API（设置页数据源）

- `GET  /dsh-destinywind-computer-user/state` — 驱动状态 + 权限快照
- `POST /dsh-destinywind-computer-user/permissions` — `{ group, enabled }`，
  必须经真人反向确认才落盘

## 已知边界（诚实声明）

HMAC 签名防「篡改内容」，不防拥有本机管理员权限的进程；AI 删除权限文件会让
插件回落默认全关（对 AI 无利）。本设计的目标是把「静默绕过」变成
「必然弹窗或必然失效」，不是密码学对抗。

## 安装

通过 GitHub 链接安装（禁止本地直接安装）：

```
dsh install <github repo url>
```
