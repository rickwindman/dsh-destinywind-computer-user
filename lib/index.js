/**
 * Host half：Computer Use —— 让模型直接操作本机桌面（原生 Cua Driver SDK）。
 *
 * 与 dsh-cua-native-enable 的关键差别（那个插件已废弃）：
 *   它把官方两个 computer-use 包放在 vendor/ 里、以「相对路径」加载，而 DSH 的
 *   link-projection 模块解析只对「包名加载」生效，vendor 产物里的
 *   `import "@deepseek-ai/cordis"` 必然 MODULE_NOT_FOUND（独立进程与宿主进程
 *   双向实测）。本插件完全自包含：只依赖 registry 真依赖 @trycua/cua-driver，
 *   与宿主服务 tools / webServer / systemPrompt / sandboxPolicy / approval，
 *   不 import 任何未发布的 @deepseek-ai 官方包。
 *
 * 权限模型 v2（2026-10 与用户确认的重构版）：
 *   1. 设置页只有一个总开关「允许 AI 控制电脑」（默认关），持久化到
 *      <DSH home>/destinywind-computer-user/permissions.json（HMAC 签名）。
 *      总开关 AI 也可以改（HTTP 直接落盘，不弹窗）——因为它不构成提权：
 *      AI 把开关打开后，受限会话里每次控制电脑依然要弹审批卡（见 2），
 *      所以改开关拿不到任何额外能力；而"关"时是绝对禁止。
 *   2. 运行时门禁（工具 execute 进程内强制，改文件/改内存都绕不过）：
 *      - 总开关关：所有 Computer Use 工具一律卸载（模型不可见）；兜底调用
 *        直接拒绝 —— 任何情况下都不能操控电脑。
 *      - 总开关开 + 会话完全权限（danger-full-access）：直接放行，不弹窗。
 *      - 总开关开 + 受限会话（workspace-write / read-only）：每次控制电脑
 *        通过 DSH 原生审批通道（ctx.approval.request）向用户弹一次审批卡；
 *        「允许」仅放行这一次调用，不落任何持久状态；无审批通道时
 *        fail closed 拒绝。
 *   3. 持久化防护：状态文件带 HMAC-SHA256 签名，密钥持久化于同目录
 *      secret.key。有限权限（沙箱/只读）下 AI 无法伪造；完全权限下伪造
 *      需要读密钥并正确重算 HMAC，难度显著增加。验签失败或损坏一律回落
 *      默认（关）。
 *
 * 已知边界（诚实声明）：不做绝对安全承诺——完全权限的 AI 理论上可读密钥
 * 重签、也可直接改总开关。但按上述模型，改开关在受限会话拿不到免弹窗能力，
 * 完全权限会话本身即用户授予的全权。这里要达到的效果是：关=绝对禁止、
 * 开=受限会话逐次弹窗、完全权限=用户既有授权。
 *
 * @module dsh-destinywind-computer-user
 */

import { createHmac, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const name = 'dsh-destinywind-computer-user';
export const inject = ['tools', 'webServer', 'systemPrompt', 'sandboxPolicy'];

const ROUTE = '/dsh-destinywind-computer-user';
const TOOL_PREFIX = 'computer_use__';
const PROVIDER_NAME = 'destinywind-computer-user';
const OUTPUT_LIMIT = 60000;
const BODY_LIMIT = 256 * 1024;

/* ----------------------- 权限存储（HMAC 签名，v3 单开关） ----------------------- */

function resolveHome() {
  const fromEnv = typeof process.env.DSH_HOME === 'string' ? process.env.DSH_HOME.trim() : '';
  if (fromEnv) return fromEnv;
  return path.join(os.homedir(), '.dsh');
}

/**
 * 签名密钥持久化在 <DSH home>/destinywind-computer-user/secret.key：
 *   - 用户合法保存的设置重启后验签通过，永久生效（设置绝对生效）。
 *   - 有限权限（沙箱/只读）下 AI 写不了本目录 → 无法伪造。
 *   - 完全权限（全盘可写）下伪造需要读密钥 + 正确重算 HMAC-SHA256 +
 *     拼对格式，伪造难度显著增加（不做绝对安全承诺）。
 *   - 验签失败或损坏一律回落默认（关）。
 */
function loadOrCreateSigningKey(dir) {
  const keyFile = path.join(dir, 'secret.key');
  try {
    if (existsSync(keyFile)) {
      const raw = readFileSync(keyFile);
      if (raw.length >= 32) return raw.subarray(0, 64);
    }
  } catch { /* 读失败走重建 */ }
  const key = randomBytes(64);
  try {
    mkdirSync(dir, { recursive: true });
    writeFileSync(keyFile, key, { mode: 0o600 });
  } catch { /* 密钥写盘失败：退化为内存密钥（本进程内仍可签验） */ }
  return key;
}

function signState(enabled, key) {
  return createHmac('sha256', key).update(JSON.stringify(enabled)).digest('hex');
}

function createPermissionStore() {
  const dir = path.join(resolveHome(), 'destinywind-computer-user');
  const file = path.join(dir, 'permissions.json');
  const signingKey = loadOrCreateSigningKey(dir);
  let enabled = false; // 默认关：未开启 = 任何情况都不能控制电脑

  // 启动时读盘并验签；验签失败或损坏一律回落默认（关）。
  try {
    if (existsSync(file)) {
      const parsed = JSON.parse(readFileSync(file, 'utf8'));
      const body = parsed && typeof parsed === 'object' ? parsed.enabled : undefined;
      const mac = parsed && typeof parsed === 'object' ? parsed.mac : undefined;
      if (typeof body === 'boolean' && typeof mac === 'string'
        && signState(body, signingKey) === mac) {
        enabled = body;
      }
    }
  } catch {
    enabled = false;
  }

  function persist() {
    try {
      mkdirSync(dir, { recursive: true });
      writeFileSync(file, JSON.stringify({ version: 3, enabled, mac: signState(enabled, signingKey) }, null, 2), 'utf8');
      return true;
    } catch {
      return false;
    }
  }

  return {
    file,
    get enabled() { return enabled === true; },
    /** 设置页与 AI 的 HTTP 修改都走这里：直接落盘，不弹窗（v2 模型：改开关不构成提权）。 */
    set(value) {
      enabled = value === true;
      return persist();
    },
  };
}

/* ------------------------------ 驱动管理 ------------------------------ */

function createDriverManager() {
  const lifetime = new AbortController();
  let driver = null;
  let catalog = null;
  let error = null;
  let readyPromise = null;

  async function load() {
    const mod = await import('@trycua/cua-driver');
    const active = mod.CuaDriver.create(undefined);
    // 注意：listToolsJson / callTool 的 asyncOpts.signal 必须是真 AbortSignal，
    // 传 { signal: undefined } 会触发 @ubjs/core 的 `signal.aborted` TypeError。
    const raw = await active.listToolsJson({ signal: lifetime.signal });
    const parsed = JSON.parse(raw);
    const tools = Array.isArray(parsed?.tools) ? parsed.tools : [];
    driver = active;
    catalog = tools;
    return tools;
  }

  return {
    get driver() { return driver; },
    lifetime,
    status() {
      return {
        ready: driver !== null,
        toolCount: catalog ? catalog.length : 0,
        error: error === null ? null : String(error?.message ?? error),
      };
    },
    ensure() {
      if (readyPromise === null) {
        readyPromise = load().catch((err) => {
          error = err;
          // 失败后清空：下次 ensure()（HTTP 访问/开关变更/下一轮懒加载定时器）可重试。
          readyPromise = null;
          throw err;
        });
      }
      return readyPromise;
    },
    async dispose() {
      lifetime.abort();
      const active = driver;
      driver = null;
      if (active) {
        try { await active.shutdown(); } catch { /* 关闭失败不影响卸载 */ }
        try { active.uniffiDestroy(); } catch { /* 同上 */ }
      }
    },
  };
}

/* ------------------------------ 工具渲染辅助 ------------------------------ */

function renderValue(value) {
  let text;
  try {
    text = JSON.stringify(value, null, 2) ?? 'null';
  } catch {
    text = String(value);
  }
  if (text.length > OUTPUT_LIMIT) {
    text = `${text.slice(0, OUTPUT_LIMIT)}\n…（输出截断，原文 ${text.length} 字符）`;
  }
  return text;
}

function describeResult(value) {
  // cua 工具结果里常见 { status / ok / success / error } 形态，取一句话给模型。
  if (value && typeof value === 'object') {
    const status = value.status ?? value.state ?? value.kind;
    const ok = value.ok ?? value.success;
    if (typeof value.error === 'string' && value.error) return `失败：${value.error}`;
    if (ok === false) return '执行完成（结果标记为未成功，请核验）。';
    if (typeof status === 'string') return `执行完成（${status}）。`;
  }
  return '执行完成。';
}

/* ------------------------------ HTTP 处理器 ------------------------------ */

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > BODY_LIMIT) {
        reject(new Error('请求体过大'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

/**
 * @param {object} deps
 * @param {ReturnType<createPermissionStore>} deps.permissions
 * @param {ReturnType<createDriverManager>} deps.manager
 * @param {() => void} deps.ensureDriver 懒加载触发器（GET state / POST 时调用）
 * @param {(message: string) => void} deps.log
 */
function makeHandler({ permissions, manager, ensureDriver, log }) {
  const json = (res, status, body) => {
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(body));
  };

  function snapshot() {
    return {
      ok: true,
      enabled: permissions.enabled,
      driver: manager.status(),
      file: permissions.file,
    };
  }

  return async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://dsh');
    const parts = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);
    if (parts[0] === 'dsh-destinywind-computer-user') parts.shift();
    try {
      if (req.method === 'GET' && parts[0] === 'state') {
        ensureDriver(); // 懒加载触发：首次访问即开始加载驱动（幂等，后台进行）
        return json(res, 200, snapshot());
      }

      // 修改总开关：不弹窗直接落盘（v2 模型——改开关不构成提权，见头注释 1）。
      if (req.method === 'POST' && parts[0] === 'permissions') {
        const body = JSON.parse((await readBody(req)) || '{}');
        if (typeof body.enabled !== 'boolean') {
          return json(res, 400, { ok: false, error: '请求体必须为 {"enabled": true|false}' });
        }
        const persisted = permissions.set(body.enabled);
        ensureDriver(); // 开关变更：确保工具挂载跟上（幂等）
        log(`Computer Use 总开关变更为 ${body.enabled ? '开' : '关'}（落盘：${persisted ? '是' : '否'}）`);
        return json(res, 200, { ok: persisted, snapshot: snapshot(), persisted });
      }

      return json(res, 404, { ok: false, error: '未知接口' });
    } catch (error) {
      return json(res, 500, { ok: false, error: String(error?.message ?? error) });
    }
  };
}

/* ------------------------------ apply ------------------------------ */

export function apply(ctx, config = {}) {
  const permissions = createPermissionStore();
  const manager = createDriverManager();
  const toolDisposers = [];
  const log = (message) => {
    try {
      const logger = ctx.get('logger');
      logger?.warn?.(`dsh-destinywind-computer-user: ${message}`);
    } catch { /* logger 不可用时静默 */ }
  };

  /** 当前调用所属会话的权限模式；取不到时按受限处理（fail closed → 弹窗路径）。 */
  function sessionMode(exec) {
    try {
      const policy = ctx.sandboxPolicy;
      if (policy && typeof policy.resolve === 'function') {
        return policy.resolve(exec?.agent ? { session: exec.agent.session } : {}).mode;
      }
    } catch { /* 服务异常按受限处理 */ }
    return 'workspace-write';
  }

  /**
   * 执行期门禁（v2）：
   * - 总开关关 → 拒绝（工具理论上已卸载，此处兜底防竞态）。
   * - 开 + 完全权限 → 直接放行。
   * - 开 + 受限 → DSH 原生审批弹窗，allowed-once 仅放行这一次。
   */
  async function gate(tool, exec) {
    if (!permissions.enabled) {
      throw new Error('Computer Use 总开关当前为关闭。任何情况下都不能操控电脑；确属必要，请用户在 设置 → Computer Use 中开启「允许 AI 控制电脑」。');
    }
    const mode = sessionMode(exec);
    if (mode === 'danger-full-access') return;
    let approval;
    try {
      approval = ctx.get('approval');
    } catch {
      approval = undefined;
    }
    if (!approval || typeof approval.request !== 'function' || !exec?.agent) {
      throw new Error(`Computer Use 总开关已开启，但当前会话（权限 ${mode}）没有可用的审批通道。按用户设置，受限会话内控制电脑必须经真人逐次确认；请让用户直接批准，或由用户把会话切到完全权限。`);
    }
    const outcome = await approval.request({
      agent: exec.agent,
      toolName: TOOL_PREFIX + tool.name,
      callId: exec.callId,
      reason: `AI 请求使用 Computer Use 工具 ${tool.name}（当前会话权限 ${mode}）。按用户设置，受限会话内控制电脑需真人确认`,
      displayReason: {
        en: `Allow AI to use Computer Use tool "${tool.name}"? (this call only)`,
        zh: `允许 AI 使用 Computer Use 工具「${tool.name}」吗？（仅本次调用生效）`,
      },
      ...(exec?.signal ? { signal: exec.signal } : {}),
    });
    if (outcome === 'allowed-once') return;
    if (outcome === 'rejected') {
      throw new Error(`用户拒绝了这次 Computer Use 调用（${tool.name}）。不要重试该操作；若确属必要，请向用户说明用途，或请用户在 设置 → Computer Use 中调整。`);
    }
    if (outcome === 'cancelled') {
      throw new Error(`Computer Use（${tool.name}）的审批被取消。`);
    }
    throw new Error(`Computer Use（${tool.name}）没有可用的审批通道，按 fail closed 拒绝执行。`);
  }

  function buildDefinition(tool) {
    const publicName = TOOL_PREFIX + tool.name;
    const baseDescription = typeof tool.description === 'string' && tool.description.trim() !== ''
      ? tool.description
      : `Cua Driver 工具 ${tool.name}`;
    const parameters = tool.inputSchema && typeof tool.inputSchema === 'object' && !Array.isArray(tool.inputSchema)
      ? tool.inputSchema
      : { type: 'object', properties: {} };
    return {
      name: publicName,
      description: `[Computer Use] ${baseDescription}`,
      parameters,
      output: {
        schema: { type: 'object', additionalProperties: true },
        render(_args, value) {
          return [{ type: 'text', text: `${describeResult(value)}\n${renderValue(value)}` }];
        },
      },
      async execute(args, exec) {
        // 锁：执行路径内的强制门禁（读取实时设置 + 会话权限模式，进程内状态绕不过）。
        await gate(tool, exec);
        const active = manager.driver;
        if (!active) {
          ensureDriver(); // 触发重试（失败后 readyPromise 已清空）
          throw new Error(`Computer Use 驱动未就绪：${manager.status().error ?? '正在加载'}。请稍后重试一次；若持续失败请检查 Cua Driver 安装。`);
        }
        const combined = exec?.signal ? AbortSignal.any([exec.signal, manager.lifetime.signal]) : manager.lifetime.signal;
        combined.throwIfAborted();
        const result = await active.callTool(tool.name, JSON.stringify(args ?? {}), { signal: combined });
        return JSON.parse(result.rawJson);
      },
    };
  }

  const TOOL_NAME_RE = /^[A-Za-z0-9_-]{1,64}$/u;

  /** 按总开关挂载/卸载全部工具（关闭时不注册，模型根本看不到）。 */
  function syncTools(catalog) {
    const enabled = permissions.enabled;
    const mounted = toolDisposers.length > 0;
    if (enabled && !mounted) {
      for (const tool of catalog) {
        const publicName = TOOL_PREFIX + tool.name;
        if (!TOOL_NAME_RE.test(publicName)) {
          log(`工具名越界，已跳过：${tool.name}`);
          continue;
        }
        try {
          toolDisposers.push(ctx.tools.register(buildDefinition(tool)));
        } catch (error) {
          log(`注册工具 ${tool.name} 失败：${String(error?.message ?? error)}`);
        }
      }
      log(`Computer Use 已开启，挂载 ${toolDisposers.length} 个工具`);
    } else if (!enabled && mounted) {
      for (const dispose of toolDisposers) {
        try { dispose(); } catch { /* 卸载失败忽略 */ }
      }
      toolDisposers.length = 0;
      log('Computer Use 已关闭，卸载全部工具');
    }
  }

  // 驱动懒加载：启动期不做任何 CuaDriver 工作（消除启动期风险）。
  // 触发时机：启动后 8 秒的延迟定时器 / 首次 HTTP state 访问 / 开关变更。均幂等。
  function ensureDriver() {
    void manager.ensure()
      .then(catalog => syncTools(catalog))
      .catch(error => log(`驱动加载失败：${String(error?.message ?? error)}（工具不可用，设置页仍可访问）`));
  }
  const lazyTimer = setTimeout(ensureDriver, 8000);
  try { lazyTimer.unref?.(); } catch { /* 老环境无 unref，忽略 */ }

  // 1) 占用 computerUse 独占 provider 槽（服务存在才注册；失败不影响工具能力）。
  let computerUse;
  try {
    computerUse = ctx.get('computerUse');
  } catch {
    computerUse = undefined;
  }
  if (computerUse && typeof computerUse.register === 'function') {
    try {
      ctx.effect(() => computerUse.register(PROVIDER_NAME), 'dsh-destinywind-computer-user: provider slot');
    } catch (error) {
      log(`provider 槽被占用（${String(error?.message ?? error)}），继续以独立工具方式提供能力`);
    }
  }

  // 2) HTTP 路由（设置页数据源；GET state 与开关变更都会触发懒加载）。
  ctx.effect(
    () => ctx.webServer.register({
      kind: 'prefix',
      path: ROUTE,
      handler: makeHandler({ permissions, manager, ensureDriver, log }),
    }),
    'dsh-destinywind-computer-user: routes',
  );

  // 3) 系统提示：告诉模型能力边界与运行规则（动态反映总开关）。
  ctx.effect(
    () => ctx.systemPrompt.section({
      name: 'plugin:destinywind-computer-user',
      order: 2000,
      text: () => {
        if (!permissions.enabled) {
          return '## Computer Use\nComputer Use 总开关当前为关闭，你没有任何桌面操作工具可用，任何情况下都不能操控电脑。请勿尝试调用；确属必要请让用户在 设置 → Computer Use 中开启「允许 AI 控制电脑」。';
        }
        return [
          '## Computer Use',
          '用户已开启「允许 AI 控制电脑」总开关，桌面操作工具已挂载（前缀 computer_use__）。执行规则：',
          '- 完全权限会话：直接执行，无需确认。',
          '- 受限权限（workspace-write / read-only）会话：每次控制电脑都会自动弹出审批卡向用户请求；不要试图绕过；被拒绝的操作不要重试。',
          '操作前先观察（computer_use__get_desktop_state / list_windows），用最新快照的元素定位；一次输入操作不等于结果达成，操作后重新观察核验。',
        ].join('\n');
      },
    }),
    'dsh-destinywind-computer-user: prompt section',
  );

  // 4) 卸载：停定时器、停工具、关驱动。
  ctx.effect(() => () => {
    clearTimeout(lazyTimer);
    for (const dispose of toolDisposers) {
      try { dispose(); } catch { /* 忽略 */ }
    }
    toolDisposers.length = 0;
    void manager.dispose();
  }, 'dsh-destinywind-computer-user: lifetime');
}
