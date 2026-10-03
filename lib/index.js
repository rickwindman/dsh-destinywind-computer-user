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
 * 权限模型 v2.1（2026-10 与用户确认：「不允许 AI 自行打开开关」）：
 *   1. 设置页只有一个总开关「允许 AI 控制电脑」（默认关），持久化到
 *      <DSH home>/destinywind-computer-user/permissions.json（HMAC 签名）。
 *      人机分叉（借鉴 agentgate/Aegis 的「agent 无 UI 凭证进不了特权通道」）：
 *      - 开（=放权）：POST 必须携带 DSH Web GUI 的浏览器签名 cookie
 *        （HttpOnly+SameSite=Strict，宿主 client-connection 签发，密钥存
 *        宿主 credentials 服务且受 DPAPI 保护）；AI 的 HTTP 调用没有该
 *        cookie，一律 403 —— AI 永远无法自行打开开关。
 *      - 关（=收权）：保持自由，AI 可随时帮用户关闭（关闭无风险）。
 *      闭环：开关关时所有桌面工具已卸载，AI 连「用桌面点设置页」的能力都
 *      没有，因此也不存在「操控浏览器代点开关」的旁路；开关开时 AI 理论上
 *      能点关闭（允许），不构成新风险。
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
 * 重签状态文件、可关总开关。「开」这条路由宿主 DPAPI 保护的密钥签发的
 * HttpOnly cookie 把守，AI 伪造不出有效 cookie（伪造就得读 DPAPI 解密后的
 * 凭证，那是宿主进程的运行时资产）；受限会话拿不到免弹窗能力。目标效果：
 * 关=绝对禁止、开只能由真人浏览器操作、开+完全权限=用户既有授权、
 * 开+受限=逐次弹窗。
 *
 * @module dsh-destinywind-computer-user
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const name = 'dsh-destinywind-computer-user';
export const inject = ['tools', 'webServer', 'systemPrompt', 'sandboxPolicy', 'credentials'];

const ROUTE = '/dsh-destinywind-computer-user';
const TOOL_PREFIX = 'computer_use__';
const PROVIDER_NAME = 'destinywind-computer-user';
const OUTPUT_LIMIT = 60000;
const BODY_LIMIT = 256 * 1024;

/* --------------------- 浏览器签名 cookie 验证（v2.1 人机分叉） ---------------------
 * 算法与宿主 client-connection 的 browser-auth.ts 完全一致（不 import，复刻）：
 *   cookie 名 = 'dsh-auth-' + base64url(sha256(authority))
 *   cookie 值 = 'v1.' + base64url(JSON payload) + '.' + base64url(HMAC-SHA256(secret, body))
 *   payload   = { version: 1, authority, issuedAt, expiresAt }
 * 密钥（32B base64url）存宿主 credentials 服务的 grant 记录
 * `client-connection/browser-session`，由 DPAPI 加密落盘 —— AI 无法读出明文，
 * 因此无法伪造有效 cookie；浏览器请求自动携带（HttpOnly+SameSite=Strict）。 */

const BROWSER_RECORD_KEY = 'client-connection/browser-session';
const COOKIE_PREFIX = 'dsh-auth-';
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/u;

function encodeBase64Url(value) {
  return Buffer.from(value).toString('base64').replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

function decodeBase64Url(value) {
  if (!BASE64URL_PATTERN.test(value) || value.length % 4 === 1) return undefined;
  const padding = '='.repeat(4 - (value.length % 4));
  let decoded;
  try {
    decoded = Buffer.from(value.replaceAll('-', '+').replaceAll('_', '/') + padding, 'base64');
  } catch {
    return undefined;
  }
  return encodeBase64Url(decoded) === value ? decoded : undefined;
}

function requestAuthority(headers) {
  const raw = headers instanceof Headers ? headers.get('host') : headers?.host;
  if (typeof raw !== 'string') return undefined;
  try {
    return new URL(`http://${raw}`).host;
  } catch {
    return undefined;
  }
}

function cookieName(authority) {
  return COOKIE_PREFIX + encodeBase64Url(createHash('sha256').update(authority).digest());
}

function cookieValue(headerValue, name) {
  for (const segment of headerValue.split(';')) {
    const at = segment.indexOf('=');
    if (at === -1 || segment.slice(0, at).trim() !== name) continue;
    return segment.slice(at + 1).trim();
  }
  return undefined;
}

function browserCookieSignature(secret, body) {
  return createHmac('sha256', secret).update(body).digest();
}

function decodeBrowserCookie(value, secret) {
  const parts = value.split('.');
  const [version, body, encodedSignature] = parts;
  if (parts.length !== 3 || version !== 'v1' || body === undefined || encodedSignature === undefined) return undefined;
  const actual = decodeBase64Url(encodedSignature);
  if (actual === undefined) return undefined;
  const expected = browserCookieSignature(secret, body);
  if (actual.byteLength !== expected.byteLength || !timingSafeEqual(actual, expected)) return undefined;
  let decoded;
  try {
    const bodyBytes = decodeBase64Url(body);
    if (bodyBytes === undefined) return undefined;
    decoded = JSON.parse(bodyBytes.toString('utf8'));
  } catch {
    return undefined;
  }
  if (decoded === null || typeof decoded !== 'object' || Array.isArray(decoded)
    || decoded.version !== 1
    || typeof decoded.authority !== 'string'
    || !Number.isSafeInteger(decoded.issuedAt)
    || !Number.isSafeInteger(decoded.expiresAt)) return undefined;
  return decoded;
}

/**
 * 从宿主 credentials 服务读 browser-session 签名密钥。调用方保证 credentials
 * 可用；读不到/格式不对返回 undefined（此时「开」一律 403，fail closed）。
 */
async function loadBrowserSecret(credentials) {
  if (!credentials || typeof credentials.readRecord !== 'function') return undefined;
  let record;
  try {
    record = await credentials.readRecord(BROWSER_RECORD_KEY);
  } catch {
    return undefined;
  }
  if (record === undefined || record === null || record.kind !== 'grant') return undefined;
  const payload = record.payload;
  if (payload === undefined || payload === null || typeof payload !== 'object' || Array.isArray(payload)) return undefined;
  if (payload.version !== 1 || typeof payload.secret !== 'string') return undefined;
  return decodeBase64Url(payload.secret);
}

/**
 * 校验请求是否来自已认证的真人浏览器会话。
 * @returns {Promise<boolean>} 仅当 cookie 由当前宿主密钥签发、未过期且绑定本 authority 时为 true。
 */
async function isBrowserRequest(headers, credentials) {
  const authority = requestAuthority(headers);
  const rawCookie = headers instanceof Headers ? headers.get('cookie') : headers?.cookie;
  if (authority === undefined || typeof rawCookie !== 'string') return false;
  const secret = await loadBrowserSecret(credentials);
  if (secret === undefined) return false;
  const value = cookieValue(rawCookie, cookieName(authority));
  if (value === undefined) return false;
  const payload = decodeBrowserCookie(value, secret);
  if (payload === undefined || payload.authority !== authority) return false;
  const now = Date.now();
  return payload.issuedAt <= now
    && payload.expiresAt > now
    && payload.expiresAt > payload.issuedAt;
}

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
 * @param {import('@deepseek-ai/dsh-credentials').CredentialProvider|undefined} deps.credentials 宿主凭证服务（验浏览器 cookie）
 * @param {(message: string) => void} deps.log
 */
function makeHandler({ permissions, manager, ensureDriver, credentials, log }) {
  const json = (res, status, body) => {
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(body));
  };

  function snapshot(humanGate) {
    return {
      ok: true,
      enabled: permissions.enabled,
      humanGate: humanGate === undefined ? undefined : {
        active: humanGate === true,
        message: humanGate === true
          ? '浏览器凭证校验通过（真人操作）'
          : '浏览器凭证校验失败（AI 或未认证请求；开启总开关将被拒绝）',
      },
      driver: manager.status(),
      file: permissions.file,
    };
  }

  /** 请求头里是否带了有效的浏览器签名 cookie（诊断字段，不做授权）。 */
  async function probeHumanGate(req) {
    try {
      return await isBrowserRequest(req.headers, credentials);
    } catch {
      return false;
    }
  }

  return async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://dsh');
    const parts = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);
    if (parts[0] === 'dsh-destinywind-computer-user') parts.shift();
    try {
      if (req.method === 'GET' && parts[0] === 'state') {
        ensureDriver(); // 懒加载触发：首次访问即开始加载驱动（幂等，后台进行）
        return json(res, 200, snapshot(await probeHumanGate(req)));
      }

      // 修改总开关（v2.1 人机分叉）：
      // - 关（收权）：自由，AI 可随时帮用户关闭。
      // - 开（放权）：必须携带 DSH 浏览器签名 cookie（真人）；AI 一律 403。
      //   这是用户明确要求的「不允许 AI 自行打开开关」的唯一开入口。
      if (req.method === 'POST' && parts[0] === 'permissions') {
        const body = JSON.parse((await readBody(req)) || '{}');
        if (typeof body.enabled !== 'boolean') {
          return json(res, 400, { ok: false, error: '请求体必须为 {"enabled": true|false}' });
        }
        if (body.enabled === true) {
          const human = await probeHumanGate(req);
          if (!human) {
            log('拒绝开启请求：无有效浏览器凭证（可能是 AI 调用）。只有用户在浏览器设置页操作才能开启。');
            return json(res, 403, {
              ok: false,
              error: '开启「允许 AI 控制电脑」只能由用户在浏览器设置页完成（需要浏览器登录凭证）。AI 无法自行开启；如确属必要，请请用户在设置页打开。',
            });
          }
        }
        const persisted = permissions.set(body.enabled);
        ensureDriver(); // 开关变更：确保工具挂载跟上（幂等）
        log(`Computer Use 总开关变更为 ${body.enabled ? '开' : '关'}（落盘：${persisted ? '是' : '否'}）`);
        return json(res, 200, { ok: persisted, snapshot: snapshot(true), persisted });
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

  // 宿主凭证服务：读 browser-session 签名密钥用（v2.1 人机分叉的信任根）。
  // 取不到时「开」一律 403（fail closed）——代价是设置页也无法开启，
  // 状态字段 humanGate 会如实呈现原因。
  let credentials;
  try {
    credentials = ctx.get('credentials');
  } catch {
    credentials = undefined;
  }

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
      handler: makeHandler({ permissions, manager, ensureDriver, credentials, log }),
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
          return '## Computer Use\nComputer Use 总开关当前为关闭，你没有任何桌面操作工具可用，任何情况下都不能操控电脑。请勿尝试调用；也不要尝试通过 HTTP 接口或修改状态文件开启总开关——开启只能由用户在浏览器设置页完成，你没有权限，尝试必然失败。确属必要请直接请用户在 设置 → Computer Use 中开启「允许 AI 控制电脑」。';
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
