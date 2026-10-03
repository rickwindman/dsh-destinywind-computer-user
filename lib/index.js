/**
 * Host half：Computer Use —— 让模型直接操作本机桌面（原生 Cua Driver SDK）。
 *
 * 与 dsh-cua-native-enable 的关键差别（那个插件已废弃）：
 *   它把官方两个 computer-use 包放在 vendor/ 里、以「相对路径」加载，而 DSH 的
 *   link-projection 模块解析只对「包名加载」生效，vendor 产物里的
 *   `import "@deepseek-ai/cordis"` 必然 MODULE_NOT_FOUND（独立进程与宿主进程
 *   双向实测）。本插件完全自包含：只依赖 registry 真依赖 @trycua/cua-driver，
 *   与宿主服务 tools / webServer / systemPrompt / userQuestions，不 import
 *   任何未发布的 @deepseek-ai 官方包。
 *
 * 权限模型（硬性设计，不得削弱）：
 *   1. 持久开关只有一个入口 —— Web 设置页（client.js）。每个权限组开/关两态，
 *      持久化到 <DSH home>/destinywind-computer-user/permissions.json（HMAC 签名）。
 *   2. AI 调用未开启权限的工具时，插件当场弹窗询问用户，只有「允许（仅本次）/
 *      拒绝」两个选项；「允许」只放行这一次调用，不落任何持久状态，下次再问。
 *      想永久开启，唯一途径是用户本人在设置页操作。
 *   3. 防绕过三重锁：
 *      a. 门禁在工具 execute 进程内强制（模型无法伪造弹窗结果）；
 *      b. 设置页的 POST 修改一律反向弹窗确认「是否本人操作」，AI 冒充设置页
 *         调用 HTTP 接口同样会被弹窗拦住；
 *      c. 权限文件带 HMAC-SHA256 签名，签名密钥只在 DSH 进程内存、每次启动
 *         随机生成 —— AI 用文件工具篡改 permissions.json 在本进程内不生效；
 *         重启后验签失败则整体回落默认（观察开、其余全关）。
 *
 * 已知边界（诚实声明）：签名只防"篡改内容"，不防 AI 删除文件后由插件重建
 * （重建会回落默认全关，对 AI 无利）；也不防拥有本机管理员权限的进程。这不
 * 是密码学对抗 AI 的方案，而是把"静默绕过"变成"必然弹窗或必然失效"。
 *
 * @module dsh-destinywind-computer-user
 */

import { createHmac, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const name = 'dsh-destinywind-computer-user';
export const inject = ['tools', 'webServer', 'systemPrompt'];

const ROUTE = '/dsh-destinywind-computer-user';
const TOOL_PREFIX = 'computer_use__';
const PROVIDER_NAME = 'destinywind-computer-user';
const OUTPUT_LIMIT = 60000;
const BODY_LIMIT = 256 * 1024;

/**
 * 权限分组：组序即设置页展示序；defaultEnabled 为出厂默认。
 * 组内 tools 是 SDK 0.28.0 的原始工具名；SDK 未来新增的未归类工具自动落入
 * other 组（默认关），保证"新增能力默认不可用"。
 */
export const PERMISSION_GROUPS = [
  {
    key: 'observe',
    label: '观察（只读）',
    description: '枚举应用与窗口、读取窗口/桌面状态、屏幕尺寸、光标位置、辅助功能树、健康检查等只读信息。',
    risk: 'low',
    defaultEnabled: true,
    tools: [
      'list_apps', 'list_windows', 'get_window_state', 'verify_state', 'debug_window_info',
      'get_screen_size', 'get_desktop_state', 'get_cursor_position', 'get_agent_cursor_state',
      'check_permissions', 'health_report', 'get_config', 'get_accessibility_tree',
      'zoom', 'page', 'get_browser_state', 'get_recording_state',
      'list_sessions', 'get_session', 'get_session_state',
    ],
  },
  {
    key: 'pointer',
    label: '鼠标与指针输入',
    description: '单击、双击、右键、拖拽、滚动、移动光标 —— 直接操控屏幕指针。',
    risk: 'high',
    defaultEnabled: false,
    tools: ['click', 'double_click', 'right_click', 'drag', 'scroll', 'move_cursor'],
  },
  {
    key: 'keyboard',
    label: '键盘输入',
    description: '输入文字、按键、组合热键、设置控件值 —— 直接向窗口注入键盘事件。',
    risk: 'high',
    defaultEnabled: false,
    tools: ['type_text', 'press_key', 'hotkey', 'set_value'],
  },
  {
    key: 'clipboard',
    label: '剪贴板读写',
    description: '读取与写入系统剪贴板（涉及隐私，读与写都默认关闭）。',
    risk: 'medium',
    defaultEnabled: false,
    tools: ['clipboard_read', 'clipboard_write'],
  },
  {
    key: 'window',
    label: '应用与窗口管理',
    description: '启动/关闭应用、置顶窗口、调整窗口位置尺寸、调用应用菜单 —— 含 kill_app 等破坏性操作。',
    risk: 'high',
    defaultEnabled: false,
    tools: ['launch_app', 'kill_app', 'bring_to_front', 'set_window_frame', 'invoke_menu'],
  },
  {
    key: 'browser',
    label: '浏览器自动化',
    description: '准备浏览器、导航、点击、输入、处理对话框、上传文件、下载等浏览器内操作。',
    risk: 'medium',
    defaultEnabled: false,
    tools: [
      'browser_prepare', 'browser_navigate', 'browser_click', 'browser_type',
      'browser_dialog', 'browser_set_input_files', 'browser_download', 'browser_pointer',
    ],
  },
  {
    key: 'recording',
    label: '屏幕录制与回放',
    description: '开始/停止屏幕录制、回放操作轨迹、安装 ffmpeg 依赖。',
    risk: 'medium',
    defaultEnabled: false,
    tools: ['start_recording', 'stop_recording', 'replay_trajectory', 'install_ffmpeg'],
  },
  {
    key: 'session',
    label: '驱动会话与提权',
    description: '创建驱动会话、申请提权（escalate）、结束会话。',
    risk: 'high',
    defaultEnabled: false,
    tools: ['start_session', 'escalate_session', 'end_session'],
  },
  {
    key: 'cursor',
    label: 'Agent 光标外观',
    description: '开关/调节 Agent 可视光标（显示、动效、主题）。',
    risk: 'low',
    defaultEnabled: false,
    tools: ['set_agent_cursor_enabled', 'set_agent_cursor_motion', 'set_agent_cursor_theme'],
  },
  {
    key: 'config',
    label: '驱动配置写入',
    description: '修改 Cua Driver 运行配置（set_config）。',
    risk: 'medium',
    defaultEnabled: false,
    tools: ['set_config'],
  },
  {
    key: 'other',
    label: '未归类（SDK 新增）',
    description: 'SDK 新增、本插件尚未归类的工具。为安全起见默认关闭。',
    risk: 'high',
    defaultEnabled: false,
    tools: [],
  },
];

const GROUP_BY_KEY = new Map(PERMISSION_GROUPS.map(group => [group.key, group]));
const TOOL_TO_GROUP = new Map();
for (const group of PERMISSION_GROUPS) {
  for (const toolName of group.tools) TOOL_TO_GROUP.set(toolName, group.key);
}

function groupOfTool(toolName) {
  return TOOL_TO_GROUP.get(toolName) ?? 'other';
}

function labelOf(groupKey) {
  return GROUP_BY_KEY.get(groupKey)?.label ?? groupKey;
}

/* ------------------------------ 权限存储（HMAC 签名） ------------------------------ */

function resolveHome() {
  const fromEnv = typeof process.env.DSH_HOME === 'string' ? process.env.DSH_HOME.trim() : '';
  if (fromEnv) return fromEnv;
  return path.join(os.homedir(), '.dsh');
}

/**
 * 每次进程启动随机生成签名密钥，只存在于本进程内存。
 * AI 篡改磁盘文件 → 本进程验签失败 → 视为未授权回落默认。
 */
const SIGNING_KEY = randomBytes(32);

function signState(state) {
  return createHmac('sha256', SIGNING_KEY).update(JSON.stringify(state)).digest('hex');
}

function defaultState() {
  const state = {};
  for (const group of PERMISSION_GROUPS) state[group.key] = group.defaultEnabled === true;
  return state;
}

function createPermissionStore() {
  const dir = path.join(resolveHome(), 'destinywind-computer-user');
  const file = path.join(dir, 'permissions.json');
  let state = defaultState();

  // 启动时读盘并验签；验签失败或损坏一律回落默认（观察开、其余全关）。
  try {
    if (existsSync(file)) {
      const parsed = JSON.parse(readFileSync(file, 'utf8'));
      const body = parsed && typeof parsed === 'object' ? parsed.state : undefined;
      const mac = parsed && typeof parsed === 'object' ? parsed.mac : undefined;
      if (body && typeof body === 'object' && typeof mac === 'string'
        && signState(body) === mac) {
        for (const group of PERMISSION_GROUPS) {
          if (typeof body[group.key] === 'boolean') state[group.key] = body[group.key];
        }
      }
    }
  } catch {
    state = defaultState();
  }

  function persist() {
    try {
      mkdirSync(dir, { recursive: true });
      writeFileSync(file, JSON.stringify({ version: 1, state, mac: signState(state) }, null, 2), 'utf8');
      return true;
    } catch {
      return false;
    }
  }

  return {
    file,
    all() { return { ...state }; },
    get(groupKey) { return state[groupKey] === true; },
    /** 只有 HTTP 反向确认后的路径才会调用到这里。 */
    set(groupKey, value) {
      if (!GROUP_BY_KEY.has(groupKey)) throw new Error(`未知权限组 "${groupKey}"`);
      state[groupKey] = value === true;
      return persist();
    },
    setAll(value) {
      for (const group of PERMISSION_GROUPS) state[group.key] = value === true;
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
        readyPromise = load().catch((err) => { error = err; throw err; });
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
 * @param {(request: object) => Promise<{ approved: boolean }>} deps.confirmHuman
 *   反向确认：任何试图修改权限的请求都必须先通过真人弹窗。
 * @param {() => void} deps.ensureDriver 懒加载触发器（GET state / POST 时调用）
 * @param {(message: string) => void} deps.log
 */
function makeHandler({ permissions, manager, confirmHuman, ensureDriver, log }) {
  const json = (res, status, body) => {
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(body));
  };

  function snapshot() {
    const groups = PERMISSION_GROUPS.map(group => ({
      key: group.key,
      label: group.label,
      description: group.description,
      risk: group.risk,
      tools: group.tools,
      enabled: permissions.get(group.key),
    }));
    return {
      ok: true,
      driver: manager.status(),
      permissions: permissions.all(),
      groups,
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

      // 修改权限：无论请求来自哪里（设置页 / AI 伪造 / 脚本），必须通过真人反向确认。
      if (req.method === 'POST' && parts[0] === 'permissions') {
        const body = JSON.parse((await readBody(req)) || '{}');
        const groupKey = typeof body.group === 'string' ? body.group : '';
        const enabled = body.enabled === true;
        if (groupKey !== 'all' && !GROUP_BY_KEY.has(groupKey)) {
          return json(res, 400, { ok: false, error: `未知权限组 "${groupKey}"` });
        }
        const confirmed = await confirmHuman({
          title: 'Computer Use 权限变更确认',
          question: enabled
            ? `有人（可能是你，也可能是 AI）请求【永久开启】Computer Use 权限组「${labelOf(groupKey)}」。永久开启只能由你本人确认。允许吗？`
            : `有人请求【关闭】Computer Use 权限组「${labelOf(groupKey)}」。允许吗？`,
          groupLabel: groupKey === 'all' ? '全部权限组' : labelOf(groupKey),
          enabled,
        });
        if (!confirmed.approved) {
          log('权限变更被反向确认拒绝（未落盘）');
          return json(res, 403, { ok: false, error: '变更未通过真人确认，未生效。' });
        }
        const persisted = groupKey === 'all' ? permissions.setAll(enabled) : permissions.set(groupKey, enabled);
        ensureDriver(); // 权限已变更：确保驱动与工具挂载跟上（幂等）
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
  const toolDisposers = new Map();
  const log = (message) => {
    try {
      const logger = ctx.get('logger');
      logger?.warn?.(`dsh-destinywind-computer-user: ${message}`);
    } catch { /* logger 不可用时静默 */ }
  };

  /** 反向确认：把"谁在改设置"这个问题交给真人。userQuestions 不可用 = 拒绝。 */
  async function confirmHuman(question) {
    let userQuestions;
    try {
      userQuestions = ctx.get('userQuestions');
    } catch {
      userQuestions = undefined;
    }
    if (!userQuestions || typeof userQuestions.ask !== 'function') {
      return { approved: false };
    }
    try {
      const answer = await userQuestions.ask({
        questions: [{
          id: 'cua-confirm',
          header: question.title,
          question: question.question,
          multi_select: false,
          options: [
            { label: '确认，是我本人操作', description: '通过真人确认，权限状态落盘生效。' },
            { label: '拒绝', description: '拒绝本次变更，权限状态保持不变。' },
          ],
        }],
      });
      const picked = answer?.answers?.[0] ?? answer?.[0] ?? answer;
      const value = typeof picked === 'string' ? picked : picked?.value ?? picked?.label;
      return { approved: value === 'cua-confirm' || value === '确认，是我本人操作' };
    } catch {
      return { approved: false };
    }
  }

  /**
   * 执行期门禁：绝对以设置为准。
   * - 开启：放行。
   * - 关闭：弹窗问用户，仅「允许（仅本次）/拒绝」两种结果；允许只放行这一次。
   */
  async function gate(groupKey, toolName) {
    if (permissions.get(groupKey)) return { allowed: true };
    let userQuestions;
    try {
      userQuestions = ctx.get('userQuestions');
    } catch {
      userQuestions = undefined;
    }
    if (!userQuestions || typeof userQuestions.ask !== 'function') {
      throw new Error(`Computer Use 权限「${labelOf(groupKey)}」未开启（且无法发起用户确认）。请用户在 设置 → Computer Use 中手动开启。`);
    }
    const answer = await userQuestions.ask({
      questions: [{
        id: 'cua-permission',
        header: 'Computer Use 权限请求',
        question: `AI 请求使用权限组「${labelOf(groupKey)}」（工具 ${toolName}），该权限当前在设置中未开启。允许这一次调用吗？（永久开启请到 设置 → Computer Use 手动操作）`,
        multi_select: false,
        options: [
          { label: '允许（仅本次）', description: '只放行当前这一次调用，不保存；下次调用会再次询问。' },
          { label: '拒绝', description: '拒绝本次调用；AI 将收到拒绝说明。' },
        ],
      }],
    });
    const picked = answer?.answers?.[0] ?? answer?.[0] ?? answer;
    const value = typeof picked === 'string' ? picked : picked?.value ?? picked?.label;
    if (value === 'cua-permission' || value === '允许（仅本次）') return { allowed: true };
    throw new Error(`用户拒绝了你使用「${labelOf(groupKey)}」权限（工具 ${toolName}）。不要重试该操作；若确属必要，请让用户在 设置 → Computer Use 中手动开启该权限组。`);
  }

  function buildDefinition(tool) {
    const groupKey = groupOfTool(tool.name);
    const publicName = TOOL_PREFIX + tool.name;
    const groupLabel = labelOf(groupKey);
    const baseDescription = typeof tool.description === 'string' && tool.description.trim() !== ''
      ? tool.description
      : `Cua Driver 工具 ${tool.name}`;
    const parameters = tool.inputSchema && typeof tool.inputSchema === 'object' && !Array.isArray(tool.inputSchema)
      ? tool.inputSchema
      : { type: 'object', properties: {} };
    return {
      name: publicName,
      description: `[Computer Use · ${groupLabel}] ${baseDescription}`,
      parameters,
      output: {
        schema: { type: 'object', additionalProperties: true },
        render(_args, value) {
          return [{ type: 'text', text: `${describeResult(value)}\n${renderValue(value)}` }];
        },
      },
      async execute(args, exec) {
        // 锁 1：执行路径内的强制门禁（读取实时设置，改文件/改内存都绕不过进程内状态）。
        await gate(groupKey, tool.name);
        const active = manager.driver;
        if (!active) {
          throw new Error(`Computer Use 驱动未就绪：${manager.status().error ?? '正在加载'}`);
        }
        const combined = exec?.signal ? AbortSignal.any([exec.signal, manager.lifetime.signal]) : manager.lifetime.signal;
        combined.throwIfAborted();
        const result = await active.callTool(tool.name, JSON.stringify(args ?? {}), { signal: combined });
        return JSON.parse(result.rawJson);
      },
    };
  }

  const TOOL_NAME_RE = /^[A-Za-z0-9_-]{1,64}$/u;

  /** 按当前设置挂载/卸载各组工具（关闭的组不注册，模型根本看不到）。 */
  function syncTools(catalog) {
    const byGroup = new Map(PERMISSION_GROUPS.map(group => [group.key, []]));
    for (const tool of catalog) {
      const publicName = TOOL_PREFIX + tool.name;
      if (!TOOL_NAME_RE.test(publicName)) {
        log(`工具名越界，已跳过：${tool.name}`);
        continue;
      }
      byGroup.get(groupOfTool(tool.name))?.push(tool);
    }
    for (const group of PERMISSION_GROUPS) {
      const enabled = permissions.get(group.key);
      const mounted = toolDisposers.has(group.key);
      if (enabled && !mounted) {
        const disposers = [];
        for (const tool of byGroup.get(group.key) ?? []) {
          try {
            disposers.push(ctx.tools.register(buildDefinition(tool)));
          } catch (error) {
            log(`注册工具 ${tool.name} 失败：${String(error?.message ?? error)}`);
          }
        }
        toolDisposers.set(group.key, disposers);
        log(`权限组「${group.label}」已开启，挂载 ${disposers.length} 个工具`);
      } else if (!enabled && mounted) {
        for (const dispose of toolDisposers.get(group.key) ?? []) {
          try { dispose(); } catch { /* 卸载失败忽略 */ }
        }
        toolDisposers.delete(group.key);
        log(`权限组「${group.label}」已关闭，卸载其工具`);
      }
    }
  }

  // 锁 2：设置页与 HTTP 修改都必须通过真人反向确认（见 makeHandler.confirmHuman）。

  // 驱动懒加载：启动期不做任何 CuaDriver 工作（消除启动期风险）。
  // 触发时机：启动后 8 秒的延迟定时器 / 首次 HTTP state 访问 / 权限变更。均幂等。
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

  // 3) HTTP 路由（设置页数据源；GET state 与权限变更都会触发懒加载）。
  ctx.effect(
    () => ctx.webServer.register({
      kind: 'prefix',
      path: ROUTE,
      handler: makeHandler({ permissions, manager, confirmHuman, ensureDriver, log }),
    }),
    'dsh-destinywind-computer-user: routes',
  );

  // 4) 系统提示：告诉模型能力边界与权限现状（动态反映设置）。
  ctx.effect(
    () => ctx.systemPrompt.section({
      name: 'plugin:destinywind-computer-user',
      order: 2000,
      text: () => {
        const enabledGroups = PERMISSION_GROUPS.filter(group => permissions.get(group.key));
        if (enabledGroups.length === 0) {
          return '## Computer Use\n当前所有 Computer Use 权限组均已关闭，你没有任何桌面操作工具可用。请勿尝试调用；确属必要请让用户在 设置 → Computer Use 中开启。';
        }
        const lines = enabledGroups.map(group => `- ${group.label}（${group.tools.length} 个工具，前缀 ${TOOL_PREFIX}）`);
        return [
          '## Computer Use',
          '本机桌面操作能力已按用户授权开放以下权限组，工具名前缀 computer_use__：',
          ...lines,
          '未列出的权限组未获授权：相关工具不存在，不要尝试猜测调用；如确属必要，先向用户说明并请其到 设置 → Computer Use 手动开启。',
          '操作前先观察（computer_use__get_desktop_state / list_windows），用最新快照的元素定位；一次输入操作不等于结果达成，操作后重新观察核验。',
        ].join('\n');
      },
    }),
    'dsh-destinywind-computer-user: prompt section',
  );

  // 5) 卸载：停定时器、停工具、关驱动。
  ctx.effect(() => () => {
    clearTimeout(lazyTimer);
    for (const disposers of toolDisposers.values()) {
      for (const dispose of disposers) {
        try { dispose(); } catch { /* 忽略 */ }
      }
    }
    toolDisposers.clear();
    void manager.dispose();
  }, 'dsh-destinywind-computer-user: lifetime');
}
