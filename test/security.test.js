/**
 * 安全核心测试（node --test，无外部依赖）。
 *
 * 覆盖 v2.1 的三道防线：
 *   1. 浏览器签名 cookie 验证（人机分叉的信任根）；
 *   2. 权限状态文件防篡改（HMAC 验签，篡改回落「关」）；
 *   3. HTTP 接口的人机分叉（AI 开启 → 403；关闭自由；诚实 humanGate）。
 *
 * 运行：npm test（或 node --test test/）
 * 隔离：测试通过 DSH_HOME 环境变量把状态文件导向临时目录，不触碰真实设置。
 */

import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomBytes, createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { EventEmitter } from 'node:events';

import { __internals } from '../lib/index.js';

const {
  encodeBase64Url, decodeBase64Url, cookieName, cookieValue,
  decodeBrowserCookie, browserCookieSignature, loadBrowserSecret, isBrowserRequest,
  loadOrCreateSigningKey, signState, createPermissionStore, makeHandler,
} = __internals;

/* --------------------------------- 工具 --------------------------------- */

let homeDir;

function freshHome() {
  homeDir = mkdtempSync(path.join(tmpdir(), 'dsh-cu-test-'));
  process.env.DSH_HOME = homeDir;
}

function cleanupHome() {
  delete process.env.DSH_HOME;
  if (homeDir) {
    rmSync(homeDir, { recursive: true, force: true });
    homeDir = undefined;
  }
}

/** 用给定密钥签一个合法浏览器 cookie（复刻宿主签发算法）。 */
function mintCookie(secret, authority, { issuedAt = Date.now() - 1000, expiresAt = Date.now() + 3600_000, version = 1 } = {}) {
  const payload = { version, authority, issuedAt, expiresAt };
  const body = encodeBase64Url(JSON.stringify(payload));
  const sig = encodeBase64Url(browserCookieSignature(secret, body));
  return { name: cookieName(authority), value: `v1.${body}.${sig}` };
}

/** 最小可用的 credentials 服务桩：返回固定 secret。 */
function fakeCredentials(secretB64Url) {
  return {
    async readRecord(key) {
      if (key !== 'client-connection/browser-session') return undefined;
      return { kind: 'grant', payload: { version: 1, secret: secretB64Url } };
    },
  };
}

/** 模拟 HTTP 请求-响应，跑一遍 handler。 */
function mockRes() {
  const res = new EventEmitter();
  const captured = {};
  res.writeHead = (status, headers) => { captured.status = status; captured.headers = headers; };
  res.end = (chunk) => { captured.body = chunk ? JSON.parse(chunk) : undefined; };
  return { res, captured };
}

async function call(handler, method, url, { body, headers = {} } = {}) {
  const req = new EventEmitter();
  req.method = method;
  req.url = url;
  req.headers = headers;
  req.destroy = () => { req.destroyed = true; }; // 对齐真实 http.IncomingMessage（readBody 超限时调用）
  const { res, captured } = mockRes();
  const promise = handler(req, res);
  // readBody 是异步收包的：等一拍让 promise 链走到 readBody，再喂 body。
  await new Promise((r) => setImmediate(r));
  if (body !== undefined) req.emit('data', Buffer.from(body));
  req.emit('end');
  return promise.then(() => captured);
}

function buildHandler({ permissions, credentials, logs = [] } = {}) {
  const manager = {
    status: () => ({ ready: false, toolCount: 0, error: null }),
  };
  return makeHandler({
    permissions: permissions ?? createPermissionStore(),
    manager,
    ensureDriver: () => {},
    credentials,
    log: (m) => logs.push(m),
  });
}

/* ------------------------- 1. base64url 编解码 ------------------------- */

describe('base64url 编解码', () => {
  test('round-trip：编码后解码还原', () => {
    const raw = randomBytes(32);
    const encoded = encodeBase64Url(raw);
    assert.equal(decodeBase64Url(encoded).toString('hex'), raw.toString('hex'));
  });

  test('输出字符集只含 base64url 字母表（无 + / =）', () => {
    for (let i = 0; i < 20; i++) {
      const encoded = encodeBase64Url(randomBytes(33)); // 33B 故意不整除 3，逼出 padding
      assert.match(encoded, /^[A-Za-z0-9_-]+$/);
      assert.ok(!encoded.includes('='));
    }
  });

  test('非规范输入（尾部 padding / 非法字符 / 长度 mod 4 == 1）返回 undefined', () => {
    assert.equal(decodeBase64Url('abc='), undefined); // 尾随等号：非规范
    assert.equal(decodeBase64Url('aGVsbG8!'), undefined); // 非法字符
    assert.equal(decodeBase64Url('abcde'), undefined); // len%4==1 不可能合法
  });

  test('长度 mod 4 == 0 的输入（3 字节倍数）正确解码（回归：padding 计算不得多补）', () => {
    // 'YWJj' = base64('abc')，编码后 4 字符、无需 padding；旧实现会多补 4 个 '='
    assert.equal(decodeBase64Url('YWJj')?.toString('utf8'), 'abc');
    // 更长的 3 字节倍数随机样本
    for (let i = 0; i < 10; i++) {
      const raw = randomBytes(3 * (1 + i));
      const encoded = encodeBase64Url(raw);
      assert.equal(decodeBase64Url(encoded)?.toString('hex'), raw.toString('hex'));
    }
  });
});

/* ---------------------- 2. 浏览器 cookie 验证 ---------------------- */

describe('浏览器 cookie 验证（人机分叉信任根）', () => {
  const authority = '127.0.0.1:19387';
  let secret;
  let secretB64Url;

  beforeEach(() => {
    secret = randomBytes(32);
    secretB64Url = encodeBase64Url(secret);
  });

  test('合法签名 + 未过期 + authority 匹配 → 通过', async () => {
    const cookie = mintCookie(secret, authority);
    const headers = { host: authority, cookie: `${cookie.name}=${cookie.value}` };
    assert.equal(await isBrowserRequest(headers, fakeCredentials(secretB64Url)), true);
  });

  test('AI 请求（无 cookie）→ 拒绝', async () => {
    const headers = { host: authority };
    assert.equal(await isBrowserRequest(headers, fakeCredentials(secretB64Url)), false);
  });

  test('密钥不匹配（伪造签名）→ 拒绝', async () => {
    const attackerKey = randomBytes(32);
    const cookie = mintCookie(attackerKey, authority);
    const headers = { host: authority, cookie: `${cookie.name}=${cookie.value}` };
    assert.equal(await isBrowserRequest(headers, fakeCredentials(secretB64Url)), false);
  });

  test('过期 cookie → 拒绝', async () => {
    const cookie = mintCookie(secret, authority, { issuedAt: Date.now() - 7200_000, expiresAt: Date.now() - 3600_000 });
    const headers = { host: authority, cookie: `${cookie.name}=${cookie.value}` };
    assert.equal(await isBrowserRequest(headers, fakeCredentials(secretB64Url)), false);
  });

  test('authority 不匹配（cookie 绑定其他主机）→ 拒绝', async () => {
    const cookie = mintCookie(secret, 'evil.example.com:9999');
    const headers = { host: authority, cookie: `${cookie.name}=${cookie.value}` };
    assert.equal(await isBrowserRequest(headers, fakeCredentials(secretB64Url)), false);
  });

  test('payload 结构不合法（缺字段/类型错/version 错）→ decodeBrowserCookie 返回 undefined', () => {
    const cases = [
      { version: 2, authority, issuedAt: 1, expiresAt: 2 },           // version ≠ 1
      { authority, issuedAt: 1, expiresAt: 2 },                        // 缺 version
      { version: 1, authority: 123, issuedAt: 1, expiresAt: 2 },       // authority 非字符串
      { version: 1, authority, issuedAt: 1.5, expiresAt: 2 },          // 非安全整数
    ];
    for (const payload of cases) {
      const body = encodeBase64Url(JSON.stringify(payload));
      const sig = encodeBase64Url(browserCookieSignature(secret, body));
      assert.equal(decodeBrowserCookie(`v1.${body}.${sig}`, secret), undefined, JSON.stringify(payload));
    }
  });

  test('格式破坏（段数错 / version 前缀错 / 签名非 base64url）→ 拒绝', () => {
    const cookie = mintCookie(secret, authority);
    assert.equal(decodeBrowserCookie('v2.x.y', secret), undefined);
    assert.equal(decodeBrowserCookie('v1.only-two-parts', secret), undefined);
    assert.equal(decodeBrowserCookie(`${cookie.value.split('.')[0]}.${cookie.value.split('.')[1]}.!!!`, secret), undefined);
  });

  test('多 cookie 头：按名字精确取出目标 cookie', () => {
    const cookie = mintCookie(secret, authority);
    const header = `other=1; ${cookie.name}=${cookie.value}; another=2`;
    assert.equal(cookieValue(header, cookie.name), cookie.value);
    assert.equal(cookieValue(header, 'not-exist'), undefined);
  });

  test('credentials 不可用 / 读失败 / kind 错 / secret 非法 → loadBrowserSecret 返回 undefined（fail closed）', async () => {
    assert.equal(await loadBrowserSecret(undefined), undefined);
    assert.equal(await loadBrowserSecret({ readRecord: async () => { throw new Error('boom'); } }), undefined);
    assert.equal(await loadBrowserSecret({ readRecord: async () => ({ kind: 'other' }) }), undefined);
    assert.equal(await loadBrowserSecret({ readRecord: async () => ({ kind: 'grant', payload: { version: 1, secret: '!!!' } }) }), undefined);
  });

  test('secret 非 32 字节（合法 base64url 但长度错）→ 拒绝（对齐宿主 canonicalSecret）', async () => {
    // 31 字节与 33 字节都是合法 base64url，但宿主密钥恒为 32B —— 长度不对必须拒绝
    const short31 = encodeBase64Url(randomBytes(31));
    const long33 = encodeBase64Url(randomBytes(33));
    assert.equal(await loadBrowserSecret(fakeCredentials(short31)), undefined, '31B 密钥必须拒绝');
    assert.equal(await loadBrowserSecret(fakeCredentials(long33)), undefined, '33B 密钥必须拒绝');
    // 对照：32B 正常通过
    assert.ok((await loadBrowserSecret(fakeCredentials(secretB64Url))) instanceof Buffer);
  });

  test('cookie 名 = dsh-auth- + base64url(sha256(authority))，与宿主算法一致', () => {
    const digest = createHash('sha256').update(authority).digest();
    assert.equal(cookieName(authority), 'dsh-auth-' + encodeBase64Url(digest));
  });
});

/* --------------------- 3. 权限存储（防篡改） --------------------- */

describe('权限存储：默认关 + HMAC 防篡改 + 持久化', () => {
  beforeEach(freshHome);
  afterEach(cleanupHome);

  test('无状态文件 → 默认关', () => {
    assert.equal(createPermissionStore().enabled, false);
  });

  test('set(true) 落盘后新建 store 读回为开（重启语义）', () => {
    const store = createPermissionStore();
    assert.equal(store.set(true), true);
    assert.equal(store.enabled, true);
    // 模拟重启：全新 store 读同一文件
    const reloaded = createPermissionStore();
    assert.equal(reloaded.enabled, true);
  });

  test('篡改 enabled 不重算 mac → 验签失败 → 回落关', () => {
    const store = createPermissionStore();
    store.set(true);
    const raw = JSON.parse(readFileSync(store.file, 'utf8'));
    raw.enabled = false; // 攻击者直接改文件
    writeFileSync(store.file, JSON.stringify(raw), 'utf8');
    assert.equal(createPermissionStore().enabled, false, '篡改后必须回落关');
  });

  test('mac 换成乱串 → 回落关', () => {
    const store = createPermissionStore();
    store.set(true);
    const raw = JSON.parse(readFileSync(store.file, 'utf8'));
    raw.mac = 'deadbeef';
    writeFileSync(store.file, JSON.stringify(raw), 'utf8');
    assert.equal(createPermissionStore().enabled, false);
  });

  test('文件损坏（非 JSON）→ 回落关', () => {
    const store = createPermissionStore();
    store.set(true);
    writeFileSync(store.file, 'not json at all', 'utf8');
    assert.equal(createPermissionStore().enabled, false);
  });

  test('signState 是 HMAC-SHA256 over JSON.stringify(enabled)', () => {
    const key = randomBytes(64);
    assert.equal(signState(true, key), createHmac('sha256', key).update('true').digest('hex'));
    assert.equal(signState(false, key), createHmac('sha256', key).update('false').digest('hex'));
  });

  test('密钥文件：首次生成 64B；已存在 ≥32B 则复用', () => {
    const dir = path.join(homeDir, 'destinywind-computer-user');
    const key1 = loadOrCreateSigningKey(dir);
    assert.equal(key1.length, 64);
    const key2 = loadOrCreateSigningKey(dir);
    assert.equal(key1.compare(key2), 0, '第二次应复用同一密钥');
  });
});

/* --------------------- 4. HTTP 接口（人机分叉） --------------------- */

describe('HTTP 接口：人机分叉 + 输入校验', () => {
  const authority = '127.0.0.1:19387';
  const STATE_URL = '/dsh-destinywind-computer-user/state';
  const PERM_URL = '/dsh-destinywind-computer-user/permissions';
  let secret;
  let secretB64Url;
  let humanHeaders;

  beforeEach(() => {
    freshHome();
    secret = randomBytes(32);
    secretB64Url = encodeBase64Url(secret);
    const cookie = mintCookie(secret, authority);
    humanHeaders = { host: authority, cookie: `${cookie.name}=${cookie.value}` };
  });
  afterEach(cleanupHome);

  test('AI 开启总开关（无 cookie）→ 403，开关保持关', async () => {
    const store = createPermissionStore();
    const handler = buildHandler({ permissions: store, credentials: fakeCredentials(secretB64Url) });
    const r = await call(handler, 'POST', PERM_URL, { body: '{"enabled":true}', headers: { host: authority } });
    assert.equal(r.status, 403);
    assert.equal(r.body.ok, false);
    assert.equal(store.enabled, false, '开关必须保持关');
  });

  test('真人开启（有效 cookie）→ 200，开关落盘为开', async () => {
    const store = createPermissionStore();
    const handler = buildHandler({ permissions: store, credentials: fakeCredentials(secretB64Url) });
    const r = await call(handler, 'POST', PERM_URL, { body: '{"enabled":true}', headers: humanHeaders });
    assert.equal(r.status, 200);
    assert.equal(store.enabled, true);
    assert.equal(r.body.snapshot.humanGate.active, true);
  });

  test('真人开启但落盘失败 → 409 + ok:false（不再伪装 200）（回归：持久化失败必须如实报告）', async () => {
    const failingStore = {
      file: 'D:/fake/permissions.json',
      get enabled() { return false; },
      set() { return false; }, // 模拟磁盘写失败
    };
    const handler = buildHandler({ permissions: failingStore, credentials: fakeCredentials(secretB64Url) });
    const r = await call(handler, 'POST', PERM_URL, { body: '{"enabled":true}', headers: humanHeaders });
    assert.equal(r.status, 409);
    assert.equal(r.body.ok, false);
    assert.equal(r.body.persisted, false);
    assert.ok(typeof r.body.error === 'string' && r.body.error.includes('写入失败'));
  });

  test('AI 关闭总开关 → 200，且响应 humanGate.active=false（v2.1.1 诚实化）', async () => {
    const store = createPermissionStore();
    store.set(true); // 预置为开
    const handler = buildHandler({ permissions: store, credentials: fakeCredentials(secretB64Url) });
    const r = await call(handler, 'POST', PERM_URL, { body: '{"enabled":false}', headers: { host: authority } });
    assert.equal(r.status, 200);
    assert.equal(store.enabled, false);
    assert.equal(r.body.snapshot.humanGate.active, false, 'AI 关闭后 humanGate 必须如实为 false（修复 #1）');
  });

  test('坏 JSON 请求体 → 400（不再 500）（修复 #2）', async () => {
    const handler = buildHandler({ credentials: fakeCredentials(secretB64Url) });
    const r = await call(handler, 'POST', PERM_URL, { body: '{not-json', headers: { host: authority } });
    assert.equal(r.status, 400);
    assert.equal(r.body.ok, false);
  });

  test('超大请求体 → 413', async () => {
    const handler = buildHandler({ credentials: fakeCredentials(secretB64Url) });
    const r = await call(handler, 'POST', PERM_URL, { body: '{"enabled":' + 'x'.repeat(300 * 1024) + '}', headers: { host: authority } });
    assert.equal(r.status, 413);
  });

  test('enabled 非布尔（字符串/缺失）→ 400', async () => {
    const handler = buildHandler({ credentials: fakeCredentials(secretB64Url) });
    for (const body of ['{"enabled":"true"}', '{}']) {
      const r = await call(handler, 'POST', PERM_URL, { body, headers: { host: authority } });
      assert.equal(r.status, 400, body);
    }
  });

  test('GET /state：AI 请求 humanGate.active=false（预期），开关状态如实呈现', async () => {
    const store = createPermissionStore();
    store.set(true);
    const handler = buildHandler({ permissions: store, credentials: fakeCredentials(secretB64Url) });
    const r = await call(handler, 'GET', STATE_URL, { headers: { host: authority } });
    assert.equal(r.status, 200);
    assert.equal(r.body.enabled, true);
    assert.equal(r.body.humanGate.active, false);
  });

  test('GET /state：真人请求 humanGate.active=true', async () => {
    const handler = buildHandler({ credentials: fakeCredentials(secretB64Url) });
    const r = await call(handler, 'GET', STATE_URL, { headers: humanHeaders });
    assert.equal(r.status, 200);
    assert.equal(r.body.humanGate.active, true);
  });

  test('未知接口 → 404', async () => {
    const handler = buildHandler({ credentials: fakeCredentials(secretB64Url) });
    const r = await call(handler, 'GET', '/dsh-destinywind-computer-user/nope', { headers: { host: authority } });
    assert.equal(r.status, 404);
  });

  test('credentials 服务整体不可用 → 开启仍 403（fail closed）', async () => {
    const store = createPermissionStore();
    const handler = buildHandler({ permissions: store, credentials: undefined });
    const r = await call(handler, 'POST', PERM_URL, { body: '{"enabled":true}', headers: humanHeaders });
    assert.equal(r.status, 403, '凭证服务不可用时宁可拒绝也不放行');
    assert.equal(store.enabled, false);
  });
});

/* --------------------- 5. 密钥生成边界 --------------------- */

describe('签名密钥生成', () => {
  beforeEach(freshHome);
  afterEach(cleanupHome);

  test('目录不存在时自动创建（recursive mkdir）', () => {
    const dir = path.join(homeDir, 'deep', 'nested', 'destinywind-computer-user');
    const key = loadOrCreateSigningKey(dir);
    assert.equal(key.length, 64);
  });

  test('写盘失败（目录被文件占用）→ 退化为内存密钥，不抛异常', () => {
    const blocker = path.join(homeDir, 'blocker');
    writeFileSync(blocker, 'x', 'utf8');
    const key = loadOrCreateSigningKey(path.join(blocker, 'sub'));
    assert.ok(key instanceof Buffer);
    assert.equal(key.length, 64);
  });

  test('损坏的密钥文件（<32B）→ 重新生成', () => {
    const dir = path.join(homeDir, 'destinywind-computer-user');
    mkdirSync(dir, { recursive: true });
    writeFileSync(path.join(dir, 'secret.key'), 'short', 'utf8');
    const key = loadOrCreateSigningKey(dir);
    assert.equal(key.length, 64);
    assert.notEqual(key.toString('utf8'), 'short');
  });
});
