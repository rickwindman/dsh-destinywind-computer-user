/**
 * Client half：Web 设置页「Computer Use」栏目（v2.1：单总开关 + 真人开权）。
 *
 * 只有一个开关「允许 AI 控制电脑」：
 *   - 开：完全权限会话直接放行；受限会话（workspace-write / read-only）每次
 *     控制电脑由宿主通过 DSH 原生审批卡向用户逐次请求。
 *     【v2.1】开启需要浏览器登录凭证（HttpOnly cookie），AI 调 HTTP 无法开启
 *     （403）——只有真人（你）在设置页点击才能打开。
 *   - 关：任何情况下 AI 都不能操控电脑（工具整体卸载）。AI 仍可自由关闭
 *     （收权无风险，比如帮你紧急止损）。
 * 开关状态来自宿主 GET /dsh-destinywind-computer-user/state，修改 POST
 * /dsh-destinywind-computer-user/permissions。
 *
 * 与 dsh-destinywind-memory 的 client.js 同模式：
 *顶层调用 window.__ModuleLoader__.load({ id, factory(require) })，
 * React 从 factory 的 require 参数获取；组件全部用 React.createElement。
 */

window.__ModuleLoader__.load({
  id: 'dsh-destinywind-computer-user',
  factory(require) {
    const React = require('react');
    const { useState, useEffect, useCallback } = React;

    const ROUTE = '/dsh-destinywind-computer-user';
    // SECTION_ORDER 是跨插件协调值：本插件排在「记忆」插件（16）之后。
    // 若两个插件都安装，顺序由双方此常量决定；若记忆插件未安装，17 只意味着
    // 栏目前面留一个空档，无功能影响。新插件请选择互不冲突的值。
    const SECTION_ORDER = 17;

    async function api(path, init) {
      const response = await fetch(`${ROUTE}${path}`, {
        headers: { 'content-type': 'application/json' },
        ...init,
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok || body?.ok === false) {
        throw new Error(body?.error || `HTTP ${response.status}`);
      }
      return body;
    }

    function Toggle({ checked, disabled, onChange }) {
      return React.createElement(
        'button',
        {
          role: 'switch',
          'aria-checked': checked ? 'true' : 'false',
          disabled: disabled === true,
          onClick: () => onChange(!checked),
          style: {
            position: 'relative',
            width: 40,
            height: 22,
            borderRadius: 11,
            border: 'none',
            cursor: disabled ? 'not-allowed' : 'pointer',
            background: checked ? '#2f6feb' : '#8b949e',
            opacity: disabled ? 0.5 : 1,
            transition: 'background 0.15s ease',
            flexShrink: 0,
          },
        },
        React.createElement('span', {
          style: {
            position: 'absolute',
            top: 2,
            left: checked ? 20 : 2,
            width: 18,
            height: 18,
            borderRadius: 9,
            background: '#fff',
            boxShadow: '0 1px 2px rgba(0,0,0,0.25)',
            transition: 'left 0.15s ease',
          },
        }),
      );
    }

    function ComputerUseSettingsPage() {
      const [snapshot, setSnapshot] = useState(null);
      const [error, setError] = useState('');
      const [busy, setBusy] = useState(false);

      const refresh = useCallback(async () => {
        try {
          const data = await api('/state');
          setSnapshot(data);
          setError('');
        } catch (err) {
          setError(String(err?.message ?? err));
        }
      }, []);

      useEffect(() => {
        void refresh();
        const timer = setInterval(() => void refresh(), 10000);
        return () => clearInterval(timer);
      }, [refresh]);

      const toggleEnabled = useCallback(async (value) => {
        setBusy(true);
        setError('');
        try {
          await api('/permissions', {
            method: 'POST',
            body: JSON.stringify({ enabled: value }),
          });
          await refresh();
        } catch (err) {
          setError(String(err?.message ?? err));
          await refresh();
        } finally {
          setBusy(false);
        }
      }, [refresh]);

      if (error && snapshot === null) {
        return React.createElement(
          'div',
          { style: { padding: 12 } },
          React.createElement('div', { style: { color: '#cf222e' } }, `加载失败：${error}`),
          React.createElement(
            'button',
            { onClick: () => void refresh(), style: { marginTop: 8 } },
            '重试',
          ),
        );
      }
      if (snapshot === null) {
        return React.createElement('div', { style: { padding: 12, opacity: 0.6 } }, '加载中…');
      }

      const enabled = snapshot.enabled === true;
      const driver = snapshot.driver ?? {};
      return React.createElement(
        'div',
        { style: { maxWidth: 640, margin: '0 auto', padding: 12 } },
        React.createElement(
          'div',
          { style: { marginBottom: 12, fontSize: 12, opacity: 0.75, lineHeight: 1.6 } },
          'Computer Use 让 AI 直接操作本机桌面。开启后：完全权限会话可直接执行；',
          '受限权限（工作区读写 / 只读）会话每次控制电脑都会弹出审批卡向你逐次确认。',
          '关闭后：AI 在任何情况下都不能操控电脑（工具整体卸载）。',
          '开启只能由你在此页面完成（需要浏览器登录凭证，AI 无法自行开启）；',
          'AI 仍可随时关闭开关（收权无风险）。',
        ),
        // 总开关卡片
        React.createElement(
          'div',
          {
            style: {
              display: 'flex', alignItems: 'center', gap: 12,
              border: '1px solid var(--dsh-border, #30363d)',
              borderRadius: 8,
              padding: '14px 16px',
              marginBottom: 12,
              background: enabled ? 'rgba(47,111,235,0.06)' : 'transparent',
            },
          },
          React.createElement(Toggle, {
            checked: enabled,
            disabled: busy,
            onChange: toggleEnabled,
          }),
          React.createElement(
            'div',
            { style: { flex: 1 } },
            React.createElement(
              'div',
              { style: { fontWeight: 600, fontSize: 14 } },
              '允许 AI 控制电脑',
            ),
            React.createElement(
              'div',
              { style: { fontSize: 12, opacity: 0.7, marginTop: 2 } },
              enabled
                ? '已开启：AI 可按会话权限使用桌面操作工具（受限会话逐次审批）。'
                : '已关闭：AI 任何情况下都不能操控电脑。只有你能在浏览器里开启此开关。',
            ),
          ),
        ),
        // 驱动状态行
        React.createElement(
          'div',
          {
            style: {
              display: 'flex', alignItems: 'center', gap: 10,
              padding: '8px 12px', marginBottom: 12,
              borderRadius: 8,
              border: '1px solid var(--dsh-border, #30363d)',
              fontSize: 13,
            },
          },
          React.createElement('span', null, '驱动状态：'),
          React.createElement(
            'strong',
            { style: { color: driver.ready ? '#1a7f37' : '#9a6700' } },
            driver.ready ? `就绪（${driver.toolCount} 个工具）` : '未就绪',
          ),
          driver.error
            ? React.createElement(
              'span',
              { style: { color: '#cf222e', fontSize: 12 } },
              String(driver.error),
            )
            : null,
          React.createElement(
            'button',
            { onClick: () => void refresh(), style: { marginLeft: 'auto', fontSize: 12 } },
            '刷新',
          ),
        ),
        error
          ? React.createElement(
            'div',
            { style: { marginBottom: 12, padding: '8px 12px', borderRadius: 8, fontSize: 12, color: '#cf222e', background: 'rgba(207,34,46,0.12)' } },
            error,
          )
          : null,
        React.createElement(
          'div',
          { style: { marginTop: 12, fontSize: 11, opacity: 0.5, lineHeight: 1.6 } },
          `开关状态持久化于 ${snapshot.file}（HMAC 签名，重启保留；篡改不生效）。`,
        ),
      );
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        ctx.effect(() => ctx.slots.inject(
          'settings.section',
          () => ctx.slots.register(
            { name: 'settings.section', id: 'destinywind-computer-user', order: SECTION_ORDER, label: 'Computer Use' },
            ComputerUseSettingsPage,
          ),
        ), 'dsh-destinywind-computer-user: settings section slot');
      },
    };
  },
});
