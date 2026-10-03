/**
 * Client half：Web 设置页「Computer Use」栏目。
 *
 * 展示驱动状态 + 各权限组开关。开关状态一律来自宿主 GET /dsh-destinywind-computer-user/state，
 * 修改一律 POST /dsh-destinywind-computer-user/permissions —— 宿主侧对每次修改都会
 * 反向弹窗确认"是否本人操作"，因此本页面不需要（也无法）提供绕过确认的路径。
 *
 * 与 dsh-destinywind-memory 的 client.js 同模式：
 * 顶层调用 window.__ModuleLoader__.load({ id, factory(require) })，
 * React 从 factory 的 require 参数获取；组件全部用 React.createElement。
 */

window.__ModuleLoader__.load({
  id: 'dsh-destinywind-computer-user',
  factory(require) {
    const React = require('react');
    const { useState, useEffect, useCallback } = React;

    const ROUTE = '/dsh-destinywind-computer-user';
    // 17 = 「记忆」(16) 之后。
    const SECTION_ORDER = 17;

    const RISK_LABEL = {
      low: '低风险',
      medium: '中风险',
      high: '高风险',
    };

    const RISK_STYLE = {
      low: { color: '#1a7f37', background: 'rgba(26,127,55,0.12)' },
      medium: { color: '#9a6700', background: 'rgba(154,103,0,0.12)' },
      high: { color: '#cf222e', background: 'rgba(207,34,46,0.12)' },
    };

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

    function GroupCard({ group, busy, onToggle }) {
      const [open, setOpen] = useState(false);
      const risk = RISK_STYLE[group.risk] ?? RISK_STYLE.medium;
      return React.createElement(
        'div',
        {
          key: group.key,
          style: {
            border: '1px solid var(--dsh-border, #30363d)',
            borderRadius: 8,
            padding: '10px 12px',
            marginBottom: 8,
          },
        },
        React.createElement(
          'div',
          { style: { display: 'flex', alignItems: 'center', gap: 10 } },
          React.createElement(Toggle, {
            checked: group.enabled === true,
            disabled: busy,
            onChange: value => onToggle(group.key, value),
          }),
          React.createElement(
            'div',
            { style: { flex: 1, minWidth: 0 } },
            React.createElement(
              'div',
              { style: { display: 'flex', alignItems: 'center', gap: 8 } },
              React.createElement(
                'span',
                { style: { fontWeight: 600 } },
                group.label,
              ),
              React.createElement(
                'span',
                {
                  style: {
                    fontSize: 11,
                    padding: '1px 8px',
                    borderRadius: 10,
                    color: risk.color,
                    background: risk.background,
                  },
                },
                RISK_LABEL[group.risk] ?? group.risk,
              ),
              React.createElement(
                'span',
                { style: { fontSize: 12, opacity: 0.65 } },
                `${group.tools.length} 个工具`,
              ),
            ),
            React.createElement(
              'div',
              { style: { fontSize: 12, opacity: 0.7, marginTop: 2 } },
              group.description,
            ),
          ),
          React.createElement(
            'button',
            {
              onClick: () => setOpen(!open),
              style: {
                border: 'none', background: 'transparent', cursor: 'pointer',
                fontSize: 12, opacity: 0.6, flexShrink: 0,
              },
            },
            open ? '收起 ▲' : '工具 ▼',
          ),
        ),
        open && group.tools.length > 0
          ? React.createElement(
            'div',
            { style: { marginTop: 8, display: 'flex', flexWrap: 'wrap', gap: 6 } },
            group.tools.map(tool => React.createElement(
              'code',
              {
                key: tool,
                style: {
                  fontSize: 11,
                  padding: '2px 8px',
                  borderRadius: 6,
                  background: 'var(--dsh-surface, #161b22)',
                  color: '#e6edf3',
                  border: '1px solid var(--dsh-border, #30363d)',
                  opacity: group.enabled ? 1 : 0.5,
                },
              },
              `computer_use__${tool}`,
            )),
          )
          : null,
      );
    }

    function ComputerUseSettingsPage() {
      const [snapshot, setSnapshot] = useState(null);
      const [error, setError] = useState('');
      const [notice, setNotice] = useState('');
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

      const toggleGroup = useCallback(async (groupKey, value) => {
        setBusy(true);
        setNotice('');
        try {
          await api('/permissions', {
            method: 'POST',
            body: JSON.stringify({ group: groupKey, enabled: value }),
          });
          await refresh();
          setNotice(value
            ? '已提交开启请求。注意：宿主会弹出确认框，需要你本人确认后才真正生效。'
            : '已提交关闭请求。注意：宿主会弹出确认框，需要你本人确认后才真正生效。');
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

      const driver = snapshot.driver ?? {};
      return React.createElement(
        'div',
        { style: { maxWidth: 640, margin: '0 auto', padding: 12 } },
        React.createElement(
          'div',
          { style: { marginBottom: 12, fontSize: 12, opacity: 0.75, lineHeight: 1.6 } },
          'Computer Use 让 AI 直接操作本机桌面。权限组开关只有这里能永久生效；',
          'AI 使用未开启的权限时会当场向你弹窗，仅「允许（仅本次）/拒绝」二选，允许不保存。',
          '任何权限变更（包括来自本页面的）都会经宿主反向确认后才落盘。',
        ),
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
        notice
          ? React.createElement(
            'div',
            { style: { marginBottom: 12, padding: '8px 12px', borderRadius: 8, fontSize: 12, color: '#9a6700', background: 'rgba(154,103,0,0.12)' } },
            notice,
          )
          : null,
        error
          ? React.createElement(
            'div',
            { style: { marginBottom: 12, padding: '8px 12px', borderRadius: 8, fontSize: 12, color: '#cf222e', background: 'rgba(207,34,46,0.12)' } },
            error,
          )
          : null,
        (snapshot.groups ?? []).map(group => React.createElement(GroupCard, {
          key: group.key,
          group,
          busy,
          onToggle: toggleGroup,
        })),
        React.createElement(
          'div',
          { style: { marginTop: 12, fontSize: 11, opacity: 0.5, lineHeight: 1.6 } },
          `权限状态持久化于 ${snapshot.file}（带进程内 HMAC 签名，外部篡改不生效）。`,
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
