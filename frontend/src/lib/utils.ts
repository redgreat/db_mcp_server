/** 展示 ISO 时间为本地字符串 */
export function formatDate(iso: string | null | undefined): string {
	if (!iso) return '—';
	const d = new Date(iso);
	return Number.isNaN(d.getTime())
		? String(iso)
		: d.toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
}

/** 截断过长文本 */
export function truncate(s: string | null | undefined, max = 48): string {
	if (s == null || s === '') return '';
	return s.length <= max ? s : `${s.slice(0, max)}…`;
}

/** 复制文本到剪贴板（clipboard API 不可用时降级 execCommand） */
export async function copyToClipboard(text: string): Promise<boolean> {
	try {
		await navigator.clipboard.writeText(text);
		return true;
	} catch {
		try {
			const ta = document.createElement('textarea');
			ta.value = text;
			ta.style.position = 'fixed';
			ta.style.opacity = '0';
			document.body.appendChild(ta);
			ta.select();
			const ok = document.execCommand('copy');
			document.body.removeChild(ta);
			return ok;
		} catch {
			return false;
		}
	}
}

/** DaisyUI badge 类名，按数据库类型区分颜色 */
export function dbTypeColor(dbType: string | null | undefined): string {
	const t = (dbType ?? '').toLowerCase();
	const map: Record<string, string> = {
		mysql: 'badge-info',
		mariadb: 'badge-info',
		postgresql: 'badge-success',
		postgres: 'badge-success',
		mssql: 'badge-warning',
		sqlserver: 'badge-warning'
	};
	return map[t] ?? 'badge-ghost';
}
