/** 展示 ISO 时间为本地字符串 */
export function formatDate(iso: string | null | undefined): string {
	if (!iso) return '—';
	const d = new Date(iso);
	return Number.isNaN(d.getTime()) ? String(iso) : d.toLocaleString('zh-CN');
}

/** 截断过长文本 */
export function truncate(s: string | null | undefined, max = 48): string {
	if (s == null || s === '') return '';
	return s.length <= max ? s : `${s.slice(0, max)}…`;
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
