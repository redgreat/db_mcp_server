/**
 * 明暗主题：内存状态 + localStorage 持久化，写入 <html data-theme>。
 */
export type Theme = 'dark' | 'light';

const STORAGE_KEY = 'db_mcp_admin_theme';

function readStoredTheme(): Theme {
	if (typeof window === 'undefined') return 'dark';
	try {
		const v = localStorage.getItem(STORAGE_KEY);
		return v === 'light' ? 'light' : 'dark';
	} catch {
		return 'dark';
	}
}

let theme = $state<Theme>(readStoredTheme());

function applyTheme(t: Theme) {
	if (typeof document === 'undefined') return;
	document.documentElement.dataset.theme = t;
}

function persistTheme(t: Theme) {
	try {
		localStorage.setItem(STORAGE_KEY, t);
	} catch {
		/* ignore */
	}
}

export const themeStore = {
	get theme() {
		return theme;
	},
	get isDark() {
		return theme === 'dark';
	},
	toggle() {
		theme = theme === 'dark' ? 'light' : 'dark';
		persistTheme(theme);
		applyTheme(theme);
	},
	init() {
		applyTheme(theme);
	}
};
