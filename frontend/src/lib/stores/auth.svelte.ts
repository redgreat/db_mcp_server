/**
 * 登录态：内存 + localStorage 持久化 token。
 */
export type User = {
	id: number;
	username: string;
	email?: string;
	role: 'admin' | 'user';
};

const STORAGE_KEY = 'db_mcp_admin_token';

function readStoredToken(): string | null {
	if (typeof window === 'undefined') return null;
	try {
		return localStorage.getItem(STORAGE_KEY);
	} catch {
		return null;
	}
}

let token = $state<string | null>(readStoredToken());
let user = $state<User | null>(null);

function persistToken(t: string | null) {
	if (typeof window === 'undefined') return;
	try {
		if (t) localStorage.setItem(STORAGE_KEY, t);
		else localStorage.removeItem(STORAGE_KEY);
	} catch {
		/* ignore */
	}
}

export const authStore = {
	get token() {
		return token;
	},
	get user() {
		return user;
	},
	get isAdmin() {
		return user?.role === 'admin';
	},
	login(t: string, u: User) {
		token = t;
		user = u;
		persistToken(t);
	},
	logout() {
		token = null;
		user = null;
		persistToken(null);
	},
	setUser(u: User) {
		user = u;
	}
};
