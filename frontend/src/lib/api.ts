/**
 * 调用同源后端 Admin API（FastAPI），携带 Bearer Token。
 */
import { goto } from '$app/navigation';
import { authStore } from '$lib/stores/auth.svelte';

let redirectingToLogin = false;

function handleUnauthorized(): void {
	if (redirectingToLogin) return;
	redirectingToLogin = true;
	authStore.logout();
	goto('/login').finally(() => {
		redirectingToLogin = false;
	});
}

export class ApiError extends Error {
	status: number;

	constructor(message: string, status: number) {
		super(message);
		this.name = 'ApiError';
		this.status = status;
	}
}

async function parseDetail(res: Response): Promise<string> {
	try {
		const j = (await res.json()) as { detail?: unknown };
		const d = j.detail;
		if (typeof d === 'string') return d;
		if (Array.isArray(d)) {
			return d
				.map((x: { msg?: string }) => x?.msg ?? JSON.stringify(x))
				.join('; ');
		}
		if (d && typeof d === 'object') return JSON.stringify(d);
	} catch {
		/* ignore */
	}
	return res.statusText || `HTTP ${res.status}`;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
	const headers: Record<string, string> = {
		Accept: 'application/json'
	};
	if (body !== undefined) {
		headers['Content-Type'] = 'application/json';
	}
	const token = authStore.token;
	if (token) {
		headers.Authorization = `Bearer ${token}`;
	}

	const res = await fetch(path, {
		method,
		headers,
		body: body !== undefined ? JSON.stringify(body) : undefined
	});

	if (!res.ok) {
		const msg = await parseDetail(res);
		if (res.status === 401) {
			handleUnauthorized();
		}
		throw new ApiError(msg, res.status);
	}

	if (res.status === 204) {
		return undefined as T;
	}

	const text = await res.text();
	if (!text) {
		return undefined as T;
	}
	return JSON.parse(text) as T;
}

export const api = {
	get: <T>(path: string) => request<T>('GET', path),
	post: <T>(path: string, body?: unknown) => request<T>('POST', path, body),
	put: <T>(path: string, body?: unknown) => request<T>('PUT', path, body),
	patch: <T>(path: string, body?: unknown) => request<T>('PATCH', path, body),
	delete: <T>(path: string) => request<T>('DELETE', path)
};
