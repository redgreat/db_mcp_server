export type ToastKind = 'info' | 'success' | 'error';

type ToastItem = { id: number; message: string; type: ToastKind };

let items = $state<ToastItem[]>([]);
let seq = 0;

export function toast(message: string, type: ToastKind = 'info') {
	const id = ++seq;
	items = [...items, { id, message, type }];
	setTimeout(() => {
		items = items.filter((t) => t.id !== id);
	}, 4200);
}

export function dismissToast(id: number) {
	items = items.filter((t) => t.id !== id);
}

export const toastStore = {
	get items() {
		return items;
	}
};
