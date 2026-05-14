<script lang="ts">
	import { toastStore, dismissToast } from '$lib/stores/toast.svelte';
</script>

<div class="toast toast-end toast-top z-[100] pointer-events-none">
	{#each toastStore.items as t (t.id)}
		<div
			class="alert shadow-lg pointer-events-auto max-w-md {t.type === 'error'
				? 'alert-error'
				: t.type === 'success'
					? 'alert-success'
					: 'alert-info'}"
		>
			<span class="text-sm">{t.message}</span>
			<button
				type="button"
				class="btn btn-ghost btn-xs btn-circle shrink-0"
				aria-label="关闭"
				onclick={() => dismissToast(t.id)}
			>
				✕
			</button>
		</div>
	{/each}
</div>
