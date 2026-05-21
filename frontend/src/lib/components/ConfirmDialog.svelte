<script lang="ts">
	import type { Snippet } from 'svelte';

	let {
		open = false,
		title = '',
		message = '',
		loading = false,
		bodyLoading = false,
		confirmLabel = '确认',
		confirmClass = 'btn-error',
		maxWidth = 'max-w-sm',
		onconfirm,
		oncancel,
		children
	}: {
		open?: boolean;
		title?: string;
		message?: string;
		loading?: boolean;
		bodyLoading?: boolean;
		confirmLabel?: string;
		confirmClass?: string;
		maxWidth?: string;
		onconfirm: () => void | Promise<void>;
		oncancel?: () => void;
		children?: Snippet;
	} = $props();
</script>

{#if open}
	<div class="modal modal-open z-50">
		<div class="modal-box {maxWidth}">
			<h3 class="font-bold text-lg mb-2 tracking-tight">{title}</h3>
			{#if message}
				<p class="text-sm text-base-content/70">{message}</p>
			{/if}
			<div class="mt-3">
				{#if bodyLoading}
					<div class="flex justify-center py-6">
						<span class="loading loading-spinner loading-md text-primary"></span>
					</div>
				{:else if children}
					{@render children()}
				{/if}
			</div>
			<div class="modal-action mt-4">
				<button type="button" class="btn btn-ghost btn-sm" disabled={loading} onclick={() => oncancel?.()}>
					取消
				</button>
				<button
					type="button"
					class="btn btn-sm {confirmClass}"
					disabled={loading || bodyLoading}
					onclick={() => onconfirm()}
				>
					{#if loading}
						<span class="loading loading-spinner loading-xs"></span>
					{/if}
					{confirmLabel}
				</button>
			</div>
		</div>
		<button
			type="button"
			class="modal-backdrop"
			aria-label="关闭"
			onclick={() => oncancel?.()}
		></button>
	</div>
{/if}
