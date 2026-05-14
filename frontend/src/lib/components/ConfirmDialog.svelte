<script lang="ts">
	let {
		open = false,
		title = '',
		message = '',
		loading = false,
		onconfirm,
		oncancel
	}: {
		open?: boolean;
		title?: string;
		message?: string;
		loading?: boolean;
		onconfirm: () => void | Promise<void>;
		oncancel?: () => void;
	} = $props();
</script>

{#if open}
	<div class="modal modal-open z-50">
		<div class="modal-box max-w-sm">
			<h3 class="font-bold text-base mb-2">{title}</h3>
			<p class="text-sm text-base-content/70 py-2">{message}</p>
			<div class="modal-action mt-4">
				<button type="button" class="btn btn-ghost btn-sm" onclick={() => oncancel?.()}>
					取消
				</button>
				<button type="button" class="btn btn-error btn-sm" disabled={loading} onclick={() => onconfirm()}>
					{#if loading}
						<span class="loading loading-spinner loading-xs"></span>
					{/if}
					确认
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
