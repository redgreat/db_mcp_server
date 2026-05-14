<script lang="ts">
	let {
		total = 0,
		page = 1,
		pageSize = 10,
		onchange
	}: {
		total?: number;
		page?: number;
		pageSize?: number;
		onchange: (p: number) => void;
	} = $props();

	const totalPages = $derived(Math.max(1, Math.ceil(total / pageSize)));
</script>

{#if total > pageSize}
	<div class="flex items-center justify-between gap-4 mt-4 flex-wrap">
		<p class="text-sm text-base-content/60">
			共 <span class="font-medium text-base-content">{total}</span> 条，第
			<span class="font-medium text-base-content">{page}</span> /
			{totalPages} 页
		</p>
		<div class="join">
			<button
				type="button"
				class="join-item btn btn-sm"
				disabled={page <= 1}
				onclick={() => onchange(page - 1)}
			>
				上一页
			</button>
			<button type="button" class="join-item btn btn-sm btn-disabled no-animation">
				{page}
			</button>
			<button
				type="button"
				class="join-item btn btn-sm"
				disabled={page >= totalPages}
				onclick={() => onchange(page + 1)}
			>
				下一页
			</button>
		</div>
	</div>
{/if}
