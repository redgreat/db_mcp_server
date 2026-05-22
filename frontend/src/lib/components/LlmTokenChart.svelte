<script lang="ts">
	/** 按日 Token 汇总柱状图（无第三方依赖） */
	export type DayPoint = { day: string; tokens: number; calls?: number };

	let { points = [], loading = false }: { points?: DayPoint[]; loading?: boolean } = $props();

	const maxTokens = $derived(Math.max(1, ...points.map((p) => p.tokens)));
	const totalTokens = $derived(points.reduce((s, p) => s + p.tokens, 0));
</script>

<div class="llm-chart-panel">
	<div class="llm-chart-panel-head">
		<span class="text-sm font-semibold text-base-content">近 14 日 Token 消耗</span>
		<span class="text-xs text-base-content/50">合计 {totalTokens.toLocaleString()} tokens</span>
	</div>

	{#if loading}
		<div class="llm-chart-body flex items-center justify-center">
			<span class="loading loading-spinner loading-md text-primary"></span>
		</div>
	{:else if points.length === 0}
		<div class="llm-chart-body flex items-center justify-center text-sm text-base-content/40">
			暂无调用数据
		</div>
	{:else}
		<div class="llm-chart-body">
			<div class="llm-chart-bars" role="img" aria-label="近14日Token柱状图">
				{#each points as p (p.day)}
					<div class="llm-chart-bar-col" title="{p.day}: {p.tokens.toLocaleString()} tokens">
						<span class="llm-chart-bar-value">{p.tokens >= 1000 ? `${(p.tokens / 1000).toFixed(1)}k` : p.tokens}</span>
						<div
							class="llm-chart-bar-fill"
							style="height: {Math.max(4, (p.tokens / maxTokens) * 100)}%"
						></div>
						<span class="llm-chart-bar-label">{p.day.slice(5)}</span>
					</div>
				{/each}
			</div>
		</div>
	{/if}
</div>
