<script lang="ts">
	import { onMount } from 'svelte';
	import { api, ApiError } from '$lib/api';
	import { formatDate } from '$lib/utils';
	import { LIST_PAGE_SIZE } from '$lib/constants';
	import Pagination from '$lib/components/Pagination.svelte';
	import CellTip from '$lib/components/CellTip.svelte';
	import LlmTokenChart, { type DayPoint } from '$lib/components/LlmTokenChart.svelte';
	import { toast } from '$lib/stores/toast.svelte';

	interface DailyRow {
		day: string;
		access_key: string | null;
		provider: string;
		model_name: string;
		call_count: number;
		prompt_tokens: number;
		completion_tokens: number;
		total_tokens: number;
	}

	interface CallLog {
		id: number;
		timestamp: string;
		provider: string;
		model_name: string;
		access_key: string | null;
		call_source: string;
		tool_name: string | null;
		connection_id: number | null;
		prompt_tokens: number;
		completion_tokens: number;
		total_tokens: number;
		duration_ms: number | null;
		status: string;
		error_message: string | null;
	}

	let daily = $state<DailyRow[]>([]);
	let chartPoints = $state<DayPoint[]>([]);
	let chartLoading = $state(true);
	let logs = $state<CallLog[]>([]);
	let total = $state(0);
	let page = $state(1);
	let logsLoading = $state(false);
	let filterKey = $state('');
	const pageSize = LIST_PAGE_SIZE;

	function buildChartPoints(rows: DailyRow[]): DayPoint[] {
		const map = new Map<string, { tokens: number; calls: number }>();
		for (const r of rows) {
			const d = (r.day || '').slice(0, 10);
			if (!d) continue;
			const cur = map.get(d) || { tokens: 0, calls: 0 };
			cur.tokens += r.total_tokens || 0;
			cur.calls += r.call_count || 0;
			map.set(d, cur);
		}
		return [...map.entries()]
			.sort((a, b) => a[0].localeCompare(b[0]))
			.map(([day, v]) => ({ day, tokens: v.tokens, calls: v.calls }));
	}

	async function loadDaily() {
		chartLoading = true;
		try {
			const res = await api.get<{ items: DailyRow[] }>('/admin/llm_call_logs/daily?days=14');
			daily = res.items;
			chartPoints = buildChartPoints(res.items);
		} catch {
			toast('加载每日汇总失败', 'error');
			chartPoints = [];
		} finally {
			chartLoading = false;
		}
	}

	async function loadLogs(p = 1) {
		logsLoading = true;
		page = p;
		const params = new URLSearchParams({
			page: String(p),
			page_size: String(pageSize)
		});
		if (filterKey.trim()) params.set('access_key', filterKey.trim());
		try {
			const res = await api.get<{ items: CallLog[]; total: number }>(
				`/admin/llm_call_logs?${params}`
			);
			logs = res.items;
			total = res.total;
		} catch (err) {
			toast(err instanceof ApiError ? err.message : '加载失败', 'error');
		} finally {
			logsLoading = false;
		}
	}

	onMount(() => {
		loadDaily();
		loadLogs(1);
	});
</script>

<svelte:head>
	<title>大模型调用日志 - DB MCP Server</title>
</svelte:head>

<div class="fade-in">
	<div class="mb-6">
		<h1 class="text-2xl font-bold tracking-tight">大模型调用日志</h1>
	</div>

	<LlmTokenChart points={chartPoints} loading={chartLoading} />

	<h2 class="text-sm font-semibold text-base-content/80 mb-2 mt-2">调用明细</h2>
	<div class="flex flex-wrap gap-2 mb-4">
		<input
			type="text"
			class="input input-bordered input-sm w-48"
			placeholder="筛选访问密钥"
			bind:value={filterKey}
		/>
		<button class="btn btn-sm btn-primary" onclick={() => loadLogs(1)}>查询</button>
		<button class="btn btn-sm btn-ghost" onclick={() => { filterKey = ''; loadLogs(1); }}>重置</button>
	</div>

	{#if logsLoading}
		<div class="flex justify-center py-12">
			<span class="loading loading-spinner loading-lg text-primary"></span>
		</div>
	{:else}
		<div class="table-admin-wrap overflow-x-auto">
			<table class="table table-zebra table-sm table-admin w-full">
				<thead>
					<tr>
						<th class="admin-th">时间</th>
						<th class="admin-th">访问密钥</th>
						<th class="admin-th">来源</th>
						<th class="admin-th">工具</th>
						<th class="admin-th">提供商 / 模型</th>
						<th class="admin-th text-right">Token</th>
						<th class="admin-th text-right">耗时</th>
						<th class="admin-th">状态</th>
					</tr>
				</thead>
				<tbody>
					{#each logs as log}
						<tr class="hover">
							<td class="whitespace-nowrap text-base-content/70">{formatDate(log.timestamp)}</td>
							<td><CellTip value={log.access_key || '—'} maxWidth="max-w-[9rem]" /></td>
							<td><span class="badge badge-ghost badge-xs">{log.call_source}</span></td>
							<td><CellTip value={log.tool_name || '—'} maxWidth="max-w-[8rem]" /></td>
							<td>
								<CellTip value={`${log.provider} / ${log.model_name}`} maxWidth="max-w-[12rem]" />
							</td>
							<td class="text-right font-mono text-xs whitespace-nowrap">
								{log.total_tokens}
								<span class="text-base-content/45 text-[0.7rem]">
									({log.prompt_tokens}+{log.completion_tokens})
								</span>
							</td>
							<td class="text-right text-xs">{log.duration_ms != null ? `${log.duration_ms}ms` : '—'}</td>
							<td>
								{#if log.status === 'success'}
									<span class="badge badge-success badge-xs">成功</span>
								{:else}
									<span class="badge badge-error badge-xs" title={log.error_message || ''}>失败</span>
								{/if}
							</td>
						</tr>
					{:else}
						<tr>
							<td colspan="8" class="text-center text-base-content/40 py-8">暂无明细</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
	<Pagination {total} {page} {pageSize} onchange={loadLogs} />
</div>
