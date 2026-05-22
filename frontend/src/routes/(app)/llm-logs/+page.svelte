<script lang="ts">
	import { onMount } from 'svelte';
	import { api, ApiError } from '$lib/api';
	import { formatDate } from '$lib/utils';
	import { LIST_PAGE_SIZE } from '$lib/constants';
	import Pagination from '$lib/components/Pagination.svelte';
	import CellTip from '$lib/components/CellTip.svelte';
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
	let logs = $state<CallLog[]>([]);
	let total = $state(0);
	let page = $state(1);
	let loading = $state(true);
	let filterKey = $state('');
	const pageSize = LIST_PAGE_SIZE;

	async function loadDaily() {
		try {
			const res = await api.get<{ items: DailyRow[] }>('/admin/llm_call_logs/daily?days=14');
			daily = res.items;
		} catch {
			toast('加载每日汇总失败', 'error');
		}
	}

	async function loadLogs(p = 1) {
		loading = true;
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
			loading = false;
		}
	}

	onMount(() => {
		loadDaily();
		loadLogs(1);
	});

	function maskKey(k: string | null) {
		if (!k) return '—';
		if (k.length <= 10) return k;
		return `${k.slice(0, 8)}…`;
	}
</script>

<svelte:head>
	<title>大模型调用日志 - DB MCP Server</title>
</svelte:head>

<div class="fade-in">
	<div class="mb-6">
		<h1 class="text-2xl font-bold tracking-tight">大模型调用日志</h1>
	</div>

	<h2 class="text-sm font-semibold text-base-content/70 mb-2">近 14 日 Token 汇总</h2>
	<div class="table-admin-wrap overflow-x-auto mb-8">
		<table class="table table-zebra table-sm table-admin w-full">
			<thead>
				<tr>
					<th>日期</th>
					<th>访问密钥</th>
					<th>提供商</th>
					<th>模型</th>
					<th class="text-right">调用次数</th>
					<th class="text-right">输入 Token</th>
					<th class="text-right">输出 Token</th>
					<th class="text-right">合计</th>
				</tr>
			</thead>
			<tbody>
				{#each daily as row}
					<tr class="hover">
						<td class="whitespace-nowrap">{row.day}</td>
						<td><CellTip value={maskKey(row.access_key)} maxWidth="max-w-[10rem]" /></td>
						<td>{row.provider}</td>
						<td><CellTip value={row.model_name} maxWidth="max-w-[10rem]" /></td>
						<td class="text-right font-mono text-xs">{row.call_count}</td>
						<td class="text-right font-mono text-xs">{row.prompt_tokens}</td>
						<td class="text-right font-mono text-xs">{row.completion_tokens}</td>
						<td class="text-right font-mono text-xs font-medium">{row.total_tokens}</td>
					</tr>
				{:else}
					<tr>
						<td colspan="8" class="text-center text-base-content/40 py-6">暂无调用记录</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>

	<h2 class="text-sm font-semibold text-base-content/70 mb-2">调用明细</h2>
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

	{#if loading}
		<div class="flex justify-center py-12">
			<span class="loading loading-spinner loading-lg text-primary"></span>
		</div>
	{:else}
		<div class="table-admin-wrap overflow-x-auto">
			<table class="table table-zebra table-sm table-admin w-full">
				<thead>
					<tr>
						<th>时间</th>
						<th>访问密钥</th>
						<th>来源</th>
						<th>工具</th>
						<th>提供商 / 模型</th>
						<th class="text-right">Token</th>
						<th class="text-right">耗时</th>
						<th>状态</th>
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
		<Pagination {total} {page} {pageSize} onchange={loadLogs} />
	{/if}
</div>
