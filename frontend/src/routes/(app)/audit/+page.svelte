<!--
  审计日志页面（数据库操作日志 + 系统操作日志）
  创建时间：2026-05-01
  创建人：Antigravity
-->
<script lang="ts">
	import { api } from '$lib/api';
	import { formatDate, truncate } from '$lib/utils';
	import Pagination from '$lib/components/Pagination.svelte';
	import { toast } from '$lib/stores/toast.svelte';

	type LogTab = 'audit' | 'system';

	interface AuditLog {
		id: number;
		timestamp: string;
		access_key: string;
		client_ip: string;
		operation: string;
		sql_text: string;
		rows_affected: number | null;
		duration_ms: number;
		status: 'success' | 'error';
		error_message: string | null;
	}

	interface SystemLog {
		id: number;
		timestamp: string;
		username: string;
		operation: string;
		resource_type: string;
		resource_id: number | null;
		details: Record<string, unknown>;
		client_ip: string;
	}

	let activeTab = $state<LogTab>('audit');

	// 审计日志
	let auditLogs = $state<AuditLog[]>([]);
	let auditTotal = $state(0);
	let auditPage = $state(1);
	let auditLoading = $state(false);
	let filterKey = $state('');
	let filterOp = $state('');

	// 系统日志
	let sysLogs = $state<SystemLog[]>([]);
	let sysTotal = $state(0);
	let sysPage = $state(1);
	let sysLoading = $state(false);
	let sysFilterOp = $state('');
	let sysFilterResource = $state('');

	const pageSize = 20;

	async function loadAudit(p = 1) {
		auditLoading = true;
		auditPage = p;
		const params = new URLSearchParams({ page: String(p), page_size: String(pageSize) });
		if (filterKey) params.set('access_key', filterKey);
		if (filterOp) params.set('operation', filterOp);
		try {
			const data = await api.get<{ items: AuditLog[]; total: number }>(`/admin/audit/logs?${params}`);
			auditLogs = data.items;
			auditTotal = data.total;
		} catch {
			toast('加载审计日志失败', 'error');
		} finally {
			auditLoading = false;
		}
	}

	async function loadSys(p = 1) {
		sysLoading = true;
		sysPage = p;
		const params = new URLSearchParams({ page: String(p), page_size: String(pageSize) });
		if (sysFilterOp) params.set('operation', sysFilterOp);
		if (sysFilterResource) params.set('resource_type', sysFilterResource);
		try {
			const data = await api.get<{ items: SystemLog[]; total: number }>(`/admin/system/logs?${params}`);
			sysLogs = data.items;
			sysTotal = data.total;
		} catch {
			toast('加载系统日志失败', 'error');
		} finally {
			sysLoading = false;
		}
	}

	function switchTab(tab: LogTab) {
		activeTab = tab;
		if (tab === 'audit' && auditLogs.length === 0) loadAudit();
		if (tab === 'system' && sysLogs.length === 0) loadSys();
	}

	loadAudit();
</script>

<svelte:head>
	<title>审计日志 - DB MCP Server</title>
</svelte:head>

<div class="fade-in">
	<div class="mb-6">
		<h1 class="text-2xl font-bold tracking-tight">审计日志</h1>
	</div>

	<!-- Tab 切换 -->
	<div class="tabs tabs-boxed bg-base-200 w-fit mb-5">
		<button
			class="tab {activeTab === 'audit' ? 'tab-active' : ''}"
			onclick={() => switchTab('audit')}
		>
			数据库操作日志
		</button>
		<button
			class="tab {activeTab === 'system' ? 'tab-active' : ''}"
			onclick={() => switchTab('system')}
		>
			系统操作日志
		</button>
	</div>

	<!-- 数据库操作日志 -->
	{#if activeTab === 'audit'}
		<!-- 过滤器 -->
		<div class="flex flex-wrap gap-2 mb-4">
			<input
				type="text"
				class="input input-bordered input-sm w-44"
				placeholder="访问密钥"
				bind:value={filterKey}
			/>
			<select class="select select-bordered select-sm" bind:value={filterOp}>
				<option value="">所有操作</option>
				<option value="query">查询</option>
				<option value="sse_query">SSE查询</option>
				<option value="metadata_tables">表列表</option>
				<option value="metadata_table_info">表结构</option>
			</select>
			<button class="btn btn-sm btn-primary" onclick={() => loadAudit(1)}>查询</button>
			<button class="btn btn-sm btn-ghost" onclick={() => { filterKey = ''; filterOp = ''; loadAudit(1); }}>重置</button>
		</div>

		{#if auditLoading}
			<div class="flex justify-center py-12">
				<span class="loading loading-spinner loading-md text-primary"></span>
			</div>
		{:else}
			<div class="overflow-x-auto">
				<table class="table table-zebra table-sm">
					<thead>
						<tr class="text-xs text-base-content/60">
							<th>时间</th>
							<th>访问密钥</th>
							<th>客户端 IP</th>
							<th>操作</th>
							<th>SQL 语句</th>
							<th class="text-right">行数</th>
							<th class="text-right">耗时</th>
							<th>状态</th>
						</tr>
					</thead>
					<tbody>
						{#each auditLogs as log}
							<tr class="hover">
								<td class="text-xs text-base-content/60 whitespace-nowrap">{formatDate(log.timestamp)}</td>
								<td><code class="text-xs">{truncate(log.access_key, 20)}</code></td>
								<td class="text-xs font-mono">{log.client_ip || '-'}</td>
								<td>
									<span class="badge badge-ghost badge-xs">{log.operation}</span>
								</td>
								<td>
									<div class="tooltip tooltip-bottom" data-tip={log.sql_text || ''}>
										<code class="text-xs text-base-content/70">{truncate(log.sql_text, 40)}</code>
									</div>
								</td>
								<td class="text-right text-xs">{log.rows_affected ?? '-'}</td>
								<td class="text-right text-xs">{log.duration_ms}ms</td>
								<td>
									{#if log.status === 'success'}
										<span class="badge badge-success badge-xs">成功</span>
									{:else}
										<div class="tooltip tooltip-left" data-tip={log.error_message || ''}>
											<span class="badge badge-error badge-xs">失败</span>
										</div>
									{/if}
								</td>
							</tr>
						{:else}
							<tr>
								<td colspan="8" class="text-center text-base-content/40 py-8">暂无日志记录</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
			<Pagination total={auditTotal} page={auditPage} {pageSize} onchange={loadAudit} />
		{/if}
	{/if}

	<!-- 系统操作日志 -->
	{#if activeTab === 'system'}
		<div class="flex flex-wrap gap-2 mb-4">
			<select class="select select-bordered select-sm" bind:value={sysFilterOp}>
				<option value="">所有操作</option>
				<option value="create_key">创建密钥</option>
				<option value="delete_key">删除密钥</option>
				<option value="toggle_key">启用/禁用密钥</option>
				<option value="assign_permission">分配权限</option>
				<option value="delete_permission">删除权限</option>
				<option value="add_whitelist">添加白名单</option>
				<option value="delete_whitelist">删除白名单</option>
				<option value="create_connection">创建连接</option>
				<option value="delete_connection">删除连接</option>
				<option value="create_user">创建用户</option>
				<option value="delete_user">删除用户</option>
				<option value="update_user">更新用户</option>
				<option value="reset_password">重置密码</option>
			</select>
			<select class="select select-bordered select-sm" bind:value={sysFilterResource}>
				<option value="">所有资源类型</option>
				<option value="access_key">访问密钥</option>
				<option value="permission">权限</option>
				<option value="whitelist">IP 白名单</option>
				<option value="connection">数据库连接</option>
				<option value="admin_user">管理员用户</option>
			</select>
			<button class="btn btn-sm btn-primary" onclick={() => loadSys(1)}>查询</button>
			<button class="btn btn-sm btn-ghost" onclick={() => { sysFilterOp = ''; sysFilterResource = ''; loadSys(1); }}>重置</button>
		</div>

		{#if sysLoading}
			<div class="flex justify-center py-12">
				<span class="loading loading-spinner loading-md text-primary"></span>
			</div>
		{:else}
			<div class="overflow-x-auto">
				<table class="table table-zebra table-sm">
					<thead>
						<tr class="text-xs text-base-content/60">
							<th>时间</th>
							<th>操作人</th>
							<th>操作类型</th>
							<th>资源类型</th>
							<th>资源 ID</th>
							<th>详情</th>
							<th>客户端 IP</th>
						</tr>
					</thead>
					<tbody>
						{#each sysLogs as log}
							<tr class="hover">
								<td class="text-xs text-base-content/60 whitespace-nowrap">{formatDate(log.timestamp)}</td>
								<td class="font-medium text-sm">{log.username || '-'}</td>
								<td><span class="badge badge-ghost badge-xs">{log.operation}</span></td>
								<td class="text-xs">{log.resource_type}</td>
								<td class="text-xs text-base-content/60">{log.resource_id ?? '-'}</td>
								<td>
									<div class="tooltip tooltip-bottom" data-tip={JSON.stringify(log.details || {})}>
										<code class="text-xs text-base-content/60">{truncate(JSON.stringify(log.details || {}), 45)}</code>
									</div>
								</td>
								<td class="text-xs font-mono">{log.client_ip || '-'}</td>
							</tr>
						{:else}
							<tr>
								<td colspan="7" class="text-center text-base-content/40 py-8">暂无日志记录</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
			<Pagination total={sysTotal} page={sysPage} {pageSize} onchange={loadSys} />
		{/if}
	{/if}
</div>
