<!--
  审计日志页面（数据库操作日志 + 系统操作日志）
  创建时间：2026-05-01
  创建人：Antigravity
-->
<script lang="ts">
	import { api, ApiError } from '$lib/api';
	import { formatDate } from '$lib/utils';
	import { LOG_PAGE_SIZE } from '$lib/constants';
	import Pagination from '$lib/components/Pagination.svelte';
	import CellTip from '$lib/components/CellTip.svelte';
	import { toast } from '$lib/stores/toast.svelte';
	import { authStore } from '$lib/stores/auth.svelte';

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

	// 详情弹窗（替代原生 tooltip，避免长文本错乱）
	let auditDetail = $state<AuditLog | null>(null);
	let sysDetail = $state<SystemLog | null>(null);

	function closeDetail() {
		auditDetail = null;
		sysDetail = null;
	}

	function prettyJson(value: unknown): string {
		if (value == null) return '';
		try {
			return JSON.stringify(value, null, 2);
		} catch {
			return String(value);
		}
	}

	const pageSize = LOG_PAGE_SIZE;

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
		} catch (err) {
			if (err instanceof ApiError && (err.status === 401 || err.status === 403)) return;
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
		} catch (err) {
			if (err instanceof ApiError && (err.status === 401 || err.status === 403)) return;
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
	<div class="tabs tabs-boxed admin-tabs bg-base-200 w-fit mb-5">
		<button
			class="tab {activeTab === 'audit' ? 'tab-active' : ''}"
			onclick={() => switchTab('audit')}
		>
			数据库操作日志
		</button>
		{#if authStore.isAdmin}
			<button
				class="tab {activeTab === 'system' ? 'tab-active' : ''}"
				onclick={() => switchTab('system')}
			>
				系统操作日志
			</button>
		{/if}
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
			<div class="table-admin-wrap overflow-x-auto">
				<table class="table table-zebra table-sm table-admin w-full">
					<thead>
						<tr>
							<th class="admin-th">时间</th>
							<th class="admin-th">访问密钥</th>
							<th class="admin-th">客户端 IP</th>
							<th class="admin-th">操作</th>
							<th class="admin-th">SQL 语句</th>
							<th class="admin-th text-right">行数</th>
							<th class="admin-th text-right">耗时</th>
							<th class="admin-th">状态</th>
							<th class="admin-th text-right">详情</th>
						</tr>
					</thead>
					<tbody>
						{#each auditLogs as log}
							<tr class="hover">
								<td class="text-xs text-base-content/60 whitespace-nowrap">{formatDate(log.timestamp)}</td>
								<td><CellTip value={log.access_key} class="font-mono text-xs" maxWidth="max-w-[10rem]" /></td>
								<td class="text-xs font-mono">{log.client_ip || '-'}</td>
								<td>
									<span class="badge badge-ghost badge-xs">{log.operation}</span>
								</td>
								<td>
									<CellTip value={log.sql_text || '—'} class="font-mono text-xs text-base-content/70" maxWidth="max-w-[16rem]" />
								</td>
								<td class="text-right text-xs">{log.rows_affected ?? '-'}</td>
								<td class="text-right text-xs">{log.duration_ms}ms</td>
								<td>
									{#if log.status === 'success'}
										<span class="badge badge-success badge-xs">成功</span>
									{:else}
										<button
											type="button"
											class="badge badge-error badge-xs cursor-pointer hover:opacity-80"
											onclick={() => (auditDetail = log)}
										>
											失败
										</button>
									{/if}
								</td>
								<td class="text-right">
									<button
										type="button"
										class="btn btn-xs btn-ghost"
										title="查看详情"
										onclick={() => (auditDetail = log)}
									>
										查看
									</button>
								</td>
							</tr>
						{:else}
							<tr>
								<td colspan="9" class="text-center text-base-content/40 py-8">暂无日志记录</td>
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
				<optgroup label="认证">
					<option value="login">用户登录</option>
					<option value="logout">用户登出</option>
					<option value="change_password">修改密码</option>
				</optgroup>
				<optgroup label="用户管理">
					<option value="create_user">创建用户</option>
					<option value="update_user">更新用户</option>
					<option value="delete_user">删除用户</option>
					<option value="reset_password">重置密码</option>
				</optgroup>
				<optgroup label="访问密钥">
					<option value="create_key">创建密钥</option>
					<option value="update_key_description">更新密钥描述</option>
					<option value="toggle_sql_risk_check">切换SQL风险检查</option>
					<option value="toggle_key">启用/禁用密钥</option>
					<option value="delete_key">删除密钥</option>
					<option value="assign_key_users">分配密钥用户</option>
					<option value="remove_key_user">移除密钥用户</option>
				</optgroup>
				<optgroup label="数据库连接">
					<option value="create_connection">创建连接</option>
					<option value="update_connection">更新连接</option>
					<option value="delete_connection">删除连接</option>
					<option value="test_connection">测试连接</option>
				</optgroup>
				<optgroup label="权限">
					<option value="assign_permission">分配权限</option>
					<option value="delete_permission">删除权限</option>
				</optgroup>
				<optgroup label="IP 白名单">
					<option value="add_whitelist">添加白名单</option>
					<option value="delete_whitelist">删除白名单</option>
				</optgroup>
				<optgroup label="大模型配置">
					<option value="update_llm_config">更新大模型配置</option>
					<option value="activate_llm_config">激活大模型配置</option>
				</optgroup>
			</select>
			<select class="select select-bordered select-sm" bind:value={sysFilterResource}>
				<option value="">所有资源类型</option>
				<option value="auth">认证</option>
				<option value="admin_user">管理员用户</option>
				<option value="access_key">访问密钥</option>
				<option value="connection">数据库连接</option>
				<option value="permission">权限</option>
				<option value="whitelist">IP 白名单</option>
				<option value="llm_config">大模型配置</option>
			</select>
			<button class="btn btn-sm btn-primary" onclick={() => loadSys(1)}>查询</button>
			<button class="btn btn-sm btn-ghost" onclick={() => { sysFilterOp = ''; sysFilterResource = ''; loadSys(1); }}>重置</button>
		</div>

		{#if sysLoading}
			<div class="flex justify-center py-12">
				<span class="loading loading-spinner loading-md text-primary"></span>
			</div>
		{:else}
			<div class="table-admin-wrap overflow-x-auto">
				<table class="table table-zebra table-sm table-admin w-full">
					<thead>
						<tr>
							<th class="admin-th">时间</th>
							<th class="admin-th">操作人</th>
							<th class="admin-th">操作类型</th>
							<th class="admin-th">资源类型</th>
							<th class="admin-th">资源 ID</th>
							<th class="admin-th">详情</th>
							<th class="admin-th">客户端 IP</th>
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
									{#if log.details && Object.keys(log.details).length > 0}
										<button
											type="button"
											class="btn btn-xs btn-ghost text-primary"
											onclick={() => (sysDetail = log)}
										>
											查看
										</button>
									{:else}
										<span class="text-xs text-base-content/40">—</span>
									{/if}
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

<!-- 数据库操作日志详情弹窗 -->
{#if auditDetail}
	<div class="modal modal-open z-50">
		<div class="modal-box max-w-3xl max-h-[85vh] overflow-y-auto">
			<h3 class="font-bold text-lg mb-1 flex items-center gap-2 tracking-tight">
				数据库操作日志详情
				{#if auditDetail.status === 'success'}
					<span class="badge badge-success badge-xs">成功</span>
				{:else}
					<span class="badge badge-error badge-xs">失败</span>
				{/if}
			</h3>
			<div class="text-xs text-base-content/50 mb-4">{formatDate(auditDetail.timestamp)}</div>

			<div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4 text-xs">
				<div>
					<div class="text-base-content/50 mb-0.5">访问密钥</div>
					<div class="font-mono break-all">{auditDetail.access_key || '-'}</div>
				</div>
				<div>
					<div class="text-base-content/50 mb-0.5">客户端 IP</div>
					<div class="font-mono">{auditDetail.client_ip || '-'}</div>
				</div>
				<div>
					<div class="text-base-content/50 mb-0.5">操作</div>
					<div class="font-mono">{auditDetail.operation || '-'}</div>
				</div>
				<div>
					<div class="text-base-content/50 mb-0.5">行数 / 耗时</div>
					<div class="font-mono">
						{auditDetail.rows_affected ?? '-'} 行 / {auditDetail.duration_ms}ms
					</div>
				</div>
			</div>

			{#if auditDetail.sql_text}
				<div class="mb-3">
					<div class="text-xs text-base-content/50 mb-1">SQL 语句</div>
					<pre class="bg-base-200 rounded-lg p-3 text-xs font-mono whitespace-pre-wrap break-all max-h-48 overflow-y-auto">{auditDetail.sql_text}</pre>
				</div>
			{/if}

			{#if auditDetail.status === 'error' && auditDetail.error_message}
				<div>
					<div class="text-xs text-error mb-1">错误信息</div>
					<pre class="bg-error/10 border border-error/30 rounded-lg p-3 text-xs font-mono text-error whitespace-pre-wrap break-all max-h-48 overflow-y-auto">{auditDetail.error_message}</pre>
				</div>
			{/if}

			<div class="modal-action">
				<button type="button" class="btn btn-sm" onclick={closeDetail}>关闭</button>
			</div>
		</div>
		<button type="button" class="modal-backdrop" aria-label="关闭" onclick={closeDetail}></button>
	</div>
{/if}

<!-- 系统操作日志详情弹窗 -->
{#if sysDetail}
	<div class="modal modal-open z-50">
		<div class="modal-box max-w-3xl max-h-[85vh] overflow-y-auto">
			<h3 class="font-bold text-lg mb-1 tracking-tight">系统操作日志详情</h3>
			<div class="text-xs text-base-content/50 mb-4">{formatDate(sysDetail.timestamp)}</div>

			<div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4 text-xs">
				<div>
					<div class="text-base-content/50 mb-0.5">操作人</div>
					<div>{sysDetail.username || '-'}</div>
				</div>
				<div>
					<div class="text-base-content/50 mb-0.5">操作类型</div>
					<div class="font-mono">{sysDetail.operation || '-'}</div>
				</div>
				<div>
					<div class="text-base-content/50 mb-0.5">资源类型</div>
					<div class="font-mono">{sysDetail.resource_type || '-'}</div>
				</div>
				<div>
					<div class="text-base-content/50 mb-0.5">客户端 IP</div>
					<div class="font-mono">{sysDetail.client_ip || '-'}</div>
				</div>
			</div>

			{#if sysDetail.details && Object.keys(sysDetail.details).length > 0}
				<div>
					<div class="text-xs text-base-content/50 mb-1">操作详情</div>
					<pre class="bg-base-200 rounded-lg p-3 text-xs font-mono whitespace-pre-wrap break-all max-h-72 overflow-y-auto">{prettyJson(sysDetail.details)}</pre>
				</div>
			{/if}

			<div class="modal-action">
				<button type="button" class="btn btn-sm" onclick={closeDetail}>关闭</button>
			</div>
		</div>
		<button type="button" class="modal-backdrop" aria-label="关闭" onclick={closeDetail}></button>
	</div>
{/if}
