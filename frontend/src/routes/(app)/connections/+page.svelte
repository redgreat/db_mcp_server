<!--
  连接管理页面
  创建时间：2026-05-01
  创建人：Antigravity
-->
<script lang="ts">
	import { api, ApiError } from '$lib/api';
	import { authStore } from '$lib/stores/auth.svelte';
	import { dbTypeColor, formatDate } from '$lib/utils';
	import { LIST_PAGE_SIZE } from '$lib/constants';
	import Pagination from '$lib/components/Pagination.svelte';
	import CellTip from '$lib/components/CellTip.svelte';
	import RowActions from '$lib/components/RowActions.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import { toast } from '$lib/stores/toast.svelte';

	interface Connection {
		id: number;
		name: string;
		host: string;
		port: number;
		db_type: string;
		database: string;
		username: string;
		password_enc: string;
		description: string;
		created_at: string;
	}

	let connections = $state<Connection[]>([]);
	let total = $state(0);
	let page = $state(1);
	const pageSize = LIST_PAGE_SIZE;
	let loading = $state(false);

	let showConnModal = $state(false);
	let editingConnId = $state<number | null>(null);
	let saveLoading = $state(false);
	let saveError = $state('');
	let testLoading = $state(false);
	let testMessage = $state('');
	let testError = $state('');
	let rowTestingId = $state<number | null>(null);

	const DEFAULT_PORTS: Record<string, string> = {
		mysql: '3306',
		postgresql: '5432',
		mssql: '1433'
	};

	interface DeletePreview {
		connection: {
			id: number;
			name: string;
			host: string;
			port: number;
			db_type: string;
			database: string;
			username: string;
		};
		permission_count: number;
		db_rule_count: number;
		audit_log_count: number;
	}

	let deleteTarget = $state<Connection | null>(null);
	let deletePreview = $state<DeletePreview | null>(null);
	let deletePreviewLoading = $state(false);
	let deleteLoading = $state(false);

	// 表单字段
	let form = $state({
		name: '',
		host: '',
		port: '3306',
		db_type: 'mysql',
		database: '',
		username: '',
		password: '',
		description: ''
	});

	async function load(p = 1) {
		loading = true;
		page = p;
		try {
			const data = await api.get<{ items: Connection[]; total: number }>(
				`/admin/connections?page=${p}&page_size=${pageSize}`
			);
			connections = data.items;
			total = data.total;
		} catch {
			toast('加载连接列表失败', 'error');
		} finally {
			loading = false;
		}
	}

	function openAddModal() {
		editingConnId = null;
		saveError = '';
		resetTestResult();
		resetForm();
		showConnModal = true;
	}

	function openEditModal(conn: Connection) {
		if (!authStore.isAdmin) {
			toast('仅管理员可编辑连接', 'error');
			return;
		}
		editingConnId = conn.id;
		saveError = '';
		resetTestResult();
		form = {
			name: conn.name,
			host: conn.host,
			port: String(conn.port),
			db_type: conn.db_type,
			database: conn.database,
			username: conn.username,
			password: '',
			description: conn.description || ''
		};
		showConnModal = true;
	}

	function closeConnModal() {
		showConnModal = false;
		editingConnId = null;
		saveError = '';
		resetTestResult();
		resetForm();
	}

	async function handleTestConnection() {
		if (!authStore.isAdmin) {
			toast('仅管理员可测试连接', 'error');
			return;
		}
		testLoading = true;
		testMessage = '';
		testError = '';
		try {
			const res = await api.post<{ ok: boolean; message: string }>('/admin/connections/test', {
				host: form.host,
				port: Number(form.port),
				db_type: form.db_type,
				database: form.database,
				username: form.username,
				password: form.password || undefined,
				connection_id: editingConnId ?? undefined
			});
			testMessage = res.message || '连接测试成功';
		} catch (err) {
			testError = err instanceof ApiError ? err.message : '连接测试失败';
		} finally {
			testLoading = false;
		}
	}

	async function handleTestExistingConnection(conn: Connection) {
		if (!authStore.isAdmin) {
			toast('仅管理员可测试连接', 'error');
			return;
		}
		rowTestingId = conn.id;
		try {
			await api.post('/admin/connections/test', {
				host: conn.host,
				port: conn.port,
				db_type: conn.db_type,
				database: conn.database,
				username: conn.username,
				connection_id: conn.id
			});
			toast('连接测试成功', 'success');
		} catch (err) {
			toast(err instanceof ApiError ? err.message : '连接测试失败', 'error');
		} finally {
			rowTestingId = null;
		}
	}

	async function handleSaveConn(e: SubmitEvent) {
		e.preventDefault();
		if (!authStore.isAdmin) {
			toast('仅管理员可管理连接', 'error');
			return;
		}
		saveLoading = true;
		saveError = '';
		const base = {
			name: form.name,
			host: form.host,
			port: form.port,
			db_type: form.db_type,
			database: form.database,
			username: form.username,
			description: form.description
		};
		const reloadPage = editingConnId !== null ? page : 1;
		try {
			if (editingConnId !== null) {
				const params = new URLSearchParams(base);
				if (form.password.trim()) params.set('password', form.password);
				await api.put(`/admin/connections/${editingConnId}?${params}`);
				toast('连接已更新', 'success');
			} else {
				const params = new URLSearchParams({ ...base, password: form.password });
				await api.post(`/admin/connections?${params}`);
				toast('数据库连接创建成功', 'success');
			}
			closeConnModal();
			load(reloadPage);
		} catch (err) {
			saveError = err instanceof ApiError ? err.message : editingConnId !== null ? '更新失败' : '创建失败';
		} finally {
			saveLoading = false;
		}
	}

	async function openDeleteConfirm(conn: Connection) {
		if (!authStore.isAdmin) {
			toast('仅管理员可删除连接', 'error');
			return;
		}
		deleteTarget = conn;
		deletePreview = null;
		deletePreviewLoading = true;
		try {
			deletePreview = await api.get<DeletePreview>(
				`/admin/connections/${conn.id}/delete-preview`
			);
		} catch (err) {
			deleteTarget = null;
			toast(err instanceof ApiError ? err.message : '无法加载删除预览', 'error');
		} finally {
			deletePreviewLoading = false;
		}
	}

	function closeDeleteConfirm() {
		deleteTarget = null;
		deletePreview = null;
		deletePreviewLoading = false;
	}

	async function handleDelete() {
		if (!deleteTarget || !authStore.isAdmin) return;
		deleteLoading = true;
		try {
			await api.delete(`/admin/connections/${deleteTarget.id}`);
			closeDeleteConfirm();
			toast('连接已删除', 'success');
			load(page);
		} catch (err) {
			toast(err instanceof ApiError ? err.message : '删除失败', 'error');
		} finally {
			deleteLoading = false;
		}
	}

	function resetForm() {
		form = { name: '', host: '', port: '3306', db_type: 'mysql', database: '', username: '', password: '', description: '' };
	}

	function handleDbTypeChange(nextType: string) {
		const prevType = form.db_type;
		const prevDefaultPort = DEFAULT_PORTS[prevType] ?? '3306';
		const nextDefaultPort = DEFAULT_PORTS[nextType] ?? form.port;
		const shouldReplacePort = editingConnId === null || form.port === prevDefaultPort || !form.port.trim();
		form = {
			...form,
			db_type: nextType,
			port: shouldReplacePort ? nextDefaultPort : form.port
		};
	}

	function resetTestResult() {
		testLoading = false;
		testMessage = '';
		testError = '';
		rowTestingId = null;
	}

	load();
</script>

<svelte:head>
	<title>连接管理 - DB MCP Server</title>
</svelte:head>

<div class="fade-in">
	<!-- 页头 -->
	<div class="flex items-center justify-between mb-6">
		<div>
			<h1 class="text-2xl font-bold tracking-tight">连接管理</h1>
		</div>
		{#if authStore.isAdmin}
			<button class="btn btn-primary btn-sm gap-2" onclick={openAddModal}>
				<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.5v15m7.5-7.5h-15" />
				</svg>
				添加连接
			</button>
		{/if}
	</div>

	{#if loading}
		<div class="flex justify-center items-center py-20">
			<span class="loading loading-spinner loading-lg text-primary"></span>
		</div>
	{:else}
		<div class="table-admin-wrap overflow-x-auto">
			<table class="table table-zebra table-sm table-admin w-full">
				<thead>
					<tr>
						<th class="admin-th w-14">ID</th>
						<th class="admin-th">名称</th>
						<th class="admin-th">类型</th>
						<th class="admin-th">主机</th>
						<th class="admin-th w-16">端口</th>
						<th class="admin-th">数据库</th>
						<th class="admin-th">用户名</th>
						<th class="admin-th">密码</th>
						<th class="admin-th">描述</th>
						<th class="admin-th">创建时间</th>
						{#if authStore.isAdmin}
							<th class="admin-th col-actions">操作</th>
						{/if}
					</tr>
				</thead>
				<tbody>
					{#each connections as conn}
						<tr class="hover">
							<td class="text-base-content/50 font-mono text-xs">{conn.id}</td>
							<td class="font-medium"><CellTip value={conn.name} maxWidth="max-w-[10rem]" /></td>
							<td>
								<span class="badge badge-sm {dbTypeColor(conn.db_type)}">{conn.db_type}</span>
							</td>
							<td class="font-mono text-xs"><CellTip value={conn.host} maxWidth="max-w-[14rem]" /></td>
							<td class="font-mono text-xs">{conn.port}</td>
							<td class="font-mono text-xs"><CellTip value={conn.database} maxWidth="max-w-[8rem]" /></td>
							<td class="text-xs"><CellTip value={conn.username} maxWidth="max-w-[8rem]" /></td>
							<td class="text-xs text-base-content/50">已加密</td>
							<td class="text-xs text-base-content/50">
								<CellTip value={conn.description || '—'} maxWidth="max-w-[8rem]" />
							</td>
							<td class="text-xs text-base-content/50 whitespace-nowrap">{formatDate(conn.created_at)}</td>
							{#if authStore.isAdmin}
								<td class="col-actions">
									<RowActions>
										<button
											type="button"
											class="btn-act btn-act-success"
											disabled={rowTestingId === conn.id}
											onclick={() => handleTestExistingConnection(conn)}
										>
											{rowTestingId === conn.id ? '测试中' : '测试'}
										</button>
										<button type="button" class="btn-act btn-act-primary" onclick={() => openEditModal(conn)}>编辑</button>
										<button type="button" class="btn-act btn-act-error" onclick={() => openDeleteConfirm(conn)}>删除</button>
									</RowActions>
								</td>
							{/if}
						</tr>
					{:else}
						<tr>
							<td colspan={authStore.isAdmin ? 11 : 10} class="text-center text-base-content/40 py-12">
								暂无连接配置
								{#if authStore.isAdmin}
									<button class="btn btn-primary btn-sm mt-3 block mx-auto" onclick={openAddModal}>
										添加连接
									</button>
								{/if}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
		<Pagination {total} {page} {pageSize} onchange={load} />
	{/if}
</div>

<!-- 添加 / 编辑连接 Modal -->
{#if showConnModal}
	<div class="modal modal-open">
		<div class="modal-box max-w-md">
			<h3 class="font-bold text-lg mb-4 tracking-tight">
				{editingConnId !== null ? '编辑数据库连接' : '添加数据库连接'}
			</h3>
			<form onsubmit={handleSaveConn}>
				<div class="grid grid-cols-2 gap-3">
					<div class="form-control col-span-2">
						<label class="label pb-1 text-sm" for="conn-name">名称</label>
						<input id="conn-name" type="text" class="input input-bordered input-sm"
							placeholder="如：生产MySQL" bind:value={form.name} required />
					</div>
					<div class="form-control">
						<label class="label pb-1 text-sm" for="conn-host">主机</label>
						<input id="conn-host" type="text" class="input input-bordered input-sm"
							placeholder="127.0.0.1" bind:value={form.host} required />
					</div>
					<div class="form-control">
						<label class="label pb-1 text-sm" for="conn-port">端口</label>
						<input id="conn-port" type="number" class="input input-bordered input-sm"
							bind:value={form.port} required />
					</div>
					<div class="form-control">
						<label class="label pb-1 text-sm" for="conn-type">类型</label>
						<select
							id="conn-type"
							class="select select-bordered select-sm"
							bind:value={form.db_type}
							onchange={(e) => handleDbTypeChange((e.currentTarget as HTMLSelectElement).value)}
						>
							<option value="mysql">MySQL</option>
							<option value="postgresql">PostgreSQL</option>
							<option value="mssql">SQL Server</option>
						</select>
					</div>
					<div class="form-control">
						<label class="label pb-1 text-sm" for="conn-db">数据库名</label>
						<input id="conn-db" type="text" class="input input-bordered input-sm"
							bind:value={form.database} required />
					</div>
					<div class="form-control">
						<label class="label pb-1 text-sm" for="conn-user">用户名</label>
						<input id="conn-user" type="text" class="input input-bordered input-sm"
							bind:value={form.username} required />
					</div>
					<div class="form-control">
						<label class="label pb-1 text-sm" for="conn-pwd">密码</label>
						<input id="conn-pwd" type="password" class="input input-bordered input-sm"
							bind:value={form.password}
							required={editingConnId === null}
							placeholder={editingConnId !== null ? '留空表示不修改密码' : ''} />
					</div>
					<div class="form-control col-span-2">
						<label class="label pb-1 text-sm" for="conn-desc">描述（可选）</label>
						<input id="conn-desc" type="text" class="input input-bordered input-sm"
							placeholder="连接用途说明" bind:value={form.description} />
					</div>
				</div>
				{#if testMessage}
					<div class="alert alert-success py-2 px-3 mt-3 text-sm"><span>{testMessage}</span></div>
				{/if}
				{#if testError}
					<div class="alert alert-error py-2 px-3 mt-3 text-sm"><span>{testError}</span></div>
				{/if}
				{#if saveError}
					<div class="alert alert-error py-2 px-3 mt-3 text-sm"><span>{saveError}</span></div>
				{/if}
				<div class="modal-action mt-4 justify-between">
					<button type="button" class="btn btn-outline btn-sm" onclick={handleTestConnection} disabled={testLoading || saveLoading}>
						{#if testLoading}<span class="loading loading-spinner loading-xs"></span>{/if}
						测试连接
					</button>
					<div class="flex gap-2">
						<button type="button" class="btn btn-ghost btn-sm" onclick={closeConnModal}>
							取消
						</button>
						<button type="submit" class="btn btn-primary btn-sm" disabled={saveLoading || testLoading}>
							{#if saveLoading}<span class="loading loading-spinner loading-xs"></span>{/if}
							{editingConnId !== null ? '保存' : '创建连接'}
						</button>
					</div>
				</div>
			</form>
		</div>
		<button type="button" class="modal-backdrop" aria-label="关闭" onclick={closeConnModal}></button>
	</div>
{/if}

<!-- 删除确认 -->
<ConfirmDialog
	open={!!deleteTarget}
	title="确认删除数据库连接"
	message="此操作不可撤销。请确认以下连接及关联数据处理方式："
	maxWidth="max-w-md"
	confirmLabel="确认删除"
	bodyLoading={deletePreviewLoading}
	loading={deleteLoading}
	onconfirm={handleDelete}
	oncancel={closeDeleteConfirm}
>
	{#if deletePreview}
		<div class="rounded-lg border border-base-300 bg-base-200/80 p-3 text-sm space-y-1">
			<div class="font-semibold text-base">{deletePreview.connection.name}</div>
			<div class="text-base-content/60 font-mono text-xs">
				ID {deletePreview.connection.id} · {deletePreview.connection.db_type} ·
				{deletePreview.connection.host}:{deletePreview.connection.port} / {deletePreview.connection.database}
			</div>
			<div class="text-base-content/55 text-xs">用户 {deletePreview.connection.username}</div>
		</div>
		<div class="mt-4 space-y-2 text-sm">
			<p class="font-medium text-base-content/80">将执行以下操作：</p>
			<ul class="list-disc list-inside space-y-1.5 text-base-content/70 pl-0.5">
				<li><span class="text-error font-medium">删除</span> 本条数据库连接配置</li>
				<li>
					<span class="text-error font-medium">删除</span> 访问密钥上的授权
					<strong class="text-base-content">{deletePreview.permission_count}</strong> 条
				</li>
				{#if deletePreview.db_rule_count > 0}
					<li>
						<span class="text-error font-medium">删除</span> 数据库规则文档
						<strong class="text-base-content">{deletePreview.db_rule_count}</strong> 条
					</li>
				{:else}
					<li class="text-base-content/50">无关联的数据库规则文档</li>
				{/if}
				{#if deletePreview.audit_log_count > 0}
					<li>
						<span class="text-warning font-medium">保留</span> 历史审计日志
						<strong class="text-base-content">{deletePreview.audit_log_count}</strong> 条（仅解除与本连接的关联，不删记录）
					</li>
				{:else}
					<li class="text-base-content/50">无需要解除关联的审计日志</li>
				{/if}
			</ul>
		</div>
	{/if}
</ConfirmDialog>
