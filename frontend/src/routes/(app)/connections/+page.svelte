<!--
  连接管理页面
  创建时间：2026-05-01
  创建人：Antigravity
-->
<script lang="ts">
	import { api, ApiError } from '$lib/api';
	import { authStore } from '$lib/stores/auth.svelte';
	import { dbTypeColor } from '$lib/utils';
	import Pagination from '$lib/components/Pagination.svelte';
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
	const pageSize = 10;
	let loading = $state(false);

	let showConnModal = $state(false);
	let editingConnId = $state<number | null>(null);
	let saveLoading = $state(false);
	let saveError = $state('');

	let deleteId = $state<number | null>(null);
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
		resetForm();
		showConnModal = true;
	}

	function openEditModal(conn: Connection) {
		editingConnId = conn.id;
		saveError = '';
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
		resetForm();
	}

	async function handleSaveConn(e: SubmitEvent) {
		e.preventDefault();
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

	async function handleDelete() {
		if (!deleteId) return;
		deleteLoading = true;
		try {
			await api.delete(`/admin/connections/${deleteId}`);
			deleteId = null;
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

	<!-- 连接卡片网格 -->
	{#if loading}
		<div class="flex justify-center items-center py-20">
			<span class="loading loading-spinner loading-lg text-primary"></span>
		</div>
	{:else if connections.length === 0}
		<div class="flex flex-col items-center justify-center py-20 text-base-content/40">
			<svg class="w-12 h-12 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1" d="M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375" />
			</svg>
			<p class="text-sm">暂无连接配置</p>
			{#if authStore.isAdmin}
				<button class="btn btn-primary btn-sm mt-3" onclick={openAddModal}>添加第一个连接</button>
			{/if}
		</div>
	{:else}
		<div class="grid gap-4 grid-cols-1 md:grid-cols-2 xl:grid-cols-3">
			{#each connections as conn}
				<div class="card bg-base-200 border border-base-300 hover:border-primary/30 hover:shadow-md transition-all">
					<div class="card-body p-4">
						<div class="flex items-start justify-between mb-2">
							<div class="flex-1 min-w-0">
								<h3 class="text-base font-semibold tracking-tight truncate">{conn.name}</h3>
								<p class="text-xs text-base-content/55 mt-0.5 truncate font-mono">
									{conn.host}:{conn.port} / <code class="text-xs">{conn.database}</code>
								</p>
							</div>
							<span class="badge badge-sm {dbTypeColor(conn.db_type)} ml-2 flex-shrink-0">
								{conn.db_type}
							</span>
						</div>

						<div class="flex items-center gap-2 text-xs text-base-content/55">
							<svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.75 6a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0ZM4.501 20.118a7.5 7.5 0 0 1 14.998 0A17.933 17.933 0 0 1 12 21.75c-2.676 0-5.216-.584-7.499-1.632Z" />
							</svg>
							<span>{conn.username}</span>
							<span class="text-base-content/20">·</span>
							<span class="text-base-content/30">密码已加密</span>
						</div>

						{#if conn.description}
							<p class="text-xs text-base-content/45 mt-1 line-clamp-2">{conn.description}</p>
						{/if}

						{#if authStore.isAdmin}
							<div class="card-actions justify-end gap-1 mt-3 pt-3 border-t border-base-300">
								<button
									type="button"
									class="btn btn-ghost btn-xs gap-1"
									onclick={() => openEditModal(conn)}
								>
									<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
										<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="m16.862 4.487 1.687-1.688a1.875 1.875 0 1 1 2.652 2.652L10.582 16.07a4.5 4.5 0 0 1-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 0 1 1.13-1.897l8.932-8.931Zm0 0L19.5 7.125" />
									</svg>
									编辑
								</button>
								<button
									class="btn btn-error btn-xs btn-outline gap-1"
									onclick={() => (deleteId = conn.id)}
								>
									<svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
										<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="m14.74 9-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 0-7.5 0" />
									</svg>
									删除
								</button>
							</div>
						{/if}
					</div>
				</div>
			{/each}
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
						<select id="conn-type" class="select select-bordered select-sm" bind:value={form.db_type}>
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
				{#if saveError}
					<div class="alert alert-error py-2 px-3 mt-3 text-sm"><span>{saveError}</span></div>
				{/if}
				<div class="modal-action mt-4">
					<button type="button" class="btn btn-ghost btn-sm" onclick={closeConnModal}>
						取消
					</button>
					<button type="submit" class="btn btn-primary btn-sm" disabled={saveLoading}>
						{#if saveLoading}<span class="loading loading-spinner loading-xs"></span>{/if}
						{editingConnId !== null ? '保存' : '创建连接'}
					</button>
				</div>
			</form>
		</div>
		<button type="button" class="modal-backdrop" aria-label="关闭" onclick={closeConnModal}></button>
	</div>
{/if}

<!-- 删除确认 -->
<ConfirmDialog
	open={!!deleteId}
	title="确认删除连接"
	message="删除后无法恢复，相关权限配置也将失效。"
	loading={deleteLoading}
	onconfirm={handleDelete}
	oncancel={() => (deleteId = null)}
/>
