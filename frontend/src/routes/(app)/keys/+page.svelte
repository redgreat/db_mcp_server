<!--
  访问密钥管理页面
  创建时间：2026-05-01
  创建人：Antigravity
-->
<script lang="ts">
	import { api, ApiError } from '$lib/api';
	import { authStore } from '$lib/stores/auth.svelte';
	import { formatDate, truncate } from '$lib/utils';
	import { LIST_PAGE_SIZE } from '$lib/constants';
	import Pagination from '$lib/components/Pagination.svelte';
	import CellTip from '$lib/components/CellTip.svelte';
	import RowActions from '$lib/components/RowActions.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import { toast } from '$lib/stores/toast.svelte';

	interface Key {
		id: number;
		ak: string;
		description: string;
		enabled: boolean;
		sql_risk_check_enabled: boolean;
		created_by: number | null;
		created_at: string;
	}

	interface Permission {
		id: number;
		key_id: number;
		connection_id: number;
		select_only: boolean;
		allow_ddl: boolean;
	}

	interface Whitelist {
		id: number;
		key_id: number;
		cidr: string;
		description: string;
	}

	interface Connection {
		id: number;
		name: string;
		host: string;
		port: number;
		database: string;
	}

	interface KeyUser {
		id: number;
		username: string;
		email: string;
		role: string;
	}

	let keys = $state<Key[]>([]);
	let permissions = $state<Permission[]>([]);
	let whitelists = $state<Whitelist[]>([]);
	let connections = $state<Connection[]>([]);
	let keyUsersMap = $state<Record<number, KeyUser[]>>({});
	let total = $state(0);
	let page = $state(1);
	const pageSize = LIST_PAGE_SIZE;
	let loading = $state(false);

	// 创建密钥
	let showAddKeyModal = $state(false);
	let newDesc = $state('');
	let newSqlRiskCheckEnabled = $state(true);
	let addKeyLoading = $state(false);

	// 删除密钥
	let deleteKeyId = $state<number | null>(null);
	let deleteKeyLoading = $state(false);

	// 权限分配
	let permKeyId = $state<number | null>(null);
	let selectedPerms = $state<Record<number, string>>({});

	// 白名单
	let wlKeyId = $state<number | null>(null);
	let wlCidr = $state('');
	let wlDesc = $state('');
	let wlLoading = $state(false);
	let wlError = $state('');

	// 删除权限/白名单
	let deletePermId = $state<number | null>(null);
	let deleteWlId = $state<number | null>(null);
	let detailKeyId = $state<number | null>(null);

	// 行内编辑描述
	let editingDescId = $state<number | null>(null);
	let editDescValue = $state('');
	let saveDescLoading = $state(false);

	// 分配用户
	let assignKeyId = $state<number | null>(null);
	let allUsers = $state<KeyUser[]>([]);
	let assignedUserIds = $state<Set<number>>(new Set());
	let assignLoading = $state(false);

	async function load(p = 1) {
		loading = true;
		page = p;
		try {
			const [keysRes, connsRes, permsRes, wlRes] = await Promise.all([
				api.get<{ items: Key[]; total: number }>(`/admin/keys?page=${p}&page_size=${pageSize}`),
				api.get<{ items: Connection[] }>('/admin/connections?page_size=1000'),
				api.get<{ items: Permission[] }>('/admin/permissions'),
				api.get<{ items: Whitelist[] }>('/admin/whitelist')
			]);
			keys = keysRes.items;
			total = keysRes.total;
			connections = connsRes.items;
			permissions = permsRes.items;
			whitelists = wlRes.items;

			if (authStore.isAdmin) {
				const userResults = await Promise.all(
					keys.map((k) => api.get<{ users: KeyUser[] }>(`/admin/keys/${k.id}/users`).catch(() => ({ users: [] })))
				);
				const map: Record<number, KeyUser[]> = {};
				keys.forEach((k, i) => (map[k.id] = userResults[i].users));
				keyUsersMap = map;
			}
		} catch {
			toast('加载数据失败', 'error');
		} finally {
			loading = false;
		}
	}

	async function handleAddKey(e: SubmitEvent) {
		e.preventDefault();
		addKeyLoading = true;
		try {
			await api.post('/admin/keys', {
				description: newDesc,
				enabled: true,
				sql_risk_check_enabled: newSqlRiskCheckEnabled
			});
			showAddKeyModal = false;
			newDesc = '';
			newSqlRiskCheckEnabled = true;
			toast('密钥创建成功', 'success');
			load(1);
		} catch (err) {
			toast(err instanceof ApiError ? err.message : '创建失败', 'error');
		} finally {
			addKeyLoading = false;
		}
	}

	async function toggleKey(id: number, enabled: boolean) {
		try {
			await api.patch(`/admin/keys/${id}/toggle`, { enabled });
			keys = keys.map((k) => (k.id === id ? { ...k, enabled } : k));
			toast(`密钥已${enabled ? '启用' : '禁用'}`, 'success');
		} catch (err) {
			toast(err instanceof ApiError ? err.message : '操作失败', 'error');
		}
	}
	
	async function toggleSqlRiskCheck(id: number, enabled: boolean) {
		try {
			await api.patch(`/admin/keys/${id}/sql_risk_check`, { sql_risk_check_enabled: enabled });
			keys = keys.map((k) => (k.id === id ? { ...k, sql_risk_check_enabled: enabled } : k));
			toast(`SQL 风险监测已${enabled ? '开启' : '关闭'}`, 'success');
		} catch (err) {
			toast(err instanceof ApiError ? err.message : '操作失败', 'error');
		}
	}

	async function handleDeleteKey() {
		if (!deleteKeyId) return;
		deleteKeyLoading = true;
		try {
			await api.delete(`/admin/keys/${deleteKeyId}`);
			deleteKeyId = null;
			toast('密钥已删除', 'success');
			load(page);
		} catch (err) {
			toast(err instanceof ApiError ? err.message : '删除失败', 'error');
		} finally {
			deleteKeyLoading = false;
		}
	}

	function openPermModal(keyId: number) {
		detailKeyId = null;
		permKeyId = keyId;
		selectedPerms = {};
	}

	async function handleAddPerm(e: SubmitEvent) {
		e.preventDefault();
		const entries = Object.entries(selectedPerms).filter(([, v]) => v);
		if (entries.length === 0) { toast('请至少选择一个连接', 'error'); return; }
		try {
			for (const [connId, permType] of entries) {
				const params = new URLSearchParams({
					key_id: String(permKeyId),
					connection_id: connId,
					select_only: String(permType === 'readonly'),
					allow_ddl: String(permType === 'full')
				});
				await api.post(`/admin/permissions?${params}`);
			}
			permKeyId = null;
			toast('权限分配成功', 'success');
			load(page);
		} catch (err) {
			toast(err instanceof ApiError ? err.message : '分配失败', 'error');
		}
	}

	async function handleDeletePerm() {
		if (!deletePermId) return;
		try {
			await api.delete(`/admin/permissions/${deletePermId}`);
			deletePermId = null;
			toast('权限已移除', 'success');
			load(page);
		} catch (err) {
			toast(err instanceof ApiError ? err.message : '移除失败', 'error');
		}
	}

	async function handleAddWhitelist(e: SubmitEvent) {
		e.preventDefault();
		wlLoading = true;
		wlError = '';
		const params = new URLSearchParams({
			key_id: String(wlKeyId),
			cidr: wlCidr,
			description: wlDesc
		});
		try {
			await api.post(`/admin/whitelist?${params}`);
			wlKeyId = null;
			wlCidr = '';
			wlDesc = '';
			toast('IP 白名单添加成功', 'success');
			load(page);
		} catch (err) {
			wlError = err instanceof ApiError ? err.message : '添加失败';
		} finally {
			wlLoading = false;
		}
	}

	async function handleDeleteWl() {
		if (!deleteWlId) return;
		try {
			await api.delete(`/admin/whitelist/${deleteWlId}`);
			deleteWlId = null;
			toast('白名单规则已删除', 'success');
			load(page);
		} catch (err) {
			toast(err instanceof ApiError ? err.message : '删除失败', 'error');
		}
	}

	async function openAssignModal(keyId: number) {
		detailKeyId = null;
		assignKeyId = keyId;
		try {
			const [usersRes, assignedRes] = await Promise.all([
				api.get<{ items: KeyUser[] }>('/admin/users?page_size=1000'),
				api.get<{ users: KeyUser[] }>(`/admin/keys/${keyId}/users`)
			]);
			allUsers = usersRes.items;
			assignedUserIds = new Set(assignedRes.users.map((u) => u.id));
		} catch {
			toast('加载用户列表失败', 'error');
		}
	}

	async function handleAssignUsers(e: SubmitEvent) {
		e.preventDefault();
		assignLoading = true;
		try {
			const ids = Array.from(assignedUserIds);
			await api.post(`/admin/keys/${assignKeyId}/users`, ids);
			assignKeyId = null;
			toast('用户分配成功', 'success');
			load(page);
		} catch (err) {
			toast(err instanceof ApiError ? err.message : '分配失败', 'error');
		} finally {
			assignLoading = false;
		}
	}

	function toggleAssignUser(uid: number, checked: boolean) {
		const s = new Set(assignedUserIds);
		if (checked) s.add(uid); else s.delete(uid);
		assignedUserIds = s;
	}

	function getConnName(id: number) {
		return connections.find((c) => c.id === id)?.name ?? `连接#${id}`;
	}

	function getKeyPerms(keyId: number) {
		return permissions.filter((p) => p.key_id === keyId);
	}

	function getKeyWl(keyId: number) {
		return whitelists.filter((w) => w.key_id === keyId);
	}

	function getKeyUsers(keyId: number) {
		return keyUsersMap[keyId] ?? [];
	}

	function getAvailableConns(keyId: number) {
		const used = new Set(getKeyPerms(keyId).map((p) => p.connection_id));
		return connections.filter((c) => !used.has(c.id));
	}

	function getSummaryText(total: number, emptyText: string) {
		if (total === 0) return emptyText;
		return `${total} 项`;
	}

	function openDetailModal(keyId: number) {
		detailKeyId = keyId;
	}

	function closeDetailModal() {
		detailKeyId = null;
	}

	function openDetailPermModal() {
		if (detailKeyId !== null) {
			openPermModal(detailKeyId);
		}
	}

	function openDetailWhitelistModal() {
		if (detailKeyId !== null) {
			wlKeyId = detailKeyId;
			detailKeyId = null;
			wlCidr = '';
			wlDesc = '';
			wlError = '';
		}
	}

	function openDetailAssignModal() {
		if (detailKeyId !== null) {
			openAssignModal(detailKeyId);
		}
	}

	async function saveDesc(keyId: number) {
		if (!authStore.isAdmin) return;
		saveDescLoading = true;
		try {
			await api.patch(`/admin/keys/${keyId}/description`, { description: editDescValue });
			keys = keys.map((k) => (k.id === keyId ? { ...k, description: editDescValue } : k));
			editingDescId = null;
			toast('描述已更新', 'success');
		} catch (err) {
			toast(err instanceof ApiError ? err.message : '更新失败', 'error');
		} finally {
			saveDescLoading = false;
		}
	}

	function startEditDesc(keyId: number, currentDesc: string) {
		if (!authStore.isAdmin) return;
		editingDescId = keyId;
		editDescValue = currentDesc || '';
	}

	function cancelEditDesc() {
		editingDescId = null;
		editDescValue = '';
	}

	load();
</script>

<svelte:head>
	<title>访问密钥 - DB MCP Server</title>
</svelte:head>

<div class="fade-in">
	<div class="flex items-center justify-between mb-6">
		<div>
			<h1 class="text-2xl font-bold tracking-tight">访问密钥</h1>
		</div>
		{#if authStore.isAdmin}
			<button class="btn btn-primary btn-sm gap-2" onclick={() => (showAddKeyModal = true)}>
				<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.5v15m7.5-7.5h-15" />
				</svg>
				创建密钥
			</button>
		{/if}
	</div>

	{#if loading}
		<div class="flex justify-center items-center py-20">
			<span class="loading loading-spinner loading-lg text-primary"></span>
		</div>
	{:else if keys.length === 0}
		<div class="flex flex-col items-center justify-center py-20 text-base-content/40">
			<svg class="w-12 h-12 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1" d="M15.75 5.25a3 3 0 0 1 3 3m3 0a6 6 0 0 1-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 0 1 21.75 8.25Z" />
			</svg>
			<p class="text-sm">暂无访问密钥</p>
		</div>
	{:else}
		<div class="table-admin-wrap overflow-x-auto">
			<table class="table table-zebra table-sm table-admin w-full">
				<thead>
					<tr>
						<th class="admin-th">密钥 (AK)</th>
						<th class="admin-th">描述</th>
						<th class="admin-th">状态</th>
						<th class="admin-th">SQL 风险监测</th>
						<th class="admin-th">授权连接</th>
						<th class="admin-th">IP 白名单</th>
						{#if authStore.isAdmin}
							<th class="admin-th">已分配用户</th>
						{/if}
						<th class="admin-th">创建时间</th>
						{#if authStore.isAdmin}
							<th class="admin-th col-actions">操作</th>
						{/if}
					</tr>
				</thead>
				<tbody>
					{#each keys as key}
						<tr class="hover">
							<td>
								<CellTip value={key.ak} class="font-mono text-xs" maxWidth="max-w-[12rem]" />
							</td>
							<td class="text-base-content/60 text-xs cursor-pointer hover:bg-base-200 rounded px-0.5 -mx-0.5 min-w-[6rem]"
							onclick={() => startEditDesc(key.id, key.description)}
							onkeydown={() => {}} role="button" tabindex="0"
						>
							{#if editingDescId === key.id}
								<div class="flex items-center gap-1">
									<input
										type="text"
										class="input input-bordered input-xs flex-1 min-w-0"
										bind:value={editDescValue}
										onkeydown={(e) => {
											if (e.key === 'Enter') saveDesc(key.id);
											if (e.key === 'Escape') cancelEditDesc();
										}}
										disabled={saveDescLoading}
									/>
									<button
										type="button"
										class="btn btn-ghost btn-xs px-1"
										onclick={(e) => { e.stopPropagation(); saveDesc(key.id); }}
										disabled={saveDescLoading}
									>
										✓
									</button>
									<button
										type="button"
										class="btn btn-ghost btn-xs px-1"
										onclick={(e) => { e.stopPropagation(); cancelEditDesc(); }}
										disabled={saveDescLoading}
									>
										✕
									</button>
								</div>
							{:else}
								<CellTip value={key.description || '—'} maxWidth="max-w-[10rem]" />
							{/if}
						</td>
							<td>
								<div class="flex items-center gap-2">
									<div class="w-1.5 h-1.5 rounded-full {key.enabled ? 'bg-success pulse-dot' : 'bg-error'}"></div>
									<span class="text-xs {key.enabled ? 'text-success' : 'text-error'}">
										{key.enabled ? '启用' : '禁用'}
									</span>
								</div>
							</td>
							<td>
								<div class="flex items-center gap-2">
									<div class="w-1.5 h-1.5 rounded-full {key.sql_risk_check_enabled ? 'bg-success' : 'bg-base-content/30'}"></div>
									<span class="text-xs {key.sql_risk_check_enabled ? 'text-success' : 'text-base-content/50'}">
										{key.sql_risk_check_enabled ? '开启' : '关闭'}
									</span>
								</div>
							</td>
							<td>
								<div class="flex items-center gap-2 min-w-0">
									<span class="text-xs text-base-content/65">{getSummaryText(getKeyPerms(key.id).length, '未授权')}</span>
									<button
										type="button"
										class="badge badge-outline badge-sm cursor-pointer hover:badge-primary text-xs"
										onclick={() => openDetailModal(key.id)}
									>
										详情
									</button>
								</div>
							</td>
							<td>
								<div class="flex items-center gap-2 min-w-0">
									<span class="text-xs text-base-content/65">{getSummaryText(getKeyWl(key.id).length, '未限制')}</span>
									<button
										type="button"
										class="badge badge-outline badge-sm cursor-pointer hover:badge-primary text-xs"
										onclick={() => openDetailModal(key.id)}
									>
										详情
									</button>
								</div>
							</td>
							{#if authStore.isAdmin}
								<td>
									<div class="flex items-center gap-2 min-w-0">
										<span class="text-xs text-base-content/65">{getSummaryText(getKeyUsers(key.id).length, '未分配')}</span>
										<button
											type="button"
											class="badge badge-outline badge-sm cursor-pointer hover:badge-primary text-xs"
											onclick={() => openDetailModal(key.id)}
										>
											详情
										</button>
									</div>
								</td>
							{/if}
							<td class="text-xs text-base-content/50">{formatDate(key.created_at)}</td>
							{#if authStore.isAdmin}
								<td class="col-actions">
									<RowActions>
										<button
											type="button"
											class="btn-act {key.enabled ? 'btn-act-warning' : 'btn-act-success'}"
											onclick={() => toggleKey(key.id, !key.enabled)}
										>
											{key.enabled ? '禁用' : '启用'}
										</button>
										<button
											type="button"
											class="btn-act {key.sql_risk_check_enabled ? 'btn-act-warning' : 'btn-act-success'}"
											onclick={() => toggleSqlRiskCheck(key.id, !key.sql_risk_check_enabled)}
										>
											{key.sql_risk_check_enabled ? '关闭风控' : '开启风控'}
										</button>
										<button type="button" class="btn-act btn-act-error" onclick={() => (deleteKeyId = key.id)}>删除</button>
									</RowActions>
								</td>
							{/if}
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
		<Pagination {total} {page} {pageSize} onchange={load} />
	{/if}
</div>

<!-- 密钥详情 Modal -->
{#if detailKeyId !== null}
	{@const currentKey = keys.find((k) => k.id === detailKeyId)}
	{@const detailPerms = getKeyPerms(detailKeyId)}
	{@const detailWl = getKeyWl(detailKeyId)}
	{@const detailUsers = getKeyUsers(detailKeyId)}
	<div class="modal modal-open">
		<div class="modal-box max-w-4xl">
			<h3 class="font-bold text-base mb-2">访问密钥详情</h3>
			{#if currentKey}
				<div class="rounded-lg border border-base-300 bg-base-200/80 p-3 mb-4 space-y-1">
					<div class="font-mono text-xs break-all">{currentKey.ak}</div>
					<div class="text-sm text-base-content/70">{currentKey.description || '无描述'}</div>
				</div>
			{/if}
			<div class="grid gap-4 md:grid-cols-3">
				<div class="rounded-lg border border-base-300 bg-base-200/60 p-3">
					<div class="flex items-center justify-between gap-2 mb-3">
						<h4 class="font-medium text-sm">授权连接</h4>
						{#if authStore.isAdmin}
							<button
								type="button"
								class="badge badge-outline badge-sm cursor-pointer hover:badge-primary text-xs"
								onclick={openDetailPermModal}
							>
								+ 授权
							</button>
						{/if}
					</div>
					<div class="space-y-2 max-h-80 overflow-y-auto pr-1">
						{#if detailPerms.length === 0}
							<p class="text-xs text-base-content/45">暂无授权连接</p>
						{:else}
							{#each detailPerms as perm}
								<div class="flex items-center justify-between gap-2 rounded-lg border border-base-300 px-2 py-2">
									<div class="min-w-0">
										<div class="text-sm truncate">{getConnName(perm.connection_id)}</div>
										<div class="text-xs text-base-content/50">
											{perm.select_only ? '只读' : perm.allow_ddl ? '完全权限（含 DDL）' : '读写'}
										</div>
									</div>
									<div class="flex items-center gap-2 shrink-0">
										<span class="badge badge-xs {perm.select_only ? 'badge-info' : perm.allow_ddl ? 'badge-error' : 'badge-warning'}">
											{perm.select_only ? 'RO' : perm.allow_ddl ? 'Full' : 'RW'}
										</span>
										{#if authStore.isAdmin}
											<button type="button" class="btn btn-ghost btn-xs text-error" onclick={() => (deletePermId = perm.id)}>移除</button>
										{/if}
									</div>
								</div>
							{/each}
						{/if}
					</div>
				</div>
				<div class="rounded-lg border border-base-300 bg-base-200/60 p-3">
					<div class="flex items-center justify-between gap-2 mb-3">
						<h4 class="font-medium text-sm">IP 白名单</h4>
						{#if authStore.isAdmin}
							<button
								type="button"
								class="badge badge-outline badge-sm cursor-pointer hover:badge-primary text-xs"
								onclick={openDetailWhitelistModal}
							>
								+ IP
							</button>
						{/if}
					</div>
					<div class="space-y-2 max-h-80 overflow-y-auto pr-1">
						{#if detailWl.length === 0}
							<p class="text-xs text-base-content/45">暂无白名单限制</p>
						{:else}
							{#each detailWl as wl}
								<div class="flex items-center justify-between gap-2 rounded-lg border border-base-300 px-2 py-2">
									<div class="min-w-0">
										<div class="font-mono text-xs break-all">{wl.cidr}</div>
										<div class="text-xs text-base-content/50">{wl.description || '—'}</div>
									</div>
									{#if authStore.isAdmin}
										<button type="button" class="btn btn-ghost btn-xs text-error shrink-0" onclick={() => (deleteWlId = wl.id)}>删除</button>
									{/if}
								</div>
							{/each}
						{/if}
					</div>
				</div>
				<div class="rounded-lg border border-base-300 bg-base-200/60 p-3">
					<div class="flex items-center justify-between gap-2 mb-3">
						<h4 class="font-medium text-sm">已分配用户</h4>
						{#if authStore.isAdmin}
							<button
								type="button"
								class="badge badge-outline badge-sm cursor-pointer hover:badge-primary text-xs"
								onclick={openDetailAssignModal}
							>
								+ 分配
							</button>
						{/if}
					</div>
					<div class="space-y-2 max-h-80 overflow-y-auto pr-1">
						{#if detailUsers.length === 0}
							<p class="text-xs text-base-content/45">暂无分配用户</p>
						{:else}
							{#each detailUsers as u}
								<div class="flex items-center justify-between gap-2 rounded-lg border border-base-300 px-2 py-2">
									<div class="min-w-0">
										<div class="text-sm truncate">{u.username}</div>
										<div class="text-xs text-base-content/50">{u.email || '—'}</div>
									</div>
									<span class="badge badge-xs {u.role === 'admin' ? 'badge-error' : 'badge-info'}">
										{u.role === 'admin' ? '管理员' : '普通用户'}
									</span>
								</div>
							{/each}
						{/if}
					</div>
				</div>
			</div>
			<div class="modal-action">
				<button type="button" class="btn btn-ghost btn-sm" onclick={closeDetailModal}>关闭</button>
			</div>
		</div>
		<button type="button" class="modal-backdrop" aria-label="关闭" onclick={closeDetailModal}></button>
	</div>
{/if}

<!-- 创建密钥 Modal -->
{#if showAddKeyModal}
	<div class="modal modal-open">
		<div class="modal-box max-w-sm">
			<h3 class="font-bold text-base mb-4">创建访问密钥</h3>
			<form onsubmit={handleAddKey}>
				<div class="form-control mb-3">
					<label class="label pb-1 text-sm" for="new-desc">描述</label>
					<input id="new-desc" type="text" class="input input-bordered input-sm"
						placeholder="如：给数据分析助手使用" bind:value={newDesc} />
					<div class="label"><span class="label-text-alt text-base-content/40">AK 将自动生成 32 位随机密钥</span></div>
				</div>
				<div class="form-control mb-4">
					<label class="label cursor-pointer justify-start gap-3">
						<input type="checkbox" class="toggle toggle-sm toggle-primary" bind:checked={newSqlRiskCheckEnabled} />
						<span class="label-text text-sm">启用 SQL 风险监测</span>
					</label>
					<div class="label"><span class="label-text-alt text-base-content/40">关闭后将不再拦截风险 SQL（仍保留白名单、审计日志、权限校验）</span></div>
				</div>
				<div class="modal-action mt-0">
					<button type="button" class="btn btn-ghost btn-sm" onclick={() => (showAddKeyModal = false)}>取消</button>
					<button type="submit" class="btn btn-primary btn-sm" disabled={addKeyLoading}>
						{#if addKeyLoading}<span class="loading loading-spinner loading-xs"></span>{/if}
						创建
					</button>
				</div>
			</form>
		</div>
		<button type="button" class="modal-backdrop" aria-label="关闭" onclick={() => (showAddKeyModal = false)}></button>
	</div>
{/if}

<!-- 授权连接 Modal -->
{#if permKeyId !== null}
	{@const available = getAvailableConns(permKeyId)}
	<div class="modal modal-open">
		<div class="modal-box max-w-md">
			<h3 class="font-bold text-base mb-4">为密钥分配数据库权限</h3>
			{#if available.length === 0}
				<p class="text-base-content/50 text-sm text-center py-6">所有连接已全部授权</p>
				<div class="modal-action"><button class="btn btn-ghost btn-sm" onclick={() => (permKeyId = null)}>关闭</button></div>
			{:else}
				<form onsubmit={handleAddPerm}>
					<div class="space-y-2 max-h-80 overflow-y-auto pr-1">
						{#each available as conn}
							<div class="card card-compact bg-base-200 border border-base-300">
								<div class="card-body p-3">
									<div class="flex items-center gap-2 mb-2">
										<input type="checkbox" class="checkbox checkbox-sm checkbox-primary"
											id="perm-conn-{conn.id}"
											onchange={(e) => {
												const target = e.target as HTMLInputElement;
												if (target.checked) selectedPerms[conn.id] = 'readonly';
												else { const s = {...selectedPerms}; delete s[conn.id]; selectedPerms = s; }
											}} />
										<label for="perm-conn-{conn.id}" class="font-medium text-sm cursor-pointer">
											{conn.name}
											<span class="text-xs text-base-content/40 ml-1">{conn.host}/{conn.database}</span>
										</label>
									</div>
									{#if selectedPerms[conn.id] !== undefined}
										<div class="flex gap-3 ml-6 text-sm">
											<label class="flex items-center gap-1.5 cursor-pointer">
												<input type="radio" name="perm-{conn.id}" class="radio radio-xs"
													checked={selectedPerms[conn.id] === 'readonly'}
													onchange={() => (selectedPerms = {...selectedPerms, [conn.id]: 'readonly'})} />
												<span>只读</span>
											</label>
											<label class="flex items-center gap-1.5 cursor-pointer">
												<input type="radio" name="perm-{conn.id}" class="radio radio-xs"
													checked={selectedPerms[conn.id] === 'readwrite'}
													onchange={() => (selectedPerms = {...selectedPerms, [conn.id]: 'readwrite'})} />
												<span>读写</span>
											</label>
											<label class="flex items-center gap-1.5 cursor-pointer">
												<input type="radio" name="perm-{conn.id}" class="radio radio-xs"
													checked={selectedPerms[conn.id] === 'full'}
													onchange={() => (selectedPerms = {...selectedPerms, [conn.id]: 'full'})} />
												<span>完全（含DDL）</span>
											</label>
										</div>
									{/if}
								</div>
							</div>
						{/each}
					</div>
					<div class="modal-action mt-4">
						<button type="button" class="btn btn-ghost btn-sm" onclick={() => (permKeyId = null)}>取消</button>
						<button type="submit" class="btn btn-primary btn-sm">确认授权</button>
					</div>
				</form>
			{/if}
		</div>
		<button type="button" class="modal-backdrop" aria-label="关闭" onclick={() => (permKeyId = null)}></button>
	</div>
{/if}

<!-- 添加白名单 Modal -->
{#if wlKeyId !== null}
	<div class="modal modal-open">
		<div class="modal-box max-w-sm">
			<h3 class="font-bold text-base mb-4">添加 IP 白名单</h3>
			<form onsubmit={handleAddWhitelist}>
				<div class="form-control mb-3">
					<label class="label pb-1 text-sm" for="wl-cidr">IP 地址 / CIDR</label>
					<input id="wl-cidr" type="text" class="input input-bordered input-sm font-mono"
						placeholder="如：192.168.1.0/24 或 10.0.0.1" bind:value={wlCidr} required />
					<div class="label"><span class="label-text-alt text-base-content/40">0.0.0.0/0 表示允许所有（不推荐）</span></div>
				</div>
				<div class="form-control mb-4">
					<label class="label pb-1 text-sm" for="wl-desc">描述（可选）</label>
					<input id="wl-desc" type="text" class="input input-bordered input-sm"
						placeholder="如：办公室网络" bind:value={wlDesc} />
				</div>
				{#if wlError}
					<div class="alert alert-error py-2 px-3 mb-3 text-sm"><span>{wlError}</span></div>
				{/if}
				<div class="modal-action mt-0">
					<button type="button" class="btn btn-ghost btn-sm" onclick={() => (wlKeyId = null)}>取消</button>
					<button type="submit" class="btn btn-primary btn-sm" disabled={wlLoading}>
						{#if wlLoading}<span class="loading loading-spinner loading-xs"></span>{/if}
						添加
					</button>
				</div>
			</form>
		</div>
		<button type="button" class="modal-backdrop" aria-label="关闭" onclick={() => (wlKeyId = null)}></button>
	</div>
{/if}

<!-- 分配用户 Modal -->
{#if assignKeyId !== null}
	<div class="modal modal-open">
		<div class="modal-box max-w-sm">
			<h3 class="font-bold text-base mb-4">分配用户权限</h3>
			<form onsubmit={handleAssignUsers}>
				<div class="space-y-1 max-h-72 overflow-y-auto">
					{#each allUsers as u}
						<label class="flex items-center gap-3 p-2 rounded-lg hover:bg-base-200 cursor-pointer">
							<input type="checkbox" class="checkbox checkbox-sm checkbox-primary"
								checked={assignedUserIds.has(u.id)}
								onchange={(e) => toggleAssignUser(u.id, (e.target as HTMLInputElement).checked)} />
							<span class="flex-1 text-sm font-medium">{u.username}</span>
							<span class="badge badge-xs {u.role === 'admin' ? 'badge-error' : 'badge-info'}">
								{u.role === 'admin' ? '管理员' : '普通用户'}
							</span>
						</label>
					{/each}
				</div>
				<p class="text-xs text-base-content/40 mt-2">选中的用户可以在密钥列表中看到此密钥</p>
				<div class="modal-action mt-3">
					<button type="button" class="btn btn-ghost btn-sm" onclick={() => (assignKeyId = null)}>取消</button>
					<button type="submit" class="btn btn-primary btn-sm" disabled={assignLoading}>
						{#if assignLoading}<span class="loading loading-spinner loading-xs"></span>{/if}
						确认分配
					</button>
				</div>
			</form>
		</div>
		<button type="button" class="modal-backdrop" aria-label="关闭" onclick={() => (assignKeyId = null)}></button>
	</div>
{/if}

<!-- 删除密钥确认 -->
<ConfirmDialog
	open={!!deleteKeyId}
	title="确认删除密钥"
	message="删除后 AI 将无法使用此密钥访问数据库，相关权限将自动清理。"
	loading={deleteKeyLoading}
	onconfirm={handleDeleteKey}
	oncancel={() => (deleteKeyId = null)}
/>

<!-- 删除权限确认 -->
<ConfirmDialog
	open={!!deletePermId}
	title="确认移除授权"
	message="移除后该密钥将无法访问对应数据库连接。"
	onconfirm={handleDeletePerm}
	oncancel={() => (deletePermId = null)}
/>

<!-- 删除白名单确认 -->
<ConfirmDialog
	open={!!deleteWlId}
	title="确认删除白名单规则"
	message="删除后对应 IP 将不再被允许访问。"
	onconfirm={handleDeleteWl}
	oncancel={() => (deleteWlId = null)}
/>
