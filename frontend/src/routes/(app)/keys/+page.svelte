<!--
  访问密钥管理页面
  创建时间：2026-05-01
  创建人：Antigravity
-->
<script lang="ts">
	import { api, ApiError } from '$lib/api';
	import { authStore } from '$lib/stores/auth.svelte';
	import { formatDate, truncate } from '$lib/utils';
	import Pagination from '$lib/components/Pagination.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import { toast } from '$lib/stores/toast.svelte';

	interface Key {
		id: number;
		ak: string;
		description: string;
		enabled: boolean;
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
	const pageSize = 10;
	let loading = $state(false);

	// 创建密钥
	let showAddKeyModal = $state(false);
	let newAk = $state('');
	let newDesc = $state('');
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
			await api.post('/admin/keys', { ak: newAk, description: newDesc, enabled: true });
			showAddKeyModal = false;
			newAk = '';
			newDesc = '';
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
		permKeyId = keyId;
		selectedPerms = {};
	}

	async function handleAddPerm(e: SubmitEvent) {
		e.preventDefault();
		const entries = Object.entries(selectedPerms).filter(([, v]) => v);
		if (entries.length === 0) { toast('请至少选择一个连接', 'warning'); return; }
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

	load();
</script>

<svelte:head>
	<title>访问密钥 - DB MCP Server</title>
</svelte:head>

<div class="fade-in">
	<div class="flex items-center justify-between mb-6">
		<div>
			<h1 class="text-xl font-bold">访问密钥</h1>
			<p class="text-base-content/50 text-sm mt-0.5">管理 AI 访问数据库的密钥与权限</p>
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
		<div class="overflow-x-auto">
			<table class="table table-zebra table-sm">
				<thead>
					<tr class="text-base-content/60 text-xs">
						<th>密钥 (AK)</th>
						<th>描述</th>
						<th>状态</th>
						<th>授权连接</th>
						<th>IP 白名单</th>
						{#if authStore.isAdmin}
							<th>已分配用户</th>
						{/if}
						<th>创建时间</th>
						{#if authStore.isAdmin}
							<th class="text-right">操作</th>
						{/if}
					</tr>
				</thead>
				<tbody>
					{#each keys as key}
						<tr class="hover">
							<td>
								<code class="text-xs bg-base-300 px-2 py-0.5 rounded font-mono">{key.ak}</code>
							</td>
							<td class="text-base-content/60 text-xs max-w-32 truncate">{key.description || '-'}</td>
							<td>
								<div class="flex items-center gap-2">
									<div class="w-1.5 h-1.5 rounded-full {key.enabled ? 'bg-success pulse-dot' : 'bg-error'}"></div>
									<span class="text-xs {key.enabled ? 'text-success' : 'text-error'}">
										{key.enabled ? '启用' : '禁用'}
									</span>
								</div>
							</td>
							<td>
								<div class="flex flex-wrap gap-1 max-w-48">
									{#each getKeyPerms(key.id) as perm}
										<div class="badge badge-ghost badge-sm gap-1 group relative">
											<span class="max-w-20 truncate text-xs">{getConnName(perm.connection_id)}</span>
											<span class="badge badge-xs {perm.select_only ? 'badge-info' : perm.allow_ddl ? 'badge-error' : 'badge-warning'}">
												{perm.select_only ? 'RO' : perm.allow_ddl ? 'Full' : 'RW'}
											</span>
											{#if authStore.isAdmin}
												<button
													class="opacity-0 group-hover:opacity-100 text-error ml-0.5 leading-none"
													onclick={() => (deletePermId = perm.id)}
												>×</button>
											{/if}
										</div>
									{/each}
									{#if authStore.isAdmin}
										<button
											class="badge badge-outline badge-sm cursor-pointer hover:badge-primary text-xs"
											onclick={() => openPermModal(key.id)}
										>+ 授权</button>
									{/if}
								</div>
							</td>
							<td>
								<div class="flex flex-wrap gap-1 max-w-36">
									{#each getKeyWl(key.id) as wl}
										<div class="badge badge-ghost badge-sm group relative">
											<span class="font-mono text-xs">{wl.cidr}</span>
											{#if authStore.isAdmin}
												<button
													class="opacity-0 group-hover:opacity-100 text-error ml-0.5"
													onclick={() => (deleteWlId = wl.id)}
												>×</button>
											{/if}
										</div>
									{/each}
									{#if authStore.isAdmin}
										<button
											class="badge badge-outline badge-sm cursor-pointer hover:badge-primary text-xs"
											onclick={() => { wlKeyId = key.id; wlCidr = ''; wlDesc = ''; wlError = ''; }}
										>+ IP</button>
									{/if}
								</div>
							</td>
							{#if authStore.isAdmin}
								<td>
									<div class="flex flex-wrap gap-1 max-w-36">
										{#each getKeyUsers(key.id) as u}
											<span class="badge badge-ghost badge-sm text-xs">{u.username}</span>
										{/each}
										<button
											class="badge badge-outline badge-sm cursor-pointer hover:badge-primary text-xs"
											onclick={() => openAssignModal(key.id)}
										>+ 分配</button>
									</div>
								</td>
							{/if}
							<td class="text-xs text-base-content/50">{formatDate(key.created_at)}</td>
							{#if authStore.isAdmin}
								<td>
									<div class="flex justify-end gap-1">
										<button
											class="btn btn-xs {key.enabled ? 'btn-ghost' : 'btn-success'} btn-outline"
											onclick={() => toggleKey(key.id, !key.enabled)}
										>
											{key.enabled ? '禁用' : '启用'}
										</button>
										<button
											class="btn btn-xs btn-error btn-outline"
											onclick={() => (deleteKeyId = key.id)}
										>删除</button>
									</div>
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

<!-- 创建密钥 Modal -->
{#if showAddKeyModal}
	<div class="modal modal-open">
		<div class="modal-box max-w-sm">
			<h3 class="font-bold text-base mb-4">创建访问密钥</h3>
			<form onsubmit={handleAddKey}>
				<div class="form-control mb-3">
					<label class="label pb-1 text-sm" for="new-ak">AK (Access Key)</label>
					<input id="new-ak" type="text" class="input input-bordered input-sm font-mono"
						placeholder="如：mcp_key_prod_01" bind:value={newAk} required />
					<div class="label"><span class="label-text-alt text-base-content/40">唯一标识符，AI 调用时使用</span></div>
				</div>
				<div class="form-control mb-4">
					<label class="label pb-1 text-sm" for="new-desc">描述</label>
					<input id="new-desc" type="text" class="input input-bordered input-sm"
						placeholder="如：给数据分析助手使用" bind:value={newDesc} />
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
		<div class="modal-backdrop" onclick={() => (showAddKeyModal = false)}></div>
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
		<div class="modal-backdrop" onclick={() => (permKeyId = null)}></div>
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
		<div class="modal-backdrop" onclick={() => (wlKeyId = null)}></div>
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
		<div class="modal-backdrop" onclick={() => (assignKeyId = null)}></div>
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
