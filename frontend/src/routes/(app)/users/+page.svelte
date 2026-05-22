<!--
  用户管理页面（仅管理员可访问）
  创建时间：2026-05-01
  创建人：Antigravity
-->
<script lang="ts">
	import { goto } from '$app/navigation';
	import { api, ApiError } from '$lib/api';
	import { authStore } from '$lib/stores/auth.svelte';
	import { formatDate } from '$lib/utils';
	import { LIST_PAGE_SIZE } from '$lib/constants';
	import Pagination from '$lib/components/Pagination.svelte';
	import CellTip from '$lib/components/CellTip.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import { toast } from '$lib/stores/toast.svelte';
	import { onMount } from 'svelte';

	interface AdminUser {
		id: number;
		username: string;
		email: string;
		role: 'admin' | 'user';
		is_active: boolean;
		created_at: string;
	}

	let users = $state<AdminUser[]>([]);
	let total = $state(0);
	let page = $state(1);
	const pageSize = LIST_PAGE_SIZE;
	let loading = $state(false);

	// 创建用户
	let showCreateModal = $state(false);
	let createLoading = $state(false);
	let createError = $state('');
	let newUser = $state({ username: '', password: '', email: '', role: 'user' as 'admin' | 'user' });

	// 编辑用户
	let editUser = $state<AdminUser | null>(null);
	let editLoading = $state(false);
	let editRole = $state<'admin' | 'user'>('user');
	let editActive = $state(true);

	// 重置密码
	let resetUser = $state<AdminUser | null>(null);
	let resetPwd = $state('');
	let resetConfirm = $state('');
	let resetLoading = $state(false);
	let resetError = $state('');

	// 删除
	let deleteUserId = $state<number | null>(null);
	let deleteLoading = $state(false);

	onMount(() => {
		if (!authStore.isAdmin) {
			goto('/connections');
		}
	});

	async function load(p = 1) {
		loading = true;
		page = p;
		try {
			const data = await api.get<{ items: AdminUser[]; total: number }>(
				`/admin/users?page=${p}&page_size=${pageSize}`
			);
			users = data.items;
			total = data.total;
		} catch {
			toast('加载用户列表失败', 'error');
		} finally {
			loading = false;
		}
	}

	async function handleCreate(e: SubmitEvent) {
		e.preventDefault();
		createLoading = true;
		createError = '';
		try {
			await api.post('/admin/users', newUser);
			showCreateModal = false;
			newUser = { username: '', password: '', email: '', role: 'user' };
			toast('用户创建成功', 'success');
			load(1);
		} catch (err) {
			createError = err instanceof ApiError ? err.message : '创建失败';
		} finally {
			createLoading = false;
		}
	}

	function openEdit(u: AdminUser) {
		editUser = u;
		editRole = u.role;
		editActive = u.is_active;
	}

	async function handleEdit(e: SubmitEvent) {
		e.preventDefault();
		if (!editUser) return;
		editLoading = true;
		try {
			await api.put(`/admin/users/${editUser.id}`, { role: editRole, is_active: editActive });
			editUser = null;
			toast('用户信息已更新', 'success');
			load(page);
		} catch (err) {
			toast(err instanceof ApiError ? err.message : '更新失败', 'error');
		} finally {
			editLoading = false;
		}
	}

	function openReset(u: AdminUser) {
		resetUser = u;
		resetPwd = '';
		resetConfirm = '';
		resetError = '';
	}

	async function handleReset(e: SubmitEvent) {
		e.preventDefault();
		if (!resetUser) return;
		if (resetPwd !== resetConfirm) { resetError = '两次密码不一致'; return; }
		resetLoading = true;
		resetError = '';
		try {
			await api.post(`/admin/users/${resetUser.id}/reset-password`, { new_password: resetPwd });
			resetUser = null;
			toast('密码重置成功', 'success');
		} catch (err) {
			resetError = err instanceof ApiError ? err.message : '重置失败';
		} finally {
			resetLoading = false;
		}
	}

	async function handleDelete() {
		if (!deleteUserId) return;
		deleteLoading = true;
		try {
			await api.delete(`/admin/users/${deleteUserId}`);
			deleteUserId = null;
			toast('用户已删除', 'success');
			load(page);
		} catch (err) {
			toast(err instanceof ApiError ? err.message : '删除失败', 'error');
		} finally {
			deleteLoading = false;
		}
	}

	load();
</script>

<svelte:head>
	<title>用户管理 - DB MCP Server</title>
</svelte:head>

<div class="fade-in">
	<div class="flex items-center justify-between mb-6">
		<div>
			<h1 class="text-2xl font-bold tracking-tight">用户管理</h1>
		</div>
		<button class="btn btn-primary btn-sm gap-2" onclick={() => (showCreateModal = true)}>
			<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18 7.5v3m0 0v3m0-3h3m-3 0h-3m-2.25-4.125a3.375 3.375 0 1 1-6.75 0 3.375 3.375 0 0 1 6.75 0ZM3 19.235v-.11a6.375 6.375 0 0 1 12.75 0v.109A12.318 12.318 0 0 1 9.374 21c-2.331 0-4.512-.645-6.374-1.766Z" />
			</svg>
			添加用户
		</button>
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
						<th>用户名</th>
						<th>邮箱</th>
						<th>角色</th>
						<th>状态</th>
						<th>创建时间</th>
						<th class="text-right">操作</th>
					</tr>
				</thead>
				<tbody>
					{#each users as u}
						<tr class="hover">
							<td>
								<div class="flex items-center gap-2">
									<div class="w-7 h-7 rounded-full bg-primary/15 text-primary text-xs font-bold flex items-center justify-center flex-shrink-0">
										{u.username[0].toUpperCase()}
									</div>
									<span class="font-medium text-sm">{u.username}</span>
								</div>
							</td>
							<td class="text-xs text-base-content/60">
								<CellTip value={u.email || '—'} maxWidth="max-w-[12rem]" />
							</td>
							<td>
								<span class="badge badge-sm {u.role === 'admin' ? 'badge-error' : 'badge-info'}">
									{u.role === 'admin' ? '管理员' : '普通用户'}
								</span>
							</td>
							<td>
								<div class="flex items-center gap-1.5">
									<div class="w-1.5 h-1.5 rounded-full {u.is_active ? 'bg-success' : 'bg-error'}"></div>
									<span class="text-xs {u.is_active ? 'text-success' : 'text-error'}">
										{u.is_active ? '启用' : '禁用'}
									</span>
								</div>
							</td>
							<td class="text-xs text-base-content/50">{formatDate(u.created_at)}</td>
							<td>
								<div class="flex justify-end gap-1.5">
									<button type="button" class="btn btn-xs btn-table btn-primary" onclick={() => openEdit(u)}>编辑</button>
									<button type="button" class="btn btn-xs btn-table btn-warning" onclick={() => openReset(u)}>重置密码</button>
									<button
										type="button"
										class="btn btn-xs btn-table btn-error"
										disabled={u.id === authStore.user?.id}
										onclick={() => (deleteUserId = u.id)}
									>删除</button>
								</div>
							</td>
						</tr>
					{:else}
						<tr>
							<td colspan="6" class="text-center text-base-content/40 py-8">暂无用户</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
		<Pagination {total} {page} {pageSize} onchange={load} />
	{/if}
</div>

<!-- 创建用户 Modal -->
{#if showCreateModal}
	<div class="modal modal-open">
		<div class="modal-box max-w-sm">
			<h3 class="font-bold text-base mb-4">创建新用户</h3>
			<form onsubmit={handleCreate}>
				<div class="form-control mb-3">
					<label class="label pb-1 text-sm" for="cu-username">用户名</label>
					<input id="cu-username" type="text" class="input input-bordered input-sm"
						placeholder="登录用户名" bind:value={newUser.username} required />
				</div>
				<div class="form-control mb-3">
					<label class="label pb-1 text-sm" for="cu-password">密码</label>
					<input id="cu-password" type="password" class="input input-bordered input-sm"
						placeholder="初始密码" bind:value={newUser.password} required />
				</div>
				<div class="form-control mb-3">
					<label class="label pb-1 text-sm" for="cu-email">邮箱（可选）</label>
					<input id="cu-email" type="email" class="input input-bordered input-sm"
						placeholder="user@example.com" bind:value={newUser.email} />
				</div>
				<div class="form-control mb-4">
					<label class="label pb-1 text-sm" for="cu-role">角色</label>
					<select id="cu-role" class="select select-bordered select-sm" bind:value={newUser.role}>
						<option value="user">普通用户（只读权限）</option>
						<option value="admin">管理员（完全权限）</option>
					</select>
				</div>
				{#if createError}
					<div class="alert alert-error py-2 px-3 mb-3 text-sm"><span>{createError}</span></div>
				{/if}
				<div class="modal-action mt-0">
					<button type="button" class="btn btn-ghost btn-sm" onclick={() => (showCreateModal = false)}>取消</button>
					<button type="submit" class="btn btn-primary btn-sm" disabled={createLoading}>
						{#if createLoading}<span class="loading loading-spinner loading-xs"></span>{/if}
						创建
					</button>
				</div>
			</form>
		</div>
		<button type="button" class="modal-backdrop" aria-label="关闭" onclick={() => (showCreateModal = false)}></button>
	</div>
{/if}

<!-- 编辑用户 Modal -->
{#if editUser}
	<div class="modal modal-open">
		<div class="modal-box max-w-sm">
			<h3 class="font-bold text-base mb-4">编辑用户：{editUser.username}</h3>
			<form onsubmit={handleEdit}>
				<div class="form-control mb-3">
					<label class="label pb-1 text-sm" for="eu-role">角色</label>
					<select id="eu-role" class="select select-bordered select-sm" bind:value={editRole}>
						<option value="user">普通用户</option>
						<option value="admin">管理员</option>
					</select>
				</div>
				<div class="form-control mb-4">
					<label class="label pb-1 text-sm" for="eu-active">状态</label>
					<select id="eu-active" class="select select-bordered select-sm" bind:value={editActive}>
						<option value={true}>启用</option>
						<option value={false}>禁用</option>
					</select>
				</div>
				<div class="modal-action mt-0">
					<button type="button" class="btn btn-ghost btn-sm" onclick={() => (editUser = null)}>取消</button>
					<button type="submit" class="btn btn-primary btn-sm" disabled={editLoading}>
						{#if editLoading}<span class="loading loading-spinner loading-xs"></span>{/if}
						保存
					</button>
				</div>
			</form>
		</div>
		<button type="button" class="modal-backdrop" aria-label="关闭" onclick={() => (editUser = null)}></button>
	</div>
{/if}

<!-- 重置密码 Modal -->
{#if resetUser}
	<div class="modal modal-open">
		<div class="modal-box max-w-sm">
			<h3 class="font-bold text-base mb-4">重置密码：{resetUser.username}</h3>
			<form onsubmit={handleReset}>
				<div class="form-control mb-3">
					<label class="label pb-1 text-sm" for="rp-pwd">新密码</label>
					<input id="rp-pwd" type="password" class="input input-bordered input-sm"
						placeholder="输入新密码" bind:value={resetPwd} required />
				</div>
				<div class="form-control mb-4">
					<label class="label pb-1 text-sm" for="rp-confirm">确认密码</label>
					<input id="rp-confirm" type="password" class="input input-bordered input-sm"
						placeholder="再次输入新密码" bind:value={resetConfirm} required />
				</div>
				{#if resetError}
					<div class="alert alert-error py-2 px-3 mb-3 text-sm"><span>{resetError}</span></div>
				{/if}
				<div class="modal-action mt-0">
					<button type="button" class="btn btn-ghost btn-sm" onclick={() => (resetUser = null)}>取消</button>
					<button type="submit" class="btn btn-warning btn-sm" disabled={resetLoading}>
						{#if resetLoading}<span class="loading loading-spinner loading-xs"></span>{/if}
						重置密码
					</button>
				</div>
			</form>
		</div>
		<button type="button" class="modal-backdrop" aria-label="关闭" onclick={() => (resetUser = null)}></button>
	</div>
{/if}

<!-- 删除确认 -->
<ConfirmDialog
	open={!!deleteUserId}
	title="确认删除用户"
	message="删除后此用户将无法登录系统，操作不可恢复。"
	loading={deleteLoading}
	onconfirm={handleDelete}
	oncancel={() => (deleteUserId = null)}
/>
