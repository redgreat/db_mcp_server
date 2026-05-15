<!--
  应用主布局：侧边栏 + 顶部导航栏
  创建时间：2026-05-01
  创建人：Antigravity
-->
<script lang="ts">
	import { goto, beforeNavigate } from '$app/navigation';
	import { page } from '$app/stores';
	import { authStore } from '$lib/stores/auth.svelte';
	import { api } from '$lib/api';
	import { onMount } from 'svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';

	let { children } = $props();

	let showChangePwd = $state(false);
	let oldPassword = $state('');
	let newPassword = $state('');
	let confirmPassword = $state('');
	let pwdLoading = $state(false);
	let pwdError = $state('');

	let showLogoutConfirm = $state(false);
	let sidebarOpen = $state(true);

	const navItems = $derived([
		{
			path: '/connections',
			label: '连接管理',
			icon: `<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M13.19 8.688a4.5 4.5 0 0 1 1.242 7.244l-4.5 4.5a4.5 4.5 0 0 1-6.364-6.364l1.757-1.757m13.35-.622 1.757-1.757a4.5 4.5 0 0 0-6.364-6.364l-4.5 4.5a4.5 4.5 0 0 0 1.242 7.244" />`
		},
		{
			path: '/keys',
			label: '访问密钥',
			icon: `<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15.75 5.25a3 3 0 0 1 3 3m3 0a6 6 0 0 1-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 0 1 21.75 8.25Z" />`
		},
		...(authStore.isAdmin
			? [
					{
						path: '/audit',
						label: '审计日志',
						icon: `<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3.75 12h16.5m-16.5 3.75h16.5M3.75 19.5h16.5M5.625 4.5h12.75a1.875 1.875 0 0 1 0 3.75H5.625a1.875 1.875 0 0 1 0-3.75Z" />`
					},
					{
						path: '/users',
						label: '用户管理',
						icon: `<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 19.128a9.38 9.38 0 0 0 2.625.372 9.337 9.337 0 0 0 4.121-.952 4.125 4.125 0 0 0-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 0 1 8.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0 1 11.964-3.07M12 6.375a3.375 3.375 0 1 1-6.75 0 3.375 3.375 0 0 1 6.75 0Zm8.25 2.25a2.625 2.625 0 1 1-5.25 0 2.625 2.625 0 0 1 5.25 0Z" />`
					},
					{
						path: '/ai-settings',
						label: '大模型配置',
						icon: `<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25m18 0A2.25 2.25 0 0018.75 3H5.25A2.25 2.25 0 003 5.25m18 0V12a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 12V5.25" />`
					}
				]
			: [])
	]);

	onMount(async () => {
		if (!authStore.token) {
			goto('/login');
			return;
		}
		if (!authStore.user) {
			try {
				const data = await api.get<{ user: import('$lib/stores/auth.svelte').User }>('/admin/me');
				authStore.setUser(data.user);
			} catch {
				authStore.logout();
				goto('/login');
			}
		}
	});

	function handleLogout() {
		authStore.logout();
		goto('/login');
	}

	async function handleChangePwd(e: SubmitEvent) {
		e.preventDefault();
		if (newPassword !== confirmPassword) {
			pwdError = '两次输入的新密码不一致';
			return;
		}
		pwdLoading = true;
		pwdError = '';
		try {
			await api.post('/admin/change_password', {
				old_password: oldPassword,
				new_password: newPassword
			});
			showChangePwd = false;
			oldPassword = '';
			newPassword = '';
			confirmPassword = '';
			authStore.logout();
			goto('/login');
		} catch (err: unknown) {
			pwdError = err instanceof Error ? err.message : '修改失败';
		} finally {
			pwdLoading = false;
		}
	}

	function isActive(path: string) {
		return $page.url.pathname.startsWith(path);
	}
</script>

<div class="drawer lg:drawer-open min-h-screen">
	<input id="sidebar-drawer" type="checkbox" class="drawer-toggle" bind:checked={sidebarOpen} />

	<!-- 侧边栏 -->
	<div class="drawer-side z-40">
		<label for="sidebar-drawer" class="drawer-overlay"></label>
		<aside class="w-72 min-h-screen bg-base-200 border-r border-base-300 flex flex-col">
			<!-- Logo -->
			<div class="p-4 border-b border-base-300">
				<div class="flex items-center gap-3">
					<div class="w-9 h-9 rounded-xl bg-primary/15 flex items-center justify-center flex-shrink-0">
						<svg class="w-5 h-5 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5"
								d="M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375m16.5 5.625c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125" />
						</svg>
					</div>
					<div>
						<div class="font-bold text-sm leading-tight">DB MCP Server</div>
						<div class="text-xs text-base-content/40">管理后台</div>
					</div>
				</div>
			</div>

			<!-- 导航菜单 -->
			<nav class="flex-1 p-3 space-y-0.5">
				{#each navItems as item}
					<a
						href={item.path}
						class="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all relative
							{isActive(item.path)
							? 'bg-primary/10 text-primary sidebar-active'
							: 'text-base-content/60 hover:text-base-content hover:bg-base-300'}"
					>
						<svg class="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
							{@html item.icon}
						</svg>
						{item.label}
					</a>
				{/each}
			</nav>

			<!-- 底部用户信息 -->
			<div class="p-3 border-t border-base-300">
				{#if authStore.user}
					<div class="flex items-center gap-2 px-2 py-1.5 rounded-lg">
						<div class="avatar placeholder">
							<div class="w-7 h-7 rounded-full bg-primary/20 text-primary text-xs font-bold flex items-center justify-center">
								{authStore.user.username[0].toUpperCase()}
							</div>
						</div>
						<div class="flex-1 min-w-0">
							<div class="text-sm font-medium truncate">{authStore.user.username}</div>
							<div class="text-xs text-base-content/40">
								{authStore.user.role === 'admin' ? '管理员' : '普通用户'}
							</div>
						</div>
					</div>
					<div class="flex gap-1 mt-2">
						<button
							class="btn btn-ghost btn-xs flex-1"
							onclick={() => (showChangePwd = true)}
						>
							修改密码
						</button>
						<button
							class="btn btn-ghost btn-xs flex-1 text-error hover:bg-error/10"
							onclick={() => (showLogoutConfirm = true)}
						>
							退出
						</button>
					</div>
				{/if}
			</div>
		</aside>
	</div>

	<!-- 主内容区 -->
	<div class="drawer-content flex flex-col">
		<!-- 顶部栏（移动端） -->
		<header class="lg:hidden navbar bg-base-100 border-b border-base-300 px-4">
			<label for="sidebar-drawer" class="btn btn-ghost btn-sm">
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
				</svg>
			</label>
			<span class="text-sm font-semibold ml-2">DB MCP Server</span>
		</header>

		<!-- 页面内容 -->
		<main class="flex-1 p-6 overflow-auto">
			{@render children()}
		</main>
	</div>
</div>

<!-- 修改密码 Modal -->
{#if showChangePwd}
	<div class="modal modal-open">
		<div class="modal-box max-w-sm">
			<h3 class="font-bold text-base mb-4">修改密码</h3>
			<form onsubmit={handleChangePwd}>
				<div class="form-control mb-3">
					<label class="label pb-1 text-sm" for="old-pwd">当前密码</label>
					<input id="old-pwd" type="password" class="input input-bordered input-sm"
						bind:value={oldPassword} required />
				</div>
				<div class="form-control mb-3">
					<label class="label pb-1 text-sm" for="new-pwd">新密码</label>
					<input id="new-pwd" type="password" class="input input-bordered input-sm"
						bind:value={newPassword} required />
				</div>
				<div class="form-control mb-4">
					<label class="label pb-1 text-sm" for="confirm-pwd">确认新密码</label>
					<input id="confirm-pwd" type="password" class="input input-bordered input-sm"
						bind:value={confirmPassword} required />
				</div>
				{#if pwdError}
					<div class="alert alert-error py-2 px-3 mb-3 text-sm"><span>{pwdError}</span></div>
				{/if}
				<div class="modal-action mt-0">
					<button type="button" class="btn btn-ghost btn-sm"
						onclick={() => { showChangePwd = false; pwdError = ''; }}>
						取消
					</button>
					<button type="submit" class="btn btn-primary btn-sm" disabled={pwdLoading}>
						{#if pwdLoading}<span class="loading loading-spinner loading-xs"></span>{/if}
						确认修改
					</button>
				</div>
			</form>
		</div>
		<button type="button" class="modal-backdrop" aria-label="关闭" onclick={() => (showChangePwd = false)}></button>
	</div>
{/if}

<!-- 退出确认 -->
<ConfirmDialog
	open={showLogoutConfirm}
	title="确认退出"
	message="确定要退出登录吗？"
	onconfirm={handleLogout}
	oncancel={() => (showLogoutConfirm = false)}
/>
