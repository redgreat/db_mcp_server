<!--
  应用主布局：可收缩侧边栏 + 顶栏（主题切换 / 用户菜单）
  创建时间：2026-05-01
  创建人：Antigravity
-->
<script lang="ts">
	import { goto, beforeNavigate } from '$app/navigation';
	import { page } from '$app/stores';
	import { authStore } from '$lib/stores/auth.svelte';
	import { themeStore } from '$lib/stores/theme.svelte';
	import { api, ApiError } from '$lib/api';
	import { onMount } from 'svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';

	let { children } = $props();

	const SIDEBAR_KEY = 'db_mcp_sidebar_collapsed';

	let showChangePwd = $state(false);
	let oldPassword = $state('');
	let newPassword = $state('');
	let confirmPassword = $state('');
	let pwdLoading = $state(false);
	let pwdError = $state('');

	let showLogoutConfirm = $state(false);

	// 桌面端：侧边栏收起为图标栏（持久化，手动展开后不再自动收缩）
	let sidebarCollapsed = $state(false);
	// 移动端：抽屉式侧边栏开关
	let mobileOpen = $state(false);

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
		{
			path: '/audit',
			label: '审计日志',
			icon: `<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3.75 12h16.5m-16.5 3.75h16.5M3.75 19.5h16.5M5.625 4.5h12.75a1.875 1.875 0 0 1 0 3.75H5.625a1.875 1.875 0 0 1 0-3.75Z" />`
		},
		{
			path: '/llm-logs',
			label: '大模型调用日志',
			icon: `<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75ZM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625ZM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125Z" />`
		},
		...(authStore.isAdmin
			? [
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

	// 顶栏显示的当前页面标题
	const currentNavLabel = $derived(
		navItems.find((i) => $page.url.pathname.startsWith(i.path))?.label ?? 'DB MCP Server'
	);

	onMount(async () => {
		try {
			sidebarCollapsed = localStorage.getItem(SIDEBAR_KEY) === '1';
		} catch {
			/* ignore */
		}
		if (!authStore.token) {
			goto('/login');
			return;
		}
		if (!authStore.user) {
			try {
				const data = await api.get<{ user: import('$lib/stores/auth.svelte').User }>('/admin/me');
				authStore.setUser(data.user);
			} catch (err) {
				if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
					return;
				}
				authStore.logout();
				goto('/login');
			}
		}
	});

	// 路由变化时关闭移动端抽屉
	beforeNavigate(() => {
		mobileOpen = false;
	});

	function toggleSidebar() {
		sidebarCollapsed = !sidebarCollapsed;
		try {
			localStorage.setItem(SIDEBAR_KEY, sidebarCollapsed ? '1' : '0');
		} catch {
			/* ignore */
		}
	}

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

{#snippet sidebarContent(expanded: boolean)}
	<!-- Logo -->
	<div class="border-b border-base-300 {expanded ? 'p-4' : 'p-3'}">
		<div class="flex items-center {expanded ? 'gap-3' : 'justify-center'}">
			<div class="w-10 h-10 rounded-xl bg-primary/15 flex items-center justify-center flex-shrink-0">
				<svg class="w-5 h-5 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5"
						d="M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375m16.5 5.625c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125" />
				</svg>
			</div>
			{#if expanded}
				<div class="min-w-0">
					<div class="admin-sidebar-brand-title font-bold leading-tight">DB MCP Server</div>
					<div class="admin-sidebar-brand-sub text-base-content/45">管理后台</div>
				</div>
			{/if}
		</div>
	</div>

	<!-- 导航菜单 -->
	<nav class="flex-1 p-3 space-y-1 overflow-y-auto">
		{#each navItems as item}
			<a
				href={item.path}
				title={expanded ? '' : item.label}
				class="admin-sidebar-link flex items-center rounded-lg font-medium transition-all relative
					{expanded ? 'gap-3 px-3 py-3' : 'justify-center px-0 py-3'}
					{isActive(item.path)
					? 'bg-primary/10 text-primary sidebar-active'
					: 'text-base-content/60 hover:text-base-content hover:bg-base-300'}"
			>
				<svg class="w-5 h-5 flex-shrink-0 opacity-90" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					{@html item.icon}
				</svg>
				{#if expanded}
					<span class="truncate">{item.label}</span>
				{/if}
			</a>
		{/each}
	</nav>
{/snippet}

<div class="flex min-h-screen">
	<!-- 桌面端侧边栏（图标栏 / 展开，手动切换且持久化） -->
	<aside
		class="admin-sidebar hidden lg:flex flex-col flex-shrink-0 min-h-screen bg-base-200 border-r border-base-300 overflow-hidden transition-[width] duration-200
			{sidebarCollapsed ? 'w-[4.5rem]' : 'w-72'}"
	>
		{@render sidebarContent(!sidebarCollapsed)}
	</aside>

	<!-- 移动端抽屉侧边栏 -->
	{#if mobileOpen}
		<div class="fixed inset-0 z-40 lg:hidden">
			<button
				type="button"
				class="absolute inset-0 bg-black/50 cursor-default"
				aria-label="关闭菜单"
				onclick={() => (mobileOpen = false)}
			></button>
			<aside class="admin-sidebar absolute left-0 top-0 h-full w-72 bg-base-200 border-r border-base-300 flex flex-col shadow-2xl">
				{@render sidebarContent(true)}
			</aside>
		</div>
	{/if}

	<!-- 主内容区 -->
	<div class="flex-1 flex flex-col min-w-0">
		<!-- 顶栏 -->
		<header class="sticky top-0 z-30 flex items-center gap-2 h-14 px-3 sm:px-4 bg-base-100/90 backdrop-blur border-b border-base-300">
			<!-- 菜单开关：桌面切换折叠，移动端打开抽屉 -->
			<button
				type="button"
				class="btn btn-ghost btn-sm btn-square hidden lg:inline-flex"
				title={sidebarCollapsed ? '展开菜单' : '收起菜单'}
				onclick={toggleSidebar}
			>
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
				</svg>
			</button>
			<button
				type="button"
				class="btn btn-ghost btn-sm btn-square lg:hidden"
				aria-label="打开菜单"
				onclick={() => (mobileOpen = true)}
			>
				<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
				</svg>
			</button>

			<span class="font-semibold text-base tracking-tight truncate">{currentNavLabel}</span>

			<div class="flex-1"></div>

			<!-- 主题切换 -->
			<button
				type="button"
				class="btn btn-ghost btn-sm btn-square"
				title={themeStore.isDark ? '切换到亮色主题' : '切换到暗色主题'}
				onclick={() => themeStore.toggle()}
			>
				{#if themeStore.isDark}
					<!-- 太阳图标：点击切到亮色 -->
					<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5"
							d="M12 3v2.25m6.364.386-1.591 1.591M21 12h-2.25m-.386 6.364-1.591-1.591M12 18.75V21m-4.773-4.227-1.591 1.591M5.25 12H3m4.227-4.773L5.636 5.636M15.75 12a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0Z" />
					</svg>
				{:else}
					<!-- 月亮图标：点击切到暗色 -->
					<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5"
							d="M21.752 15.002A9.72 9.72 0 0 1 18 15.75c-5.385 0-9.75-4.365-9.75-9.75 0-1.33.266-2.597.748-3.752A9.753 9.753 0 0 0 3 11.25C3 16.635 7.365 21 12.75 21a9.753 9.753 0 0 0 9.002-5.998Z" />
					</svg>
				{/if}
			</button>

			<!-- 用户下拉 -->
			{#if authStore.user}
				<div class="dropdown dropdown-end">
					<button tabindex="0" class="btn btn-ghost btn-sm gap-2 pl-1.5">
						<div class="w-7 h-7 rounded-full bg-primary/20 text-primary text-xs font-bold flex items-center justify-center">
							{authStore.user.username[0].toUpperCase()}
						</div>
						<span class="max-w-32 truncate">{authStore.user.username}</span>
						<svg class="w-3.5 h-3.5 opacity-60" fill="none" stroke="currentColor" viewBox="0 0 24 24">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="m19.5 8.25-7.5 7.5-7.5-7.5" />
						</svg>
					</button>
					<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
					<ul tabindex="0" class="dropdown-content menu bg-base-100 rounded-box z-50 w-44 p-2 shadow-xl border border-base-300">
						<li>
							<button
								type="button"
								onclick={(e) => { (e.currentTarget as HTMLElement).blur(); showChangePwd = true; }}
							>
								修改密码
							</button>
						</li>
						<li>
							<button
								type="button"
								class="text-error"
								onclick={(e) => { (e.currentTarget as HTMLElement).blur(); showLogoutConfirm = true; }}
							>
								退出登录
							</button>
						</li>
					</ul>
				</div>
			{/if}
		</header>

		<!-- 页面内容 -->
		<main class="flex-1 p-4 sm:p-6 overflow-auto">
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
