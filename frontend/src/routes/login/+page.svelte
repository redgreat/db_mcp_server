<!--
  登录页面
  创建时间：2026-05-01
  创建人：Antigravity
-->
<script lang="ts">
	import { goto } from '$app/navigation';
	import { api, ApiError } from '$lib/api';
	import { authStore } from '$lib/stores/auth.svelte';

	let username = $state('');
	let password = $state('');
	let loading = $state(false);
	let error = $state('');

	async function handleLogin(e: SubmitEvent) {
		e.preventDefault();
		loading = true;
		error = '';
		try {
			const data = await api.post<{
				token: string;
				user: import('$lib/stores/auth.svelte').User;
			}>('/admin/login', { username, password });
			authStore.login(data.token, data.user);
			goto('/connections');
		} catch (err) {
			error = err instanceof ApiError ? err.message : '登录失败，请稍后重试';
		} finally {
			loading = false;
		}
	}
</script>

<svelte:head>
	<title>登录 - DB MCP Server</title>
</svelte:head>

<div class="min-h-screen bg-slate-950 flex items-center justify-center p-6 relative overflow-hidden">
	<!-- 动态艺术背景 -->
	<div class="absolute inset-0 z-0">
		<div class="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-primary/10 rounded-full blur-[120px] animate-pulse"></div>
		<div class="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] bg-secondary/10 rounded-full blur-[120px] animate-pulse" style="animation-delay: 2s;"></div>
		<div class="absolute inset-0 opacity-[0.03]" style="background-image: radial-gradient(#fff 1px, transparent 1px); background-size: 32px 32px;"></div>
	</div>

	<div class="card w-full max-w-[420px] bg-base-100/70 backdrop-blur-2xl shadow-[0_0_50px_-12px_rgba(0,0,0,0.5)] border border-white/5 relative z-10 overflow-hidden">
		<!-- 顶部渐变条 -->
		<div class="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-primary via-secondary to-accent"></div>
		
		<div class="card-body p-8">
			<!-- Logo 区域 -->
			<div class="flex flex-col items-center mb-8">
				<div class="w-16 h-16 rounded-2xl bg-gradient-to-br from-primary to-secondary p-[1px] mb-4 shadow-lg shadow-primary/20">
					<div class="w-full h-full rounded-2xl bg-base-100 flex items-center justify-center">
						<svg class="w-9 h-9 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5"
								d="M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375m16.5 5.625c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125" />
						</svg>
					</div>
				</div>
				<h1 class="text-2xl font-black tracking-tight text-base-content bg-clip-text">DB MCP Server</h1>
				<p class="text-base-content/60 text-sm mt-2 font-medium">企业数据库安全访问管理平台</p>
			</div>

			<!-- 登录表单 -->
			<form onsubmit={handleLogin} class="space-y-5">
				<div class="form-control">
					<label class="label pt-0" for="username">
						<span class="label-text text-xs font-bold uppercase tracking-wider opacity-70">用户名</span>
					</label>
					<div class="relative group">
						<input
							id="username"
							type="text"
							class="input input-bordered w-full bg-base-200/50 focus:bg-base-100 transition-all border-white/5 focus:border-primary/50"
							placeholder="输入管理员账号"
							bind:value={username}
							required
							autocomplete="username"
						/>
					</div>
				</div>

				<div class="form-control">
					<label class="label pt-0" for="password">
						<span class="label-text text-xs font-bold uppercase tracking-wider opacity-70">密码</span>
					</label>
					<div class="relative group">
						<input
							id="password"
							type="password"
							class="input input-bordered w-full bg-base-200/50 focus:bg-base-100 transition-all border-white/5 focus:border-primary/50"
							placeholder="输入登录密码"
							bind:value={password}
							required
							autocomplete="current-password"
						/>
					</div>
				</div>

				{#if error}
					<div class="alert alert-error bg-error/10 border-error/20 text-error text-sm py-3 animate-shake">
						<svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-4 w-4" fill="none" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
						<span>{error}</span>
					</div>
				{/if}

				<div class="pt-2">
					<button
						type="submit"
						class="btn btn-primary w-full shadow-lg shadow-primary/20 hover:shadow-primary/40 transition-all duration-300 group"
						disabled={loading}
					>
						{#if loading}
							<span class="loading loading-spinner loading-sm"></span>
						{:else}
							<span>立即登录</span>
							<svg class="w-4 h-4 ml-2 group-hover:translate-x-1 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7l5 5m0 0l-5 5m5-5H6" /></svg>
						{/if}
					</button>
				</div>
			</form>

			<div class="divider text-[10px] uppercase tracking-widest opacity-30 mt-8 mb-4">Security Access Control</div>
			<p class="text-center text-[11px] text-base-content/40 leading-relaxed font-medium">
				所有连接均经过 AES-256 加密存储<br/>
				操作日志将实时记录至审计系统
			</p>
		</div>
	</div>
</div>

<style>
	:global(.animate-shake) {
		animation: shake 0.5s cubic-bezier(.36,.07,.19,.97) both;
	}
	@keyframes shake {
		10%, 90% { transform: translate3d(-1px, 0, 0); }
		20%, 80% { transform: translate3d(2px, 0, 0); }
		30%, 50%, 70% { transform: translate3d(-4px, 0, 0); }
		40%, 60% { transform: translate3d(4px, 0, 0); }
	}
</style>
