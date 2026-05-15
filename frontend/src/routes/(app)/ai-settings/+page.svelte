<!--
  AI 配置管理页面
  创建时间：2026-05-01
  创建人：Antigravity
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { api } from '$lib/api';

	interface LLMConfig {
		id: number;
		provider: string;
		base_url: string;
		model_name: string;
		has_api_key: boolean;
		is_active: boolean;
		created_at: string;
		updated_at: string;
	}

	let configs = $state<LLMConfig[]>([]);
	let loading = $state(true);
	let error = $state('');

	let editingConfig = $state<LLMConfig | null>(null);
	let editBaseUrl = $state('');
	let editApiKey = $state('');
	let editModelName = $state('');
	let editLoading = $state(false);

	async function loadConfigs() {
		try {
			loading = true;
			const res = await api.get<{ items: LLMConfig[] }>('/admin/llm_configs');
			configs = res.items;
		} catch (err: unknown) {
			error = err instanceof Error ? err.message : '加载失败';
		} finally {
			loading = false;
		}
	}

	onMount(() => {
		loadConfigs();
	});

	function openEdit(config: LLMConfig) {
		editingConfig = config;
		editBaseUrl = config.base_url || '';
		editApiKey = '';
		editModelName = config.model_name || '';
	}

	function closeEdit() {
		editingConfig = null;
	}

	async function handleSave(e: SubmitEvent) {
		e.preventDefault();
		if (!editingConfig) return;
		
		try {
			editLoading = true;
			await api.put(`/admin/llm_configs/${editingConfig.id}`, {
				base_url: editBaseUrl,
				api_key: editApiKey,
				model_name: editModelName
			});
			closeEdit();
			await loadConfigs();
		} catch (err: unknown) {
			alert(err instanceof Error ? err.message : '保存失败');
		} finally {
			editLoading = false;
		}
	}

	async function activateConfig(id: number) {
		try {
			await api.post(`/admin/llm_configs/${id}/activate`, {});
			await loadConfigs();
		} catch (err: unknown) {
			alert(err instanceof Error ? err.message : '激活失败');
		}
	}

	function getProviderLabel(provider: string) {
		const map: Record<string, string> = {
			openai: 'OpenAI (GPT)',
			claude: 'Anthropic (Claude)',
			deepseek: 'DeepSeek'
		};
		return map[provider] || provider;
	}
	
	function getProviderBadgeColor(provider: string) {
		const map: Record<string, string> = {
			openai: 'badge-info',
			claude: 'badge-secondary',
			deepseek: 'badge-primary'
		};
		return map[provider] || 'badge-neutral';
	}
</script>

<div class="max-w-5xl mx-auto space-y-6">
	<!-- 顶部标题区 -->
	<div class="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-base-100 p-6 rounded-2xl shadow-sm border border-base-200">
		<div>
			<h1 class="text-2xl font-bold tracking-tight">大模型 AI 配置</h1>
		</div>
	</div>

	{#if loading}
		<div class="flex justify-center p-12">
			<span class="loading loading-spinner loading-lg text-primary"></span>
		</div>
	{:else if error}
		<div class="alert alert-error shadow-sm rounded-xl">
			<svg class="stroke-current shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
			</svg>
			<span>{error}</span>
			<button class="btn btn-sm" onclick={loadConfigs}>重试</button>
		</div>
	{:else}
		<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
			{#each configs as config}
				<div class="card bg-base-100 border border-base-200 shadow-sm hover:shadow-md transition-shadow relative overflow-hidden">
					{#if config.is_active}
						<div class="absolute top-0 right-0">
							<div class="bg-success text-success-content text-xs font-bold px-3 py-1 rounded-bl-lg shadow-sm">
								当前激活
							</div>
						</div>
					{/if}
					
					<div class="card-body p-6">
						<div class="flex items-center gap-3 mb-2">
							<div class="badge {getProviderBadgeColor(config.provider)} font-semibold px-3 py-3">
								{getProviderLabel(config.provider)}
							</div>
						</div>
						
						<div class="space-y-3 mt-4 flex-1">
							<div>
								<div class="text-xs text-base-content/50 font-medium mb-1">Base URL</div>
								<div class="text-sm font-mono bg-base-200 p-2 rounded-md break-all">
									{config.base_url || '未设置'}
								</div>
							</div>
							
							<div>
								<div class="text-xs text-base-content/50 font-medium mb-1">默认模型 (Model)</div>
								<div class="text-sm font-mono bg-base-200 p-2 rounded-md">
									{config.model_name || '未设置'}
								</div>
							</div>
							
							<div>
								<div class="text-xs text-base-content/50 font-medium mb-1">API Key 状态</div>
								<div class="text-sm flex items-center gap-2">
									{#if config.has_api_key}
										<div class="w-2 h-2 rounded-full bg-success"></div>
										<span class="text-success font-medium">已配置 (安全存储)</span>
									{:else}
										<div class="w-2 h-2 rounded-full bg-error"></div>
										<span class="text-error font-medium">未配置</span>
									{/if}
								</div>
							</div>
						</div>

						<div class="card-actions justify-end mt-6 pt-4 border-t border-base-200">
							<button class="btn btn-sm btn-ghost" onclick={() => openEdit(config)}>编辑</button>
							{#if !config.is_active}
								<button class="btn btn-sm btn-primary" onclick={() => activateConfig(config.id)} disabled={!config.has_api_key}>
									激活使用
								</button>
							{:else}
								<button class="btn btn-sm btn-success cursor-default">
									<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
										<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
									</svg>
									使用中
								</button>
							{/if}
						</div>
					</div>
				</div>
			{/each}
		</div>
	{/if}
</div>

<!-- 编辑配置弹窗 -->
{#if editingConfig}
	<div class="modal modal-open bg-base-300/60 backdrop-blur-sm">
		<div class="modal-box max-w-md shadow-2xl border border-base-200">
			<h3 class="font-bold text-lg mb-6 flex items-center gap-2">
				<svg class="w-5 h-5 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
				</svg>
				配置 {getProviderLabel(editingConfig.provider)}
			</h3>
			
			<form onsubmit={handleSave} class="space-y-4">
				<div class="form-control">
					<label class="label pb-1" for="base_url">
						<span class="label-text font-medium">Base URL</span>
						<span class="label-text-alt text-base-content/50">支持代理/私有化地址</span>
					</label>
					<input id="base_url" type="url" class="input input-bordered w-full font-mono text-sm" 
						bind:value={editBaseUrl} placeholder="https://api.openai.com/v1" required />
				</div>
				
				<div class="form-control">
					<label class="label pb-1" for="model_name">
						<span class="label-text font-medium">模型名称 (Model)</span>
					</label>
					<input id="model_name" type="text" class="input input-bordered w-full font-mono text-sm" 
						bind:value={editModelName} placeholder="gpt-4o" required />
				</div>
				
				<div class="form-control">
					<label class="label pb-1" for="api_key">
						<span class="label-text font-medium">API Key</span>
						{#if editingConfig.has_api_key}
							<span class="label-text-alt text-warning">留空表示不修改现有Key</span>
						{/if}
					</label>
					<input id="api_key" type="password" class="input input-bordered w-full font-mono text-sm" 
						bind:value={editApiKey} placeholder="sk-..." />
				</div>

				<div class="modal-action mt-8 border-t border-base-200 pt-4">
					<button type="button" class="btn btn-ghost" onclick={closeEdit}>取消</button>
					<button type="submit" class="btn btn-primary" disabled={editLoading}>
						{#if editLoading}<span class="loading loading-spinner loading-xs"></span>{/if}
						保存配置
					</button>
				</div>
			</form>
		</div>
		<button type="button" class="modal-backdrop" aria-label="关闭" onclick={closeEdit}></button>
	</div>
{/if}
