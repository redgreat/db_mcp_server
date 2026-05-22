<!--
  大模型配置（表格 + 编辑弹窗）
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { api, ApiError } from '$lib/api';
	import { toast } from '$lib/stores/toast.svelte';

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

	let editingConfig = $state<LLMConfig | null>(null);
	let editBaseUrl = $state('');
	let editApiKey = $state('');
	let editModelName = $state('');
	let editLoading = $state(false);

	const providerLabels: Record<string, string> = {
		openai: 'OpenAI (GPT)',
		claude: 'Anthropic (Claude)',
		deepseek: 'DeepSeek'
	};

	function providerLabel(p: string) {
		return providerLabels[p] || p;
	}

	async function loadConfigs() {
		loading = true;
		try {
			const res = await api.get<{ items: LLMConfig[] }>('/admin/llm_configs');
			configs = res.items;
		} catch (err) {
			toast(err instanceof ApiError ? err.message : '加载失败', 'error');
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
		editLoading = true;
		try {
			await api.put(`/admin/llm_configs/${editingConfig.id}`, {
				base_url: editBaseUrl,
				api_key: editApiKey,
				model_name: editModelName
			});
			closeEdit();
			toast('配置已保存', 'success');
			await loadConfigs();
		} catch (err) {
			toast(err instanceof ApiError ? err.message : '保存失败', 'error');
		} finally {
			editLoading = false;
		}
	}

	async function activateConfig(id: number) {
		try {
			await api.post(`/admin/llm_configs/${id}/activate`, {});
			toast('已切换激活模型', 'success');
			await loadConfigs();
		} catch (err) {
			toast(err instanceof ApiError ? err.message : '激活失败', 'error');
		}
	}
</script>

<svelte:head>
	<title>大模型配置 - DB MCP Server</title>
</svelte:head>

<div class="fade-in">
	<div class="mb-6">
		<h1 class="text-2xl font-bold tracking-tight">大模型配置</h1>
		<p class="text-sm text-base-content/50 mt-1">
			配置并激活一个提供商后，ER 分析、SQL 审查、性能诊断等工具将统一通过该模型调用。
		</p>
	</div>

	{#if loading}
		<div class="flex justify-center py-12">
			<span class="loading loading-spinner loading-lg text-primary"></span>
		</div>
	{:else}
		<div class="overflow-x-auto">
			<table class="table table-zebra table-sm">
				<thead>
					<tr class="text-xs text-base-content/60">
						<th>提供商</th>
						<th>Base URL</th>
						<th>默认模型</th>
						<th>API Key</th>
						<th>状态</th>
						<th class="text-right">操作</th>
					</tr>
				</thead>
				<tbody>
					{#each configs as config}
						<tr class="hover">
							<td class="font-medium text-sm">{providerLabel(config.provider)}</td>
							<td class="text-xs font-mono max-w-[240px] truncate" title={config.base_url || ''}>
								{config.base_url || '—'}
							</td>
							<td class="text-xs font-mono">{config.model_name || '—'}</td>
							<td>
								<div class="flex items-center gap-1.5">
									<div
										class="w-1.5 h-1.5 rounded-full {config.has_api_key ? 'bg-success' : 'bg-error'}"
									></div>
									<span class="text-xs {config.has_api_key ? 'text-success' : 'text-error'}">
										{config.has_api_key ? '已配置' : '未配置'}
									</span>
								</div>
							</td>
							<td>
								{#if config.is_active}
									<span class="badge badge-success badge-sm">使用中</span>
								{:else}
									<span class="badge badge-ghost badge-sm">未激活</span>
								{/if}
							</td>
							<td>
								<div class="flex justify-end gap-1">
									<button class="btn btn-xs btn-ghost" onclick={() => openEdit(config)}>编辑</button>
									{#if !config.is_active}
										<button
											class="btn btn-xs btn-primary"
											disabled={!config.has_api_key}
											onclick={() => activateConfig(config.id)}
										>
											激活
										</button>
									{/if}
								</div>
							</td>
						</tr>
					{:else}
						<tr>
							<td colspan="6" class="text-center text-base-content/40 py-8">暂无配置</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>

{#if editingConfig}
	<div class="modal modal-open">
		<div class="modal-box max-w-md">
			<h3 class="font-bold text-base mb-4">编辑 — {providerLabel(editingConfig.provider)}</h3>
			<form onsubmit={handleSave} class="space-y-3">
				<div class="form-control">
					<label class="label pb-1 text-sm" for="base_url">Base URL</label>
					<input
						id="base_url"
						type="url"
						class="input input-bordered input-sm w-full font-mono"
						bind:value={editBaseUrl}
						required
					/>
				</div>
				<div class="form-control">
					<label class="label pb-1 text-sm" for="model_name">默认模型</label>
					<input
						id="model_name"
						type="text"
						class="input input-bordered input-sm w-full font-mono"
						bind:value={editModelName}
						required
					/>
				</div>
				<div class="form-control">
					<label class="label pb-1 text-sm" for="api_key">API Key</label>
					{#if editingConfig.has_api_key}
						<span class="label-text-alt text-warning text-xs mb-1">留空表示不修改</span>
					{/if}
					<input
						id="api_key"
						type="password"
						class="input input-bordered input-sm w-full font-mono"
						bind:value={editApiKey}
						placeholder="sk-..."
					/>
				</div>
				<div class="modal-action mt-4">
					<button type="button" class="btn btn-ghost btn-sm" onclick={closeEdit}>取消</button>
					<button type="submit" class="btn btn-primary btn-sm" disabled={editLoading}>
						{#if editLoading}<span class="loading loading-spinner loading-xs"></span>{/if}
						保存
					</button>
				</div>
			</form>
		</div>
		<button type="button" class="modal-backdrop" aria-label="关闭" onclick={closeEdit}></button>
	</div>
{/if}
