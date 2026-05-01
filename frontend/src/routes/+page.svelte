<!--
  根路由：根据认证状态重定向
  创建时间：2026-05-01
  创建人：Antigravity
-->
<script lang="ts">
	import { goto } from '$app/navigation';
	import { authStore } from '$lib/stores/auth.svelte';
	import { onMount } from 'svelte';
	import { api } from '$lib/api';

	onMount(async () => {
		if (!authStore.token) {
			goto('/login');
			return;
		}
		try {
			const data = await api.get<{ user: import('$lib/stores/auth.svelte').User }>('/admin/me');
			authStore.setUser(data.user);
			goto('/connections');
		} catch {
			authStore.logout();
			goto('/login');
		}
	});
</script>
