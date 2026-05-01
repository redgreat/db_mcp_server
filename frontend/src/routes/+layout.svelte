<script lang="ts">
	import '../app.css';
	import Toast from '$lib/components/Toast.svelte';

	let { children } = $props();
</script>

<svelte:head>
	<title>DB MCP Server 管理后台</title>
</svelte:head>

{@render children()}
<Toast />
