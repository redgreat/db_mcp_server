<script lang="ts">
	let {
		value = '',
		class: className = '',
		maxWidth = 'max-w-[14rem]'
	}: {
		value?: string | number | null;
		class?: string;
		maxWidth?: string;
	} = $props();

	const text = $derived(String(value ?? '').trim() || '—');
</script>

<span
	class="admin-cell-tip {maxWidth} {className}"
	title={text === '—' ? '' : text}
>{text}</span>
