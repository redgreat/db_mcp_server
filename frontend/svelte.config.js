import adapter from '@sveltejs/adapter-static';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	compilerOptions: {
		runes: ({ filename }) => (filename.split(/[/\\]/).includes('node_modules') ? undefined : true)
	},
	onwarn: (warning, handler) => {
		// 忽略 DaisyUI modal-backdrop 相关的 a11y 警告
		if (warning.code.startsWith('a11y')) return;
		handler(warning);
	},
	kit: {
		adapter: adapter({
			pages: '../src/static',
			assets: '../src/static',
			fallback: 'index.html',
			precompress: false,
			strict: false
		}),
		paths: {
			base: ''
		}
	}
};

export default config;
