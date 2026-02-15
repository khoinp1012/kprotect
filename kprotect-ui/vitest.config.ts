import { defineConfig, mergeConfig } from 'vitest/config';
import viteConfig from './vite.config';

export default defineConfig(async (configEnv) => {
    const baseConfig = typeof viteConfig === 'function' ? await viteConfig(configEnv) : viteConfig;

    return mergeConfig(
        baseConfig,
        defineConfig({
            test: {
                globals: true,
                environment: 'jsdom',
                setupFiles: './src/test/setup.ts',
                css: true,
            },
        })
    );
});
