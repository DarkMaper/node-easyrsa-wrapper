import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import eslintConfigPrettier from 'eslint-config-prettier';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

export default tseslint.config(
    eslint.configs.recommended,
    tseslint.configs.recommendedTypeChecked,
    eslintConfigPrettier,
    {
        languageOptions: {
            parserOptions: {
                project: true,
                tsconfigRootDir: __dirname
            },
        },
        ignores: [
            'tests/**/*.ts',
            'node_modules',
            'dist/**/*',
            'eslint.config.mjs',
            'jest.config.js'
        ],
        rules: {
            'quotes': ['error', 'single'],
            'linebreak-style': ['error', 'unix'],
            '@typescript-eslint/prefer-promise-reject-errors': ['off']
        }
    },
    {
        files: ['test/**/*'],
        plugins: ['jest'],
        env: {
            "jest/globals": true 
        }
    }
)