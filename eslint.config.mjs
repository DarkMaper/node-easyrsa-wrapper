import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import eslintConfigPrettier from 'eslint-config-prettier';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import eslintPluginPrettier from 'eslint-plugin-prettier/recommended';

const __dirname = dirname(fileURLToPath(import.meta.url));

/* export default tseslint.config(
    eslint.configs.recommended,
    eslintConfigPrettier,
    tseslint.configs.recommendedTypeChecked,
    {
        languageOptions: {
            parserOptions: {
                project: true,
                tsconfigRootDir: __dirname
            },
        },
        ignores: [
            'tests/**//*',
            'node_modules',
            'dist/**//*',
            'jest.config.js'
        ],
        rules: {
            'quotes': ['error', 'single'],
            'linebreak-style': ['error', 'unix'],
            '@typescript-eslint/prefer-promise-reject-errors': ['off']
        }
    },
) */

export default tseslint.config(
    {
        ignores: [
            'coverage/**/*',
            'node_modules',
            'jest.config.ts',
            'dist/**/*',
        ],
    },
    {
        files: ['src/**/*.ts'],
        extends: [
            eslint.configs.recommended,
            ...tseslint.configs.recommendedTypeChecked
        ],
        languageOptions: {
            parserOptions: {
                project: true,
                tsconfigRootDir: __dirname
            }
        },
        rules: {
            'quotes': ['error', 'single'],
            'linebreak-style': ['error', 'unix'],
            '@typescript-eslint/prefer-promise-reject-errors': ['off']
        }
    },
    {
        files: ['src/**/*.ts'],
        extends: [eslintPluginPrettier],
        rules: {
            ...eslintConfigPrettier.rules
        }
    }
)