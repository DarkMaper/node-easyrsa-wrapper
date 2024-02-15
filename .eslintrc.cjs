module.exports = {
    extends: [
        'eslint:recommended',
        'plugin:@typescript-eslint/recommended',
        'plugin:@typescript-eslint/recommended-requiring-type-checking',
        'plugin:prettier/recommended'
    ],
    parser: '@typescript-eslint/parser',
    plugins: ['@typescript-eslint'],
    parserOptions: {
        project: true,
        tsconfigRootDir: __dirname
    },
    root: true,
    ignorePatterns: [
        'tests/**/*.ts',
        'node_modules',
        'dist/**/*',
        '.eslintrc.cjs',
        'jest.config.js'
    ],
    rules: {
        'quotes': [ 'error', 'single' ],
        'linebreak-style': ['error', 'unix']
    }
}