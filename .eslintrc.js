module.exports = {
    env: {
        es2020: true,
        node:   true,
    },
    extends: [
        'eslint:recommended',
        'plugin:@typescript-eslint/eslint-recommended',
        'plugin:@typescript-eslint/recommended',
        'plugin:@typescript-eslint/recommended-requiring-type-checking',
        '@silver886/eslint-config/typescript',
    ],
    parser:        '@typescript-eslint/parser',
    parserOptions: {
        ecmaVersion: 12,
        sourceType:  'module',
        project:     '.eslintrc.tsconfig.json',
    },
    plugins: [
        '@typescript-eslint',
    ],
};
