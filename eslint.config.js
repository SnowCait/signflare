import js from '@eslint/js';
import svelte from 'eslint-plugin-svelte';
import { defineConfig, globalIgnores } from 'eslint/config';
import ts from 'typescript-eslint';

export default defineConfig(
  globalIgnores(['dist', '.wrangler', 'worker-configuration.d.ts']),
  js.configs.recommended,
  ts.configs.recommended,
  svelte.configs.recommended,
  svelte.configs.prettier,
  {
    files: ['**/*.svelte'],
    languageOptions: {
      parserOptions: {
        parser: ts.parser,
      },
    },
  },
  {
    files: ['**/*.ts', '**/*.svelte'],
    rules: {
      // TypeScript already reports undefined identifiers.
      'no-undef': 'off',
    },
  },
);
