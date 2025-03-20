import { defineConfig } from 'father';

export default defineConfig({
  cjs: {
    input: 'src',
    output: 'dist/cjs',
  },
  esm: {
    input: 'src',
    output: 'dist/esm',
  },
});