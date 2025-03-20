import { pathsToModuleNameMapper } from 'ts-jest';
import { compilerOptions } from './tsconfig.json';

export default {
  preset: 'ts-jest', // 使用 ts-jest 预设
  testEnvironment: 'node', // 测试环境
  testMatch: ['**/test/**/*.test.ts'], // 指定测试文件路径
  moduleNameMapper: pathsToModuleNameMapper(compilerOptions.paths || {}, { prefix: '<rootDir>/' }),
  // 其他配置...
};