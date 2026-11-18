export default {
  testEnvironment: 'node',
  transform: {
    // tsconfig.json turns source maps off for the shipped dist/, which left
    // Jest stack traces pointing at the wrong source lines. Tests get them back.
    '^.+\\.tsx?$': ['ts-jest', { tsconfig: { sourceMap: true } }],
  },
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/**/*.test.ts',
  ],
};
