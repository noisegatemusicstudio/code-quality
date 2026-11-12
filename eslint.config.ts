import { qualityConfig } from './dist/src/eslint.js';

export default [...qualityConfig(import.meta.dirname)];
