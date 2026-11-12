import { scanConfig } from './eslint-scan-config.js';

/**
 * Type-aware scan configuration, loaded only for the explicit `eslint-tsconfig`
 * opt-in. The reviewed tsconfig arrives as `--parser-options project:<path>`.
 */
export default scanConfig(true);
