/**
 * The version `pulsecheck-gate --version` prints. It must equal `cli/package.json` (the npm package version);
 * `cliPackage.test.ts` holds the two together so a release cannot publish one number and print another.
 */
export const CLI_VERSION = '0.1.1';
