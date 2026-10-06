import wranglerConfigText from '../wrangler.jsonc?raw';

export { wranglerConfigText };

// The parts of wrangler.jsonc that tests check.
export interface WranglerConfig {
  readonly vars: Readonly<Record<string, string>>;
  readonly secrets: { readonly required: readonly string[] };
  readonly assets: { readonly binding: string };
  readonly durable_objects: {
    readonly bindings: readonly { name: string; class_name: string }[];
  };
  readonly exports: Readonly<Record<string, unknown>>;
}

// wrangler.jsonc as JSON: without comments and trailing commas.
export const wranglerConfig = JSON.parse(
  wranglerConfigText.replace(/^\s*\/\/.*$/gm, '').replace(/,(\s*[}\]])/g, '$1'),
) as WranglerConfig;
