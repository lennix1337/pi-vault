import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { DefaultResourceLoader } from '@earendil-works/pi-coding-agent';

test('Pi loads the package: both tools and the skill are discoverable, with no load errors', async () => {
  const home = mkdtempSync(join(tmpdir(), 'pi-vault-loader-'));
  try {
    const agent = join(home, 'agent');
    const cwd = join(home, 'project');
    mkdirSync(agent);
    mkdirSync(cwd);
    writeFileSync(join(agent, 'settings.json'), JSON.stringify({ packages: [fileURLToPath(new URL('../', import.meta.url))] }));
    const loader = new DefaultResourceLoader({ cwd, agentDir: agent, disabledBuiltinExtensions: ['mcp'], noPromptTemplates: true, noThemes: true, noContextFiles: true });
    await loader.reload();
    const loaded = loader.getExtensions();
    assert.deepEqual(loaded.errors, []);
    assert.ok(loader.getSkills().skills.some(skill => skill.name === 'pi-vault'));
    const names = loaded.extensions.flatMap(extension => [...extension.tools.keys()]);
    assert.ok(names.includes('vault_run'));
    assert.ok(names.includes('vault_list'));
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
