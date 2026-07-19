import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// The experiment must not touch production enforcement. This base commit is the
// tip of `main` from which the experiment branch diverged.
const BASE_COMMIT = '355342f';
const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.join(here, '..');

// The prototype may be observed from the server through the explicitly
// non-enforcing shadow adapter, but it must not change authoritative heuristic
// policy or the database execution boundary.
const PROTECTED_PRODUCTION_FILES = [
  'src/policyEngine.mjs',
  'src/db.mjs',
];

// New experiment modules must stay offline: no server or database coupling.
const EXPERIMENT_MODULES = [
  'src/astPolicyExperiment.mjs',
  'src/astPolicyCorpus.mjs',
  'src/astPolicyDifferential.mjs',
  'benchmarks/ast-policy-differential-benchmark.mjs',
];

function changedFilesSinceBase() {
  const output = execFileSync(
    'git',
    ['diff', '--name-only', `${BASE_COMMIT}..HEAD`],
    { cwd: repoRoot, encoding: 'utf8' },
  );
  return output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

test('experiment does not modify authoritative policy or database files', () => {
  const changed = changedFilesSinceBase();
  for (const protectedFile of PROTECTED_PRODUCTION_FILES) {
    assert.ok(
      !changed.includes(protectedFile),
      `experiment must not modify production file ${protectedFile}`,
    );
  }
});

test('experiment leaves the SQL compiler and parser adapter untouched', () => {
  const changed = changedFilesSinceBase();
  for (const untouched of ['src/sqlCompiler.mjs', 'src/astParserExperiment.mjs']) {
    assert.ok(
      !changed.includes(untouched),
      `experiment must not modify ${untouched}`,
    );
  }
});

test('experiment modules never import server.mjs or db.mjs', () => {
  for (const modulePath of EXPERIMENT_MODULES) {
    const source = readFileSync(path.join(repoRoot, modulePath), 'utf8');
    assert.ok(
      !/from\s+['"][^'"]*server\.mjs['"]/.test(source),
      `${modulePath} must not import server.mjs`,
    );
    assert.ok(
      !/from\s+['"][^'"]*db\.mjs['"]/.test(source),
      `${modulePath} must not import db.mjs`,
    );
  }
});
