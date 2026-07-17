#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { simulatePolicyDecision } from '../src/policySimulation.mjs';

function usageError(message) {
  throw new Error(`${message} Usage: policy-simulate --bundle <path> --fixture <path>`);
}

function parseArgs(argv) {
  if (argv.length !== 4) usageError('Expected exactly --bundle <path> --fixture <path>.');
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!['--bundle', '--fixture'].includes(flag) || !value || Object.hasOwn(values, flag.slice(2))) {
      usageError('Expected exactly --bundle <path> --fixture <path> (in either order).');
    }
    values[flag.slice(2)] = value;
  }
  if (!values.bundle || !values.fixture) usageError('Both --bundle and --fixture are required.');
  return { bundlePath: values.bundle, fixturePath: values.fixture };
}

function loadFixture(fixturePath) {
  let source;
  try {
    source = readFileSync(fixturePath, 'utf8');
  } catch {
    throw new Error(`Unable to read fixture at ${fixturePath}.`);
  }
  let fixture;
  try {
    fixture = JSON.parse(source);
  } catch {
    throw new Error(`Fixture at ${fixturePath} is not valid JSON.`);
  }
  if (!fixture || typeof fixture !== 'object' || Array.isArray(fixture)
    || !Object.hasOwn(fixture, 'principal') || !Object.hasOwn(fixture, 'request')) {
    throw new Error('Fixture must be a JSON object containing principal and request.');
  }
  return fixture;
}

try {
  const { bundlePath, fixturePath } = parseArgs(process.argv.slice(2));
  const fixture = loadFixture(fixturePath);
  const result = simulatePolicyDecision({ bundlePath, principal: fixture.principal, request: fixture.request });
  if (result.decision !== 'allow') {
    throw new Error(`Policy denied request: ${result.reason ?? 'request is not permitted.'}`);
  }
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (error) {
  process.stderr.write(`policy simulation failed: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}
