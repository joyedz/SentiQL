#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { simulatePolicyDecision } from '../src/policySimulation.mjs';

function usageError(message) {
  throw new Error(`${message} Usage: policy-simulate --bundle <path> --fixture <path> [--pretty] | --demo [--pretty]`);
}

function parseArgs(argv) {
  let pretty = false;
  let demo = false;
  const pairs = [];
  for (const argument of argv) {
    if (argument === '--pretty') {
      if (pretty) usageError('The --pretty flag may only be provided once.');
      pretty = true;
    } else if (argument === '--demo') {
      if (demo) usageError('The --demo flag may only be provided once.');
      demo = true;
    } else {
      pairs.push(argument);
    }
  }
  if (demo && pairs.length > 0) usageError('The --demo flag cannot be combined with --bundle or --fixture.');
  if (demo) return { demo, pretty };
  if (pairs.length !== 4) usageError('Expected exactly --bundle <path> --fixture <path>.');
  const values = {};
  for (let index = 0; index < pairs.length; index += 2) {
    const flag = pairs[index];
    const value = pairs[index + 1];
    if (!['--bundle', '--fixture'].includes(flag) || !value || Object.hasOwn(values, flag.slice(2))) {
      usageError('Expected exactly --bundle <path> --fixture <path> (in either order).');
    }
    values[flag.slice(2)] = value;
  }
  if (!values.bundle || !values.fixture) usageError('Both --bundle and --fixture are required.');
  return { bundlePath: values.bundle, fixturePath: values.fixture, pretty, demo };
}

function formatPretty(result) {
  const constraints = result.constraints ?? {};
  const formatList = (values) => Array.isArray(values) && values.length > 0 ? values.join(', ') : 'none';
  return [
    `Decision: ${String(result.decision ?? 'unknown').toUpperCase()}`,
    '',
    'Policy',
    `  Version: ${result.policyVersion ?? 'unknown'}`,
    `  Hash: ${result.policyHash ?? 'unknown'}`,
    '',
    'Access constraints',
    `  Resource: ${constraints.resource ?? 'unknown'}`,
    `  Scope: ${constraints.rowScope ?? 'unknown'}`,
    `  Max rows: ${constraints.maxRows ?? 'unknown'}`,
    `  Allowed fields: ${formatList(constraints.fields)}`,
    `  Selector fields: ${formatList(constraints.selectorFields)}`,
  ].join('\n');
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

function loadDemoCases() {
  const source = readFileSync(new URL('../fixtures/demo-cases.json', import.meta.url), 'utf8');
  return JSON.parse(source);
}

function formatDemoReport(results) {
  const passed = results.filter((result) => result.passed).length;
  const lines = results.map((result, index) => {
    const status = result.passed ? 'PASS' : 'FAIL';
    const decision = String(result.actualDecision).toUpperCase();
    const expected = result.passed ? '' : ` (expected ${String(result.expectedDecision).toUpperCase()})`;
    return `${status} ${String(index + 1).padStart(2, '0')} ${result.name} ${decision}${expected}`;
  });
  return [
    `SentiQL policy demo: ${results.length} cases`,
    '',
    ...lines,
    '',
    `Summary: ${passed} passed, ${results.length - passed} failed`,
  ].join('\n');
}

function runDemo(bundlePath) {
  return loadDemoCases().map((demoCase) => {
    try {
      const result = simulatePolicyDecision({ bundlePath, principal: demoCase.principal, request: demoCase.request });
      return {
        name: demoCase.name,
        expectedDecision: demoCase.expectedDecision,
        actualDecision: result.decision,
        passed: result.decision === demoCase.expectedDecision,
        result,
      };
    } catch (error) {
      return {
        name: demoCase.name,
        expectedDecision: demoCase.expectedDecision,
        actualDecision: 'error',
        passed: false,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  });
}

try {
  const parsed = parseArgs(process.argv.slice(2));
  const bundlePath = parsed.demo
    ? fileURLToPath(new URL('../config/policy.example.json', import.meta.url))
    : parsed.bundlePath;
  if (parsed.demo) {
    const results = runDemo(bundlePath);
    const failed = results.filter((result) => !result.passed);
    process.stdout.write(`${parsed.pretty ? formatDemoReport(results) : JSON.stringify(results)}\n`);
    if (failed.length > 0) process.exitCode = 1;
  } else {
    const { fixturePath, pretty } = parsed;
    const fixture = loadFixture(fixturePath);
    const result = simulatePolicyDecision({ bundlePath, principal: fixture.principal, request: fixture.request });
    if (result.decision !== 'allow') {
      throw new Error(`Policy denied request: ${result.reason ?? 'request is not permitted.'}`);
    }
    process.stdout.write(`${pretty ? formatPretty(result) : JSON.stringify(result)}\n`);
  }
} catch (error) {
  process.stderr.write(`policy simulation failed: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}
