import { createHash } from 'node:crypto';
import { getSupportedAstParserVersions } from './astParserExperiment.mjs';
import { evaluateAstPolicy } from './astPolicyExperiment.mjs';
import { classifyDecision } from './astPolicyDifferential.mjs';

const SHADOW_SOURCES = new Set(['raw_query_compatibility', 'typed_capability']);
const SHADOW_MODES = new Set(['read-only', 'read-write']);
const SHADOW_CONTRACT_VERSION = 1;
const MAX_FACT_ITEMS = 32;
const MAX_FACT_STRING_LENGTH = 64;
const MAX_FACT_COUNT = 1000;

function sqlDigest(sql) {
  return `sha256:${createHash('sha256').update(typeof sql === 'string' ? sql : '', 'utf8').digest('hex')}`;
}

function compactFacts(facts = {}) {
  if (facts === null || typeof facts !== 'object' || Array.isArray(facts)) {
    throw new Error('Invalid AST policy shadow facts.');
  }
  const whereClauseSafety = ['absent', 'trivial', 'non_trivial', 'unknown'].includes(facts.whereClauseSafety)
    ? facts.whereClauseSafety
    : facts.whereClauseSafety === undefined ? 'unknown' : null;
  if (whereClauseSafety === null) throw new Error('Invalid AST policy shadow where clause safety.');
  const statementCount = facts.statementCount === undefined ? 0 : facts.statementCount;
  const nestedWriteCount = facts.nestedWriteCount === undefined ? 0 : facts.nestedWriteCount;
  if (!Number.isInteger(statementCount) || statementCount < 0 || statementCount > MAX_FACT_COUNT) {
    throw new Error('Invalid AST policy shadow statement count.');
  }
  if (!Number.isInteger(nestedWriteCount) || nestedWriteCount < 0 || nestedWriteCount > MAX_FACT_COUNT) {
    throw new Error('Invalid AST policy shadow nested write count.');
  }
  const topLevelKinds = facts.topLevelKinds === undefined ? [] : facts.topLevelKinds;
  if (!Array.isArray(topLevelKinds) || topLevelKinds.length > MAX_FACT_ITEMS || topLevelKinds.some(
    (kind) => typeof kind !== 'string' || kind.length > MAX_FACT_STRING_LENGTH || !/^[A-Za-z][A-Za-z0-9_]*$/.test(kind),
  )) {
    throw new Error('Invalid AST policy shadow top-level kinds.');
  }
  for (const field of ['hasSelectInto', 'hasUtilityStatement', 'hasContextMutation', 'hasTrivialWhere']) {
    if (facts[field] !== undefined && typeof facts[field] !== 'boolean') {
      throw new Error(`Invalid AST policy shadow ${field}.`);
    }
  }
  return {
    statementCount,
    topLevelKinds,
    nestedWriteCount,
    hasSelectInto: facts.hasSelectInto === true,
    hasUtilityStatement: facts.hasUtilityStatement === true,
    hasContextMutation: facts.hasContextMutation === true,
    whereClauseSafety,
    hasTrivialWhere: facts.hasTrivialWhere === true,
  };
}

function normalizedSource(source) {
  return SHADOW_SOURCES.has(source) ? source : 'raw_query_compatibility';
}

function normalizedMode(mode) {
  return SHADOW_MODES.has(mode) ? mode : 'read-only';
}

function safeLog(logError) {
  try {
    logError('AST policy shadow observation failed.');
  } catch {
    // Shadow logging must never affect a request path.
  }
}

/**
 * Creates the non-enforcing AST policy shadow observer.
 *
 * The observer evaluates SQL only when enabled and records a digest plus fixed,
 * non-sensitive AST metadata. It never returns or throws an enforcement result.
 * `evaluate` is an optional test collaborator; production uses evaluateAstPolicy.
 */
export function createAstPolicyShadow({
  enabled = false,
  parserVersion = 16,
  record,
  logError = (message) => console.error(message),
  evaluate = evaluateAstPolicy,
} = {}) {
  if (!enabled) {
    return {
      async observe() {
        return { status: 'disabled' };
      },
    };
  }

  if (!getSupportedAstParserVersions().includes(parserVersion)) {
    throw new Error(`Unsupported AST policy shadow parser version: ${parserVersion}.`);
  }

  return {
    async observe({ sql, mode, heuristicDecision, correlationId, source } = {}) {
      try {
        const ast = await evaluate(sql, { mode: normalizedMode(mode), parserVersion });
        const classification = classifyDecision({
          heuristicDecision,
          astDecision: ast?.decision,
          astParseStatus: ast?.parseStatus,
          astReasonCode: ast?.reasonCode,
          reasonDiffers: heuristicDecision === 'deny' && ast?.decision === 'deny',
        });
        const event = {
          contractVersion: SHADOW_CONTRACT_VERSION,
          timestamp: new Date().toISOString(),
          correlationId: typeof correlationId === 'string' ? correlationId : null,
          source: normalizedSource(source),
          mode: normalizedMode(mode),
          parserVersion,
          parserVersionValidity: 'supported',
          sqlDigest: sqlDigest(sql),
          heuristicDecision: heuristicDecision === 'allow' ? 'allow' : 'deny',
          astDecision: ast?.decision === 'allow' ? 'allow' : 'deny',
          astReasonCode: typeof ast?.reasonCode === 'string' ? ast.reasonCode : 'unknown',
          astParseStatus: typeof ast?.parseStatus === 'string' ? ast.parseStatus : 'unknown',
          classification,
          facts: compactFacts(ast?.facts),
        };
        await record(event);
        return { status: 'recorded' };
      } catch {
        safeLog(logError);
        return { status: 'failed' };
      }
    },
  };
}
