import { evaluatePolicy } from './policyEngine.mjs';
import { evaluateAstPolicy } from './astPolicyExperiment.mjs';
import { getSupportedAstParserVersions } from './astParserExperiment.mjs';

// The fixed set of classifications this harness can emit. Kept explicit so the
// summary and any downstream report can rely on a closed vocabulary.
export const CLASSIFICATIONS = Object.freeze([
  'match',
  'ast_deny_heuristic_allow',
  'ast_allow_heuristic_deny',
  'decision_match_reason_diff',
  'parse_error',
  'unsupported',
]);

/**
 * Classify a single heuristic-vs-AST comparison into exactly one category.
 *
 * Contract (evaluated in this fixed order):
 *   1. astParseStatus === 'parse_error'                    -> 'parse_error'
 *   2. astParseStatus === 'unsupported_version'
 *      OR astReasonCode === 'unsupported_version'          -> 'unsupported'
 *   3. decisions equal:
 *        - both 'deny' AND reasonDiffers === true          -> 'decision_match_reason_diff'
 *        - otherwise                                       -> 'match'
 *   4. heuristic 'allow' & ast 'deny'                       -> 'ast_deny_heuristic_allow'
 *   5. heuristic 'deny'  & ast 'allow'                      -> 'ast_allow_heuristic_deny'
 *
 * `reasonDiffers` is supplied by the caller because heuristic rationales are
 * free text while the AST prototype uses stable reason codes; the two cannot be
 * compared directly. `runDifferential` sets it true when both evaluators deny,
 * since their denial rationales are represented differently.
 */
export function classifyDecision({
  heuristicDecision,
  astDecision,
  astParseStatus,
  astReasonCode,
  reasonDiffers = false,
} = {}) {
  if (astParseStatus === 'parse_error') {
    return 'parse_error';
  }

  if (astParseStatus === 'unsupported_version' || astReasonCode === 'unsupported_version') {
    return 'unsupported';
  }

  if (heuristicDecision === astDecision) {
    if (heuristicDecision === 'deny' && reasonDiffers) {
      return 'decision_match_reason_diff';
    }
    return 'match';
  }

  if (heuristicDecision === 'allow' && astDecision === 'deny') {
    return 'ast_deny_heuristic_allow';
  }

  // heuristic 'deny' & ast 'allow': the prototype widens a heuristic denial.
  return 'ast_allow_heuristic_deny';
}

// Retain only the stable, auditable subset of AST facts in each record.
function compactFacts(facts = {}) {
  return {
    statementCount: facts.statementCount ?? null,
    topLevelKinds: Array.isArray(facts.topLevelKinds) ? [...facts.topLevelKinds] : [],
    nestedWriteCount: facts.nestedWriteCount ?? 0,
    hasSelectInto: facts.hasSelectInto ?? false,
    hasUtilityStatement: facts.hasUtilityStatement ?? false,
    hasContextMutation: facts.hasContextMutation ?? false,
    whereClauseSafety: facts.whereClauseSafety ?? 'unknown',
    hasTrivialWhere: facts.hasTrivialWhere ?? false,
  };
}

/**
 * Run the corpus against each requested parser version.
 *
 * For each (parserVersion, case) pair this calls the synchronous heuristic
 * `evaluatePolicy` and, when the version is supported, the async
 * `evaluateAstPolicy`. Unsupported versions are never substituted: they are
 * recorded with classification 'unsupported' and parserAvailability
 * 'unavailable_version'. No database or network access occurs.
 */
export async function runDifferential({ corpus = [], parserVersions = [] } = {}) {
  const supported = new Set(getSupportedAstParserVersions());
  const records = [];

  for (const parserVersion of parserVersions) {
    const isAvailable = supported.has(parserVersion);

    for (const testCase of corpus) {
      const { id: sqlId, sql, mode } = testCase;
      const heuristicResult = evaluatePolicy(sql, { mode });
      const heuristic = {
        decision: heuristicResult.decision,
        reason: heuristicResult.reason,
      };

      if (!isAvailable) {
        // Do not substitute another version; record the gap distinctly.
        records.push({
          sqlId,
          parserVersion,
          parserAvailability: 'unavailable_version',
          heuristic,
          ast: {
            decision: 'deny',
            reasonCode: 'unsupported_version',
            parseStatus: 'unsupported_version',
            facts: compactFacts(),
          },
          classification: 'unsupported',
        });
        continue;
      }

      const astResult = await evaluateAstPolicy(sql, { parserVersion, mode });
      const reasonDiffers =
        heuristic.decision === 'deny' && astResult.decision === 'deny';
      const classification = classifyDecision({
        heuristicDecision: heuristic.decision,
        astDecision: astResult.decision,
        astParseStatus: astResult.parseStatus,
        astReasonCode: astResult.reasonCode,
        reasonDiffers,
      });

      records.push({
        sqlId,
        parserVersion,
        parserAvailability: 'available',
        heuristic,
        ast: {
          decision: astResult.decision,
          reasonCode: astResult.reasonCode,
          parseStatus: astResult.parseStatus,
          facts: compactFacts(astResult.facts),
        },
        classification,
      });
    }
  }

  return records;
}

function emptyClassificationCounts() {
  const counts = {};
  for (const classification of CLASSIFICATIONS) counts[classification] = 0;
  return counts;
}

/**
 * Aggregate differential records into totals grouped by parser version and by
 * classification, and surface safety-sensitive widenings and unavailable
 * parser versions distinctly.
 */
export function summarizeDifferential(records = []) {
  const byClassification = emptyClassificationCounts();
  const byParserVersion = {};
  const safetySensitiveWidenings = [];
  const unavailableVersions = new Set();

  for (const record of records) {
    if (record.classification in byClassification) {
      byClassification[record.classification] += 1;
    } else {
      byClassification[record.classification] = 1;
    }

    if (!byParserVersion[record.parserVersion]) {
      byParserVersion[record.parserVersion] = {
        total: 0,
        availability: 'available',
        byClassification: emptyClassificationCounts(),
      };
    }
    const versionSummary = byParserVersion[record.parserVersion];
    versionSummary.total += 1;
    if (record.classification in versionSummary.byClassification) {
      versionSummary.byClassification[record.classification] += 1;
    } else {
      versionSummary.byClassification[record.classification] = 1;
    }

    if (record.parserAvailability === 'unavailable_version') {
      versionSummary.availability = 'unavailable_version';
      unavailableVersions.add(record.parserVersion);
    }

    if (record.classification === 'ast_allow_heuristic_deny') {
      safetySensitiveWidenings.push(record);
    }
  }

  return {
    totalRecords: records.length,
    byParserVersion,
    byClassification,
    safetySensitiveWidenings,
    unavailableVersions: [...unavailableVersions].sort((a, b) => a - b),
  };
}
