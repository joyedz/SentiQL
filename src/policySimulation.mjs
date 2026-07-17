import { authorizeCapabilityRequest } from './semanticPolicy.mjs';
import { loadPolicyBundle } from './policyBundle.mjs';
import { fileURLToPath } from 'node:url';

/**
 * Evaluate a typed capability request against a policy bundle without any
 * identity, database, network, or token dependencies.
 */
export function simulatePolicyDecision({ bundlePath, principal, request } = {}) {
  const normalizedBundlePath = bundlePath instanceof URL
    ? (bundlePath.protocol === 'file:' ? fileURLToPath(bundlePath) : null)
    : bundlePath;
  if (typeof normalizedBundlePath !== 'string' || !normalizedBundlePath.trim()) {
    throw new Error('A policy bundle path is required.');
  }
  if (!principal || typeof principal !== 'object' || Array.isArray(principal)) {
    throw new Error('A principal fixture is required.');
  }
  if (!request || typeof request !== 'object' || Array.isArray(request)) {
    throw new Error('A request fixture is required.');
  }

  const policy = loadPolicyBundle(normalizedBundlePath);
  const decision = authorizeCapabilityRequest(request, principal, policy);
  return {
    policyVersion: policy.version,
    policyHash: policy.hash,
    ...decision,
  };
}
