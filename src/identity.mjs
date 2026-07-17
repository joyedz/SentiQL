import { readFile } from 'node:fs/promises';
import {
  createLocalJWKSet,
  createRemoteJWKSet,
  decodeJwt,
  jwtVerify,
} from 'jose';

const ALLOWED_ALGORITHMS = ['RS256', 'ES256'];
const CLOCK_SKEW_SECONDS = 60;

function identityError(reason) {
  return new Error(`Identity verification failed: ${reason}`);
}

function nonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function validateIssuerConfig(config, { allowStaticJwks = false } = {}) {
  if (!config || typeof config !== 'object') {
    throw identityError('issuer configuration is invalid.');
  }
  if (!nonEmptyString(config.issuer) || !nonEmptyString(config.audience)) {
    throw identityError('issuer configuration is invalid.');
  }
  let issuerUrl;
  let jwksUrl;
  try {
    issuerUrl = new URL(config.issuer);
  } catch {
    throw identityError('issuer configuration is invalid.');
  }
  if (issuerUrl.protocol !== 'https:') {
    throw identityError('issuer configuration is invalid.');
  }
  if (nonEmptyString(config.jwksUrl)) {
    try {
      jwksUrl = new URL(config.jwksUrl);
    } catch {
      throw identityError('issuer configuration is invalid.');
    }
    if (jwksUrl.protocol !== 'https:') {
      throw identityError('issuer configuration is invalid.');
    }
  } else if (!allowStaticJwks) {
    throw identityError('issuer configuration is invalid.');
  }
}

function resolverForIssuer(config, injectedJwks) {
  if (typeof config.jwksResolver === 'function') {
    return config.jwksResolver;
  }
  if (typeof config.jwks === 'function') {
    return config.jwks;
  }
  if (config.jwks && typeof config.jwks === 'object') {
    return createLocalJWKSet(config.jwks);
  }
  if (injectedJwks) {
    if (typeof injectedJwks === 'function') {
      return injectedJwks;
    }
    if (typeof injectedJwks === 'object') {
      return createLocalJWKSet(injectedJwks);
    }
  }
  if (!nonEmptyString(config.jwksUrl)) {
    throw identityError('issuer configuration is invalid.');
  }
  return createRemoteJWKSet(new URL(config.jwksUrl));
}

function errorReason(error) {
  switch (error?.code) {
    case 'ERR_JWT_EXPIRED':
      return 'token is expired.';
    case 'ERR_JWT_CLAIM_VALIDATION_FAILED':
    case 'ERR_JWT_MISSING_CLAIM':
      return 'token claims are invalid.';
    case 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED':
    case 'ERR_JWS_NO_MATCHING_KEY':
      return 'token signature is invalid.';
    case 'ERR_JOSE_ALG_NOT_ALLOWED':
      return 'token algorithm is not allowed.';
    default:
      return 'token verification failed.';
  }
}

/**
 * Creates a verifier for host-supplied OIDC workload tokens.
 *
 * `jwks` and per-issuer `jwks`/`jwksResolver` are test-only injection hooks;
 * normal configuration uses each issuer's HTTPS jwksUrl.
 */
export function createIdentityVerifier({ issuers, claims, jwks } = {}) {
  if (!Array.isArray(issuers) || issuers.length === 0) {
    throw identityError('at least one issuer is required.');
  }
  if (!claims || !nonEmptyString(claims.organization)
    || !nonEmptyString(claims.tenant) || !nonEmptyString(claims.roles)) {
    throw identityError('claim mappings are invalid.');
  }

  const configs = issuers.map((config) => {
    const hasStaticJwks = Boolean(config?.jwks || config?.jwksResolver || jwks);
    validateIssuerConfig(config, { allowStaticJwks: hasStaticJwks });
    return {
      ...config,
      resolver: resolverForIssuer(
        config,
        jwks && typeof jwks === 'object' && !('keys' in jwks)
          ? (jwks[config.issuer] ?? jwks[config.jwksUrl])
          : jwks,
      ),
    };
  });

  const byIssuer = new Map();
  for (const config of configs) {
    if (byIssuer.has(config.issuer)) {
      throw identityError('issuer configuration is invalid.');
    }
    byIssuer.set(config.issuer, config);
  }

  return async function verify(token) {
    if (!nonEmptyString(token)) {
      throw identityError('token is missing.');
    }

    let unverifiedIssuer;
    try {
      // Unverified iss is used only to route to one configured key resolver.
      // Authorization uses only the payload returned by jwtVerify below.
      unverifiedIssuer = decodeJwt(token).iss;
    } catch {
      throw identityError('token is malformed.');
    }
    const config = byIssuer.get(unverifiedIssuer);
    if (!config) {
      throw identityError('issuer is not trusted.');
    }

    let payload;
    try {
      ({ payload } = await jwtVerify(token, config.resolver, {
        issuer: config.issuer,
        audience: config.audience,
        algorithms: ALLOWED_ALGORITHMS,
        requiredClaims: ['iss', 'aud', 'exp', 'iat', 'sub'],
      }));
    } catch (error) {
      throw identityError(errorReason(error));
    }

    const subject = payload.sub;
    const organization = payload[claims.organization];
    const tenant = payload[claims.tenant];
    const roles = payload[claims.roles];
    if (!nonEmptyString(subject)) {
      throw identityError('subject claim is missing.');
    }
    if (!nonEmptyString(organization) || !nonEmptyString(tenant)) {
      throw identityError('organization and tenant claims are required.');
    }
    const principalRoles = Array.isArray(roles)
      ? roles.map((role) => (typeof role === 'string' ? role.trim() : role))
      : roles;
    if (!Array.isArray(principalRoles) || principalRoles.length === 0
      || principalRoles.some((role) => !nonEmptyString(role))
      || new Set(principalRoles).size !== principalRoles.length) {
      throw identityError('roles claim is invalid.');
    }
    if (typeof payload.iat !== 'number' || !Number.isFinite(payload.iat)
      || payload.iat > (Date.now() / 1000) + CLOCK_SKEW_SECONDS) {
      throw identityError('issued-at claim is invalid.');
    }

    const immutableRoles = Object.freeze(principalRoles);
    return Object.freeze({
      subject: subject.trim(),
      organization: organization.trim(),
      tenantId: tenant.trim(),
      roles: immutableRoles,
    });
  };
}

/** Reads a fresh, trimmed workload token from the configured token file. */
export async function readWorkloadToken(tokenFile) {
  if (!nonEmptyString(tokenFile)) {
    throw identityError('token file is required.');
  }
  let source;
  try {
    source = await readFile(tokenFile, 'utf8');
  } catch {
    throw identityError('token file could not be read.');
  }
  const token = source.trim();
  if (!token) {
    throw identityError('token file is empty.');
  }
  return token;
}
