import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createIdentityVerifier, readWorkloadToken } from '../src/identity.mjs';

const ISSUER = 'https://issuer.example';
const AUDIENCE = 'agentconnect';
const claims = { organization: 'org_id', tenant: 'tenant_id', roles: 'roles' };

const { privateKey, publicKey } = await generateKeyPair('RS256');
const publicJwk = await exportJWK(publicKey);
publicJwk.kid = 'workload-key';
publicJwk.alg = 'RS256';

function verifier() {
  return createIdentityVerifier({
    issuers: [{
      issuer: ISSUER,
      audience: AUDIENCE,
      jwksUrl: 'https://issuer.example/.well-known/jwks.json',
      jwks: { keys: [publicJwk] },
    }],
    claims,
  });
}

async function token(payload = {}) {
  return new SignJWT({
    org_id: 'acme',
    tenant_id: 'tenant-7',
    roles: ['support-agent'],
    ...payload,
  })
    .setProtectedHeader({ alg: 'RS256', kid: 'workload-key' })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setSubject('workload-123')
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(privateKey);
}

test('verifies a signed workload token and returns an immutable principal', async () => {
  const principal = await verifier()(await token());

  assert.deepEqual(principal, {
    subject: 'workload-123',
    organization: 'acme',
    tenantId: 'tenant-7',
    roles: ['support-agent'],
  });
  assert.equal(Object.isFrozen(principal), true);
  assert.equal(Object.isFrozen(principal.roles), true);
  assert.throws(() => { principal.tenantId = 'other'; }, TypeError);
});

test('rejects a token with the wrong audience', async () => {
  const invalid = await new SignJWT({ org_id: 'acme', tenant_id: 'tenant-7', roles: ['support-agent'] })
    .setProtectedHeader({ alg: 'RS256', kid: 'workload-key' })
    .setIssuer(ISSUER)
    .setAudience('other-audience')
    .setSubject('workload-123')
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(privateKey);

  await assert.rejects(verifier()(invalid), /audience|identity|workload/i);
});

test('rejects a token missing the mapped organization claim', async () => {
  const invalid = await token({ org_id: undefined });
  await assert.rejects(verifier()(invalid), /organization|claim|identity/i);
});

test('supports a static JWKS issuer without a remote jwksUrl', async () => {
  const verify = createIdentityVerifier({
    issuers: [{ issuer: ISSUER, audience: AUDIENCE, jwks: { keys: [publicJwk] } }],
    claims,
  });
  assert.equal((await verify(await token())).tenantId, 'tenant-7');
});

test('rejects duplicate roles', async () => {
  await assert.rejects(verifier()(
    await token({ roles: ['support-agent', 'support-agent'] }),
  ), /roles|identity|workload/i);
  await assert.rejects(verifier()(
    await token({ roles: [' support-agent', 'support-agent '] }),
  ), /roles|identity|workload/i);
});

test('rejects a token issued too far in the future', async () => {
  const futureIssuedAt = Math.floor(Date.now() / 1000) + 3600;
  const invalid = await new SignJWT({ org_id: 'acme', tenant_id: 'tenant-7', roles: ['support-agent'] })
    .setProtectedHeader({ alg: 'RS256', kid: 'workload-key' })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setSubject('workload-123')
    .setIssuedAt(futureIssuedAt)
    .setExpirationTime(futureIssuedAt + 300)
    .sign(privateKey);

  await assert.rejects(verifier()(invalid), /issued|future|identity|workload/i);
});

test('rejects a token with an invalid signature or unknown issuer', async () => {
  const { privateKey: otherPrivateKey } = await generateKeyPair('RS256');
  const badSignature = await new SignJWT({ org_id: 'acme', tenant_id: 'tenant-7', roles: ['support-agent'] })
    .setProtectedHeader({ alg: 'RS256', kid: 'workload-key' })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setSubject('workload-123')
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(otherPrivateKey);
  await assert.rejects(verifier()(badSignature), /signature|identity|workload/i);

  const unknownIssuer = await new SignJWT({ org_id: 'acme', tenant_id: 'tenant-7', roles: ['support-agent'] })
    .setProtectedHeader({ alg: 'RS256', kid: 'workload-key' })
    .setIssuer('https://other.example')
    .setAudience(AUDIENCE)
    .setSubject('workload-123')
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(privateKey);
  await assert.rejects(verifier()(unknownIssuer), /issuer|identity|workload/i);
});

test('routes by issuer before invoking a configured JWKS resolver', async () => {
  let resolverCalls = 0;
  const verify = createIdentityVerifier({
    issuers: [{
      issuer: ISSUER,
      audience: AUDIENCE,
      jwksResolver: async () => {
        resolverCalls += 1;
        return publicKey;
      },
    }],
    claims,
  });
  const unknownIssuer = await new SignJWT({ org_id: 'acme', tenant_id: 'tenant-7', roles: ['support-agent'] })
    .setProtectedHeader({ alg: 'RS256', kid: 'workload-key' })
    .setIssuer('https://other.example')
    .setAudience(AUDIENCE)
    .setSubject('workload-123')
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(privateKey);
  await assert.rejects(verify(unknownIssuer), /issuer|identity|workload/i);
  assert.equal(resolverCalls, 0);
});

test('rejects tokens signed with an unsupported algorithm', async () => {
  const invalid = await new SignJWT({ org_id: 'acme', tenant_id: 'tenant-7', roles: ['support-agent'] })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setSubject('workload-123')
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(new TextEncoder().encode('not-a-configured-key'));

  await assert.rejects(verifier()(invalid), /algorithm|identity|workload/i);
});

test('reads a fresh trimmed workload token and rejects an empty token file', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sentiql-identity-'));
  const tokenPath = join(directory, 'token');
  const signed = await token();
  await writeFile(tokenPath, `\n ${signed} \n`, 'utf8');
  assert.equal(await readWorkloadToken(tokenPath), signed);

  await writeFile(tokenPath, '   \n', 'utf8');
  await assert.rejects(readWorkloadToken(tokenPath), /token|empty|identity/i);
  await assert.rejects(readWorkloadToken(join(directory, 'missing-token')), /token|read|identity/i);
});

test('verifies an ES256 workload token', async () => {
  const { privateKey: ecPrivateKey, publicKey: ecPublicKey } = await generateKeyPair('ES256');
  const ecJwk = await exportJWK(ecPublicKey);
  ecJwk.kid = 'ec-workload-key';
  ecJwk.alg = 'ES256';
  const verify = createIdentityVerifier({
    issuers: [{ issuer: ISSUER, audience: AUDIENCE, jwks: { keys: [ecJwk] } }],
    claims,
  });
  const signed = await new SignJWT({ org_id: 'acme', tenant_id: 'tenant-7', roles: ['support-agent'] })
    .setProtectedHeader({ alg: 'ES256', kid: 'ec-workload-key' })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setSubject('workload-ec')
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(ecPrivateKey);
  assert.equal((await verify(signed)).subject, 'workload-ec');
});
