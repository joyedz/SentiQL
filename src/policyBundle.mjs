import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { z } from 'zod';

const nonEmptyString = z.string().trim().min(1);
const identifier = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/);
const uniqueStrings = z
  .array(nonEmptyString)
  .refine((values) => new Set(values).size === values.length, {
    message: 'values must be unique',
  });
const uniqueIdentifiers = z
  .array(identifier)
  .refine((values) => new Set(values).size === values.length, {
    message: 'values must be unique',
  });

const scalar = z.union([z.string(), z.number(), z.boolean(), z.null()]);
const httpsUrl = z.url().refine((url) => {
  try {
    return new URL(url).protocol === 'https:';
  } catch {
    return false;
  }
}, { message: 'must use https URL' });

const issuerSchema = z
  .object({
    issuer: httpsUrl,
    audience: nonEmptyString,
    jwksUrl: httpsUrl,
  })
  .strict();

const claimsSchema = z
  .object({
    organization: nonEmptyString,
    tenant: nonEmptyString,
    roles: nonEmptyString,
  })
  .strict();

const mutationSchema = z
  .object({
    fields: uniqueIdentifiers,
    maxRows: z.number().int().positive(),
  })
  .strict();

const grantFieldsSchema = z
  .object({
    readable: uniqueIdentifiers.optional(),
    aggregatable: uniqueIdentifiers.optional(),
    writable: uniqueIdentifiers.optional(),
  })
  .strict();

const resourceSchema = z
  .object({
    schema: identifier,
    table: identifier,
    tenantColumn: identifier,
    fields: z
      .object({
        readable: uniqueIdentifiers,
        aggregatable: uniqueIdentifiers,
        writable: uniqueIdentifiers,
      })
      .strict(),
    selectors: uniqueIdentifiers,
    mutations: z.record(z.string(), mutationSchema),
  })
  .strict();

const grantSchema = z
  .object({
    subject: nonEmptyString,
    capability: z.enum(['schema.discover', 'data.read', 'data.aggregate', 'data.mutate']),
    resource: nonEmptyString,
    purposes: uniqueStrings,
    rowScope: z.literal('tenant'),
    maxRows: z.number().int().positive().optional(),
    mutationActions: uniqueIdentifiers.optional(),
    fields: grantFieldsSchema.optional(),
    approval: z
      .object({
        requiredWhen: z
          .object({ field: nonEmptyString, equals: scalar })
          .strict(),
      })
      .strict()
      .optional(),
  })
  .strict();

const policyBundleSchema = z
  .object({
    version: nonEmptyString,
    identity: z
      .object({
        issuers: z.array(issuerSchema).min(1),
        claims: claimsSchema,
      })
      .strict(),
    resources: z.record(z.string(), resourceSchema),
    grants: z.array(grantSchema),
  })
  .strict()
  .superRefine((bundle, context) => {
    for (const [resourceName, resource] of Object.entries(bundle.resources)) {
      if (!resourceName.trim()) {
        context.addIssue({
          code: 'custom',
          path: ['resources', resourceName],
          message: 'resource names must be non-empty',
        });
      }

      for (const fieldType of ['readable', 'aggregatable', 'writable']) {
        if (resource.fields[fieldType].includes(resource.tenantColumn)) {
          context.addIssue({
            code: 'custom',
            path: ['resources', resourceName, 'fields', fieldType],
            message: 'tenantColumn cannot be exposed as a capability field',
          });
        }
      }
      if (resource.selectors.includes(resource.tenantColumn)) {
        context.addIssue({
          code: 'custom',
          path: ['resources', resourceName, 'selectors'],
          message: 'tenantColumn cannot be a selector',
        });
      }

      for (const [actionName, action] of Object.entries(resource.mutations)) {
        if (!identifier.safeParse(actionName).success) {
          context.addIssue({
            code: 'custom',
            path: ['resources', resourceName, 'mutations', actionName],
            message: 'mutation action names must be SQL identifiers',
          });
        }
        for (const field of action.fields) {
          if (!resource.fields.writable.includes(field)) {
            context.addIssue({
              code: 'custom',
              path: ['resources', resourceName, 'mutations', actionName, 'fields'],
              message: `mutation field ${field} must be writable for resource ${resourceName}`,
            });
          }
        }
      }
    }

    bundle.grants.forEach((grant, index) => {
      const hasResource = Object.hasOwn(bundle.resources, grant.resource);
      const resource = hasResource ? bundle.resources[grant.resource] : undefined;
      if (!hasResource) {
        context.addIssue({
          code: 'custom',
          path: ['grants', index, 'resource'],
          message: `unknown resource ${grant.resource}`,
        });
        return;
      }

      if (grant.capability === 'data.mutate') {
        if (!grant.mutationActions?.length) {
          context.addIssue({
            code: 'custom',
            path: ['grants', index, 'mutationActions'],
            message: 'data.mutate grants require mutationActions',
          });
        } else {
          for (const action of grant.mutationActions) {
            if (!Object.hasOwn(resource.mutations, action)) {
              context.addIssue({
                code: 'custom',
                path: ['grants', index, 'mutationActions'],
                message: `unknown mutation action ${action} for resource ${grant.resource}`,
              });
            }
          }
        }
      } else if (grant.mutationActions) {
        context.addIssue({
          code: 'custom',
          path: ['grants', index, 'mutationActions'],
          message: 'mutationActions are only valid for data.mutate grants',
        });
      }

      if (grant.fields) {
        for (const fieldType of ['readable', 'aggregatable', 'writable']) {
          const restricted = grant.fields[fieldType];
          if (!restricted) continue;
          for (const field of restricted) {
            if (field === resource.tenantColumn || !resource.fields[fieldType].includes(field)) {
              context.addIssue({
                code: 'custom',
                path: ['grants', index, 'fields', fieldType],
                message: `grant field ${field} is not permitted for resource ${grant.resource}`,
              });
            }
          }
        }
      }
    });
  });

/** Returns compact canonical JSON with recursively sorted object keys. */
export function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function formatValidationError(error) {
  return error.issues
    .map((issue) => `${issue.path.length ? `${issue.path.join('.')}: ` : ''}${issue.message}`)
    .join('; ');
}

/** Validates a policy bundle and computes its stable content hash. */
export function validatePolicyBundle(input) {
  const parsed = policyBundleSchema.safeParse(input);
  if (!parsed.success) {
    throw new Error(`Invalid policy bundle: ${formatValidationError(parsed.error)}`);
  }

  const bundle = parsed.data;
  const hash = createHash('sha256').update(canonicalJson(bundle), 'utf8').digest('hex');
  return { ...bundle, hash };
}

/** Loads and validates an explicit UTF-8 JSON policy-bundle file. */
export function loadPolicyBundle(filePath) {
  if (typeof filePath !== 'string' || !filePath.trim()) {
    throw new Error('Invalid policy bundle path: an explicit file path is required.');
  }

  let source;
  try {
    source = readFileSync(filePath, 'utf8');
  } catch (error) {
    throw new Error(`Invalid policy bundle at ${filePath}: unable to read file.`);
  }

  let input;
  try {
    input = JSON.parse(source);
  } catch (error) {
    throw new Error(`Invalid policy bundle at ${filePath}: malformed JSON.`);
  }

  try {
    return validatePolicyBundle(input);
  } catch (error) {
    throw new Error(`Invalid policy bundle at ${filePath}: ${error.message.replace(/^Invalid policy bundle:\s*/, '')}`);
  }
}
