const CAPABILITIES = new Set(['schema.discover', 'data.read', 'data.aggregate', 'data.mutate']);
const FORBIDDEN_KEYS = new Set(['__proto__', 'prototype', 'constructor']);
const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;

const deny = (reason) => ({ decision: 'deny', reason });

function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function safeKeys(value) {
  if (!isPlainRecord(value)) return false;
  return Object.keys(value).every((key) => !FORBIDDEN_KEYS.has(key));
}

function hasOnlyKeys(value, allowed, required = []) {
  if (!safeKeys(value)) return false;
  const keys = Object.keys(value);
  return keys.every((key) => allowed.has(key)) && required.every((key) => Object.hasOwn(value, key));
}

function nonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function validIdentifier(value) {
  return typeof value === 'string' && IDENTIFIER.test(value);
}

function validScalar(value) {
  return value === null || typeof value === 'string' || typeof value === 'boolean'
    || (typeof value === 'number' && Number.isFinite(value));
}

function stringArray(value, { nonEmpty = false, identifiers = false } = {}) {
  if (!Array.isArray(value) || (nonEmpty && value.length === 0)) return false;
  if (!value.every((item) => (identifiers ? validIdentifier(item) : nonEmptyString(item)))) return false;
  return new Set(value).size === value.length;
}

function cloneArray(value) {
  return Array.isArray(value) ? [...value] : value;
}

function resourceMetadata(resource) {
  const metadata = {
    schema: resource.schema,
    table: resource.table,
    tenantColumn: resource.tenantColumn,
    fields: {
      readable: cloneArray(resource.fields.readable),
      aggregatable: cloneArray(resource.fields.aggregatable),
      writable: cloneArray(resource.fields.writable),
    },
    selectors: cloneArray(resource.selectors),
    mutations: {},
  };
  for (const action of Object.keys(resource.mutations)) {
    const definition = resource.mutations[action];
    metadata.mutations[action] = { fields: cloneArray(definition.fields) };
    if (Number.isInteger(definition.maxRows)) metadata.mutations[action].maxRows = definition.maxRows;
  }
  return metadata;
}

function normalizeResource(resources, resourceName) {
  if (!isPlainRecord(resources) || !nonEmptyString(resourceName) || FORBIDDEN_KEYS.has(resourceName) || !Object.hasOwn(resources, resourceName)) {
    return { error: 'Unknown resource.' };
  }
  const resource = resources[resourceName];
  if (!safeKeys(resource) || !['schema', 'table', 'tenantColumn', 'fields', 'selectors', 'mutations'].every((key) => Object.hasOwn(resource, key))
    || !safeKeys(resource.fields) || !['readable', 'aggregatable', 'writable'].every((key) => Object.hasOwn(resource.fields, key))
    || !Object.hasOwn(resource, 'selectors') || !Object.hasOwn(resource, 'mutations') || !safeKeys(resource.mutations)) {
    return { error: 'Invalid resource policy.' };
  }
  if (!validIdentifier(resource.schema) || !validIdentifier(resource.table) || !validIdentifier(resource.tenantColumn)) {
    return { error: 'Invalid resource policy.' };
  }
  const fieldKeys = new Set(['readable', 'aggregatable', 'writable']);
  if (!Object.keys(resource.fields).every((key) => fieldKeys.has(key))) return { error: 'Invalid resource policy.' };
  for (const key of fieldKeys) {
    if (!stringArray(resource.fields[key], { identifiers: true })) return { error: 'Invalid resource policy.' };
    if (resource.fields[key].includes(resource.tenantColumn)) return { error: 'Invalid resource policy.' };
  }
  if (!stringArray(resource.selectors, { identifiers: true }) || resource.selectors.includes(resource.tenantColumn)) return { error: 'Invalid resource policy.' };
  for (const action of Object.keys(resource.mutations)) {
    if (!validIdentifier(action) || FORBIDDEN_KEYS.has(action)) return { error: 'Invalid resource policy.' };
    const definition = resource.mutations[action];
    if (!safeKeys(definition) || !Object.hasOwn(definition, 'fields') || !stringArray(definition.fields, { nonEmpty: true, identifiers: true })) {
      return { error: 'Invalid resource policy.' };
    }
    if (!definition.fields.every((field) => resource.fields.writable.includes(field)) || definition.fields.includes(resource.tenantColumn)) return { error: 'Invalid resource policy.' };
    if (Object.hasOwn(definition, 'maxRows') && (!Number.isInteger(definition.maxRows) || definition.maxRows <= 0)) return { error: 'Invalid resource policy.' };
  }
  return { resource };
}

function validatePrincipal(principal) {
  const required = ['subject', 'organization', 'tenantId', 'roles'];
  if (!hasOnlyKeys(principal, new Set(required), required)) return 'Invalid principal.';
  if (!nonEmptyString(principal.subject) || !nonEmptyString(principal.organization) || !nonEmptyString(principal.tenantId)) return 'Invalid principal.';
  if (!Array.isArray(principal.roles) || !principal.roles.every(nonEmptyString) || new Set(principal.roles).size !== principal.roles.length) return 'Invalid principal.';
  return null;
}

function validateRequestBase(request, allowed) {
  if (!hasOnlyKeys(request, allowed, ['capability', 'resource', 'purpose'])) return 'Invalid request shape.';
  if (!CAPABILITIES.has(request.capability)) return 'Unsupported capability.';
  if (!nonEmptyString(request.resource)) return 'Resource is required.';
  if (!nonEmptyString(request.purpose)) return 'Purpose is required.';
  return null;
}

function validateSelector(selector, resource) {
  if (!isPlainRecord(selector) || !hasOnlyKeys(selector, new Set(['field', 'op', 'value']), ['field', 'op', 'value'])) return 'Invalid selector.';
  if (!validIdentifier(selector.field) || selector.field === resource.tenantColumn) return 'Selector field is not permitted.';
  if (selector.op !== 'eq') return 'Selector operator is not permitted.';
  if (!validScalar(selector.value)) return 'Invalid selector.';
  if (!resource.selectors.includes(selector.field)) return 'Selector field is not permitted.';
  return null;
}

function validateLimit(limit) {
  return limit === undefined || (Number.isInteger(limit) && limit > 0);
}

function grantsFor(policy, request, principal, resource) {
  if (!Array.isArray(policy?.grants)) return null;
  const subjects = new Set([principal.subject, ...principal.roles.map((role) => `role:${role}`)]);
  const candidates = policy.grants.filter((grant) => safeKeys(grant) && subjects.has(grant.subject)
    && grant.capability === request.capability && grant.resource === request.resource);
  if (candidates.some((grant) => !validGrantShape(grant, resource))) return null;
  return candidates.filter((grant) => grant.purposes.includes(request.purpose));
}

function validGrantShape(grant, resource) {
  if (!hasOnlyKeys(grant, new Set(['subject', 'capability', 'resource', 'purposes', 'rowScope', 'maxRows', 'mutationActions', 'approval', 'fields']), ['subject', 'capability', 'resource', 'purposes', 'rowScope'])) return false;
  if (!nonEmptyString(grant.subject) || !CAPABILITIES.has(grant.capability) || !nonEmptyString(grant.resource) || !stringArray(grant.purposes, { nonEmpty: true })) return false;
  if (grant.rowScope !== 'tenant') return false;
  if (Object.hasOwn(grant, 'maxRows') && (!Number.isInteger(grant.maxRows) || grant.maxRows <= 0)) return false;
  if (Object.hasOwn(grant, 'mutationActions') && (!stringArray(grant.mutationActions, { nonEmpty: true, identifiers: true }) || grant.capability !== 'data.mutate')) return false;
  if (grant.capability === 'data.mutate' && (!Object.hasOwn(grant, 'mutationActions') || !stringArray(grant.mutationActions, { nonEmpty: true, identifiers: true }))) return false;
  if (grant.capability === 'data.mutate' && grant.mutationActions.some((action) => !resource || !Object.hasOwn(resource.mutations, action))) return false;
  if (Object.hasOwn(grant, 'approval')) {
    if (!safeKeys(grant.approval) || !hasOnlyKeys(grant.approval, new Set(['requiredWhen']), ['requiredWhen']) || !safeKeys(grant.approval.requiredWhen)
      || !hasOnlyKeys(grant.approval.requiredWhen, new Set(['field', 'equals']), ['field', 'equals'])
      || !validIdentifier(grant.approval.requiredWhen.field) || !validScalar(grant.approval.requiredWhen.equals)) return false;
  }
  if (Object.hasOwn(grant, 'fields')) {
    if (!safeKeys(grant.fields) || !Object.keys(grant.fields).every((key) => ['readable', 'aggregatable', 'writable'].includes(key))) return false;
    for (const key of Object.keys(grant.fields)) {
      if (!stringArray(grant.fields[key], { identifiers: true })) return false;
      if (resource && grant.fields[key].some((field) => field === resource.tenantColumn || !resource.fields[key].includes(field))) return false;
    }
  }
  return true;
}

function noGrantReason(policy, request, principal) {
  if (!Array.isArray(policy?.grants)) return 'No matching grant permits this request.';
  const subjects = new Set([principal.subject, ...principal.roles.map((role) => `role:${role}`)]);
  const sameTarget = policy.grants.some((grant) => safeKeys(grant) && subjects.has(grant.subject) && grant.capability === request.capability && grant.resource === request.resource);
  return sameTarget ? 'Purpose is not permitted by the grant.' : 'No matching grant permits this request.';
}

function permissionSet(grants, fieldType, resourceFields) {
  const allowed = new Set();
  for (const grant of grants) {
    const restricted = grant.fields;
    if (restricted !== undefined && (!safeKeys(restricted) || (Object.hasOwn(restricted, fieldType) && !stringArray(restricted[fieldType], { identifiers: true })))) continue;
    const values = restricted && Object.hasOwn(restricted, fieldType) ? restricted[fieldType] : resourceFields;
    for (const value of values) allowed.add(value);
  }
  return allowed;
}

function matchingLimits(grants, requestLimit, action) {
  const values = [];
  if (requestLimit !== undefined) values.push(requestLimit);
  for (const grant of grants) if (Number.isInteger(grant.maxRows) && grant.maxRows > 0) values.push(grant.maxRows);
  if (action && Number.isInteger(action.maxRows) && action.maxRows > 0) values.push(action.maxRows);
  return values.length ? Math.min(...values) : undefined;
}

function rowScope(grants) {
  const scopes = grants.map((grant) => grant.rowScope).filter(nonEmptyString);
  return scopes.includes('tenant') ? 'tenant' : scopes[0];
}

function constraintsFor({ fields, selectorFields, maxRows, rowScopeValue, resourceName }) {
  return { fields, selectorFields, maxRows, rowScope: rowScopeValue, resource: resourceName };
}

function approvalTriggered(grants, values) {
  return grants.some((grant) => {
    const requiredWhen = grant.approval?.requiredWhen;
    return safeKeys(requiredWhen) && nonEmptyString(requiredWhen.field) && Object.hasOwn(values, requiredWhen.field) && Object.is(values[requiredWhen.field], requiredWhen.equals);
  });
}

/** Authorize a typed capability request without I/O or mutation of inputs. */
export function authorizeCapabilityRequest(request, principal, policy) {
  const principalError = validatePrincipal(principal);
  if (principalError) return deny(principalError);
  if (!isPlainRecord(policy) || !safeKeys(policy) || !Object.hasOwn(policy, 'resources') || !Object.hasOwn(policy, 'grants')) return deny('Invalid policy.');
  if (!isPlainRecord(request) || !safeKeys(request)) return deny('Invalid request shape.');

  const baseAllowed = new Set(['capability', 'resource', 'purpose']);
  const capability = request.capability;
  if (!CAPABILITIES.has(capability)) return deny('Unsupported capability.');
  const allowedKeys = new Set(baseAllowed);
  if (capability === 'data.read') ['fields', 'selector', 'limit'].forEach((key) => allowedKeys.add(key));
  if (capability === 'data.aggregate') ['metric', 'groupBy', 'selector', 'limit'].forEach((key) => allowedKeys.add(key));
  if (capability === 'data.mutate') ['action', 'selector', 'values', 'limit'].forEach((key) => allowedKeys.add(key));
  const baseError = validateRequestBase(request, allowedKeys);
  if (baseError) return deny(baseError);

  const resourceResult = normalizeResource(policy.resources, request.resource);
  if (resourceResult.error) return deny(resourceResult.error);
  const resource = resourceResult.resource;

  if (capability === 'data.read') {
    if (!stringArray(request.fields, { nonEmpty: true, identifiers: true })) return deny('Read fields are required.');
    if (request.fields.some((field) => !resource.fields.readable.includes(field))) return deny('Requested field is not readable.');
    if (!validateLimit(request.limit)) return deny('Limit must be a positive integer.');
    if (Object.hasOwn(request, 'selector')) {
      const selectorError = validateSelector(request.selector, resource);
      if (selectorError) return deny(selectorError);
    }
    const grants = grantsFor(policy, request, principal, resource);
    if (grants === null) return deny('Invalid policy grant.');
    if (!grants.length) return deny(noGrantReason(policy, request, principal));
    const permitted = permissionSet(grants, 'readable', resource.fields.readable);
    if (request.fields.some((field) => !permitted.has(field))) return deny('Requested field is not permitted by the grant.');
    const selectorFields = resource.selectors.filter((field) => field !== resource.tenantColumn);
    if (request.selector && !selectorFields.includes(request.selector.field)) return deny('Selector field is not permitted by the grant.');
    return { decision: 'allow', constraints: constraintsFor({ fields: [...request.fields], selectorFields, maxRows: matchingLimits(grants, request.limit), rowScopeValue: rowScope(grants), resourceName: request.resource }) };
  }

  if (capability === 'data.aggregate') {
    if (!isPlainRecord(request.metric) || !hasOnlyKeys(request.metric, new Set(['op', 'field']), ['op'])) return deny('Invalid aggregate metric.');
    if (!['count', 'sum'].includes(request.metric.op)) return deny('Aggregate operator is not permitted.');
    if (request.metric.op === 'count' && Object.hasOwn(request.metric, 'field')) return deny('Count metric cannot specify a field.');
    if (request.metric.op === 'sum' && (!Object.hasOwn(request.metric, 'field') || !validIdentifier(request.metric.field) || !resource.fields.aggregatable.includes(request.metric.field))) return deny('Aggregate field is not permitted.');
    if (Object.hasOwn(request, 'groupBy') && !stringArray(request.groupBy, { identifiers: true })) return deny('Invalid group-by fields.');
    if (request.groupBy?.some((field) => !resource.fields.aggregatable.includes(field))) return deny('Group-by field is not aggregatable.');
    if (Object.hasOwn(request, 'selector')) {
      const selectorError = validateSelector(request.selector, resource);
      if (selectorError) return deny(selectorError);
    }
    if (!validateLimit(request.limit)) return deny('Limit must be a positive integer.');
    const grants = grantsFor(policy, request, principal, resource);
    if (grants === null) return deny('Invalid policy grant.');
    if (!grants.length) return deny(noGrantReason(policy, request, principal));
    const permitted = permissionSet(grants, 'aggregatable', resource.fields.aggregatable);
    const aggregateFields = [...(request.groupBy ?? [])];
    if (request.metric.op === 'sum') aggregateFields.push(request.metric.field);
    if (aggregateFields.some((field) => !permitted.has(field))) return deny('Aggregate field is not permitted by the grant.');
    const selectorFields = resource.selectors.filter((field) => field !== resource.tenantColumn);
    if (request.selector && !selectorFields.includes(request.selector.field)) return deny('Selector field is not permitted by the grant.');
    return { decision: 'allow', constraints: constraintsFor({ fields: [...new Set(aggregateFields)], selectorFields, maxRows: matchingLimits(grants, request.limit), rowScopeValue: rowScope(grants), resourceName: request.resource }) };
  }

  if (capability === 'data.mutate') {
    if (!nonEmptyString(request.action) || !Object.hasOwn(resource.mutations, request.action)) return deny('Mutation action is not permitted.');
    const action = resource.mutations[request.action];
    if (!Object.hasOwn(request, 'selector')) return deny('Mutation requires exactly one selector.');
    const selectorError = validateSelector(request.selector, resource);
    if (selectorError) return deny(selectorError);
    if (!isPlainRecord(request.values) || !safeKeys(request.values) || Object.keys(request.values).length === 0) return deny('Mutation values are required.');
    if (Object.values(request.values).some((value) => !validScalar(value))) return deny('Mutation values must be scalar.');
    if (Object.keys(request.values).some((field) => !action.fields.includes(field) || !resource.fields.writable.includes(field))) return deny('Mutation value field is not writable.');
    if (!validateLimit(request.limit)) return deny('Limit must be a positive integer.');
    const grants = grantsFor(policy, request, principal, resource);
    if (grants === null) return deny('Invalid policy grant.');
    if (!grants.length) return deny(noGrantReason(policy, request, principal));
    if (!grants.some((grant) => Array.isArray(grant.mutationActions) && grant.mutationActions.includes(request.action))) return deny('Mutation action is not permitted by the grant.');
    const permitted = permissionSet(grants, 'writable', resource.fields.writable);
    if (Object.keys(request.values).some((field) => !permitted.has(field))) return deny('Mutation value field is not permitted by the grant.');
    const selectorFields = resource.selectors.filter((field) => field !== resource.tenantColumn);
    if (!selectorFields.includes(request.selector.field)) return deny('Selector field is not permitted by the grant.');
    const policyMaxRows = matchingLimits(grants, undefined, action);
    if (request.limit !== undefined && policyMaxRows !== undefined && request.limit > policyMaxRows) return deny('Requested mutation row limit exceeds permission.');
    const constraints = constraintsFor({ fields: action.fields.filter((field) => permitted.has(field)), selectorFields, maxRows: matchingLimits(grants, request.limit, action), rowScopeValue: rowScope(grants), resourceName: request.resource });
    if (approvalTriggered(grants, request.values)) return { decision: 'approval_required', reason: 'Mutation requires approval.', constraints };
    return { decision: 'allow', constraints };
  }

  // schema.discover
  const grants = grantsFor(policy, request, principal, resource);
  if (grants === null) return deny('Invalid policy grant.');
  if (!grants.length) return deny(noGrantReason(policy, request, principal));
  return { decision: 'allow', constraints: { discover: true, resource: resourceMetadata(resource) } };
}
