const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;

function validIdentifier(value) {
  return typeof value === 'string' && IDENTIFIER.test(value);
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function identifier(value, label = 'identifier') {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) throw new Error(`Invalid ${label}.`);
  return `"${value}"`;
}

function rawIdentifier(value, label = 'identifier') {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) throw new Error(`Invalid ${label}.`);
  return value;
}

function uniqueSorted(values, label) {
  if (!Array.isArray(values) || values.length === 0 || values.some((value) => typeof value !== 'string')) throw new Error(`Invalid ${label}.`);
  return [...new Set(values)].sort();
}

function scalar(value) {
  return value === null || typeof value === 'string' || (typeof value === 'number' && Number.isFinite(value)) || typeof value === 'boolean';
}

function validateResource(resource) {
  if (!isRecord(resource)) throw new Error('Invalid resource metadata.');
  identifier(resource.schema, 'schema identifier');
  identifier(resource.table, 'table identifier');
  identifier(resource.tenantColumn, 'tenant column');
  if (!isRecord(resource.fields)) throw new Error('Invalid resource fields.');
  for (const key of ['readable', 'aggregatable', 'writable']) {
    if (!Array.isArray(resource.fields[key]) || resource.fields[key].some((field) => !validIdentifier(field) || field === resource.tenantColumn)) throw new Error('Invalid resource fields.');
  }
  if (!Array.isArray(resource.selectors) || resource.selectors.some((field) => !validIdentifier(field) || field === resource.tenantColumn)) throw new Error('Invalid resource selectors.');
  if (!isRecord(resource.mutations)) throw new Error('Invalid resource mutations.');
  for (const [name, action] of Object.entries(resource.mutations)) {
    rawIdentifier(name, 'mutation action');
    if (!isRecord(action) || !Array.isArray(action.fields) || action.fields.some((field) => !validIdentifier(field) || field === resource.tenantColumn)) throw new Error('Invalid mutation metadata.');
    if (action.maxRows !== undefined && (!Number.isInteger(action.maxRows) || action.maxRows <= 0)) throw new Error('Invalid mutation maxRows.');
  }
}

function effectiveLimit(request, constraints, isMutation = false) {
  const requested = request.limit;
  if (requested !== undefined && (!Number.isInteger(requested) || requested <= 0)) throw new Error('Invalid row limit.');
  const constrained = constraints.maxRows;
  if (constrained !== undefined && (!Number.isInteger(constrained) || constrained <= 0)) throw new Error('Invalid constraint row limit.');
  const limits = [requested, constrained].filter((limit) => limit !== undefined);
  return limits.length ? Math.min(...limits) : undefined;
}

function selectorPart(request, resource, constraints, values) {
  if (request.selector === undefined) return '';
  if (!isRecord(request.selector) || Object.keys(request.selector).some((key) => !['field', 'op', 'value'].includes(key)) || Object.keys(request.selector).length !== 3 || request.selector.op !== 'eq' || !Object.hasOwn(request.selector, 'field') || !Object.hasOwn(request.selector, 'value')) throw new Error('Only equality selectors are permitted.');
  const field = rawIdentifier(request.selector.field, 'selector field');
  const permittedSelectors = constraints.selectorFields === undefined
    ? resource.selectors.filter((candidate) => candidate !== resource.tenantColumn)
    : constraints.selectorFields;
  if (field === resource.tenantColumn || !resource.selectors.includes(field) || !Array.isArray(permittedSelectors) || !permittedSelectors.includes(field)) throw new Error('Selector field is not permitted.');
  if (!scalar(request.selector.value)) throw new Error('Selector value must be scalar.');
  values.push(request.selector.value);
  return ` WHERE ${identifier(field)} = $${values.length}`;
}

function limitPart(limit, values) {
  if (limit === undefined) return '';
  values.push(limit);
  return ` LIMIT $${values.length}`;
}

/** Compile an authorized capability request into parameterized SQL. */
export function compileCapabilityRequest(request, { resource, constraints } = {}) {
  if (!isRecord(request) || !isRecord(constraints)) throw new Error('Invalid capability request metadata.');
  validateResource(resource);
  const capability = request.capability;
  const table = `${identifier(resource.schema, 'schema identifier')}.${identifier(resource.table, 'table identifier')}`;
  const values = [];
  if (constraints.maxRows !== undefined && (!Number.isInteger(constraints.maxRows) || constraints.maxRows <= 0)) throw new Error('Invalid constraint row limit.');
  const fieldsConstraint = new Set(Array.isArray(constraints.fields) ? constraints.fields : []);

  if (capability === 'data.read') {
    const fields = uniqueSorted(request.fields, 'read fields');
    if (fields.some((field) => !resource.fields.readable.includes(field) || !fieldsConstraint.has(field))) throw new Error('Read field is not permitted.');
    const text = `SELECT ${fields.map((field) => identifier(rawIdentifier(field, 'field'))).join(', ')} FROM ${table}${selectorPart(request, resource, constraints, values)}${limitPart(effectiveLimit(request, constraints), values)}`;
    return { text, values, command: 'read' };
  }

  if (capability === 'data.aggregate') {
    if (!isRecord(request.metric) || !['count', 'sum'].includes(request.metric.op)) throw new Error('Invalid aggregate metric.');
    if (request.metric.op === 'count' && Object.hasOwn(request.metric, 'field')) throw new Error('Count metric cannot specify a field.');
    if (request.metric.op === 'sum' && (typeof request.metric.field !== 'string' || !resource.fields.aggregatable.includes(request.metric.field) || !fieldsConstraint.has(request.metric.field))) throw new Error('Aggregate field is not permitted.');
    const groups = request.groupBy === undefined ? [] : uniqueSorted(request.groupBy, 'group-by fields');
    if (groups.some((field) => !resource.fields.aggregatable.includes(field) || !fieldsConstraint.has(field))) throw new Error('Group-by field is not permitted.');
    const selections = groups.map((field) => identifier(rawIdentifier(field, 'group-by field')));
    selections.push(request.metric.op === 'count' ? 'COUNT(*) AS "count"' : `SUM(${identifier(rawIdentifier(request.metric.field, 'aggregate field'))}) AS "sum"`);
    const groupClause = groups.length ? ` GROUP BY ${groups.map((field) => identifier(field)).join(', ')}` : '';
    const text = `SELECT ${selections.join(', ')} FROM ${table}${selectorPart(request, resource, constraints, values)}${groupClause}${limitPart(effectiveLimit(request, constraints), values)}`;
    return { text, values, command: 'aggregate' };
  }

  if (capability === 'data.mutate') {
    if (typeof request.action !== 'string' || !Object.hasOwn(resource.mutations, request.action)) throw new Error('Mutation action is not permitted.');
    const action = resource.mutations[request.action];
    const fields = uniqueSorted(Object.keys(request.values ?? {}), 'mutation values');
    if (!isRecord(request.values) || fields.some((field) => !action.fields.includes(field) || !resource.fields.writable.includes(field) || !fieldsConstraint.has(field) || !scalar(request.values[field]))) throw new Error('Mutation value field is not permitted.');
    const assignments = fields.map((field) => `${identifier(field)} = $${values.push(request.values[field])}`);
    const where = selectorPart(request, resource, constraints, values);
    if (!where) throw new Error('Mutation requires exactly one selector.');
    const returning = fieldsConstraint.size ? [...fieldsConstraint].filter((field) => action.fields.includes(field) && resource.fields.writable.includes(field) && validIdentifier(field)).sort() : [];
    if (!returning.length) throw new Error('Mutation requires authorized returning fields.');
    const requestedLimit = request.limit;
    if (requestedLimit !== undefined && (!Number.isInteger(requestedLimit) || requestedLimit <= 0)) throw new Error('Invalid row limit.');
    const mutationLimits = [requestedLimit, constraints.maxRows, action.maxRows].filter((limit) => limit !== undefined);
    const maxRows = mutationLimits.length ? Math.min(...mutationLimits) : undefined;
    if (maxRows === undefined) throw new Error('Mutation maxRows is required.');
    const text = `UPDATE ${table} SET ${assignments.join(', ')}${where} RETURNING ${returning.map((field) => identifier(rawIdentifier(field, 'returning field'))).join(', ')}`;
    return { text, values, command: 'mutate', maxRows };
  }

  throw new Error('Unsupported capability.');
}
