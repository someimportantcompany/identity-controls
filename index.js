const isPlainObject = require('lodash.isplainobject');
const micromatch = require('micromatch');

/**
 * @param value
 * @param {(Error|string)} err
 * @throws {Error}
 * @return {boolean}
 */
function assert(value, err) {
  if (Boolean(value) === false) {
    /* istanbul ignore if */
    if ((err instanceof Error) === false) {
      err = new Error(`${err}`);
      if (typeof Error.captureStackTrace === 'function') {
        Error.captureStackTrace(err, assert);
      }
    }

    throw err;
  }

  return true;
}

/**
 * @param {Array<Object>} permissions
 * @param {string} identity
 * @param {string} resource
 * @param {Object} conditions
 * @return {boolean}
 */
function can(permissions, action, resource, conditions) {
  assert(Array.isArray(permissions), new TypeError('Expected permissions to be an array'));
  assert(typeof action === 'string' && action.length, new TypeError('Expected action to be a string'));
  assert(typeof resource === 'string' && resource.length, new TypeError('Expected resource to be a string'));

  const matches = permissions.reduce((result, statement) => {
    const actions = statement && Array.isArray(statement.actions) ? statement.actions : [];

    if (statement && statement.effect && (actions.includes(action) || micromatch.isMatch(action, actions))) {
      const template = string => string.includes('{{')
        ? string.replace(/{{([\s\S]+?)}}/g, (value, key) => conditions.hasOwnProperty(key) ? conditions[key] : value)
        : string;

      const resources = (Array.isArray(statement.resources) ? statement.resources : []).map(template);
      if (resources.includes(resource) || micromatch.isMatch(resource, resources)) {
        result.push(statement.effect);
      }
    }

    return result;
  }, []);

  return matches.length ? matches.includes('DENY') === false : false;
}

/**
 * @param {string} identity
 * @param {Array<Object<string,Function>>} permissions
 * @param {Object} defaultConditions
 * @return {Object}
 */
function createIdentityControls(identity, permissions, defaultConditions) {
  assert(typeof identity === 'string' && identity.length, new TypeError('Expected identity to be a string'));
  assert(Array.isArray(permissions), new TypeError('Expected permissions to be an array'));
  assert(defaultConditions === undefined || isPlainObject(defaultConditions),
    new TypeError('Expected defaultConditions to be a plain object'));

  permissions.forEach(statement => {
    assert(isPlainObject(statement), new TypeError('Expected each statement to be a plain object'));
    const { effect, actions, resources } = statement;
    assert(typeof effect === 'string' && [ 'ALLOW', 'DENY' ].includes(effect),
      new TypeError('Expected each statement to have an effect string with ALLOW or DENY'));
    assert(Array.isArray(actions), new TypeError('Expected each statement to have an actions array of strings'));
    assert(Array.isArray(resources), new TypeError('Expected each statement to have an resources array of strings'));
    actions.forEach(a => assert(typeof a === 'string', new TypeError('Expected each action to be a string')));
    resources.forEach(r => assert(typeof r === 'string', new TypeError('Expected each resource to be a string')));
  });

  return {

    /**
     * @param {string} identity
     * @param {string} resource
     * @param {Object} conditions
     * @return {boolean}
     */
    can(action, resource, conditions) {
      assert(typeof action === 'string' && action.length, new TypeError('Expected action to be a string'));
      assert(typeof resource === 'string' && resource.length, new TypeError('Expected resource to be a string'));
      assert(conditions === undefined || isPlainObject(conditions), new TypeError('Expected conditions to be a plain object'));
      return can(permissions, action, resource, { identity, ...defaultConditions, ...conditions });
    },

    /**
     * @param {string} identity
     * @param {string} resource
     * @param {Object} conditions
     * @throws {PermissionDeniedError}
     * @return {boolean}
     */
    assert(action, resource, conditions) {
      return assert(can(permissions, action, resource, conditions), new PermissionDeniedError(identity, action, resource, conditions));
    },

  };
}

module.exports = {
  createIdentityControls,
  can,
};

class PermissionDeniedError extends Error {
  /**
   * @param {string} identity
   * @param {string} action
   * @param {string} resource
   * @param {Object} conditions
   */
  constructor(identity, action, resource, conditions) {
    super(`Permission denied to ${identity} for ${action} on ${resource}`);
    Object.defineProperties(this, {
      identity: { enumerable: true, value: identity },
      action: { enumerable: true, value: action },
      resource: { enumerable: true, value: resource },
      conditions: { enumerable: true, value: conditions },
    });
  }
}
