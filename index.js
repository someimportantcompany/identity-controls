const isPlainObject = require('lodash.isplainobject');
const micromatch = require('micromatch');

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

function can(permissions, action, resource) {
  assert(Array.isArray(permissions), new TypeError('Expected permissions to be an array'));
  assert(typeof action === 'string' && action.length, new TypeError('Expected action to be a string'));
  assert(typeof resource === 'string' && resource.length, new TypeError('Expected resource to be a string'));

  const matches = permissions.reduce((result, statement) => {
    const { effect, actions, resources } = statement || {};
    const matchesAction = actions.includes(action) || micromatch.isMatch(action, actions);
    const matchesResource = resources.includes(resource) || micromatch.isMatch(resource, resources);
    return matchesAction && matchesResource ? result.concat(effect) : result;
  }, []);

  return matches.length ? matches.includes('DENY') === false : false;
}

function createIdentityControls(identity, permissions) {
  assert(typeof identity === 'string' && identity.length, new TypeError('Expected identity to be a string'));
  assert(Array.isArray(permissions), new TypeError('Expected permissions to be an array'));
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
    can(...args) {
      return can(permissions, ...args);
    },
    assert(...args) {
      return assert(can(permissions, ...args), new PermissionDeniedError(identity, ...args));
    }
  };
}

module.exports = {
  createIdentityControls,
  can,
};

class PermissionDeniedError extends Error {
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
