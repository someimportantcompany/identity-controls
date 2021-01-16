const _ = require('lodash');
const assert = require('assert');

const urn = (...args) => `urn:someimportantcompany:${args.join(':')}`;

describe('identity-controls', () => {
  const { createIdentityControls } = require('./index');

  before(() => {
    assert.strictEqual(typeof createIdentityControls, 'function', 'Expected createIdentityControls to be a function');
  });

  it('should return a permissions instance', () => {
    const permissions = createIdentityControls('IDENTITY', []);
    assert(_.isPlainObject(permissions), 'Expected createIdentityControls to return an object');
    assert.strictEqual(typeof permissions.can, 'function', 'Expected can to be a function');
    assert.strictEqual(typeof permissions.assert, 'function', 'Expected assert to be a function');
  });

  describe('Permissions #1', () => {
    let perms = null;
    const statements = [
      { effect: 'ALLOW', actions: [ 'users:read' ], resources: [ urn('users', '*') ] },
    ];

    before(() => {
      perms = createIdentityControls(urn('user', 101), statements);
      assert(_.isPlainObject(perms), 'Expected createIdentityControls to return an object');
      assert.strictEqual(typeof perms.can, 'function', 'Expected can to be a function');
      assert.strictEqual(typeof perms.assert, 'function', 'Expected assert to be a function');
    });

    it('should allow users:read', () => assert(perms.can('users:read', urn('users', 110))));
    it('should deny posts:read', () => assert(perms.can('posts:read', urn('post', 1)) === false));

    it('should assert users:read', () => {
      perms.assert('users:read', urn('users', 110));
    });
    it('should throw posts:read', () => {
      try {
        perms.assert('posts:read', urn('post', 1));
      } catch (err) {
        assert(err instanceof Error, 'Expected err to be an Error');
        assert.strictEqual(err.message,
          'Permission denied to urn:someimportantcompany:user:101 for posts:read on urn:someimportantcompany:post:1');
        assert.strictEqual(err.identity, urn('user', 101));
        assert.strictEqual(err.action, 'posts:read');
        assert.strictEqual(err.resource, urn('post', 1));
        assert.strictEqual(err.condition, undefined);
      }
    });
  });

  describe('Permissions #2', () => {
    let perms = null;
    const statements = [
      { effect: 'ALLOW', actions: [ 'users:read' ], resources: [ urn('users', '*') ] },
      { effect: 'ALLOW', actions: [ 'posts:*' ], resources: [ urn('posts', 1) ] },
      { effect: 'DENY', actions: [ 'posts:delete' ], resources: [ urn('posts', '*') ] },
    ];

    before(() => {
      perms = createIdentityControls(urn('user', 101), statements);
      assert(_.isPlainObject(perms), 'Expected createIdentityControls to return an object');
      assert.strictEqual(typeof perms.can, 'function', 'Expected can to be a function');
      assert.strictEqual(typeof perms.assert, 'function', 'Expected assert to be a function');
    });

    it('should allow users:read', () => assert(perms.can('users:read', urn('users', 110))));
    it('should allow posts:read', () => assert(perms.can('posts:read', urn('posts', 1))));
    it('should deny posts:delete', () => assert(perms.can('posts:delete', urn('posts', 1)) === false));
  });

});
