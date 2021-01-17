# identity-controls

[![NPM](https://badge.fury.io/js/identity-controls.svg)](https://npm.im/identity-controls)
[![CI](https://github.com/someimportantcompany/identity-controls/workflows/Test/badge.svg?branch=master)](https://github.com/someimportantcompany/identity-controls/actions?query=branch%3Amaster)
<!-- [![Coverage](https://coveralls.io/repos/github/someimportantcompany/identity-controls/badge.svg?branch=master)](https://coveralls.io/github/someimportantcompany/identity-controls?branch=master) -->

Identity access controls for your application. Given an array of policy statements, work out if this user is allowed to perform an action on a resource. Follows the flexible pattern you encounter when working with [AWS IAM permission statements](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html).

```js
const { buildPermissions } = require('identity-controls');

const identity = 'urn:someimportantcompany:users:11211';
const permissions = [
  {
    effect: 'ALLOW',
    actions: [ 'posts:*' ],
    resources: [ 'urn:someimportantcompany:posts:*' ],
  },
  {
    effect: 'ALLOW',
    action: [ 'users:*' ],
    resource: [ '{{identity}}' ],
  },
  {
    effect: 'DENY',
    action: [ 'users:delete' ],
    resource: [ '{{identity}}' ],
  },
];

const permissions = buildPermissions(identity, permissions);

permissions.can('posts:edit', 'urn:someimportantcompany:posts:a6db9385');
// true
permissions.can('users:changePassword', 'urn:someimportantcompany:users:11211');
// true
permissions.can('users:delete', 'urn:someimportantcompany:users:11211');
// false

permissions.assert('posts:edit', 'urn:someimportantcompany:posts:a6db9385');
// true
permissions.assert('users:changePassword', 'urn:someimportantcompany:users:11211');
// true
permissions.assert('users:delete', 'urn:someimportantcompany:users:11211');
// ERROR: Permission denied to urn:someimportantcompany:users:11211
//   for users:delete on urn:someimportantcompany:users:11211
```

## Installation

```
npm install --save identity-controls
```

## API

### `buildPermissions(identity, permissions[, defaultConditions])`

Create a permissions object to capable of checking permissions.

| Argument | Description |
| ---- | ---- |
| `identity` | A string defining the current identity |
| `permissions` | An array of permission statements |

This returns a permissions object with the following methods:

#### `can(action, resource[, conditions])`

Returns a boolean on whether the `permissions` given earlier allow `action` to be undertaken on `resource`.

| Argument | Description |
| ---- | ---- |
| `action` | A string defining the select action |
| `resource` | A string defining the selected resource |
| `conditions` | An optional object defining conditions |

#### `assert(action, resource[, conditions])`

Throws a `PermissionDeniedError` if the `permissions` given earlier does not allow `action` to be undertaken on `resource`.

| Argument | Description |
| ---- | ---- |
| `action` | A string defining the select action |
| `resource` | A string defining the selected resource |
| `conditions` | An optional object defining conditions |

### `can(permissions, action, resource[, conditions])`

Returns a boolean on whether `permissions` allows `action` to be undertaken on `resource`.

| Argument | Description |
| ---- | ---- |
| `permissions` | An array of permission statements. |
| `action` | A string defining the select action |
| `resource` | A string defining the selected resource |
| `conditions` | An optional object defining conditions |

## Conditions

Conditions are key-value objects allowing you to create permissions with dynamic resources (e.g. I can change my own password). They're are simple mustache-like variables that drop into `resources`. For example:

```js
const { can } = require('identity-controls');

const permissions = [
  {
    effect: 'ALLOW',
    actions: [ 'posts:*' ],
    resources: [ 'urn:someimportantcompany:posts:*' ],
  },
  {
    effect: 'ALLOW',
    action: [ 'users:*' ],
    resource: [ '{{identity}}' ],
  },
  {
    effect: 'DENY',
    action: [ 'users:delete' ],
    resource: [ '{{identity}}' ],
  },
];

can(permissions, 'users:read', 'urn:someimportantcompany:users:1', {
  identity: 'urn:someimportantcompany:users:1',
});
// true

can(permissions, 'users:delete', 'urn:someimportantcompany:users:1', {
  identity: 'urn:someimportantcompany:users:1',
});
// false
```
