# identity-controls

[![NPM](https://badge.fury.io/js/identity-controls.svg)](https://npm.im/identity-controls)
[![CI](https://github.com/someimportantcompany/identity-controls/workflows/Test/badge.svg?branch=master)](https://github.com/someimportantcompany/identity-controls/actions?query=branch%3Amaster)
<!-- [![Coverage](https://coveralls.io/repos/github/someimportantcompany/identity-controls/badge.svg?branch=master)](https://coveralls.io/github/someimportantcompany/identity-controls?branch=master) -->

Identity access controls for your application. Given an array of policy statements, work out if this user is allowed to

```js
const { buildPermissions } = require('identity-controls');

const who = 'urn:someimportantcompany:user:11211';
const what = [
  {
    effect: 'ALLOW',
    actions: [ 'posts:*' ],
    resources: [ 'urn:someimportantcompany:posts:*' ],
  },
  {
    effect: 'ALLOW',
    action: [ 'users:*' ],
    resource: [ '${identity}' ],
  },
  {
    effect: 'DENY',
    action: [ 'users:delete' ],
    resource: [ '${identity}' ],
  },
];

const permissions = buildPermissions(who, what);

permissions.can('posts:edit', 'urn:someimportantcompany:posts:a6db9385');
// true
permissions.can('users:changePassword', 'urn:someimportantcompany:user:11211');
// true
permissions.can('users:delete', 'urn:someimportantcompany:user:11211');
// false

permissions.assert('posts:edit', 'urn:someimportantcompany:posts:a6db9385');
// true
permissions.assert('users:changePassword', 'urn:someimportantcompany:user:11211');
// true
permissions.assert('users:delete', 'urn:someimportantcompany:user:11211');
// ERROR: Permission denied to urn:someimportantcompany:user:11211
//   for users:delete on urn:someimportantcompany:user:11211
```

---
