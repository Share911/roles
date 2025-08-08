# s911-roles
Scope-aware roles and permissions helpers for applications backed by MongoDB. Keep your authorization model simple: assign permissions within scopes (e.g., per tenant/project) and use a special global scope for permissions that apply everywhere.

Based on the [Meteor roles package Version 2](https://github.com/Meteor-Community-Packages/meteor-roles/tree/v2).

## Concepts
- A user has an array of role entries. Each entry contains:
  - scope: string identifier (e.g., tenant:123, project:alpha)
  - permissions: string[] (e.g., ['admin', 'editor'])
- A special constant GLOBAL_SCOPE allows you to grant permissions that apply across all scopes.

## Quick start
- Check permissions at runtime:
```typescript
import { userIsInRole, GLOBAL_SCOPE, type RolesUser } from 's911-roles'

const user: RolesUser = {
  _id: 'user-123',
  roles: [
    { scope: 'project:alpha', permissions: ['viewer'] },
    { scope: GLOBAL_SCOPE, permissions: ['admin'] },
  ],
}

userIsInRole(user, 'admin') // true (global)
userIsInRole(user, ['editor', 'admin'], 'project:alpha') // true via global
userIsInRole(user, 'editor', 'project:beta') // false
```

- Add permissions to users for a scope:
```typescript
import { addUsersToRoles, GLOBAL_SCOPE, type RolesUser, type UpdateType } from 's911-roles'
import { MongoClient } from 'mongodb'

type User = RoleUser & {
  name: string
}

async function grantGlobalAdmin(userIds: string[]) {
 const users = client.db('<DB_NAME>').collection<User>('users')

  const updateMany: UpdateType<User> = (filter, update, options) =>
    users.updateMany(filter, update, options).bind(users)

  await addUsersToRoles(updateMany, userIds, ['admin'], GLOBAL_SCOPE);

  await client.close()
}
```

## Installation
```sh
npm install
```

Optional build step if you want compiled output in dist/:
```sh
npm run build
```

## Test
You need a MongoDB server running locally.
```sh
npm test
```
