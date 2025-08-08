# @share911/roles
Scope-aware roles and permissions helpers for applications backed by MongoDB. Keep your authorization model simple: assign permissions within scopes (e.g., per tenant/project) and use a special global scope for permissions that apply everywhere.

## Installation

Using npm:
```sh
npm install @share911/roles
```

Using yarn: 
```sh
yarn add @share911/roles
```

Using pnpm:
```sh
pnpm add @share911/roles
```


## Concepts
- A user has an array of role entries. Each entry contains:
  - scope: string identifier (e.g., project:alpha, tenant/123, organization1)
  - permissions: string[] (e.g., ['admin', 'editor'])
- A special constant GLOBAL_SCOPE allows you to grant permissions that apply across all scopes.

## Quick start
- Check permissions at runtime:
```typescript
import { userIsInRole, GLOBAL_SCOPE, type RolesUser } from '@share911/roles'

// get user object from database
const user: RolesUser = await getUserById('user-123')

// Structure of `user` object:
// {
//   _id: 'user-123',
//   roles: [
//     { scope: 'project:alpha', permissions: ['viewer'] },
//     { scope: GLOBAL_SCOPE, permissions: ['admin'] },
//   ],
// }

// check permissions
userIsInRole(user, 'admin') // true via global
userIsInRole(user, 'viewer', 'project:alpha') // true via specific scope
userIsInRole(user, ['editor', 'admin'], 'project:alpha') // true via global
userIsInRole(user, 'editor', 'project:beta') // false
```

- Add permissions to users for a scope:
```typescript
import { addUsersToRoles, GLOBAL_SCOPE, type RolesUser, type UpdateType } from '@share911/roles'
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

## Test
You need a MongoDB server running locally.
```sh
npm test
```
