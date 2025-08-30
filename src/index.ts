import type {
  Document,
  Filter, FindCursor, FindOptions,
  UpdateFilter,
  UpdateOptions,
  UpdateResult,
  WithId,
} from 'mongodb'

export const GLOBAL_SCOPE = '__global_roles__'

export type Role = {
  scope: string,
  permissions: string[]
}

export interface RolesUser {
  _id: string,
  roles: Role[]
}

export type UpdateType<T> = (filter: Filter<T>, update: UpdateFilter<T> | Partial<T>, options?: UpdateOptions) => Promise<Document | UpdateResult>
export type FindType<T> = (filter: Filter<T>, options?: FindOptions) => FindCursor<WithId<T>>
export function userIsInRole(user: RolesUser, roles: string | string[], scope?: string) {
  if (!user) {
    return false
  }

  if (typeof roles === 'string') {
    roles = [roles]
  }

  if (!scope) {
    scope = GLOBAL_SCOPE
  }

  if (typeof user === 'object' && Array.isArray(user.roles)) {
    const userRoles = user.roles as Role[]
    return userRoles
      .filter(role => role.scope === scope || role.scope === GLOBAL_SCOPE)
      .flatMap(role => role.permissions)
      .some(permission => roles.includes(permission))
  }

  return false
}

export async function addUsersToRoles (updateMany: UpdateType<RolesUser>, userIds: string | string[] , roles: string[] | string, scope: string) {
  if (!updateMany) throw new Error ("Missing 'updateMany' param")
  if (!userIds) throw new Error ("Missing 'userIds' param")
  if (!roles) throw new Error ("Missing 'roles' param")
  if (!scope) throw new Error ("Missing 'scope' param")

  if (typeof userIds === 'string') {
    userIds = [userIds]
  }

  if (typeof roles === 'string') {
    roles = [roles]
  }

  const filterUpdateExistingScope = {
    _id: { $in: userIds },
    'roles.scope': scope,
  }
  const updateUpdateExistingScope = { $addToSet: { 'roles.$[elem].permissions': { $each: roles } } }
  const optionsUpdateExistingScope = { arrayFilters: [ { "elem.scope": scope } ] }

  // First update query to insert permissions into existing scope
  // Because arrayFilters does not automatically creates scope object if not exists
  await updateMany(filterUpdateExistingScope, updateUpdateExistingScope, optionsUpdateExistingScope)
  await createNewScope(updateMany, userIds, roles, scope)
}

export async function setUserRoles (updateMany: UpdateType<RolesUser>, userIds: string | string[], rolesToSet: string | string[], scope: string) {
  if (!updateMany) throw new Error ("Missing 'updateMany' param")
  if (!userIds) throw new Error ('Missing \'users\' param')
  if (!rolesToSet) throw new Error ('Missing \'rolesToSet\' param')
  if (!scope) throw new Error ('Missing \'scope\' param')

  if (typeof userIds === 'string') {
    userIds = [userIds]
  }

  if (typeof rolesToSet === 'string') {
    rolesToSet = [rolesToSet]
  }

  const filter = {
    _id: { $in: userIds },
    'roles.scope': scope,
  }
  const update = {
    $set: { 'roles.$[elem].permissions': rolesToSet }
  }
  const options = { arrayFilters: [ { "elem.scope": scope } ] }
  await updateMany(filter, update, options)
  await createNewScope(updateMany, userIds, rolesToSet, scope)
}

export function getRolesForUser (user: Partial<RolesUser>, scope?: string, excludeGlobalScope?: boolean) {
  if (!user) throw new Error ('Missing \'user\' param')
  let roles
  if (typeof user === 'object') {
    roles = user.roles
  }

  const getRolesFilter = (role: Role) => {
    if (!scope) {
      // no scope specified
      if (excludeGlobalScope) {
        // ...return all except GLOBAL
        return role.scope !== GLOBAL_SCOPE
      }
      // ...return all scopes
      return true
    } else {
      // scope specified
      if (excludeGlobalScope) {
        // ...don't include GLOBAL
        return role.scope === scope
      }
      // ...also include GLOBAL_SCOPE
      return role.scope === scope || role.scope === GLOBAL_SCOPE
    }
    return true
  }

  if (roles && roles.length > 0) {
    return roles
      .filter(getRolesFilter)
      .flatMap((role: any) => role.permissions)
  }
  return []
}


export async function removeUsersFromScope(updateMany: UpdateType<RolesUser>, userIds: string | string[], scopesToRemove: string | string[]) {
  if (!updateMany) throw new Error ("Missing 'updateMany' param")
  if (!userIds) throw new Error ('Missing \'userIds\' param')
  if (!scopesToRemove) throw new Error ('Missing \'scope\' param')

  if (typeof userIds === 'string') {
    userIds = [userIds]
  }

  if (typeof scopesToRemove === 'string') {
    scopesToRemove = [scopesToRemove]
  }

  const filter = { _id: { $in: userIds } }
  const update = { $pull: { roles: { scope: { $in: scopesToRemove } } } }
  await updateMany(filter, update)
}

export async function removeUsersFromRoles (updateMany: UpdateType<RolesUser>, userIds: string | string[], permissionsToRemove: string | string[], scope: string) {
  if (!updateMany) throw new Error ("Missing 'updateMany' param")
  if (!userIds) throw new Error ('Missing \'userIds\' param')
  if (!permissionsToRemove) throw new Error ('Missing \'permissionsToRemove\' param')
  if (!scope) throw new Error ('Missing \'scope\' param')

  if (typeof userIds === 'string') {
    userIds = [userIds]
  }

  if (typeof permissionsToRemove === 'string') {
    permissionsToRemove = [permissionsToRemove]
  }

  const filter = {
    _id: { $in: userIds },
    'roles.scope': scope,
  }

  const update = [
    {
      $set: {
        roles: {
          $map: {
            input: "$roles",
            as: "role",
            in: {
              $cond: [
                { $eq: ["$$role.scope", scope] },
                {
                  $mergeObjects: [
                    "$$role",
                    {
                      permissions: {
                        $filter: {
                          input: "$$role.permissions",
                          as: "perm",
                          cond: { $not: { $in: ["$$perm", permissionsToRemove] } }
                        }
                      }
                    }
                  ]
                },
                "$$role"
              ]
            }
          }
        }
      }
    }
  ]

  await updateMany(filter, update)
}

export async function getUsersInRoles(find: FindType<RolesUser>, scope: string, targetRoles: string | string[]) {
  if (!find) throw new Error ("Missing 'find' param")
  if (!scope) throw new Error ('Missing \'scope\' param')
  if (!targetRoles) throw new Error ('Missing \'targetRoles\' param')

  if (typeof targetRoles === 'string') {
    targetRoles = [targetRoles]
  }

  const filter = {
    roles: {
      $elemMatch: {
        scope,
        permissions: { $all: targetRoles }
      }
    }
  }
  const users = await find(filter, { projection: { _id: 1 } }).toArray()
  return users.map(user => user._id)
}

async function createNewScope(updateMany: UpdateType<RolesUser>, userIds: string[] , roles: string[], scope: string) {
  const filter = {
    _id: { $in: userIds },
    'roles.scope': { $ne: scope },
  }
  const update = {
    $push: {
      roles: {
        scope,
        permissions: roles
      }
    }
  }

  await updateMany(filter, update)
}
