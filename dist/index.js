"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GLOBAL_SCOPE = void 0;
exports.userIsInRole = userIsInRole;
exports.addUsersToRoles = addUsersToRoles;
exports.setUserRoles = setUserRoles;
exports.getRolesForUser = getRolesForUser;
exports.removeUsersFromScope = removeUsersFromScope;
exports.removeUsersFromRoles = removeUsersFromRoles;
exports.getUsersInRoles = getUsersInRoles;
exports.GLOBAL_SCOPE = '__global_roles__';
function userIsInRole(user, roles, scope) {
    if (!user) {
        return false;
    }
    if (typeof roles === 'string') {
        roles = [roles];
    }
    if (typeof user === 'object' && Array.isArray(user.roles)) {
        const userRoles = user.roles;
        return userRoles
            .filter(role => scope ? (role.scope === scope || role.scope === exports.GLOBAL_SCOPE) : true)
            .flatMap(role => role.permissions)
            .some(permission => roles.includes(permission));
    }
    return false;
}
async function addUsersToRoles(updateMany, userIds, roles, scope) {
    if (!updateMany)
        throw new Error("Missing 'updateMany' param");
    if (!userIds)
        throw new Error("Missing 'userIds' param");
    if (!roles)
        throw new Error("Missing 'roles' param");
    if (!scope)
        throw new Error("Missing 'scope' param");
    if (typeof userIds === 'string') {
        userIds = [userIds];
    }
    if (typeof roles === 'string') {
        roles = [roles];
    }
    const filterUpdateExistingScope = {
        _id: { $in: userIds },
        'roles.scope': scope,
    };
    const updateUpdateExistingScope = { $addToSet: { 'roles.$[elem].permissions': { $each: roles } } };
    const optionsUpdateExistingScope = { arrayFilters: [{ "elem.scope": scope }] };
    // First update query to insert permissions into existing scope
    // Because arrayFilters does not automatically creates scope object if not exists
    await updateMany(filterUpdateExistingScope, updateUpdateExistingScope, optionsUpdateExistingScope);
    await createNewScope(updateMany, userIds, roles, scope);
}
async function setUserRoles(updateMany, userIds, rolesToSet, scope) {
    if (!updateMany)
        throw new Error("Missing 'updateMany' param");
    if (!userIds)
        throw new Error('Missing \'users\' param');
    if (!rolesToSet)
        throw new Error('Missing \'rolesToSet\' param');
    if (!scope)
        throw new Error('Missing \'scope\' param');
    if (typeof userIds === 'string') {
        userIds = [userIds];
    }
    if (typeof rolesToSet === 'string') {
        rolesToSet = [rolesToSet];
    }
    const filter = {
        _id: { $in: userIds },
        'roles.scope': scope,
    };
    const update = {
        $set: { 'roles.$[elem].permissions': rolesToSet }
    };
    const options = { arrayFilters: [{ "elem.scope": scope }] };
    await updateMany(filter, update, options);
    await createNewScope(updateMany, userIds, rolesToSet, scope);
}
function getRolesForUser(user, scope, excludeGlobalScope) {
    if (!user)
        throw new Error('Missing \'user\' param');
    let roles;
    if (typeof user === 'object') {
        roles = user.roles;
    }
    if (roles && roles.length > 0) {
        return roles
            .filter((role) => role.scope === scope || (!excludeGlobalScope && role.scope === exports.GLOBAL_SCOPE))
            .flatMap((role) => role.permissions);
    }
    return [];
}
async function removeUsersFromScope(updateMany, userIds, scopesToRemove) {
    if (!updateMany)
        throw new Error("Missing 'updateMany' param");
    if (!userIds)
        throw new Error('Missing \'userIds\' param');
    if (!scopesToRemove)
        throw new Error('Missing \'scope\' param');
    if (typeof userIds === 'string') {
        userIds = [userIds];
    }
    if (typeof scopesToRemove === 'string') {
        scopesToRemove = [scopesToRemove];
    }
    const filter = { _id: { $in: userIds } };
    const update = { $pull: { roles: { scope: { $in: scopesToRemove } } } };
    await updateMany(filter, update);
}
async function removeUsersFromRoles(updateMany, userIds, permissionsToRemove, scope) {
    if (!updateMany)
        throw new Error("Missing 'updateMany' param");
    if (!userIds)
        throw new Error('Missing \'userIds\' param');
    if (!permissionsToRemove)
        throw new Error('Missing \'permissionsToRemove\' param');
    if (!scope)
        throw new Error('Missing \'scope\' param');
    if (typeof userIds === 'string') {
        userIds = [userIds];
    }
    if (typeof permissionsToRemove === 'string') {
        permissionsToRemove = [permissionsToRemove];
    }
    const filter = {
        _id: { $in: userIds },
        'roles.scope': scope,
    };
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
    ];
    await updateMany(filter, update);
}
async function getUsersInRoles(find, scope, targetRoles) {
    if (!find)
        throw new Error("Missing 'find' param");
    if (!scope)
        throw new Error('Missing \'scope\' param');
    if (!targetRoles)
        throw new Error('Missing \'targetRoles\' param');
    if (typeof targetRoles === 'string') {
        targetRoles = [targetRoles];
    }
    const filter = {
        roles: {
            $elemMatch: {
                scope,
                permissions: { $all: targetRoles }
            }
        }
    };
    const users = await find(filter, { projection: { _id: 1 } }).toArray();
    return users.map(user => user._id);
}
async function createNewScope(updateMany, userIds, roles, scope) {
    const filter = {
        _id: { $in: userIds },
        'roles.scope': { $ne: scope },
    };
    const update = {
        $push: {
            roles: {
                scope,
                permissions: roles
            }
        }
    };
    await updateMany(filter, update);
}
