import type { Document, Filter, FindCursor, FindOptions, UpdateFilter, UpdateOptions, UpdateResult, WithId } from 'mongodb';
export declare const GLOBAL_SCOPE = "__global_roles__";
export type Role = {
    scope: string;
    permissions: string[];
};
export interface RolesUser {
    _id: string;
    roles: Role[];
}
export type UpdateType<T> = (filter: Filter<T>, update: UpdateFilter<T> | Partial<T>, options?: UpdateOptions) => Promise<Document | UpdateResult>;
export type FindType<T> = (filter: Filter<T>, options?: FindOptions) => FindCursor<WithId<T>>;
export declare function userIsInRole(user: RolesUser, roles: string | string[], scope?: string): boolean;
export declare function addUsersToRoles(updateMany: UpdateType<RolesUser>, userIds: string | string[], roles: string[] | string, scope: string): Promise<void>;
export declare function setUserRoles(updateMany: UpdateType<RolesUser>, userIds: string | string[], rolesToSet: string | string[], scope: string): Promise<void>;
export declare function getRolesForUser(user: Partial<RolesUser>, scope?: string, excludeGlobalScope?: boolean): any[];
export declare function removeUsersFromScope(updateMany: UpdateType<RolesUser>, userIds: string | string[], scopesToRemove: string | string[]): Promise<void>;
export declare function removeUsersFromRoles(updateMany: UpdateType<RolesUser>, userIds: string | string[], permissionsToRemove: string | string[], scope: string): Promise<void>;
export declare function getUsersInRoles(find: FindType<RolesUser>, scope: string, targetRoles: string | string[]): Promise<string[]>;
