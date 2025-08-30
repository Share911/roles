"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const assert_1 = __importDefault(require("assert"));
const mongodb_1 = require("mongodb");
const crypto_1 = __importDefault(require("crypto"));
const index_1 = require("../index");
const test = {
    equal(actual, expected, message) {
        return assert_1.default.deepEqual(actual, expected, message);
    },
    isTrue(actual, message) {
        return assert_1.default.equal(actual, true, message);
    },
    isFalse(actual, message) {
        return assert_1.default.equal(actual, false, message);
    }
};
describe('roles', function () {
    let db, usersCollection, client;
    let findOne;
    let updateMany;
    let users = {};
    const USER_ROLES = ['admin', 'editor', 'user'];
    before(async function () {
        client = await mongodb_1.MongoClient.connect('mongodb://localhost:27017/roles-npm');
        db = client.db();
        usersCollection = db.collection('users');
        findOne = usersCollection.findOne.bind(usersCollection);
        // @ts-ignore - allow assignment, some internal comparison Date vs Timestamp
        updateMany = usersCollection.updateMany.bind(usersCollection);
    });
    after(async function () {
        await client.close();
    });
    async function addUser(name) {
        const user = {
            _id: crypto_1.default.randomUUID(),
            username: name,
            createdAt: new Date(),
            roles: []
        };
        return usersCollection.insertOne(user);
    }
    async function reset() {
        await usersCollection.deleteMany({});
        await addUser('eve');
        await addUser('bob');
        await addUser('joe');
        users.eve = await findOne({ username: 'eve' });
        users.bob = await findOne({ username: 'bob' });
        users.joe = await findOne({ username: 'joe' });
    }
    async function testUser(username, expectedRoles, group) {
        const userId = users[username]._id;
        const userObj = await findOne({ _id: userId });
        if (typeof expectedRoles === 'string') {
            expectedRoles = [expectedRoles];
        }
        // check using passed-in user object
        await _innerTest(userObj, username, expectedRoles, group);
    }
    async function _innerTest(userParam, username, expectedRoles, group) {
        // test that user has only the roles expected and no others
        for (let role of USER_ROLES) {
            let expected = expectedRoles.includes(role);
            let msg = username + ' expected to have \'' + role + '\' permission but does not';
            let nmsg = username + ' had the following un-expected permission: ' + role;
            if (expected) {
                test.isTrue((0, index_1.userIsInRole)(userParam, role, group), msg);
            }
            else {
                test.isFalse((0, index_1.userIsInRole)(userParam, role, group), nmsg);
            }
        }
    }
    it('can check if user is in role', async function () {
        await reset();
        await usersCollection.updateOne({ _id: users.eve._id }, { $push: { roles: { scope: 'group1', permissions: ['admin', 'user'] } } });
        await usersCollection.updateOne({ _id: users.eve._id }, { $push: { roles: { scope: 'group2', permissions: ['editor'] } } });
        await testUser('eve', ['admin', 'user'], 'group1');
        await testUser('eve', 'editor', 'group2');
        await testUser('bob', [], 'group1');
        await testUser('joe', [], 'group1');
    });
    it('can check if null user is in role', async function () {
        const user = null;
        await reset();
        test.isFalse((0, index_1.userIsInRole)(user, 'admin'));
    });
    it('can check user against several roles at once', async function () {
        await reset();
        await (0, index_1.addUsersToRoles)(updateMany, users.eve._id, ['admin', 'user'], 'scope1');
        const user = await findOne({ _id: users.eve._id });
        test.isFalse((0, index_1.userIsInRole)(user, 'editor', 'scope1'), 'expected not to have editor role but found');
        test.isTrue((0, index_1.userIsInRole)(user, 'admin', 'scope1'), 'expected admin role but not found');
        test.isTrue((0, index_1.userIsInRole)(user, ['admin', 'user'], 'scope1'), 'expected admin or user role but not found');
        test.isTrue((0, index_1.userIsInRole)(user, ['admin', 'foo'], 'scope1'), 'expected admin or foo role but not found');
    });
    it('adding non-existent users to role does nothing', async function () {
        await reset();
        const fakeUserId = 'xyz123';
        await (0, index_1.addUsersToRoles)(updateMany, fakeUserId, ['admin'], 'scope1');
        test.equal(await findOne({ _id: fakeUserId }), null);
    });
    it('can add individual users to roles', async function () {
        await reset();
        await (0, index_1.addUsersToRoles)(updateMany, users.eve._id, ['admin', 'user'], 'scope1');
        await (0, index_1.addUsersToRoles)(updateMany, users.eve._id, ['editor'], 'scope2');
        await testUser('eve', ['admin', 'user'], 'scope1');
        await testUser('eve', ['editor'], 'scope2');
        await testUser('eve', [], 'scope3');
        await testUser('eve', []);
        await testUser('bob', [], 'scope1');
        await testUser('bob', [], 'scope2');
        await testUser('bob', [], 'scope3');
        await testUser('bob', []);
        await testUser('joe', [], 'scope1');
        await testUser('joe', [], 'scope2');
        await testUser('joe', [], 'scope3');
        await testUser('joe', []);
        await (0, index_1.addUsersToRoles)(updateMany, users.joe._id, ['editor', 'user'], 'scope1');
        await (0, index_1.addUsersToRoles)(updateMany, users.joe._id, ['admin', 'user'], 'scope3');
        await testUser('eve', ['admin', 'user'], 'scope1');
        await testUser('eve', [], 'scope3');
        await testUser('eve', []);
        await testUser('bob', [], 'scope1');
        await testUser('bob', [], 'scope2');
        await testUser('bob', [], 'scope3');
        await testUser('bob', []);
        await testUser('joe', ['editor', 'user'], 'scope1');
        await testUser('joe', [], 'scope2');
        await testUser('joe', ['admin', 'user'], 'scope3');
        await testUser('joe', []);
    });
    it('can add user to roles multiple times', async function () {
        await reset();
        await (0, index_1.addUsersToRoles)(updateMany, users.eve._id, ['admin', 'user'], 'scope1');
        await (0, index_1.addUsersToRoles)(updateMany, users.eve._id, ['admin', 'user'], 'scope1');
        await testUser('eve', ['admin', 'user'], 'scope1');
        await testUser('eve', [], 'scope2');
        await testUser('bob', [], 'scope1');
        await testUser('joe', [], 'scope1');
        await (0, index_1.addUsersToRoles)(updateMany, users.bob._id, ['admin'], 'scope1');
        await (0, index_1.addUsersToRoles)(updateMany, users.bob._id, ['editor'], 'scope1');
        await testUser('eve', ['admin', 'user'], 'scope1');
        await testUser('bob', ['admin', 'editor'], 'scope1');
        await testUser('joe', [], 'scope1');
    });
    it('can add multiple users to roles at once', async function () {
        await reset();
        await (0, index_1.addUsersToRoles)(updateMany, [users.eve._id, users.bob._id], ['admin', 'user'], 'scope1');
        await testUser('eve', ['admin', 'user'], 'scope1');
        await testUser('bob', ['admin', 'user'], 'scope1');
        await testUser('joe', [], 'scope1');
        await (0, index_1.addUsersToRoles)(updateMany, [users.bob._id, users.joe._id], ['editor', 'user'], 'scope1');
        await testUser('eve', ['admin', 'user'], 'scope1');
        await testUser('bob', ['admin', 'editor', 'user'], 'scope1');
        await testUser('joe', ['editor', 'user'], 'scope1');
    });
    it('can remove individual users from roles', async function () {
        await reset();
        await (0, index_1.addUsersToRoles)(updateMany, [users.eve._id, users.bob._id], ['editor', 'user'], 'scope1');
        await testUser('eve', ['editor', 'user'], 'scope1');
        await testUser('bob', ['editor', 'user'], 'scope1');
        // remove user role - one user
        await (0, index_1.removeUsersFromRoles)(updateMany, users.eve._id, ['user'], 'scope1');
        await testUser('eve', ['editor'], 'scope1');
        await testUser('bob', ['editor', 'user'], 'scope1');
    });
    it('can remove user from roles multiple times', async function () {
        await reset();
        await (0, index_1.addUsersToRoles)(updateMany, [users.eve._id, users.bob._id], ['editor', 'user'], 'scope1');
        await testUser('eve', ['editor', 'user'], 'scope1');
        await testUser('bob', ['editor', 'user'], 'scope1');
        // remove user role - one user
        await (0, index_1.removeUsersFromRoles)(updateMany, users.eve._id, ['user'], 'scope1');
        await testUser('eve', ['editor'], 'scope1');
        await testUser('bob', ['editor', 'user'], 'scope1');
        // try remove again
        await (0, index_1.removeUsersFromRoles)(updateMany, users.eve._id, ['user'], 'scope1');
        await testUser('eve', ['editor'], 'scope1');
        await testUser('bob', ['editor', 'user'], 'scope1');
    });
    it('can remove multiple users from roles at once', async function () {
        await reset();
        await (0, index_1.addUsersToRoles)(updateMany, [users.eve._id, users.bob._id], ['editor'], 'scope1');
        await (0, index_1.addUsersToRoles)(updateMany, [users.bob._id, users.joe._id], ['admin', 'user'], 'scope1');
        await (0, index_1.addUsersToRoles)(updateMany, [users.eve._id, users.joe._id], ['user'], 'scope1');
        await testUser('eve', ['editor', 'user'], 'scope1');
        await testUser('bob', ['admin', 'editor', 'user'], 'scope1');
        await testUser('joe', ['admin', 'user'], 'scope1');
        // remove user role - two users
        await (0, index_1.removeUsersFromRoles)(updateMany, [users.bob._id, users.joe._id], ['admin'], 'scope1');
        await testUser('eve', ['editor', 'user'], 'scope1');
        await testUser('bob', ['user', 'editor'], 'scope1');
        await testUser('joe', ['user'], 'scope1');
    });
    it('can set user roles', async function () {
        await reset();
        await (0, index_1.setUserRoles)(updateMany, [users.eve._id, users.bob._id], ['editor', 'user'], 'group1');
        await (0, index_1.setUserRoles)(updateMany, [users.bob._id, users.joe._id], ['admin'], 'group2');
        await testUser('eve', ['editor', 'user'], 'group1');
        await testUser('bob', ['editor', 'user'], 'group1');
        await testUser('joe', [], 'group1');
        await testUser('eve', [], 'group2');
        await testUser('bob', ['admin'], 'group2');
        await testUser('joe', ['admin'], 'group2');
        // use addUsersToRoles add some roles
        await (0, index_1.addUsersToRoles)(updateMany, [users.eve._id, users.bob._id], ['admin'], 'group1');
        await (0, index_1.addUsersToRoles)(updateMany, [users.bob._id, users.joe._id], ['editor'], 'group2');
        await testUser('eve', ['admin', 'editor', 'user'], 'group1');
        await testUser('bob', ['admin', 'editor', 'user'], 'group1');
        await testUser('joe', [], 'group1');
        await testUser('eve', [], 'group2');
        await testUser('bob', ['admin', 'editor'], 'group2');
        await testUser('joe', ['admin', 'editor'], 'group2');
        await (0, index_1.setUserRoles)(updateMany, [users.eve._id, users.bob._id], ['user'], 'group1');
        await (0, index_1.setUserRoles)(updateMany, [users.eve._id, users.joe._id], ['editor'], 'group2');
        await testUser('eve', ['user'], 'group1');
        await testUser('bob', ['user'], 'group1');
        await testUser('joe', [], 'group1');
        await testUser('eve', ['editor'], 'group2');
        await testUser('bob', ['admin', 'editor'], 'group2');
        await testUser('joe', ['editor'], 'group2');
        await (0, index_1.setUserRoles)(updateMany, users.bob._id, 'editor', 'group1');
        await testUser('eve', ['user'], 'group1');
        await testUser('bob', ['editor'], 'group1');
        await testUser('joe', [], 'group1');
        await testUser('eve', ['editor'], 'group2');
        await testUser('bob', ['admin', 'editor'], 'group2');
        await testUser('joe', ['editor'], 'group2');
        await (0, index_1.setUserRoles)(updateMany, [users.bob._id, users.joe._id], [], 'group1');
        await testUser('eve', ['user'], 'group1');
        await testUser('bob', [], 'group1');
        await testUser('joe', [], 'group1');
        await testUser('eve', ['editor'], 'group2');
        await testUser('bob', ['admin', 'editor'], 'group2');
        await testUser('joe', ['editor'], 'group2');
    });
    it('can set user roles by GLOBAL_SCOPE', async function () {
        await reset();
        await (0, index_1.addUsersToRoles)(updateMany, users.eve._id, 'admin', index_1.GLOBAL_SCOPE);
        await testUser('eve', ['admin'], 'group1');
        await testUser('eve', ['admin'], index_1.GLOBAL_SCOPE);
        await testUser('eve', ['admin']);
        await (0, index_1.setUserRoles)(updateMany, users.eve._id, 'editor', index_1.GLOBAL_SCOPE);
        await testUser('eve', ['editor'], 'group2');
        await testUser('eve', ['editor'], index_1.GLOBAL_SCOPE);
        await testUser('eve', ['editor']);
    });
    it('can get roles for non-existant user', async function () {
        await reset();
        test.equal(await (0, index_1.getRolesForUser)({}), []);
        test.equal(await (0, index_1.getRolesForUser)({}, 'group1'), []);
    });
    it('can get all roles for user', async function () {
        await reset();
        const userId = users.eve._id;
        let userObj;
        userObj = await findOne({ _id: userId });
        test.equal(await (0, index_1.getRolesForUser)(userObj), []);
        await (0, index_1.addUsersToRoles)(updateMany, userId, ['admin', 'user'], 'scope1');
        userObj = await findOne({ _id: userId });
        test.equal((0, index_1.getRolesForUser)(userObj, 'scope1'), ['admin', 'user']);
        test.equal((0, index_1.getRolesForUser)(userObj), ['admin', 'user']);
    });
    it('can get all roles for user by group with periods in name', async function () {
        await reset();
        await (0, index_1.addUsersToRoles)(updateMany, users.joe._id, ['admin', 'user'], 'example.k12.va.us');
        const userObj = await findOne({ _id: users.joe._id });
        test.equal(await (0, index_1.getRolesForUser)(userObj, 'example.k12.va.us'), ['admin', 'user']);
    });
    it('can get all roles for user by group including GLOBAL_SCOPE', async function () {
        await reset();
        const userId = users.eve._id;
        let userObj;
        await (0, index_1.addUsersToRoles)(updateMany, [userId], ['editor'], index_1.GLOBAL_SCOPE);
        await (0, index_1.addUsersToRoles)(updateMany, [userId], ['admin'], 'scope1');
        await (0, index_1.addUsersToRoles)(updateMany, [userId], ['user'], 'scope2');
        userObj = await findOne({ _id: userId });
        test.equal((0, index_1.getRolesForUser)(userObj, 'scope1'), ['editor', 'admin']);
        test.equal((0, index_1.getRolesForUser)(userObj), ['editor', 'admin', 'user']);
    });
    it('can get all roles for user by group excluding GLOBAL_SCOPE', async function () {
        await reset();
        const userId = users.eve._id;
        let userObj;
        await (0, index_1.addUsersToRoles)(updateMany, [userId], ['editor'], index_1.GLOBAL_SCOPE);
        await (0, index_1.addUsersToRoles)(updateMany, [userId], ['admin'], 'scope1');
        await (0, index_1.addUsersToRoles)(updateMany, [userId], ['user'], 'scope2');
        userObj = await findOne({ _id: userId });
        test.equal((0, index_1.getRolesForUser)(userObj, 'scope1'), ['editor', 'admin']);
        test.equal((0, index_1.getRolesForUser)(userObj, 'scope2'), ['editor', 'user']);
        test.equal((0, index_1.getRolesForUser)(userObj, 'scope1', true), ['admin']);
        test.equal((0, index_1.getRolesForUser)(userObj, 'scope2', true), ['user']);
        // all scopes except GLOBAL
        test.equal((0, index_1.getRolesForUser)(userObj, '', true), ['admin', 'user']);
    });
    it('getRolesForUser should not return null entries if user has no roles for group', async function () {
        await reset();
        const userId = users.eve._id;
        let userObj;
        userObj = await findOne({ _id: userId });
        test.equal((0, index_1.getRolesForUser)(userObj, 'group1'), []);
        test.equal((0, index_1.getRolesForUser)(userObj), []);
        await (0, index_1.addUsersToRoles)(updateMany, [users.eve._id], ['editor'], index_1.GLOBAL_SCOPE);
        userObj = await findOne({ _id: userId });
        test.equal((0, index_1.getRolesForUser)(userObj, 'group1'), ['editor']);
        test.equal((0, index_1.getRolesForUser)(userObj), ['editor']);
    });
    it('can use GLOBAL_SCOPE to assign blanket permissions', async function () {
        await reset();
        await (0, index_1.addUsersToRoles)(updateMany, [users.joe._id, users.bob._id], ['admin'], index_1.GLOBAL_SCOPE);
        await testUser('eve', [], 'group1');
        await testUser('joe', ['admin'], 'group2');
        await testUser('joe', ['admin'], 'group1');
        await testUser('bob', ['admin'], 'group2');
        await testUser('bob', ['admin'], 'group1');
        await (0, index_1.removeUsersFromRoles)(updateMany, users.joe._id, ['admin'], index_1.GLOBAL_SCOPE);
        await testUser('eve', [], 'group1');
        await testUser('joe', [], 'group2');
        await testUser('joe', [], 'group1');
        await testUser('bob', ['admin'], 'group2');
        await testUser('bob', ['admin'], 'group1');
    });
    it('GLOBAL_SCOPE is independent of other groups', async function () {
        await reset();
        await (0, index_1.addUsersToRoles)(updateMany, [users.joe._id, users.bob._id], ['admin'], 'group5');
        await (0, index_1.addUsersToRoles)(updateMany, [users.joe._id, users.bob._id], ['admin'], index_1.GLOBAL_SCOPE);
        await testUser('eve', [], 'group1');
        await testUser('joe', ['admin'], 'group5');
        await testUser('joe', ['admin'], 'group2');
        await testUser('joe', ['admin'], 'group1');
        await testUser('bob', ['admin'], 'group5');
        await testUser('bob', ['admin'], 'group2');
        await testUser('bob', ['admin'], 'group1');
        await (0, index_1.removeUsersFromRoles)(updateMany, users.joe._id, ['admin'], index_1.GLOBAL_SCOPE);
        await testUser('eve', [], 'group1');
        await testUser('joe', ['admin'], 'group5');
        await testUser('joe', [], 'group2');
        await testUser('joe', [], 'group1');
        await testUser('bob', ['admin'], 'group5');
        await testUser('bob', ['admin'], 'group2');
        await testUser('bob', ['admin'], 'group1');
    });
    it('GLOBAL_SCOPE is checked when group not specified', async function () {
        await reset();
        await (0, index_1.addUsersToRoles)(updateMany, users.joe._id, 'admin', index_1.GLOBAL_SCOPE);
        await testUser('joe', ['admin']);
        await (0, index_1.removeUsersFromRoles)(updateMany, users.joe._id, 'admin', index_1.GLOBAL_SCOPE);
        await testUser('joe', []);
    });
    it("can use '.' in group name", async function () {
        await reset();
        await (0, index_1.addUsersToRoles)(updateMany, users.joe._id, ['admin'], 'example.com');
        await testUser('joe', ['admin'], 'example.com');
    });
    it("can use multiple periods in group name", async function () {
        await reset();
        await (0, index_1.addUsersToRoles)(updateMany, users.joe._id, ['admin'], 'example.k12.va.us');
        await testUser('joe', ['admin'], 'example.k12.va.us');
    });
    it('scope name can start with $', async function () {
        await reset();
        await (0, index_1.addUsersToRoles)(updateMany, users.joe._id, ['admin'], '$scope');
        await reset();
        // should not throw error
        await (0, index_1.addUsersToRoles)(updateMany, users.bob._id, ['editor', 'user'], 'g$roup1');
    });
    it('userIsInRole returns false for unknown roles', async function () {
        await reset();
        await (0, index_1.addUsersToRoles)(updateMany, users.eve._id, ['admin', 'user'], 'scope1');
        await (0, index_1.addUsersToRoles)(updateMany, users.eve._id, ['editor'], 'scope2');
        test.isFalse((0, index_1.userIsInRole)(users.eve, 'unknown'));
        test.isFalse((0, index_1.userIsInRole)(users.eve, []));
    });
    it('can remove scope from user', async () => {
        await reset();
        await (0, index_1.addUsersToRoles)(updateMany, users.eve._id, ['admin', 'user'], 'scope1');
        await (0, index_1.addUsersToRoles)(updateMany, users.eve._id, ['admin', 'user'], 'scope2');
        await (0, index_1.removeUsersFromScope)(updateMany, users.eve._id, 'scope1');
        let userObj = await findOne({ _id: users.eve._id });
        test.isFalse((0, index_1.userIsInRole)(userObj, ['admin', 'user'], 'scope1'));
        test.isTrue((0, index_1.userIsInRole)(userObj, ['admin', 'user'], 'scope2'));
        await (0, index_1.removeUsersFromScope)(updateMany, users.eve._id, 'scope2');
        userObj = await findOne({ _id: users.eve._id });
        test.isFalse((0, index_1.userIsInRole)(userObj, ['admin', 'user'], 'scope2'));
    });
    it('can remove scope from multiple users', async () => {
        await reset();
        await (0, index_1.addUsersToRoles)(updateMany, users.eve._id, ['admin', 'user'], 'scope1');
        await (0, index_1.addUsersToRoles)(updateMany, users.eve._id, ['admin', 'user'], 'scope2');
        await (0, index_1.addUsersToRoles)(updateMany, users.eve._id, ['admin', 'user'], 'scope3');
        await (0, index_1.addUsersToRoles)(updateMany, users.bob._id, ['admin', 'user'], 'scope1');
        await (0, index_1.addUsersToRoles)(updateMany, users.bob._id, ['admin', 'user'], 'scope2');
        await (0, index_1.addUsersToRoles)(updateMany, users.bob._id, ['admin', 'user'], 'scope3');
        await (0, index_1.removeUsersFromScope)(updateMany, [users.eve._id, users.bob._id], 'scope1');
        let eve = await findOne({ _id: users.eve._id });
        let bob = await findOne({ _id: users.bob._id });
        test.isFalse((0, index_1.userIsInRole)(eve, ['admin', 'user'], 'scope1'));
        test.isTrue((0, index_1.userIsInRole)(eve, ['admin', 'user'], 'scope2'));
        test.isFalse((0, index_1.userIsInRole)(bob, ['admin', 'user'], 'scope1'));
        test.isTrue((0, index_1.userIsInRole)(bob, ['admin', 'user'], 'scope2'));
        await (0, index_1.removeUsersFromScope)(updateMany, [users.eve._id, users.bob._id], ['scope1', 'scope2']);
        bob = await findOne({ _id: users.bob._id });
        eve = await findOne({ _id: users.eve._id });
        test.isFalse((0, index_1.userIsInRole)(eve, ['admin', 'user'], 'scope2'));
        test.isFalse((0, index_1.userIsInRole)(bob, ['admin', 'user'], 'scope2'));
        test.isTrue((0, index_1.userIsInRole)(eve, ['admin', 'user'], 'scope3'));
        test.isTrue((0, index_1.userIsInRole)(bob, ['admin', 'user'], 'scope3'));
    });
    it('get all users in given scope', async () => {
        await reset();
        await (0, index_1.addUsersToRoles)(updateMany, users.eve._id, ['admin', 'user'], 'scope1');
        await (0, index_1.addUsersToRoles)(updateMany, users.bob._id, ['admin', 'user', 'manager'], 'scope1');
        await (0, index_1.addUsersToRoles)(updateMany, users.joe._id, ['security'], 'scope1');
        let result = await (0, index_1.getUsersInRoles)(usersCollection.find.bind(usersCollection), 'scope1', 'admin');
        test.isTrue(result.includes(users.eve._id) &&
            result.includes(users.bob._id) &&
            !result.includes(users.joe._id));
        result = await (0, index_1.getUsersInRoles)(usersCollection.find.bind(usersCollection), 'scope1', ['admin', 'manager']);
        test.isTrue(!result.includes(users.eve._id) &&
            result.includes(users.bob._id) &&
            !result.includes(users.joe._id));
        result = await (0, index_1.getUsersInRoles)(usersCollection.find.bind(usersCollection), 'scope1', ['supervisor']);
        test.isTrue(!result.includes(users.eve._id) &&
            !result.includes(users.bob._id) &&
            !result.includes(users.joe._id));
        result = await (0, index_1.getUsersInRoles)(usersCollection.find.bind(usersCollection), 'scope1', ['security']);
        test.isTrue(!result.includes(users.eve._id) &&
            !result.includes(users.bob._id) &&
            result.includes(users.joe._id));
    });
});
