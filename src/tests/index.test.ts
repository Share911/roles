import assert from 'assert'
import _ from 'underscore'
import {
  Collection,
  Db,
  Document,
  Filter,
  FindCursor,
  FindOptions,
  MongoClient,
  UpdateFilter,
  UpdateOptions,
  UpdateResult,
} from 'mongodb'
import crypto from 'crypto'
import {
  GLOBAL_SCOPE,
  RolesUser,
  addUsersToRoles,
  getRolesForUser,
  getUsersInRoles,
  removeUsersFromRoles,
  removeUsersFromScope,
  setUserRoles,
  userIsInRole,
} from '../index'

const test = {
  equal(actual:any , expected: any, message?: string) {
    return assert.deepEqual(actual, expected, message)
  },
  isTrue(actual:any, message?:string) {
    return assert.equal(actual, true, message)
  },
  isFalse(actual:any, message?:string) {
    return assert.equal(actual, false, message)
  }
}

type User = RolesUser & {
  _id: string,
  username: string,
  createdAt: Date
}

type Users = {
  [key: string]: User
}

describe('roles', function () {
  let db: Db, usersCollection:Collection<User>, client: MongoClient
  let findOne: <T extends User> (filter: Filter<T>, findOptions?: FindOptions) => Promise<T | null> 
  let updateMany: <T extends User> (filter: Filter<T>, update: UpdateFilter<T>, options?: UpdateOptions) => Promise<Document | UpdateResult>

  let users: Users = {},
    userRoles = ['admin','editor','user']

  before(async function () {
    client = await MongoClient.connect('mongodb://localhost:27017/roles-npm')
    db = client.db()
    usersCollection = db.collection<User>('users')
    findOne = usersCollection.findOne.bind(usersCollection)
    // @ts-ignore - allow assignment, some internal comparison Date vs Timestamp
    updateMany = usersCollection.updateMany.bind(usersCollection)
  })

  after(async function () {
    await client.close()
  })

  async function addUser (name: string) {
    const user: User = {
      _id: crypto.randomUUID(),
      username: name,
      createdAt: new Date(),
      roles: []
    }
    return usersCollection.insertOne(user)
  }

  async function reset () {
    await usersCollection.deleteMany({})

    await addUser('eve')
    await addUser('bob')
    await addUser('joe')
    users.eve = await findOne({username: 'eve'}) as User
    users.bob = await findOne({username: 'bob'}) as User
    users.joe = await findOne({username: 'joe'}) as User
  }

  async function testUser(username: string, expectedRoles: string[], group?: string) {
    const userId = users[username]._id,
      userObj = await findOne({_id: userId}) as User

    // check using passed-in user object
    await _innerTest(userObj, username, expectedRoles, group)
  }

  async function _innerTest (userParam:User, username:string, expectedRoles: string[], group ?: string) {
    // test that user has only the roles expected and no others
    for (let role of userRoles) {
      var expected = _.contains(expectedRoles, role),
        msg = username + ' expected to have \'' + role + '\' permission but does not',
        nmsg = username + ' had the following un-expected permission: ' + role

      if (expected) {
        test.isTrue(userIsInRole(userParam, role, group), msg)
      } else {
        test.isFalse(userIsInRole(userParam, role, group), nmsg)
      }
    }
  }

  it('can check if user is in role', async function () {
      await reset()

      await usersCollection.updateOne(
        { '_id' :users.eve._id },
        { $set : {
            roles: [
              {
                scope: 'scope',
                permissions: ['admin', 'user']
              }
            ]
          }
        }
      )
      await testUser('eve', ['admin', 'user'])
    })

  it('can check if user is in role by group', async function () {
      await reset()

      await usersCollection.updateOne(
        { _id:users.eve._id },
        { $push: { roles: {scope: 'group1', permissions: ['admin', 'user']} } })
      await usersCollection.updateOne(
        { _id:users.eve._id },
        { $push: { roles: {scope: 'group2', permissions: ['editor'] }} })


      await testUser('eve', ['admin', 'user'], 'group1')
      await testUser('eve', ['editor'], 'group2')
    })


  it('can check if null user is in role', async function () {
      const user = null as unknown as User
      await reset()

      test.isFalse(userIsInRole(user, 'admin'))
    })

  it('can check user against several roles at once', async function () {
      let user
      await reset()

      await addUsersToRoles(updateMany, users.eve._id, ['admin', 'user'], 'scope1')
      user = await findOne({_id:users.eve._id}) as User

      test.isTrue(userIsInRole(user, ['editor','admin']))
    })

  it('can\'t add non-existent user to role', async function () {
      await reset()

      await addUsersToRoles(updateMany, ['1'], ['admin'], 'scope1')
      test.equal(await findOne({_id:'1'}), undefined)
    })

  it('can add individual users to roles', async function () {
      await reset()

      await addUsersToRoles(updateMany, users.eve._id, ['admin', 'user'], 'scope1')

      await testUser('eve', ['admin', 'user'])
      await testUser('bob', [])
      await testUser('joe', [])

      await addUsersToRoles(updateMany, users.joe._id, ['editor', 'user'], 'scope1')

      await testUser('eve', ['admin', 'user'])
      await testUser('bob', [])
      await testUser('joe', ['editor', 'user'])
    })

  it('can add individual users to roles by group', async function () {
      await reset()

      await addUsersToRoles(updateMany, users.eve._id, ['admin', 'user'], 'group1')

      await testUser('eve', ['admin', 'user'], 'group1')
      await testUser('bob', [], 'group1')
      await testUser('joe', [], 'group1')

      await testUser('eve', [], 'group2')
      await testUser('bob', [], 'group2')
      await testUser('joe', [], 'group2')

      await addUsersToRoles(updateMany, users.joe._id, ['editor', 'user'], 'group1')
      await addUsersToRoles(updateMany, users.bob._id, ['editor', 'user'], 'group2')

      await testUser('eve', ['admin', 'user'], 'group1')
      await testUser('bob', [], 'group1')
      await testUser('joe', ['editor', 'user'], 'group1')

      await testUser('eve', [], 'group2')
      await testUser('bob', ['editor', 'user'], 'group2')
      await testUser('joe', [], 'group2')
    })

  it('can add user to roles via user object', async function () {
      await reset()

      await addUsersToRoles(updateMany, users.eve._id, ['admin', 'user'], 'scope1')

      await testUser('eve', ['admin', 'user'])
      await testUser('bob', [])
      await testUser('joe', [])

      await addUsersToRoles(updateMany, users.bob._id, ['editor'], 'scope2')

      await testUser('eve', ['admin', 'user'])
      await testUser('bob', ['editor'])
      await testUser('joe', [])
    })

  it('can add user to roles multiple times', async function () {
      await reset()

      await addUsersToRoles(updateMany, users.eve._id, ['admin', 'user'], 'scope1')
      await addUsersToRoles(updateMany, users.eve._id, ['admin', 'user'], 'scope1')

      await testUser('eve', ['admin', 'user'])
      await testUser('bob', [])
      await testUser('joe', [])

      await addUsersToRoles(updateMany, users.bob._id, ['admin'], 'scope1')
      await addUsersToRoles(updateMany, users.bob._id, ['editor'], 'scope1')

      await testUser('eve', ['admin', 'user'])
      await testUser('bob', ['admin', 'editor'])
      await testUser('joe', [])
    })

  it('can add user to roles multiple times by group', async function () {
      await reset()

      await addUsersToRoles(updateMany, users.eve._id, ['admin', 'user'], 'group1')
      await addUsersToRoles(updateMany, users.eve._id, ['admin', 'user'], 'group1')

      await testUser('eve', ['admin', 'user'], 'group1')
      await testUser('bob', [], 'group1')
      await testUser('joe', [], 'group1')

      await addUsersToRoles(updateMany, users.bob._id, ['admin'], 'group1')
      await addUsersToRoles(updateMany, users.bob._id, ['editor'], 'group1')

      await testUser('eve', ['admin', 'user'], 'group1')
      await testUser('bob', ['admin', 'editor'], 'group1')
      await testUser('joe', [], 'group1')
    })

  it('can add multiple users to roles', async function () {
      await reset()

      await addUsersToRoles(updateMany, [users.eve._id, users.bob._id], ['admin', 'user'], 'scope1')

      await testUser('eve', ['admin', 'user'])
      await testUser('bob', ['admin', 'user'])
      await testUser('joe', [])

      await addUsersToRoles(updateMany, [users.bob._id, users.joe._id], ['editor', 'user'], 'scope1')

      await testUser('eve', ['admin', 'user'])
      await testUser('bob', ['admin', 'editor', 'user'])
      await testUser('joe', ['editor', 'user'])
    })

  it('can add multiple users to roles by group', async function () {
      await reset()

      await addUsersToRoles(updateMany, [users.eve._id, users.bob._id], ['admin', 'user'], 'group1')

      await testUser('eve', ['admin', 'user'], 'group1')
      await testUser('bob', ['admin', 'user'], 'group1')
      await testUser('joe', [], 'group1')

      await testUser('eve', [], 'group2')
      await testUser('bob', [], 'group2')
      await testUser('joe', [], 'group2')

      await addUsersToRoles(updateMany, [users.bob._id, users.joe._id], ['editor', 'user'], 'group1')
      await addUsersToRoles(updateMany, [users.bob._id, users.joe._id], ['editor', 'user'], 'group2')

      await testUser('eve', ['admin', 'user'], 'group1')
      await testUser('bob', ['admin', 'editor', 'user'], 'group1')
      await testUser('joe', ['editor', 'user'], 'group1')

      await testUser('eve', [], 'group2')
      await testUser('bob', ['editor', 'user'], 'group2')
      await testUser('joe', ['editor', 'user'], 'group2')
    })

  it('can remove individual users from roles', async function () {
      await reset()

      // remove user role - one user
      await addUsersToRoles(updateMany, [users.eve._id, users.bob._id], ['editor', 'user'], 'scope1')
      await testUser('eve', ['editor', 'user'])
      await testUser('bob', ['editor', 'user'])
      await removeUsersFromRoles(updateMany, users.eve._id, ['user'], 'scope1')
      await testUser('eve', ['editor'])
      await testUser('bob', ['editor', 'user'])
    })
  it('can remove user from roles multiple times', async function () {
      await reset()

      // remove user role - one user
      await addUsersToRoles(updateMany, [users.eve._id, users.bob._id], ['editor', 'user'], 'scope1')
      await testUser('eve', ['editor', 'user'])
      await testUser('bob', ['editor', 'user'])
      await removeUsersFromRoles(updateMany, users.eve._id, ['user'], 'scope1')
      await testUser('eve', ['editor'])
      await testUser('bob', ['editor', 'user'])

      // try remove again
      await removeUsersFromRoles(updateMany, users.eve._id, ['user'], 'scope1')
      await testUser('eve', ['editor'])
    })

  it('can remove individual users from roles by group', async function () {
      await reset()

      // remove user role - one user
      await addUsersToRoles(updateMany, [users.eve._id, users.bob._id], ['editor', 'user'], 'group1')
      await addUsersToRoles(updateMany, [users.joe._id, users.bob._id], ['admin'], 'group2')
      await testUser('eve', ['editor', 'user'], 'group1')
      await testUser('bob', ['editor', 'user'], 'group1')
      await testUser('joe', [], 'group1')
      await testUser('eve', [], 'group2')
      await testUser('bob', ['admin'], 'group2')
      await testUser('joe', ['admin'], 'group2')

      await removeUsersFromRoles(updateMany, users.eve._id, ['user'], 'group1')
      await testUser('eve', ['editor'], 'group1')
      await testUser('bob', ['editor', 'user'], 'group1')
      await testUser('joe', [], 'group1')
      await testUser('eve', [], 'group2')
      await testUser('bob', ['admin'], 'group2')
      await testUser('joe', ['admin'], 'group2')
    })

  it('can remove multiple users from roles', async function () {
      await reset()

      // remove user role - two users
      await addUsersToRoles(updateMany, [users.eve._id, users.bob._id], ['editor', 'user'], 'scope1')
      await testUser('eve', ['editor', 'user'])
      await testUser('bob', ['editor', 'user'])

      test.isFalse(userIsInRole(users.joe, 'admin'))
      await addUsersToRoles(updateMany, [users.bob._id, users.joe._id], ['admin', 'user'], 'scope1')
      await testUser('bob', ['admin', 'user', 'editor'])
      await testUser('joe', ['admin', 'user'])
      await removeUsersFromRoles(updateMany, [users.bob._id, users.joe._id], ['admin'], 'scope1')
      await testUser('bob', ['user', 'editor'])
      await testUser('joe', ['user'])
    })

  it('can remove multiple users from roles by group', async function () {
      await reset()

      // remove user role - one user
      await addUsersToRoles(updateMany, [users.eve._id, users.bob._id], ['editor', 'user'], 'group1')
      await addUsersToRoles(updateMany, [users.joe._id, users.bob._id], ['admin'], 'group2')
      await testUser('eve', ['editor', 'user'], 'group1')
      await testUser('bob', ['editor', 'user'], 'group1')
      await testUser('joe', [], 'group1')
      await testUser('eve', [], 'group2')
      await testUser('bob', ['admin'], 'group2')
      await testUser('joe', ['admin'], 'group2')

      await removeUsersFromRoles(updateMany, [users.eve._id, users.bob._id], ['user'], 'group1')
      await testUser('eve', ['editor'], 'group1')
      await testUser('bob', ['editor'], 'group1')
      await testUser('joe', [], 'group1')
      await testUser('eve', [], 'group2')
      await testUser('bob', ['admin'], 'group2')
      await testUser('joe', ['admin'], 'group2')

      await removeUsersFromRoles(updateMany, [users.joe._id, users.bob._id], ['admin'], 'group2')
      await testUser('eve', [], 'group2')
      await testUser('bob', [], 'group2')
      await testUser('joe', [], 'group2')
    })

  it('can set user roles', async function () {
      await reset()

      await setUserRoles(updateMany, [users.eve._id, users.bob._id], ['editor', 'user'], 'scope1')
      await testUser('eve', ['editor', 'user'])
      await testUser('bob', ['editor', 'user'])
      await testUser('joe', [])

      // use addUsersToRoles add some roles
      await addUsersToRoles(updateMany, [users.bob._id, users.joe._id], ['admin'], 'scope1')
      await testUser('eve', ['editor', 'user'])
      await testUser('bob', ['admin', 'editor', 'user'])
      await testUser('joe', ['admin'])

      await setUserRoles(updateMany, [users.eve._id, users.bob._id], ['user'], 'scope1')
      await testUser('eve', ['user'])
      await testUser('bob', ['user'])
      await testUser('joe', ['admin'])

      await setUserRoles(updateMany, users.bob._id, 'editor', 'scope1')
      await testUser('eve', ['user'])
      await testUser('bob', ['editor'])
      await testUser('joe', ['admin'])

      await setUserRoles(updateMany, [users.joe._id, users.bob._id], [], 'scope1')
      await testUser('eve', ['user'])
      await testUser('bob', [])
      await testUser('joe', [])
    })

  it('can set user roles by group', async function () {
      await reset()

      await setUserRoles(updateMany, [users.eve._id, users.bob._id], ['editor', 'user'], 'group1')
      await setUserRoles(updateMany, [users.bob._id, users.joe._id], ['admin'], 'group2')
      await testUser('eve', ['editor', 'user'], 'group1')
      await testUser('bob', ['editor', 'user'], 'group1')
      await testUser('joe', [], 'group1')
      await testUser('eve', [], 'group2')
      await testUser('bob', ['admin'], 'group2')
      await testUser('joe', ['admin'], 'group2')

      // use addUsersToRoles add some roles
      await addUsersToRoles(updateMany, [users.eve._id, users.bob._id], ['admin'], 'group1')
      await addUsersToRoles(updateMany, [users.bob._id, users.joe._id], ['editor'], 'group2')
      await testUser('eve', ['admin', 'editor', 'user'], 'group1')
      await testUser('bob', ['admin', 'editor', 'user'], 'group1')
      await testUser('joe', [], 'group1')
      await testUser('eve', [], 'group2')
      await testUser('bob', ['admin','editor'], 'group2')
      await testUser('joe', ['admin','editor'], 'group2')

      await setUserRoles(updateMany, [users.eve._id, users.bob._id], ['user'], 'group1')
      await setUserRoles(updateMany, [users.eve._id, users.joe._id], ['editor'], 'group2')
      await testUser('eve', ['user'], 'group1')
      await testUser('bob', ['user'], 'group1')
      await testUser('joe', [], 'group1')
      await testUser('eve', ['editor'], 'group2')
      await testUser('bob', ['admin','editor'], 'group2')
      await testUser('joe', ['editor'], 'group2')

      await setUserRoles(updateMany, users.bob._id, 'editor', 'group1')
      await testUser('eve', ['user'], 'group1')
      await testUser('bob', ['editor'], 'group1')
      await testUser('joe', [], 'group1')
      await testUser('eve', ['editor'], 'group2')
      await testUser('bob', ['admin','editor'], 'group2')
      await testUser('joe', ['editor'], 'group2')

      await setUserRoles(updateMany, [users.bob._id, users.joe._id], [], 'group1')
      await testUser('eve', ['user'], 'group1')
      await testUser('bob', [], 'group1')
      await testUser('joe', [], 'group1')
      await testUser('eve', ['editor'], 'group2')
      await testUser('bob', ['admin','editor'], 'group2')
      await testUser('joe', ['editor'], 'group2')
    })

  it('can set user roles by group including GLOBAL_GROUP', async function () {
      await reset()

      await addUsersToRoles(updateMany, users.eve._id, 'admin', GLOBAL_SCOPE)
      await testUser('eve', ['admin'], 'group1')
      await testUser('eve', ['admin'])

      await setUserRoles(updateMany, users.eve._id, 'editor', GLOBAL_SCOPE)
      await testUser('eve', ['editor'], 'group2')
      await testUser('eve', ['editor'])
    })

  it('can get roles for non-existant user', async function () {
      await reset()
      test.equal(await getRolesForUser({}), [])
      test.equal(await getRolesForUser({}, 'group1'), [])
    })

  it('can get all roles for user', async function () {
      await reset()

      const userId = users.eve._id
      let userObj

      userObj = await findOne({_id: userId}) as User
      test.equal(await getRolesForUser(userObj), [])

      await addUsersToRoles(updateMany, userId, ['admin', 'user'], 'scope1')

      // by user object
      userObj = await findOne({_id: userId}) as User
      test.equal(getRolesForUser(userObj, 'scope1'), ['admin', 'user'])
    })

  it('can get all roles for user by group', async function () {
      await reset()

      const userId = users.eve._id
      let userObj

      userObj = await findOne({_id: userId}) as User
      test.equal(await getRolesForUser(userObj, 'group1'), [])
      // add roles
      await addUsersToRoles(updateMany, userId, ['admin', 'user'], 'group1')

      userObj = await findOne({_id: userId}) as User
      test.equal(await getRolesForUser(userObj, 'group1'), ['admin', 'user'])
      test.equal(await getRolesForUser(userObj), [])
    })

  it('can get all roles for user by group with periods in name', async function () {
      await reset()

      await addUsersToRoles(updateMany, users.joe._id, ['admin'], 'example.k12.va.us')

      const userObj = await findOne({_id: users.joe._id}) as User
      test.equal(await getRolesForUser(userObj, 'example.k12.va.us'), ['admin'])
    })

  it('can get all roles for user by group including GLOBAL_SCOPE', async function () {
      await reset()

      const userId = users.eve._id
      let userObj

      await addUsersToRoles(updateMany, [userId], ['editor'], GLOBAL_SCOPE)
      await addUsersToRoles(updateMany, [userId], ['admin', 'user'], 'scope1')

      userObj = await findOne({_id: userId}) as User
      test.equal(getRolesForUser(userObj, 'scope1'), ['editor', 'admin', 'user'])
      test.equal(getRolesForUser(userObj), ['editor'])
    })


  it('getRolesForUser should not return null entries if user has no roles for group', async function () {
      await reset()

      const userId = users.eve._id
      let userObj

      userObj = await findOne({_id: userId}) as User
      test.equal(getRolesForUser(userObj, 'group1'), [])
      test.equal(getRolesForUser(userObj), [])

      await addUsersToRoles(updateMany, [users.eve._id], ['editor'], GLOBAL_SCOPE)

      userObj = await findOne({_id: userId}) as User
      test.equal(getRolesForUser(userObj, 'group1'), ['editor'])
      test.equal(getRolesForUser(userObj), ['editor'])
    })

  it('can use GLOBAL_SCOPE to assign blanket permissions', async function () {
      await reset()

      await addUsersToRoles(updateMany, [users.joe._id, users.bob._id], ['admin'], GLOBAL_SCOPE)

      await testUser('eve', [], 'group1')
      await testUser('joe', ['admin'], 'group2')
      await testUser('joe', ['admin'], 'group1')
      await testUser('bob', ['admin'], 'group2')
      await testUser('bob', ['admin'], 'group1')

      await removeUsersFromRoles(updateMany, users.joe._id, ['admin'], GLOBAL_SCOPE)

      await testUser('eve', [], 'group1')
      await testUser('joe', [], 'group2')
      await testUser('joe', [], 'group1')
      await testUser('bob', ['admin'], 'group2')
      await testUser('bob', ['admin'], 'group1')
    })

  it('GLOBAL_SCOPE is independent of other groups', async function () {
      await reset()

      await addUsersToRoles(updateMany, [users.joe._id, users.bob._id], ['admin'], 'group5')
      await addUsersToRoles(updateMany, [users.joe._id, users.bob._id], ['admin'], GLOBAL_SCOPE)

      await testUser('eve', [], 'group1')
      await testUser('joe', ['admin'], 'group5')
      await testUser('joe', ['admin'], 'group2')
      await testUser('joe', ['admin'], 'group1')
      await testUser('bob', ['admin'], 'group5')
      await testUser('bob', ['admin'], 'group2')
      await testUser('bob', ['admin'], 'group1')

      await removeUsersFromRoles(updateMany, users.joe._id, ['admin'], GLOBAL_SCOPE)

      await testUser('eve', [], 'group1')
      await testUser('joe', ['admin'], 'group5')
      await testUser('joe', [], 'group2')
      await testUser('joe', [], 'group1')
      await testUser('bob', ['admin'], 'group5')
      await testUser('bob', ['admin'], 'group2')
      await testUser('bob', ['admin'], 'group1')
    })

  it('GLOBAL_SCOPE is checked when group not specified', async function () {
      await reset()

      await addUsersToRoles(updateMany, users.joe._id, 'admin', GLOBAL_SCOPE)

      await testUser('joe', ['admin'])

      await removeUsersFromRoles(updateMany, users.joe._id, 'admin', GLOBAL_SCOPE)

      await testUser('joe', [])
    })

  it("can use '.' in group name", async function () {
      await reset()

      await addUsersToRoles(updateMany, users.joe._id, ['admin'], 'example.com')
      await testUser('joe', ['admin'], 'example.com')
    })

  it("can use multiple periods in group name", async function () {
      await reset()

      await addUsersToRoles(updateMany, users.joe._id, ['admin'], 'example.k12.va.us')
      await testUser('joe', ['admin'], 'example.k12.va.us')
    })

  it('scope name can start with $', async function () {
      await reset()
      await addUsersToRoles(updateMany, users.joe._id, ['admin'], '$scope')

      await reset()
      // should not throw error
      await addUsersToRoles(updateMany, users.bob._id, ['editor', 'user'], 'g$roup1')
    })

  it('userIsInRole returns false for unknown roles', async function () {
      await reset()

      await addUsersToRoles(updateMany, users.eve._id, ['admin', 'user'], 'scope1')
      await addUsersToRoles(updateMany, users.eve._id, ['editor'], 'scope2')

      test.isFalse(userIsInRole(users.eve, 'unknown'))
      test.isFalse(userIsInRole(users.eve, []))
    })

  it('can remove scope from user', async () => {
    await reset()

    await addUsersToRoles(updateMany, users.eve._id, ['admin', 'user'], 'scope1')
    await addUsersToRoles(updateMany, users.eve._id, ['admin', 'user'], 'scope2')

    await removeUsersFromScope(updateMany, users.eve._id, 'scope1')

    let userObj = await findOne({_id: users.eve._id}) as User

    test.isFalse(userIsInRole(userObj, ['admin', 'user'], 'scope1'))
    test.isTrue(userIsInRole(userObj, ['admin', 'user'], 'scope2'))

    await removeUsersFromScope(updateMany, users.eve._id, 'scope2')
    userObj = await findOne({_id: users.eve._id}) as User
    test.isFalse(userIsInRole(userObj, ['admin', 'user'], 'scope2'))
  })

  it('can remove scope from multiple users', async () => {
    await reset()

    await addUsersToRoles(updateMany, users.eve._id, ['admin', 'user'], 'scope1')
    await addUsersToRoles(updateMany, users.eve._id, ['admin', 'user'], 'scope2')
    await addUsersToRoles(updateMany, users.eve._id, ['admin', 'user'], 'scope3')

    await addUsersToRoles(updateMany, users.bob._id, ['admin', 'user'], 'scope1')
    await addUsersToRoles(updateMany, users.bob._id, ['admin', 'user'], 'scope2')
    await addUsersToRoles(updateMany, users.bob._id, ['admin', 'user'], 'scope3')

    await removeUsersFromScope(updateMany, [users.eve._id, users.bob._id], 'scope1')

    let eve = await findOne({_id: users.eve._id}) as User
    let bob = await findOne({_id: users.bob._id}) as User

    test.isFalse(userIsInRole(eve, ['admin', 'user'], 'scope1'))
    test.isTrue(userIsInRole(eve, ['admin', 'user'], 'scope2'))

    test.isFalse(userIsInRole(bob, ['admin', 'user'], 'scope1'))
    test.isTrue(userIsInRole(bob, ['admin', 'user'], 'scope2'))

    await removeUsersFromScope(updateMany, [users.eve._id, users.bob._id], ['scope1', 'scope2'])

    bob = await findOne({_id: users.bob._id}) as User
    eve = await findOne({_id: users.eve._id}) as User

    test.isFalse(userIsInRole(eve, ['admin', 'user'], 'scope2'))
    test.isFalse(userIsInRole(bob, ['admin', 'user'], 'scope2'))

    test.isTrue(userIsInRole(eve, ['admin', 'user'], 'scope3'))
    test.isTrue(userIsInRole(bob, ['admin', 'user'], 'scope3'))
  })

  it('get all users in given scope', async () => {
    await reset()

    await addUsersToRoles(updateMany, users.eve._id, ['admin', 'user'], 'scope1')
    await addUsersToRoles(updateMany, users.bob._id, ['admin', 'user', 'manager'], 'scope1')
    await addUsersToRoles(updateMany, users.joe._id, ['security'], 'scope1')

    let result: string[] = await getUsersInRoles(usersCollection.find.bind(usersCollection), 'scope1', 'admin')
    test.isTrue(
      result.includes(users.eve._id) &&
      result.includes(users.bob._id) &&
      !result.includes(users.joe._id)
    )

    result = await getUsersInRoles(usersCollection.find.bind(usersCollection), 'scope1', ['admin', 'manager'])
    test.isTrue(
      !result.includes(users.eve._id) &&
      result.includes(users.bob._id) &&
      !result.includes(users.joe._id)
    )

    result = await getUsersInRoles(usersCollection.find.bind(usersCollection), 'scope1', ['supervisor'])
    test.isTrue(
      !result.includes(users.eve._id) &&
      !result.includes(users.bob._id) &&
      !result.includes(users.joe._id)
    )

    result = await getUsersInRoles(usersCollection.find.bind(usersCollection), 'scope1', ['security'])
    test.isTrue(
      !result.includes(users.eve._id) &&
      !result.includes(users.bob._id) &&
      result.includes(users.joe._id)
    )
  })
})
