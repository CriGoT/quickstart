const _ = require('lodash');
const Client = require('mongodb').MongoClient;

const passwordManager = require('../password');

const WHITELISTED_FIELDS = [ 'username', '_id', 'email', 'name' ];

const client = new Client(process.env.MONGODB_URL).connect();
const collectionName = process.env.MONGODB_COLLECTION_NAME || 'users';

const getDb = async() => (await client).db();

const load = async (username) => {
  const db = await getDb();
  const user = await db.collection(collectionName).findOne({ username });

  return user && _.pick(user, WHITELISTED_FIELDS);
}

const verify = async (username, password) => {
  const db = await getDb();
  const user = await db.collection(collectionName).findOne({ username });

  if (!user) {
    console.log(`User ${username} not found`);
    return false;
  }

  const match = await passwordManager.compare(user.password, password);

  if (!match) console.log(`Invalid password for ${username}`);

  return match && _.pick(user, WHITELISTED_FIELDS);
}

const save = async (username, profile) => {
  if (profile.password) throw new Error('You shoudl use changePassword to update a user password');

  const db = await getDb();
  const result = await db.collection(collectionName).findOneAndUpdate(
    { username },
    { $set: profile },
    { returnOriginal: false });

  if (result.ok !== 1) throw new Error('User not created');

  return _.pick(result.value, WHITELISTED_FIELDS);
}

const create = async (username, password, profile) => {
  const db = await getDb();
  const result = await db.collection(collectionName).insertOne({
    ...profile,
    _id: username,
    username: username,
    password: await passwordManager.hash(password)
  });

  if (result.insertedCount < 1) throw new Error('User not created');

  return _.pick(result.ops[0], WHITELISTED_FIELDS);
};

const loadOrCreate = async(username, profile) => {
  const db = await getDb();
  const result = await db.collection(collectionName).findOneAndUpdate(
    { username },
    { $set: { ...profile, username } },
    { returnOriginal: false, upsert: true });

  if (result.ok !== 1) throw new Error('User not created');

  return _.pick(result.value, WHITELISTED_FIELDS);
};

const changePassword = async (username, newPassword) => {
  const db = await getDb();
  const result = await db.collection(collectionName).findOneAndUpdate(
    { username },
    { $set: { password: await passwordManager.hash(newPassword) } },
    { returnOriginal: false });

  if (result.ok === 1) throw new Error('User not found');
}

module.exports = {
  verify,
  load,
  save,
  create,
  changePassword,
  loadOrCreate
}
