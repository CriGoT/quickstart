'use strict';

const utils = require('../utils');
const getDb = require('./getDb');

const collectionName = 'tokens';

const load = async (token) => {
  const db = await getDb();
  const result = await db.collection(collectionName).findOne({ _id: token });

  return result && result.expiration > Date.now() && result.payload;
}

const create = async (payload, expiration) => {
  const db = await getDb();
  const result = await db.collection(collectionName).insertOne({ _id: utils.uuid(), expiration, payload });

  if (result.insertedCount < 1) throw new Error('Token could not be created');

  return result.ops[0]._id.toString();
};


module.exports = {
  load,
  create,
}
