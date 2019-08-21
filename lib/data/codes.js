'use strict';

const utils = require('../utils');
const getDb = require('./getDb');

const collectionName = 'authz_codes';

const loadAndRemove = async (code) => {
  const db = await getDb();
  const result = await db.collection(collectionName).findOneAndDelete({ _id: code });

  return result.value && result.value.payload;
}

const create = async (payload, expiration) => {
  const db = await getDb();
  const result = await db.collection(collectionName).insertOne({ _id: utils.uuid(), payload });

  if (result.insertedCount < 1) throw new Error('Code could not be created');

  return result.ops[0]._id.toString();
};


module.exports = {
  loadAndRemove,
  create,
}
