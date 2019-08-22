'use strict';

const utils = require('../utils');
const getDb = require('./getDb');

const collectionName = 'grants';

const load = async (uid, cid) => {
  const db = await getDb();
  const result = await db.collection(collectionName).findOne({ uid, cid });

  return result;
}

const save = async (uid, cid, scopes) => {
  const db = await getDb();
  const result = await db.collection(collectionName).findOneAndUpdate(
    { uid, cid },
    { $push: { scope: { $each: scopes }}},
    {returnOriginal: false, upsert: true});

  if (result.ok !== 1) throw new Error('Grant could not be saved');

  return result.value;
};


module.exports = {
  load,
  save,
}
