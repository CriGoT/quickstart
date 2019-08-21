'use strict';

const utils = require('../utils');
const getDb = require('./getDb');

const collectionName = 'clients';

const load = async (clientID) => {
  const db = await getDb();
  const result = await db.collection(collectionName).findOne({ _id: clientID });

  return result;
}

module.exports = {
  load,
}
