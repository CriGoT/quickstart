const Client = require('mongodb').MongoClient;

const client = new Client(process.env.MONGODB_URL).connect();

module.exports = async() => (await client).db();
