const { Manager, SessionStore } = require('flowstate');
const passport = require('passport');

const manager = new Manager(new SessionStore());

require('./federated')(manager);

module.exports = manager;
