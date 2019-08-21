'use strict';

const oauth2orize = require('oauth2orize');
const express = require('express');
const passport = require('passport');
const ClientPasswordStrategy = require('passport-oauth2-client-password');

const {codes, clients, tokens} = require('../data');

const lifetime = process.env.TOKEN_LIFETIME || (24 * 3600 * 1000); // 1 day

const mustBeAuthenticated = (req, res, next) => {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    req.session.returnTo = req.originalUrl || req.url;
    return res.redirect('/login');
  }
  next();
}


passport.use(new ClientPasswordStrategy((id, secret, done) =>
  clients.load(id)
    .then(client => done(null, client && client.secret === secret && client))
    .catch(done)));

const server = oauth2orize.createServer();

server.grant(oauth2orize.grant.code((client, redirectUri, user, ares, done) =>
  codes.create({
    clientID: client._id,
    redirectUri,
    user: user.username,
    audience: ares.audience,
    scope: ares.scope
  }).then(code => done(null, code))
    .catch(done)));

server.exchange(oauth2orize.exchange.code((client, code, redirectUri, done) =>
  codes.loadAndRemove(code)
    .then(payload => {
      if (!payload) return done(new Error('Invalid authorization code'));

      if (client._id !== payload.clientID ||
          redirectUri !== payload.redirectUri) return done(new Error('Invalid authorization code'));

      tokens.create(payload, Date.now() + lifetime)
        .then(token => done(null, token))
        .catch(done);
    })
    .catch(done)));

server.serializeClient((client, done) => done(null, client._id));

server.deserializeClient((id, done) => {
  clients.load(id)
    .then(client => done(null, client))
    .catch(done)
    if (err) { return done(err); }
    return done(null, client);
  });

const router = new express.Router();

router.use('/login',
  mustBeAuthenticated,
  server.authorize((cid, redirectUri, done) => {
    clients.load(cid)
      .then(client => {
        if (!client) return done(null, false);

        done(null, client.redirectUri === redirectUri && client, client.redirectUri);
      })
      .catch(done);
  }),
  server.decision()
  );

router.post('/token',
  passport.authenticate('oauth2-client-password', { session: false }),
  server.token(),
  server.errorHandler());

module.exports = router;
