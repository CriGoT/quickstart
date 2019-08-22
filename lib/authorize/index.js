'use strict';

const _ = require('lodash');
const oauth2orize = require('oauth2orize');
const express = require('express');
const passport = require('passport');
const ClientPasswordStrategy = require('passport-oauth2-client-password');
const BearerStrategy = require('passport-http-bearer');

const {users, codes, clients, tokens, grants} = require('../data');

const lifetime = process.env.TOKEN_LIFETIME || (24 * 3600 * 1000); // 1 day

const mustBeAuthenticated = (req, res, next) => {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    req.session.returnTo = req.originalUrl || req.url;
    return res.redirect('/login');
  }
  next();
}

const mapUserProfile = (user, properties) => _.pick({
  ...user,
  sub: user._id,
  preferred_username: user.username
}, [...properties]);

passport.use(new ClientPasswordStrategy((id, secret, done) =>
  clients.load(id)
    .then(client => done(null, client && client.secret === secret && client))
    .catch(done)));


passport.use(new BearerStrategy((token, done) =>
  tokens.load(token)
    .then(payload => {
      if (!payload) return done(null, false);

      users.load(payload.user)
        .then(user => done(null, user, payload))
        .catch(done);
    })
    .catch(done)));

const server = oauth2orize.createServer();

server.grant(oauth2orize.grant.code((client, redirectUri, user, res, req, done) => {
  if (req.scope) {
    grants.save(user._id, client._id, req.scope);
  }
  codes.create({
    clientID: client._id,
    redirectUri,
    user: user.username,
    audience: req.audience,
    scope: req.scope
  }).then(code => done(null, code))
    .catch(done)
}));

server.exchange(oauth2orize.exchange.code((client, code, redirectUri, done) =>
  codes.loadAndRemove(code)
    .then(payload => {
      if (!payload) return done(new Error('Invalid authorization code'));

      if (client._id !== payload.clientID ||
          redirectUri !== payload.redirectUri) return done(new Error('Invalid authorization code'));

      tokens.create(payload, Date.now() + lifetime)
        .then(token => done(null, token, {scope: payload.scope}))
        .catch(done);
    })
    .catch(done)));

server.serializeClient((client, done) => done(null, client._id));

server.deserializeClient((id, done) =>
  clients.load(id)
    .then(client => done(null, client))
    .catch(done));

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
  (req, res, next) => {
    if (!req.oauth2 || !req.oauth2.req || !req.oauth2.req.scope || !req.oauth2.req.scope.length === 0) return next();
      grants.load(req.user._id, req.oauth2.client._id)
        .then(grant => {
          if (grant && _.difference(req.oauth2.req.scope, grant.scope).length === 0) return next();

          res.render('consent', { client: req.oauth2.client, scopes: req.oauth2.req.scope, tid: req.oauth2.transactionID });
        })
        .catch(_ => res.render('consent', { client: req.oauth2.client, scopes: req.oauth2.req.scope, tid: req.oauth2.transactionID}))
  },
  server.decision()
  );

router.post('/consent',
  mustBeAuthenticated,
  server.decision());

router.post('/token',
  passport.authenticate('oauth2-client-password', { session: false }),
  server.token(),
  server.errorHandler());

router.get('/userinfo',
  passport.authenticate('bearer', { session: false }),
  (req, res) => {
    if (!req.authInfo) return res.status(401);

    const scopes = req.authInfo.scope || [];

    if (scopes.includes('openid')) {
      const properties = new Set(['sub']);
      if (scopes.includes('profile')) {
        properties.add('name');
        properties.add('nickname');
        properties.add('preferred_username');
      }

      if (scopes.includes('email')) {
        properties.add('email');
      }

      res.send(mapUserProfile(req.user, properties));
    } else {
      res.set({
        'WWW-Authenticate' : 'error="insuficient_scope", error_description="The access token does not have the required scopes"'
      });
      res.sendStatus(403);
    }
  });
module.exports = router;
