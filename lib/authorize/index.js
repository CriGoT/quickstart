'use strict';

const _ = require('lodash');
const fs = require('fs');
const oauth2orize = require('oauth2orize');
const oidc_ext = require('oauth2orize-openid');
const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const ClientPasswordStrategy = require('passport-oauth2-client-password');
const BearerStrategy = require('passport-http-bearer');

const {users, codes, clients, tokens, grants} = require('../data');

const privateKey = fs.readFileSync(process.env.PRIVATE_KEY_FILE || 'keys/private.pem');

const lifetime = process.env.TOKEN_LIFETIME || (24 * 3600 * 1000); // 1 day

const mustBeAuthenticated = (req, res, next) => {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    req.session.returnTo = req.originalUrl || req.url;
    return res.redirect('/login');
  }
  next();
}

const mapUserProfile = (user, scopes) => {
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

    return _.pick({
        ...user,
        sub: user._id.toString(),
        preferred_username: user.username
      }, [...properties]);
  } else {
    return null;
  }
};

const getCodeHash = code => {
  const hash = crypto.createHash('sha256');
  hash.update(code, 'ascii');
  const buffer = hash.digest();
  return buffer
    .slice(0, buffer.length /2)
    .toString('base64')
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

passport.use(new ClientPasswordStrategy(async (id, secret, done) => {
  try {
    const client = await clients.load(id);
    done(null, client && client.secret === secret && client);
  } catch (e) {
    done(e);
  }
}));


passport.use(new BearerStrategy(async (token, done) => {
  try {
    const payload = await tokens.load(token);
    if (!payload) return done(null, false);

    const user = await  users.load(payload.user);
    done(null, user, payload);
  } catch (e) {
    done(e);
  }
}));
const server = oauth2orize.createServer();

const issueAuthorizationCode = async (client, redirectUri, user, res, req, done) => {
  try {
    if (req.scope) {
      await grants.save(user._id, client._id, req.scope);
    }
    const code = await codes.create({
      clientID: client._id,
      redirectUri,
      user: user.username,
      audience: req.audience,
      scope: req.scope
    });
    done(null, code);
  } catch(e) {
    done(e);
  }
};

server.grant(oauth2orize.grant.code(issueAuthorizationCode));

server.grant(oidc_ext.grant.codeIdToken(
  issueAuthorizationCode,
  (client, user, res, req, code, done) => {
    const payload = mapUserProfile(user, req.scope);
    const id_token = jwt.sign({
        ...payload,
        nonce: req.nonce,
        c_hash: getCodeHash(code.authorizationCode)
      },
      privateKey,
      {
        algorithm: 'RS256',
        audience: client._id,
        expiresIn: lifetime / 1000,
      });
    done(null, id_token);
  }
));

server.exchange(oauth2orize.exchange.code(async (client, code, redirectUri, done) => {
  try {
    const payload = await codes.loadAndRemove(code);
    if (!payload) return done(new Error('Invalid authorization code'));

    if (client._id !== payload.clientID ||
        redirectUri !== payload.redirectUri) return done(new Error('Invalid authorization code'));

    const token = tokens.create(payload, Date.now() + lifetime)
    done(null, token, {scope: payload.scope});
  } catch(e) {
    done(e);
  }
}));


server.serializeClient((client, done) => done(null, client._id));

server.deserializeClient(async (id, done) => {
  try {
    const client = await clients.load(id);
    done(null, client);
  } catch(e) {
    done(e);
  }
});

const router = new express.Router();

router.use('/login',
  mustBeAuthenticated,
  server.authorize(async (cid, redirectUri, done) => {
    try {
      const client = await clients.load(cid)
      if (!client) return done(null, false);
      done(null, client.redirectUri === redirectUri && client, client.redirectUri);
    } catch(e) {
      done(e);
    }
  }),
  async (req, res, next) => {
    try {
      if (!req.oauth2 || !req.oauth2.req || !req.oauth2.req.scope || !req.oauth2.req.scope.length === 0) return next();
      const grant = await grants.load(req.user._id, req.oauth2.client._id);
      if (grant && _.difference(req.oauth2.req.scope, grant.scope).length === 0) return next();
    } catch(e) {
    }
    res.render('consent', { client: req.oauth2.client, scopes: req.oauth2.req.scope, tid: req.oauth2.transactionID });
  },
  server.decision());

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

    const user = mapUserProfile(req.user, req.authInfo.scope || []);
    if (user) {
      res.send(user);
    } else {
      res.set({
        'WWW-Authenticate' : 'error="insuficient_scope", error_description="The access token does not have the required scopes"'
      });
      res.sendStatus(403);
    }
  });
module.exports = router;
