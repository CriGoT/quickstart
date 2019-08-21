'use strict';

const express = require('express');
const cookie = require('cookie-parser');
const body = require('body-parser');
const session = require('express-session');

const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const users = require('./lib/data/users');

const port = 3000;

const app = express();

const externalUserMapping = (profile, done) =>
  users.loadOrCreate(`${profile.provider}|${profile.id}`, {
    ...profile,
    name: profile.displayName,
    email: profile.emails && profile.emails.shift()
  }).then(user => done(null, user))
    .catch(done);

app.use(body.urlencoded({ extended: true }));
app.use(session({ secret: process.env.COOKIE_SECRET, resave: true }));
app.set('view engine', 'pug');
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy((username, password, done) =>
  users.verify(username, password)
    .then(user => done(null, user))
    .catch(err => done(null, false))
));

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    scope: 'profile',
    callbackURL: `http://localhost:${port}/callback/google`
  },
  (accessToken, refreshToken, profile, cb) => externalUserMapping(profile, cb)));

passport.serializeUser((user, done) => done(null, user.username))

passport.deserializeUser((id, done) =>
  users.load(id)
    .then(user => done(null, user))
    .catch(done)
)


app.get('/', (req, res) => res.render('home', { user: req.user}));
app.get('/login', (req, res) =>
  res.render(
    'login',
    {
      strategies: Object.keys(passport._strategies).map(s => passport._strategies[s].name).filter(s => s !=='local' && s!== 'session') }));
app.get('/login/:strategy', (req, res, next) =>
  passport.authenticate(
    req.params.strategy,
    {
      successRedirect: '/',
      failureRedirect: '/login',
    })(req, res, next));

app.use('/callback/:strategy', (req, res, next) =>
  passport.authenticate(
    req.params.strategy,
    {
      successRedirect: '/',
      failureRedirect: '/login',
    })(req, res, next));

app.post('/login', passport.authenticate(
  'local',
  {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
  }));

app.get('/register', (req, res) => res.render('register'));

app.post('/register', (req, res) => {
  const data = req.body;
  const messages = [];

  if (!data.username) messages.push('Username is required');

  if (!data.password) messages.push('Password is required');

  if (data.password !== data.confirm_password) messages.push('Password and confirmation do not match');

  if (messages.length > 0) return res.render('register', { messages });

  users.create(data.username, data.password, {
    email: data.email,
    name: data.name
  }).then(_ => res.redirect('/'))
    .catch(err => res.status(500).send(err));
});

app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
});

app.listen(port, () => console.log(`App listening on port ${port}!`));
