'use strict';

const express = require('express');
const cookie = require('cookie-parser');
const body = require('body-parser');
const session = require('express-session');

const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

const users = require('./lib/data/users');


const app = express();

app.use(cookie());
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

passport.serializeUser((user, done) => done(null, user.username))

passport.deserializeUser((id, done) =>
  users.load(id)
    .then(user => done(null, user))
    .catch(err => done(err))
)

const port = 3000;

app.get('/', (req, res) => res.render('home', { user: req.user}));
app.get('/login', (req, res) => res.render('login'));

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
