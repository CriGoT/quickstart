const express = require('express');
const passport = require('passport');

const cookie = require('cookie-parser');
const body = require('body-parser');
const session = require('express-session');

const app = express();

app.use(cookie());
app.use(body.urlencoded({ extended: true }));
app.use(session({ secret: process.env.COOKIE_SECRET, resave: true }));

const port = 3000;

app.get('/', (req, res) => res.send('Hello World!'))

app.listen(port, () => console.log(`Example app listening on port ${port}!`))
