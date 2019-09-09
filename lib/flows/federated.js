const passport = require('passport');

const FLOWNAME = 'federated';

const getCallbackUrl = req => `${req.protocol}://${req.hostname}:${req.socket.localPort}/callback/${(req.state || req.locals).strategy}`;

module.exports = flowManager =>
  flowManager.use(
    FLOWNAME,
    // Begin
    [
      (req, res, next) =>
        flowManager._store.save(
          req,
          {
            ...req.locals,
            name: FLOWNAME
          },
          (err, h) => {
            req.locals.handle = h;
            next(err);
          }),
      (req, res, next) =>
        passport.authenticate(
          req.locals.strategy,
          {
            state: req.locals.handle,
            callbackURL: getCallbackUrl(req)
          })(req, res, next)
    ],
    // Resume
    [
      (req, res, next) =>
        passport.authenticate(
          req.state.strategy,
          {
            successReturnToOrRedirect: '/',
            failureRedirect: '/login',
            callbackURL: getCallbackUrl(req)
          })(req, res, next),
    ])
