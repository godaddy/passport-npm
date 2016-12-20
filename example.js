#!/usr/bin/env node

const passport = require('passport');
const { NPMStrategy, NPMStrategyErrorHandler } = require('./');
const router = require('express')();
const sessions = Object.create(null);
let sessionId = 1;

function authenticate(id, password, done) {
  console.log(`User ${id} trying to log in`);
  if (id === 'user' && password === 'pass') {
    done(null, {
      id
    });
    return;
  }
  done(null, false);
}
function serializeNPMToken(id, pass, done) {
  const SID = sessionId++;
  console.log(`Saving Session for ${id} as SID: ${SID}`);
  sessions[SID] = {user:{id}, time:Date.now()};
  done(null, SID);
}
function deserializeNPMToken(SID, done) {
  console.log(`Session ${SID} reviving.`)
  if (!(SID in sessions)) {
    done(new Error('Unknown session'));
    return;
  }
  const session = sessions[SID];
  // only keep session valid for 10 seconds
  const TTL = 10 * 1000 - (Date.now() - session.time);
  console.log(`Session ${SID} TTL: ${TTL}`)
  if (TTL < 0) {
    const err = new Error('Session has expired, login again');
    // this may not show a msg telling client login due to `npm` cli logic
    err.status = 401;
    done(err);
    return;
  }
  done(null, session.user);
}

passport.use(new NPMStrategy({
  router,
  authenticate,
  serializeNPMToken,
  deserializeNPMToken
}));
router.use(
  (req, res, next) => {
    console.error(req.method, req.url);
    next(null);
  },
  passport.initialize(),
  passport.authenticate('npm', {
    // npm client doesn't have compatible sessions with PassportJS
    // - does not use a cookie
    // - uses bearer tokens and basic auth via HTTP authorization header
    session: false,
    // npm client doesn't have compatible response parsing with PassportJS
    failWithError: true
  }),
  NPMStrategyErrorHandler,
  (req, res) => {
    console.log(`authenticated as ${req.user.id}`)
    res.end(`{}`);
  }
);
const server = require('http').createServer(router);
server.listen(process.env.PORT || 8080, (err) => {
  if (err) {
    console.error(err);
    return;
  }
  console.log('npm login proxy started on port', server.address().port);
})
