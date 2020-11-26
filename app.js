const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors')

const cookieSession = require('cookie-session');
const cookieParser = require('cookie-parser');
const urllib = require('url');
const path = require('path');
const crypto = require('crypto');

const config = require('./config.json');
const defaultroutes = require('./routes/default');
const passwordauth = require('./routes/password');
const webuathnauth = require('./routes/webauthn.js');

const app = express();
app.use(cors({ origin: [config.origin], credentials: true }))

app.use(bodyParser.json());

/* ----- session ----- */
app.use(cookieSession({
    name: 'session',
    keys: [crypto.randomBytes(32).toString('hex')],

    // Cookie Options
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
}))
app.use(cookieParser())

/* ----- serve static ----- */
app.use(express.static(path.join(__dirname, 'static')));
app.use('/', defaultroutes)
app.use('/password', passwordauth)
app.use('/webauthn', webuathnauth)

const PORT = process.env.PORT || 5000
app.listen(PORT);
console.log(`Started app on port ${PORT}`);

module.exports = app;