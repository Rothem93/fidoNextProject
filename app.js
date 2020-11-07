const express       = require('express');
const bodyParser    = require('body-parser');
const cookieSession = require('cookie-session');
const cookieParser  = require('cookie-parser');
const urllib        = require('url');
const path          = require('path');
const crypto        = require('crypto');
const fs            = require('fs');

const config        = require('./config.json');
const defaultroutes = require('./routes/default');
const passwordauth  = require('./routes/password');
const webuathnauth  = require('./routes/webauthn.js');

var http = require('http');
var https = require('https');
var privateKey  = fs.readFileSync('./sslcert/key.pem', 'utf8');
var certificate = fs.readFileSync('./sslcert/cert.pem', 'utf8');
var credentials = {key: privateKey, cert: certificate};
const app           = express();

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

const port = config.port || 3000;
const portHttps = config.portHttps || 3030

var http = http.createServer(app)
var httpsServer = https.createServer(credentials, app)

http.listen(port);
httpsServer.listen(portHttps);
console.log(`Started app on port ${port}`);
console.log(`Started app on port ${portHttps}`);

module.exports = app;
