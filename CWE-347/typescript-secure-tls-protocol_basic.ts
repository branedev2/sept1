import * as https from 'https';
import * as tls from 'tls';
import * as fs from 'fs';
import * as crypto from 'crypto';
import * as constants from 'constants';
import { SecureContextOptions } from 'tls';

// True Positives (Vulnerable Code)

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_1() {
  const options = {
    key: fs.readFileSync('server-key.pem'),
    cert: fs.readFileSync('server-cert.pem'),
    // ruleid: typescript-secure-tls-protocol
    secureProtocol: 'SSLv3_method' // Using deprecated and insecure SSL v3
  };
  
  const server = https.createServer(options, (req, res) => {
    res.writeHead(200);
    res.end('Hello, world!');
  });
  
  server.listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_2() {
  const options = {
    key: fs.readFileSync('server-key.pem'),
    cert: fs.readFileSync('server-cert.pem'),
    // ruleid: typescript-secure-tls-protocol
    secureProtocol: 'TLSv1_method' // Using outdated TLS v1.0
  };
  
  const server = https.createServer(options, (req, res) => {
    res.writeHead(200);
    res.end('Hello, world!');
  });
  
  server.listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_3() {
  // ruleid: typescript-secure-tls-protocol
  const tlsSocket = tls.connect({
    host: 'example.com',
    port: 443,
    minVersion: 'TLSv1' // Allowing minimum TLS version 1.0 which is insecure
  });
  
  tlsSocket.on('secureConnect', () => {
    console.log('Connected securely');
    tlsSocket.write('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n');
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_4() {
  const options: https.ServerOptions = {
    key: fs.readFileSync('server-key.pem'),
    cert: fs.readFileSync('server-cert.pem'),
    // ruleid: typescript-secure-tls-protocol
    ciphers: 'RC4:HIGH:!MD5:!aNULL' // Including weak RC4 cipher
  };
  
  https.createServer(options, (req, res) => {
    res.writeHead(200);
    res.end('Hello, world!');
  }).listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_5() {
  const options: tls.TlsOptions = {
    host: 'example.com',
    port: 443,
    // ruleid: typescript-secure-tls-protocol
    secureProtocol: 'DTLSv1_method' // Using outdated DTLS v1.0
  };
  
  const socket = tls.connect(options, () => {
    console.log('Client connected');
    socket.write('Hello World!');
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_6() {
  // ruleid: typescript-secure-tls-protocol
  const httpsAgent = new https.Agent({
    secureOptions: constants.SSL_OP_NO_TLSv1_2 | constants.SSL_OP_NO_TLSv1_3, // Disabling secure TLS versions
    ciphers: 'AES128-GCM-SHA256:RC4:HIGH:!MD5:!aNULL'
  });
  
  https.get('https://example.com', { agent: httpsAgent }, (res) => {
    console.log('statusCode:', res.statusCode);
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_7() {
  const options: SecureContextOptions = {
    key: fs.readFileSync('server-key.pem'),
    cert: fs.readFileSync('server-cert.pem'),
    // ruleid: typescript-secure-tls-protocol
    secureOptions: constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION // Allowing unsafe legacy renegotiation
  };
  
  const server = tls.createServer(options, (socket) => {
    console.log('server connected', socket.authorized ? 'authorized' : 'unauthorized');
    socket.write('welcome!\n');
    socket.setEncoding('utf8');
    socket.pipe(socket);
  });
  
  server.listen(8443, () => {
    console.log('server bound');
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_8() {
  // ruleid: typescript-secure-tls-protocol
  const ctx = tls.createSecureContext({
    secureProtocol: 'TLSv1_1_method', // Using outdated TLS v1.1
    ciphers: 'ECDHE-RSA-AES128-SHA256:RC4:HIGH:!MD5:!aNULL'
  });
  
  const server = tls.createServer({
    secureContext: ctx
  }, (socket) => {
    socket.write('welcome!\n');
    socket.pipe(socket);
  });
  
  server.listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_9() {
  const options = {
    hostname: 'example.com',
    port: 443,
    path: '/',
    method: 'GET',
    // ruleid: typescript-secure-tls-protocol
    minVersion: 'TLSv1.1', // Using outdated TLS v1.1 as minimum version
    maxVersion: 'TLSv1.2'  // Not allowing TLS v1.3
  };
  
  const req = https.request(options, (res) => {
    console.log('statusCode:', res.statusCode);
  });
  
  req.end();
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_10() {
  // ruleid: typescript-secure-tls-protocol
  const options: crypto.constants.SecureOptions = 
    crypto.constants.SSL_OP_NO_TLSv1_2 | 
    crypto.constants.SSL_OP_NO_TLSv1_3 | 
    crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;
  
  const server = tls.createServer({
    key: fs.readFileSync('server-key.pem'),
    cert: fs.readFileSync('server-cert.pem'),
    secureOptions: options // Using insecure options
  });
  
  server.listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_11() {
  // ruleid: typescript-secure-tls-protocol
  const tlsSocket = tls.connect({
    host: 'example.com',
    port: 443,
    secureProtocol: 'TLSv1_2_method', // Explicitly using TLS 1.2 method instead of allowing auto-negotiation
    ciphers: 'ECDHE-RSA-AES128-SHA256:AES128-GCM-SHA256:RC4:HIGH:!MD5:!aNULL' // Including weak RC4 cipher
  });
  
  tlsSocket.on('data', (data) => {
    console.log(data.toString());
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_12() {
  const options = {
    // ruleid: typescript-secure-tls-protocol
    ciphers: 'DES-CBC3-SHA:ECDHE-RSA-AES128-SHA256', // Including weak 3DES cipher
    honorCipherOrder: true
  };
  
  const server = https.createServer({
    key: fs.readFileSync('server-key.pem'),
    cert: fs.readFileSync('server-cert.pem'),
    ...options
  });
  
  server.listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_13() {
  // ruleid: typescript-secure-tls-protocol
  const agent = new https.Agent({
    rejectUnauthorized: false // Disabling certificate validation
  });
  
  https.get('https://example.com', { agent }, (res) => {
    console.log('statusCode:', res.statusCode);
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_14() {
  // ruleid: typescript-secure-tls-protocol
  const options: tls.ConnectionOptions = {
    host: 'example.com',
    port: 443,
    checkServerIdentity: () => undefined // Bypassing hostname verification
  };
  
  const socket = tls.connect(options, () => {
    console.log('Connected');
    socket.write('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n');
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_15() {
  // ruleid: typescript-secure-tls-protocol
  const options = {
    key: fs.readFileSync('server-key.pem'),
    cert: fs.readFileSync('server-cert.pem'),
    ecdhCurve: 'prime256v1:secp384r1:secp521r1:sect283k1' // Including weak elliptic curves
  };
  
  const server = tls.createServer(options, (socket) => {
    socket.write('welcome!\n');
    socket.pipe(socket);
  });
  
  server.listen(8443);
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_1() {
  const options = {
    key: fs.readFileSync('server-key.pem'),
    cert: fs.readFileSync('server-cert.pem'),
    // ok: typescript-secure-tls-protocol
    minVersion: 'TLSv1.2' // Using secure TLS version 1.2 as minimum
  };
  
  const server = https.createServer(options, (req, res) => {
    res.writeHead(200);
    res.end('Hello, world!');
  });
  
  server.listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_2() {
  // ok: typescript-secure-tls-protocol
  const tlsSocket = tls.connect({
    host: 'example.com',
    port: 443,
    minVersion: 'TLSv1.2', // Using secure TLS version 1.2 as minimum
    maxVersion: 'TLSv1.3'  // Allowing TLS 1.3
  });
  
  tlsSocket.on('secureConnect', () => {
    console.log('Connected securely');
    tlsSocket.write('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n');
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_3() {
  const options: https.ServerOptions = {
    key: fs.readFileSync('server-key.pem'),
    cert: fs.readFileSync('server-cert.pem'),
    // ok: typescript-secure-tls-protocol
    ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384' // Strong ciphers only
  };
  
  https.createServer(options, (req, res) => {
    res.writeHead(200);
    res.end('Hello, world!');
  }).listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_4() {
  // ok: typescript-secure-tls-protocol
  const httpsAgent = new https.Agent({
    minVersion: 'TLSv1.2', // Using secure TLS version 1.2 as minimum
    maxVersion: 'TLSv1.3'  // Allowing TLS 1.3
  });
  
  https.get('https://example.com', { agent: httpsAgent }, (res) => {
    console.log('statusCode:', res.statusCode);
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_5() {
  const options: SecureContextOptions = {
    key: fs.readFileSync('server-key.pem'),
    cert: fs.readFileSync('server-cert.pem'),
    // ok: typescript-secure-tls-protocol
    minVersion: 'TLSv1.2', // Using secure TLS version 1.2 as minimum
    honorCipherOrder: true // Server chooses the cipher
  };
  
  const server = tls.createServer(options, (socket) => {
    console.log('server connected', socket.authorized ? 'authorized' : 'unauthorized');
    socket.write('welcome!\n');
    socket.setEncoding('utf8');
    socket.pipe(socket);
  });
  
  server.listen(8443, () => {
    console.log('server bound');
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_6() {
  // ok: typescript-secure-tls-protocol
  const ctx = tls.createSecureContext({
    minVersion: 'TLSv1.2', // Using secure TLS version 1.2 as minimum
    ciphers: 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384' // Strong ciphers only
  });
  
  const server = tls.createServer({
    secureContext: ctx
  }, (socket) => {
    socket.write('welcome!\n');
    socket.pipe(socket);
  });
  
  server.listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_7() {
  const options = {
    hostname: 'example.com',
    port: 443,
    path: '/',
    method: 'GET',
    // ok: typescript-secure-tls-protocol
    minVersion: 'TLSv1.2', // Using secure TLS version 1.2 as minimum
    maxVersion: 'TLSv1.3'  // Allowing TLS 1.3
  };
  
  const req = https.request(options, (res) => {
    console.log('statusCode:', res.statusCode);
  });
  
  req.end();
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_8() {
  // ok: typescript-secure-tls-protocol
  const options: crypto.constants.SecureOptions = 
    crypto.constants.SSL_OP_NO_SSLv2 | 
    crypto.constants.SSL_OP_NO_SSLv3 | 
    crypto.constants.SSL_OP_NO_TLSv1 | 
    crypto.constants.SSL_OP_NO_TLSv1_1; // Disabling insecure protocols
  
  const server = tls.createServer({
    key: fs.readFileSync('server-key.pem'),
    cert: fs.readFileSync('server-cert.pem'),
    secureOptions: options
  });
  
  server.listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_9() {
  // ok: typescript-secure-tls-protocol
  const tlsSocket = tls.connect({
    host: 'example.com',
    port: 443,
    minVersion: 'TLSv1.2', // Using secure TLS version 1.2 as minimum
    ciphers: 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384' // Strong ciphers only
  });
  
  tlsSocket.on('data', (data) => {
    console.log(data.toString());
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_10() {
  const options = {
    // ok: typescript-secure-tls-protocol
    ciphers: 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384', // Strong ciphers only
    honorCipherOrder: true
  };
  
  const server = https.createServer({
    key: fs.readFileSync('server-key.pem'),
    cert: fs.readFileSync('server-cert.pem'),
    ...options
  });
  
  server.listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_11() {
  // ok: typescript-secure-tls-protocol
  const agent = new https.Agent({
    rejectUnauthorized: true // Enabling certificate validation
  });
  
  https.get('https://example.com', { agent }, (res) => {
    console.log('statusCode:', res.statusCode);
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_12() {
  // ok: typescript-secure-tls-protocol
  const options: tls.ConnectionOptions = {
    host: 'example.com',
    port: 443,
    minVersion: 'TLSv1.2', // Using secure TLS version 1.2 as minimum
    rejectUnauthorized: true // Enabling certificate validation
  };
  
  const socket = tls.connect(options, () => {
    console.log('Connected');
    socket.write('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n');
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_13() {
  // ok: typescript-secure-tls-protocol
  const options = {
    key: fs.readFileSync('server-key.pem'),
    cert: fs.readFileSync('server-cert.pem'),
    ecdhCurve: 'prime256v1:secp384r1:secp521r1', // Using strong elliptic curves only
    minVersion: 'TLSv1.2' // Using secure TLS version 1.2 as minimum
  };
  
  const server = tls.createServer(options, (socket) => {
    socket.write('welcome!\n');
    socket.pipe(socket);
  });
  
  server.listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_14() {
  // ok: typescript-secure-tls-protocol
  const options: https.ServerOptions = {
    key: fs.readFileSync('server-key.pem'),
    cert: fs.readFileSync('server-cert.pem'),
    minVersion: 'TLSv1.3' // Using the most secure TLS version 1.3
  };
  
  const server = https.createServer(options, (req, res) => {
    res.writeHead(200);
    res.end('Hello, world!');
  });
  
  server.listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_15() {
  // ok: typescript-secure-tls-protocol
  const options = {
    host: 'example.com',
    port: 443,
    minVersion: 'TLSv1.2', // Using secure TLS version 1.2 as minimum
    ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384', // TLS 1.3 ciphers
    sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256' // Secure signature algorithms
  };
  
  const socket = tls.connect(options, () => {
    console.log('Connected securely');
    socket.write('Hello World!');
  });
}
// {/fact}