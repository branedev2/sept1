const https = require('https');
const tls = require('tls');
const fs = require('fs');
const http = require('http');
const crypto = require('crypto');
const express = require('express');
const request = require('request');
const axios = require('axios');
const fetch = require('node-fetch');

// True Positive Examples (Vulnerable Code)

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_1() {
  // Using deprecated/insecure TLS version
  const options = {
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.crt'),
    // ruleid: javascript-secure-tls-protocol
    secureProtocol: 'TLSv1_method' // Forces TLS 1.0 which is deprecated
  };
  
  https.createServer(options, (req, res) => {
    res.writeHead(200);
    res.end('Hello, world!');
  }).listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_2() {
  // Using insecure cipher suite
  const options = {
    key: fs.readFileSync('private-key.pem'),
    cert: fs.readFileSync('certificate.pem'),
    // ruleid: javascript-secure-tls-protocol
    ciphers: 'RC4-SHA:AES128-SHA' // RC4 is considered broken
  };
  
  const server = tls.createServer(options, (socket) => {
    socket.write('Welcome!\n');
    socket.pipe(socket);
  });
  
  server.listen(8443, () => {
    console.log('Server listening');
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_3() {
  // Setting minVersion too low
  const options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
    // ruleid: javascript-secure-tls-protocol
    minVersion: 'TLSv1' // TLS 1.0 is deprecated
  };
  
  https.createServer(options, (req, res) => {
    res.writeHead(200);
    res.end('Secure server');
  }).listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_4() {
  // Explicitly allowing insecure TLS renegotiation
  const options = {
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.crt'),
    // ruleid: javascript-secure-tls-protocol
    secureOptions: crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
  };
  
  const server = tls.createServer(options);
  server.listen(443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_5() {
  // Using weak DH parameters
  const options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
    // ruleid: javascript-secure-tls-protocol
    dhparam: fs.readFileSync('dh1024.pem') // 1024 bits is too weak
  };
  
  https.createServer(options, (req, res) => {
    res.writeHead(200);
    res.end('Hello');
  }).listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_6() {
  // Disabling certificate validation in HTTPS client
  const options = {
    hostname: 'example.com',
    port: 443,
    path: '/api/data',
    method: 'GET',
    // ruleid: javascript-secure-tls-protocol
    rejectUnauthorized: false // Disables certificate validation
  };
  
  const req = https.request(options, (res) => {
    console.log('statusCode:', res.statusCode);
  });
  
  req.end();
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_7() {
  // Using request library with insecure TLS
  // ruleid: javascript-secure-tls-protocol
  request.get({
    url: 'https://api.example.com/data',
    agentOptions: {
      secureProtocol: 'TLSv1_method' // Forces TLS 1.0
    }
  }, (error, response, body) => {
    console.log(body);
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_8() {
  // Using axios with insecure SSL configuration
  // ruleid: javascript-secure-tls-protocol
  axios.get('https://api.example.com', {
    httpsAgent: new https.Agent({
      rejectUnauthorized: false // Disables certificate validation
    })
  })
  .then(response => console.log(response.data))
  .catch(error => console.error(error));
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_9() {
  // Using node-fetch with insecure SSL
  const httpsAgent = new https.Agent({
    // ruleid: javascript-secure-tls-protocol
    secureOptions: crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT // Allows legacy insecure connections
  });
  
  fetch('https://api.example.com', { agent: httpsAgent })
    .then(response => response.json())
    .then(data => console.log(data));
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_10() {
  // Explicitly allowing weak ciphers
  const options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
    // ruleid: javascript-secure-tls-protocol
    ciphers: 'DEFAULT:!DH' // Excludes DH ciphers which can include strong options
  };
  
  https.createServer(options, (req, res) => {
    res.end('Hello World');
  }).listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_11() {
  // Using insecure ECDH curves
  const options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
    // ruleid: javascript-secure-tls-protocol
    ecdhCurve: 'secp160k1' // This curve is considered too weak
  };
  
  const server = tls.createServer(options);
  server.listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_12() {
  // Setting maxVersion too low
  const options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
    // ruleid: javascript-secure-tls-protocol
    maxVersion: 'TLSv1.1' // Limiting to TLS 1.1 which is deprecated
  };
  
  https.createServer(options, (req, res) => {
    res.end('Hello World');
  }).listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_13() {
  // Using weak cipher in client request
  const options = {
    hostname: 'api.example.com',
    port: 443,
    path: '/data',
    method: 'GET',
    // ruleid: javascript-secure-tls-protocol
    ciphers: 'AES128-GCM-SHA256:RC4-SHA' // Includes weak RC4 cipher
  };
  
  const req = https.request(options, (res) => {
    res.on('data', (d) => {
      process.stdout.write(d);
    });
  });
  
  req.end();
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_14() {
  // Explicitly disabling perfect forward secrecy
  const options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
    // ruleid: javascript-secure-tls-protocol
    secureOptions: crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
  };
  
  https.createServer(options, (req, res) => {
    res.end('Hello World');
  }).listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_15() {
  // Using insecure TLS settings with Express
  const app = express();
  
  const options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
    // ruleid: javascript-secure-tls-protocol
    honorCipherOrder: false, // Server doesn't control cipher selection priority
    ciphers: 'ALL' // Allows all ciphers including weak ones
  };
  
  https.createServer(options, app).listen(443);
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_1() {
  // Using secure TLS version
  const options = {
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.crt'),
    // ok: javascript-secure-tls-protocol
    minVersion: 'TLSv1.2' // TLS 1.2 is currently considered secure
  };
  
  https.createServer(options, (req, res) => {
    res.writeHead(200);
    res.end('Hello, world!');
  }).listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_2() {
  // Using secure cipher suites
  const options = {
    key: fs.readFileSync('private-key.pem'),
    cert: fs.readFileSync('certificate.pem'),
    // ok: javascript-secure-tls-protocol
    ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256'
  };
  
  const server = tls.createServer(options, (socket) => {
    socket.write('Welcome!\n');
    socket.pipe(socket);
  });
  
  server.listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_3() {
  // Setting appropriate TLS versions
  const options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
    // ok: javascript-secure-tls-protocol
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3'
  };
  
  https.createServer(options, (req, res) => {
    res.writeHead(200);
    res.end('Secure server');
  }).listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_4() {
  // Using secure options
  const options = {
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.crt'),
    // ok: javascript-secure-tls-protocol
    secureOptions: crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1
  };
  
  const server = tls.createServer(options);
  server.listen(443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_5() {
  // Using strong DH parameters
  const options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
    // ok: javascript-secure-tls-protocol
    dhparam: fs.readFileSync('dh4096.pem') // 4096 bits is strong
  };
  
  https.createServer(options, (req, res) => {
    res.writeHead(200);
    res.end('Hello');
  }).listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_6() {
  // Proper certificate validation in HTTPS client
  const options = {
    hostname: 'example.com',
    port: 443,
    path: '/api/data',
    method: 'GET',
    // ok: javascript-secure-tls-protocol
    rejectUnauthorized: true // Enables certificate validation (default)
  };
  
  const req = https.request(options, (res) => {
    console.log('statusCode:', res.statusCode);
  });
  
  req.end();
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_7() {
  // Using request library with secure TLS
  // ok: javascript-secure-tls-protocol
  request.get({
    url: 'https://api.example.com/data',
    agentOptions: {
      secureProtocol: 'TLSv1_2_method' // Forces TLS 1.2
    }
  }, (error, response, body) => {
    console.log(body);
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_8() {
  // Using axios with secure SSL configuration
  // ok: javascript-secure-tls-protocol
  axios.get('https://api.example.com', {
    httpsAgent: new https.Agent({
      rejectUnauthorized: true, // Enables certificate validation
      minVersion: 'TLSv1.2'
    })
  })
  .then(response => console.log(response.data))
  .catch(error => console.error(error));
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_9() {
  // Using node-fetch with secure SSL
  const httpsAgent = new https.Agent({
    // ok: javascript-secure-tls-protocol
    minVersion: 'TLSv1.2',
    honorCipherOrder: true
  });
  
  fetch('https://api.example.com', { agent: httpsAgent })
    .then(response => response.json())
    .then(data => console.log(data));
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_10() {
  // Using strong ciphers
  const options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
    // ok: javascript-secure-tls-protocol
    ciphers: 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384'
  };
  
  https.createServer(options, (req, res) => {
    res.end('Hello World');
  }).listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_11() {
  // Using secure ECDH curves
  const options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
    // ok: javascript-secure-tls-protocol
    ecdhCurve: 'prime256v1:secp384r1' // Strong curves
  };
  
  const server = tls.createServer(options);
  server.listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_12() {
  // Preferring server ciphers
  const options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
    // ok: javascript-secure-tls-protocol
    honorCipherOrder: true, // Server chooses the cipher based on its preferences
    ciphers: 'HIGH:!aNULL:!MD5:!RC4'
  };
  
  https.createServer(options, (req, res) => {
    res.end('Hello World');
  }).listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_13() {
  // Using secure client request options
  const options = {
    hostname: 'api.example.com',
    port: 443,
    path: '/data',
    method: 'GET',
    // ok: javascript-secure-tls-protocol
    minVersion: 'TLSv1.2',
    ciphers: 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256'
  };
  
  const req = https.request(options, (res) => {
    res.on('data', (d) => {
      process.stdout.write(d);
    });
  });
  
  req.end();
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_14() {
  // Enabling perfect forward secrecy
  const options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
    // ok: javascript-secure-tls-protocol
    ciphers: 'EECDH+AESGCM:EDH+AESGCM' // Ciphers that support PFS
  };
  
  https.createServer(options, (req, res) => {
    res.end('Hello World');
  }).listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_15() {
  // Using secure TLS settings with Express
  const app = express();
  
  const options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
    // ok: javascript-secure-tls-protocol
    minVersion: 'TLSv1.2',
    honorCipherOrder: true,
    ciphers: 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384'
  };
  
  https.createServer(options, app).listen(443);
}
// {/fact}