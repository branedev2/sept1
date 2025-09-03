// File: tls_cipher_test_cases.js
const https = require('https');
const tls = require('tls');
const fs = require('fs');
const crypto = require('crypto');
const constants = require('constants');

// TRUE POSITIVES (Vulnerable/Insecure Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_1() {
  const options = {
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.crt'),
    // ruleid: javascript-avoid-tls-cipher-with-known-issue
    ciphers: 'RC4-SHA:AES128-SHA'  // RC4 is known to be insecure
  };
  
  https.createServer(options, (req, res) => {
    res.writeHead(200);
    res.end('Hello, world!');
  }).listen(8000);
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_2() {
  const tlsOptions = {
    // ruleid: javascript-avoid-tls-cipher-with-known-issue
    ciphers: 'DES-CBC3-SHA:AES128-SHA',  // DES-CBC3-SHA (3DES) is considered weak
    secureProtocol: 'TLSv1_2_method'
  };
  
  const socket = tls.connect(443, 'example.com', tlsOptions, () => {
    console.log('Connection established');
  });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_3() {
  // ruleid: javascript-avoid-tls-cipher-with-known-issue
  const secureContextOptions = {
    ciphers: 'AES128-GCM-SHA256:AES256-GCM-SHA384:NULL-SHA',  // NULL-SHA has no encryption
    secureProtocol: 'TLSv1_2_method'
  };
  
  const secureContext = tls.createSecureContext(secureContextOptions);
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_4() {
  const server = https.createServer({
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
    // ruleid: javascript-avoid-tls-cipher-with-known-issue
    ciphers: 'ECDHE-RSA-RC4-SHA:ECDHE-RSA-AES128-SHA',  // RC4 is vulnerable
    honorCipherOrder: true
  });
  
  server.listen(443);
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_5() {
  const options = {
    // ruleid: javascript-avoid-tls-cipher-with-known-issue
    ciphers: 'AES128-SHA:AES256-SHA:DES-CBC-SHA',  // DES-CBC-SHA is weak
    minVersion: 'TLSv1.2'
  };
  
  const client = tls.connect(443, 'api.example.com', options);
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_6() {
  // Custom TLS agent with insecure ciphers
  const agent = new https.Agent({
    // ruleid: javascript-avoid-tls-cipher-with-known-issue
    ciphers: 'ECDHE-RSA-AES256-SHA:RC4-MD5',  // RC4-MD5 is insecure
    keepAlive: true
  });
  
  https.get('https://api.example.com', { agent }, (res) => {
    console.log('Connected');
  });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_7() {
  // Creating a server with weak ciphers
  // ruleid: javascript-avoid-tls-cipher-with-known-issue
  const server = tls.createServer({
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.crt'),
    ciphers: 'ECDHE-RSA-AES128-SHA:ECDHE-RSA-RC4-SHA:RC4-SHA',  // Multiple RC4 variants
    requestCert: true
  });
  
  server.listen(8443);
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_8() {
  const axios = require('axios');
  
  const httpsAgent = new https.Agent({
    // ruleid: javascript-avoid-tls-cipher-with-known-issue
    ciphers: 'ECDHE-RSA-AES128-SHA:AES128-SHA:DES-CBC3-MD5',  // DES-CBC3-MD5 is weak
    rejectUnauthorized: false
  });
  
  axios.get('https://example.com', { httpsAgent });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_9() {
  // Using a configuration object with insecure ciphers
  const config = {
    // ruleid: javascript-avoid-tls-cipher-with-known-issue
    ciphers: 'ECDHE-RSA-AES128-SHA:NULL-MD5',  // NULL-MD5 has no encryption
    secureOptions: constants.SSL_OP_NO_SSLv3 | constants.SSL_OP_NO_SSLv2
  };
  
  const server = tls.createServer(config);
  server.listen(8443);
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_10() {
  // Using weak ciphers in a request
  const request = require('request');
  
  // ruleid: javascript-avoid-tls-cipher-with-known-issue
  const requestOptions = {
    url: 'https://api.example.com',
    agentOptions: {
      ciphers: 'AES256-SHA:AES128-SHA:RC4-SHA'  // RC4-SHA is insecure
    }
  };
  
  request.get(requestOptions, (error, response, body) => {
    console.log(body);
  });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_11() {
  // Using insecure ciphers with Node.js https module
  const options = {
    hostname: 'api.example.com',
    port: 443,
    path: '/data',
    method: 'GET',
    // ruleid: javascript-avoid-tls-cipher-with-known-issue
    ciphers: 'ECDHE-RSA-AES128-SHA:EXPORT-RC4-MD5'  // EXPORT ciphers are weak
  };
  
  const req = https.request(options, (res) => {
    console.log('statusCode:', res.statusCode);
  });
  
  req.end();
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_12() {
  // Using weak ciphers in a WebSocket connection
  const WebSocket = require('ws');
  
  // ruleid: javascript-avoid-tls-cipher-with-known-issue
  const ws = new WebSocket('wss://example.com', {
    agent: new https.Agent({
      ciphers: 'ECDHE-RSA-AES128-SHA:RC4-SHA:RC4-MD5'  // Multiple RC4 variants
    })
  });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_13() {
  // Using insecure ciphers with explicit TLS method
  // ruleid: javascript-avoid-tls-cipher-with-known-issue
  const options = {
    ciphers: 'AES128-SHA:AES256-SHA:IDEA-CBC-SHA',  // IDEA-CBC-SHA is considered weak
    secureProtocol: 'TLSv1_2_method'
  };
  
  const socket = tls.connect(443, 'example.com', options);
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_14() {
  // Using weak ciphers in a custom HTTPS server
  const options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
    // ruleid: javascript-avoid-tls-cipher-with-known-issue
    ciphers: 'ECDHE-RSA-AES128-SHA:SEED-SHA',  // SEED-SHA is not recommended
    honorCipherOrder: true
  };
  
  https.createServer(options, (req, res) => {
    res.writeHead(200);
    res.end('Hello, world!');
  }).listen(8443);
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
function bad_case_15() {
  // Using weak ciphers in a TLS server with specific options
  // ruleid: javascript-avoid-tls-cipher-with-known-issue
  const server = tls.createServer({
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.crt'),
    ciphers: 'ECDHE-RSA-AES128-SHA:CAMELLIA128-SHA',  // CAMELLIA128-SHA is not recommended
    requestCert: true,
    rejectUnauthorized: true
  });
  
  server.listen(8443);
}
// {/fact}

// TRUE NEGATIVES (Safe/Secure Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_1() {
  const options = {
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.crt'),
    // ok: javascript-avoid-tls-cipher-with-known-issue
    ciphers: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
  };
  
  https.createServer(options, (req, res) => {
    res.writeHead(200);
    res.end('Hello, world!');
  }).listen(8000);
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_2() {
  const tlsOptions = {
    // ok: javascript-avoid-tls-cipher-with-known-issue
    ciphers: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    secureProtocol: 'TLSv1_2_method'
  };
  
  const socket = tls.connect(443, 'example.com', tlsOptions, () => {
    console.log('Connection established');
  });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_3() {
  // ok: javascript-avoid-tls-cipher-with-known-issue
  const secureContextOptions = {
    ciphers: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
    secureProtocol: 'TLSv1_2_method'
  };
  
  const secureContext = tls.createSecureContext(secureContextOptions);
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_4() {
  const server = https.createServer({
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
    // ok: javascript-avoid-tls-cipher-with-known-issue
    ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384',
    honorCipherOrder: true
  });
  
  server.listen(443);
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_5() {
  const options = {
    // ok: javascript-avoid-tls-cipher-with-known-issue
    ciphers: 'TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256',
    minVersion: 'TLSv1.3'
  };
  
  const client = tls.connect(443, 'api.example.com', options);
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_6() {
  // Custom TLS agent with secure ciphers
  const agent = new https.Agent({
    // ok: javascript-avoid-tls-cipher-with-known-issue
    ciphers: 'TLS_AES_128_CCM_8_SHA256:TLS_AES_128_GCM_SHA256',
    keepAlive: true
  });
  
  https.get('https://api.example.com', { agent }, (res) => {
    console.log('Connected');
  });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_7() {
  // Creating a server with secure ciphers
  // ok: javascript-avoid-tls-cipher-with-known-issue
  const server = tls.createServer({
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.crt'),
    ciphers: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    requestCert: true
  });
  
  server.listen(8443);
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_8() {
  const axios = require('axios');
  
  const httpsAgent = new https.Agent({
    // ok: javascript-avoid-tls-cipher-with-known-issue
    ciphers: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    rejectUnauthorized: true
  });
  
  axios.get('https://example.com', { httpsAgent });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_9() {
  // Using a configuration object with secure ciphers
  const config = {
    // ok: javascript-avoid-tls-cipher-with-known-issue
    ciphers: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
    secureOptions: constants.SSL_OP_NO_SSLv3 | constants.SSL_OP_NO_SSLv2
  };
  
  const server = tls.createServer(config);
  server.listen(8443);
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_10() {
  // Using secure ciphers in a request
  const request = require('request');
  
  // ok: javascript-avoid-tls-cipher-with-known-issue
  const requestOptions = {
    url: 'https://api.example.com',
    agentOptions: {
      ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256'
    }
  };
  
  request.get(requestOptions, (error, response, body) => {
    console.log(body);
  });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_11() {
  // Using secure ciphers with Node.js https module
  const options = {
    hostname: 'api.example.com',
    port: 443,
    path: '/data',
    method: 'GET',
    // ok: javascript-avoid-tls-cipher-with-known-issue
    ciphers: 'TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256'
  };
  
  const req = https.request(options, (res) => {
    console.log('statusCode:', res.statusCode);
  });
  
  req.end();
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_12() {
  // Using secure ciphers in a WebSocket connection
  const WebSocket = require('ws');
  
  // ok: javascript-avoid-tls-cipher-with-known-issue
  const ws = new WebSocket('wss://example.com', {
    agent: new https.Agent({
      ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384'
    })
  });
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_13() {
  // Using secure ciphers with explicit TLS method
  // ok: javascript-avoid-tls-cipher-with-known-issue
  const options = {
    ciphers: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    secureProtocol: 'TLSv1_2_method'
  };
  
  const socket = tls.connect(443, 'example.com', options);
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_14() {
  // Using secure ciphers in a custom HTTPS server
  const options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem'),
    // ok: javascript-avoid-tls-cipher-with-known-issue
    ciphers: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    honorCipherOrder: true
  };
  
  https.createServer(options, (req, res) => {
    res.writeHead(200);
    res.end('Hello, world!');
  }).listen(8443);
}
// {/fact}

// {fact rule=cryptographic-key-generator@v1.0 defects=0}
function good_case_15() {
  // Using secure ciphers in a TLS server with specific options
  // ok: javascript-avoid-tls-cipher-with-known-issue
  const server = tls.createServer({
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.crt'),
    ciphers: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
    requestCert: true,
    rejectUnauthorized: true
  });
  
  server.listen(8443);
}
// {/fact}