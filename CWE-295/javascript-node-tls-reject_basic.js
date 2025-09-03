// This file contains test cases for the javascript-node-tls-reject rule
// The rule detects when NODE_TLS_REJECT_UNAUTHORIZED or SSL_VERIFYPEER is set to 0 or false,
// which disables TLS certificate verification and creates security vulnerabilities.

const https = require('https');
const http = require('http');
const request = require('request');
const axios = require('axios');
const fs = require('fs');
const tls = require('tls');
const express = require('express');
const fetch = require('node-fetch');
const aws = require('aws-sdk');
const mysql = require('mysql');
const dotenv = require('dotenv');

// TRUE POSITIVES - Vulnerable code that should be detected

// Case 1: Setting NODE_TLS_REJECT_UNAUTHORIZED globally
// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_1() {
  // ruleid: javascript-node-tls-reject
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  
  https.get('https://example.com', (res) => {
    console.log('Connected to server');
    res.on('data', (data) => {
      console.log(data.toString());
    });
  });
}
// {/fact}

// Case 2: Setting NODE_TLS_REJECT_UNAUTHORIZED directly in https request options
// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_2() {
  const options = {
    hostname: 'example.com',
    port: 443,
    path: '/api/data',
    method: 'GET',
    // ruleid: javascript-node-tls-reject
    rejectUnauthorized: false
  };
  
  const req = https.request(options, (res) => {
    res.on('data', (d) => {
      console.log(d.toString());
    });
  });
  
  req.end();
}
// {/fact}

// Case 3: Setting SSL_VERIFYPEER to false in request library
// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_3() {
  // ruleid: javascript-node-tls-reject
  request.get({
    url: 'https://example.com',
    strictSSL: false
  }, (error, response, body) => {
    console.log(body);
  });
}
// {/fact}

// Case 4: Setting NODE_TLS_REJECT_UNAUTHORIZED in axios configuration
// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_4() {
  const agent = new https.Agent({
    // ruleid: javascript-node-tls-reject
    rejectUnauthorized: false
  });
  
  axios.get('https://example.com', { httpsAgent: agent })
    .then(response => {
      console.log(response.data);
    })
    .catch(error => {
      console.error(error);
    });
}
// {/fact}

// Case 5: Setting NODE_TLS_REJECT_UNAUTHORIZED in a conditional statement
// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_5() {
  const isDevelopment = process.env.NODE_ENV === 'development';
  
  if (isDevelopment) {
    // ruleid: javascript-node-tls-reject
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  }
  
  https.get('https://example.com', (res) => {
    console.log('status code:', res.statusCode);
  });
}
// {/fact}

// Case 6: Using NODE_TLS_REJECT_UNAUTHORIZED in TLS connect options
// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_6() {
  const options = {
    host: 'example.com',
    port: 443,
    // ruleid: javascript-node-tls-reject
    rejectUnauthorized: false
  };
  
  const socket = tls.connect(options, () => {
    console.log('Connection established');
    socket.write('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n');
  });
}
// {/fact}

// Case 7: Setting NODE_TLS_REJECT_UNAUTHORIZED in fetch API
// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_7() {
  const httpsAgent = new https.Agent({
    // ruleid: javascript-node-tls-reject
    rejectUnauthorized: false
  });
  
  fetch('https://example.com', { agent: httpsAgent })
    .then(response => response.text())
    .then(data => console.log(data))
    .catch(err => console.error(err));
}
// {/fact}

// Case 8: Setting NODE_TLS_REJECT_UNAUTHORIZED in AWS SDK configuration
// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_8() {
  const s3 = new aws.S3({
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    region: 'us-west-2',
    httpOptions: {
      agent: new https.Agent({
        // ruleid: javascript-node-tls-reject
        rejectUnauthorized: false
      })
    }
  });
  
  s3.listBuckets((err, data) => {
    if (err) console.log(err);
    else console.log(data);
  });
}
// {/fact}

// Case 9: Setting NODE_TLS_REJECT_UNAUTHORIZED in MySQL connection
// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_9() {
  const connection = mysql.createConnection({
    host: 'example.com',
    user: 'user',
    password: 'password',
    database: 'db',
    ssl: {
      // ruleid: javascript-node-tls-reject
      rejectUnauthorized: false
    }
  });
  
  connection.connect();
  connection.query('SELECT * FROM users', (error, results) => {
    if (error) throw error;
    console.log(results);
  });
}
// {/fact}

// Case 10: Setting NODE_TLS_REJECT_UNAUTHORIZED temporarily and then restoring
// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_10() {
  const original = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  
  try {
    // ruleid: javascript-node-tls-reject
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    
    const response = https.get('https://example.com', (res) => {
      console.log('Connected to server');
    });
  } finally {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = original;
  }
}
// {/fact}

// Case 11: Setting NODE_TLS_REJECT_UNAUTHORIZED in a function that creates an agent
// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_11() {
  function createAgent() {
    return new https.Agent({
      // ruleid: javascript-node-tls-reject
      rejectUnauthorized: false,
      keepAlive: true
    });
  }
  
  const agent = createAgent();
  https.get({
    hostname: 'example.com',
    agent: agent
  }, (res) => {
    console.log('status:', res.statusCode);
  });
}
// {/fact}

// Case 12: Setting NODE_TLS_REJECT_UNAUTHORIZED in an Express server
// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  app.get('/fetch-external', (req, res) => {
    const options = {
      hostname: 'external-api.com',
      port: 443,
      path: '/data',
      method: 'GET',
      // ruleid: javascript-node-tls-reject
      rejectUnauthorized: false
    };
    
    https.request(options, (response) => {
      let data = '';
      response.on('data', (chunk) => {
        data += chunk;
      });
      response.on('end', () => {
        res.json(JSON.parse(data));
      });
    }).end();
  });
  
  app.listen(3000);
}
// {/fact}

// Case 13: Setting NODE_TLS_REJECT_UNAUTHORIZED with numeric value
// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_13() {
  // ruleid: javascript-node-tls-reject
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;
  
  https.get('https://example.com', (res) => {
    console.log('Connected with status:', res.statusCode);
  }).on('error', (e) => {
    console.error(e);
  });
}
// {/fact}

// Case 14: Setting NODE_TLS_REJECT_UNAUTHORIZED in a complex object
// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_14() {
  const config = {
    server: {
      url: 'https://example.com',
      timeout: 5000,
      tls: {
        // ruleid: javascript-node-tls-reject
        rejectUnauthorized: false,
        ciphers: 'TLS_AES_256_GCM_SHA384'
      }
    }
  };
  
  const agent = new https.Agent(config.server.tls);
  https.get({
    hostname: 'example.com',
    agent: agent
  }, (res) => {
    console.log('Connected');
  });
}
// {/fact}

// Case 15: Setting SSL_VERIFYPEER to 0 (numeric)
// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_15() {
  // ruleid: javascript-node-tls-reject
  request.get({
    url: 'https://example.com',
    strictSSL: 0
  }, (error, response, body) => {
    if (!error && response.statusCode === 200) {
      console.log(body);
    }
  });
}
// {/fact}

// TRUE NEGATIVES - Secure code that should not be detected

// Case 1: Properly using TLS verification
// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_1() {
  // ok: javascript-node-tls-reject
  https.get('https://example.com', (res) => {
    console.log('Connected to server with verification enabled');
    res.on('data', (data) => {
      console.log(data.toString());
    });
  });
}
// {/fact}

// Case 2: Explicitly enabling TLS verification in options
// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_2() {
  const options = {
    hostname: 'example.com',
    port: 443,
    path: '/api/data',
    method: 'GET',
    // ok: javascript-node-tls-reject
    rejectUnauthorized: true
  };
  
  const req = https.request(options, (res) => {
    res.on('data', (d) => {
      console.log(d.toString());
    });
  });
  
  req.end();
}
// {/fact}

// Case 3: Using request library with proper SSL verification
// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_3() {
  // ok: javascript-node-tls-reject
  request.get({
    url: 'https://example.com',
    strictSSL: true
  }, (error, response, body) => {
    console.log(body);
  });
}
// {/fact}

// Case 4: Using axios with proper TLS verification
// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_4() {
  const agent = new https.Agent({
    // ok: javascript-node-tls-reject
    rejectUnauthorized: true
  });
  
  axios.get('https://example.com', { httpsAgent: agent })
    .then(response => {
      console.log(response.data);
    })
    .catch(error => {
      console.error(error);
    });
}
// {/fact}

// Case 5: Using custom certificates but still verifying
// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_5() {
  const options = {
    hostname: 'example.com',
    port: 443,
    path: '/api/data',
    method: 'GET',
    // ok: javascript-node-tls-reject
    ca: fs.readFileSync('custom-ca.pem'),
    rejectUnauthorized: true
  };
  
  const req = https.request(options, (res) => {
    res.on('data', (d) => {
      console.log(d.toString());
    });
  });
  
  req.end();
}
// {/fact}

// Case 6: Using TLS connect with verification
// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_6() {
  const options = {
    host: 'example.com',
    port: 443,
    // ok: javascript-node-tls-reject
    rejectUnauthorized: true,
    ca: [fs.readFileSync('ca.pem')]
  };
  
  const socket = tls.connect(options, () => {
    console.log('Connection established securely');
    socket.write('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n');
  });
}
// {/fact}

// Case 7: Using fetch API with proper verification
// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_7() {
  const httpsAgent = new https.Agent({
    // ok: javascript-node-tls-reject
    rejectUnauthorized: true
  });
  
  fetch('https://example.com', { agent: httpsAgent })
    .then(response => response.text())
    .then(data => console.log(data))
    .catch(err => console.error(err));
}
// {/fact}

// Case 8: Using AWS SDK with proper verification
// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_8() {
  // ok: javascript-node-tls-reject
  const s3 = new aws.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: 'us-west-2'
  });
  
  s3.listBuckets((err, data) => {
    if (err) console.log(err);
    else console.log(data);
  });
}
// {/fact}

// Case 9: Using MySQL connection with proper verification
// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_9() {
  const connection = mysql.createConnection({
    host: 'example.com',
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: 'db',
    ssl: {
      // ok: javascript-node-tls-reject
      ca: fs.readFileSync('ca-cert.pem'),
      rejectUnauthorized: true
    }
  });
  
  connection.connect();
  connection.query('SELECT * FROM users', (error, results) => {
    if (error) throw error;
    console.log(results);
  });
}
// {/fact}

// Case 10: Using environment variables for configuration but ensuring TLS verification
// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_10() {
  // Load environment variables
  dotenv.config();
  
  // ok: javascript-node-tls-reject
  const options = {
    hostname: process.env.API_HOST,
    port: 443,
    path: '/api/data',
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${process.env.API_TOKEN}`
    }
  };
  
  const req = https.request(options, (res) => {
    let data = '';
    res.on('data', (chunk) => {
      data += chunk;
    });
    res.on('end', () => {
      console.log(JSON.parse(data));
    });
  });
  
  req.end();
}
// {/fact}

// Case 11: Creating a secure agent factory
// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_11() {
  function createSecureAgent() {
    return new https.Agent({
      // ok: javascript-node-tls-reject
      rejectUnauthorized: true,
      keepAlive: true
    });
  }
  
  const agent = createSecureAgent();
  https.get({
    hostname: 'example.com',
    agent: agent
  }, (res) => {
    console.log('status:', res.statusCode);
  });
}
// {/fact}

// Case 12: Using Express server with proper TLS verification for external requests
// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  app.get('/fetch-external', (req, res) => {
    const options = {
      hostname: 'external-api.com',
      port: 443,
      path: '/data',
      method: 'GET',
      // ok: javascript-node-tls-reject
      rejectUnauthorized: true
    };
    
    https.request(options, (response) => {
      let data = '';
      response.on('data', (chunk) => {
        data += chunk;
      });
      response.on('end', () => {
        res.json(JSON.parse(data));
      });
    }).end();
  });
  
  app.listen(3000);
}
// {/fact}

// Case 13: Using a development certificate in production but still verifying
// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_13() {
  const options = {
    hostname: 'example.com',
    port: 443,
    path: '/api/data',
    method: 'GET',
    // ok: javascript-node-tls-reject
    ca: [
      fs.readFileSync('dev-ca.pem'),
      fs.readFileSync('prod-ca.pem')
    ],
    rejectUnauthorized: true
  };
  
  const req = https.request(options, (res) => {
    console.log('status:', res.statusCode);
  });
  
  req.end();
}
// {/fact}

// Case 14: Using a complex configuration object with proper TLS verification
// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_14() {
  const config = {
    server: {
      url: 'https://example.com',
      timeout: 5000,
      tls: {
        // ok: javascript-node-tls-reject
        rejectUnauthorized: true,
        ciphers: 'TLS_AES_256_GCM_SHA384',
        secureProtocol: 'TLSv1_2_method'
      }
    }
  };
  
  const agent = new https.Agent(config.server.tls);
  https.get({
    hostname: 'example.com',
    agent: agent
  }, (res) => {
    console.log('Connected securely');
  });
}
// {/fact}

// Case 15: Using request library with explicit SSL verification
// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_15() {
  // ok: javascript-node-tls-reject
  request.get({
    url: 'https://example.com',
    strictSSL: true,
    cert: fs.readFileSync('client.crt'),
    key: fs.readFileSync('client.key')
  }, (error, response, body) => {
    if (!error && response.statusCode === 200) {
      console.log(body);
    }
  });
}
// {/fact}