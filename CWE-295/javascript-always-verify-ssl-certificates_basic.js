// Import required modules
const https = require('https');
const axios = require('axios');
const request = require('request');
const fetch = require('node-fetch');
const tls = require('tls');
const fs = require('fs');
const AWS = require('aws-sdk');
const mysql = require('mysql');
const { Agent } = require('https');
const superagent = require('superagent');
const got = require('got');
const needle = require('needle');

// TRUE POSITIVES (Vulnerable Code Examples)

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_1() {
  // Using Node.js https module with rejectUnauthorized set to false
  const options = {
    hostname: 'api.example.com',
    port: 443,
    path: '/data',
    method: 'GET',
    // ruleid: javascript-always-verify-ssl-certificates
    rejectUnauthorized: false
  };
  
  const req = https.request(options, (res) => {
    let data = '';
    res.on('data', (chunk) => {
      data += chunk;
    });
    res.on('end', () => {
      console.log(data);
    });
  });
  
  req.end();
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_2() {
  // Using axios with insecure HTTPS
  // ruleid: javascript-always-verify-ssl-certificates
  axios.get('https://api.example.com/data', {
    httpsAgent: new https.Agent({
      rejectUnauthorized: false
    })
  })
  .then(response => {
    console.log(response.data);
  })
  .catch(error => {
    console.error(error);
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_3() {
  // Using request library with SSL verification disabled
  // ruleid: javascript-always-verify-ssl-certificates
  request({
    url: 'https://api.example.com/data',
    method: 'GET',
    strictSSL: false
  }, (error, response, body) => {
    if (!error && response.statusCode === 200) {
      console.log(body);
    }
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_4() {
  // Using node-fetch with insecure HTTPS
  const agent = new https.Agent({
    // ruleid: javascript-always-verify-ssl-certificates
    rejectUnauthorized: false
  });
  
  fetch('https://api.example.com/data', { agent })
    .then(response => response.json())
    .then(data => console.log(data))
    .catch(error => console.error(error));
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_5() {
  // Using TLS connect with checkServerIdentity disabled
  const options = {
    host: 'api.example.com',
    port: 443,
    // ruleid: javascript-always-verify-ssl-certificates
    checkServerIdentity: () => undefined
  };
  
  const socket = tls.connect(options, () => {
    console.log('Connection established');
    socket.write('GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n');
  });
  
  socket.on('data', (data) => {
    console.log(data.toString());
    socket.end();
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_6() {
  // Using AWS SDK with SSL disabled
  // ruleid: javascript-always-verify-ssl-certificates
  const s3 = new AWS.S3({
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    region: 'us-west-2',
    sslEnabled: false
  });
  
  s3.getObject({
    Bucket: 'example-bucket',
    Key: 'example-file.txt'
  }, (err, data) => {
    if (err) console.error(err);
    else console.log(data.Body.toString());
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_7() {
  // Using MySQL connection with SSL verification disabled
  const connection = mysql.createConnection({
    host: 'db.example.com',
    user: 'dbuser',
    password: 'dbpassword',
    database: 'mydb',
    ssl: {
      // ruleid: javascript-always-verify-ssl-certificates
      rejectUnauthorized: false
    }
  });
  
  connection.connect();
  connection.query('SELECT * FROM users', (error, results) => {
    if (error) throw error;
    console.log(results);
  });
  connection.end();
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_8() {
  // Using superagent with TLS verification disabled
  // ruleid: javascript-always-verify-ssl-certificates
  superagent
    .get('https://api.example.com/data')
    .disableTLSCerts()
    .end((err, res) => {
      if (err) console.error(err);
      else console.log(res.body);
    });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_9() {
  // Using got with certificate check disabled
  // ruleid: javascript-always-verify-ssl-certificates
  got('https://api.example.com/data', {
    https: {
      rejectUnauthorized: false
    }
  })
  .then(response => {
    console.log(response.body);
  })
  .catch(error => {
    console.error(error);
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_10() {
  // Using needle with SSL verification disabled
  // ruleid: javascript-always-verify-ssl-certificates
  needle.get('https://api.example.com/data', { 
    secure: false 
  }, (error, response) => {
    if (!error && response.statusCode === 200) {
      console.log(response.body);
    }
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_11() {
  // Using https module with a custom agent that disables certificate validation
  const agent = new https.Agent({
    // ruleid: javascript-always-verify-ssl-certificates
    rejectUnauthorized: false,
    keepAlive: true
  });
  
  https.get({
    hostname: 'api.example.com',
    path: '/data',
    agent: agent
  }, (res) => {
    let data = '';
    res.on('data', (chunk) => {
      data += chunk;
    });
    res.on('end', () => {
      console.log(JSON.parse(data));
    });
  }).on('error', (e) => {
    console.error(e);
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_12() {
  // Using axios with process.env but defaulting to insecure
  const verifySSL = process.env.VERIFY_SSL === 'true';
  
  // ruleid: javascript-always-verify-ssl-certificates
  axios.get('https://api.example.com/data', {
    httpsAgent: new https.Agent({
      rejectUnauthorized: verifySSL || false // Default is insecure
    })
  })
  .then(response => {
    console.log(response.data);
  })
  .catch(error => {
    console.error(error);
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_13() {
  // Using request with a conditional but insecure default
  const isProduction = process.env.NODE_ENV === 'production';
  
  // ruleid: javascript-always-verify-ssl-certificates
  request({
    url: 'https://api.example.com/data',
    method: 'GET',
    strictSSL: isProduction // Insecure in non-production
  }, (error, response, body) => {
    if (!error && response.statusCode === 200) {
      console.log(body);
    }
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_14() {
  // Using https.request with a function that returns insecure options
  function getRequestOptions(endpoint) {
    return {
      hostname: 'api.example.com',
      port: 443,
      path: endpoint,
      method: 'GET',
      // ruleid: javascript-always-verify-ssl-certificates
      rejectUnauthorized: false
    };
  }
  
  const req = https.request(getRequestOptions('/data'), (res) => {
    let data = '';
    res.on('data', (chunk) => {
      data += chunk;
    });
    res.on('end', () => {
      console.log(data);
    });
  });
  
  req.end();
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_15() {
  // Using TLS connect with a custom certificate verification function that always returns true
  const options = {
    host: 'api.example.com',
    port: 443,
    // ruleid: javascript-always-verify-ssl-certificates
    checkServerIdentity: (host, cert) => {
      // Always return true regardless of certificate validity
      return undefined;
    }
  };
  
  const socket = tls.connect(options, () => {
    console.log('Connection established');
    socket.write('GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n');
  });
  
  socket.on('data', (data) => {
    console.log(data.toString());
    socket.end();
  });
}
// {/fact}

// TRUE NEGATIVES (Secure Code Examples)

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_1() {
  // Using Node.js https module with proper certificate validation
  const options = {
    hostname: 'api.example.com',
    port: 443,
    path: '/data',
    method: 'GET',
    // ok: javascript-always-verify-ssl-certificates
    rejectUnauthorized: true // Default is true, but explicitly set for clarity
  };
  
  const req = https.request(options, (res) => {
    let data = '';
    res.on('data', (chunk) => {
      data += chunk;
    });
    res.on('end', () => {
      console.log(data);
    });
  });
  
  req.end();
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_2() {
  // Using axios with default secure settings
  // ok: javascript-always-verify-ssl-certificates
  axios.get('https://api.example.com/data')
    .then(response => {
      console.log(response.data);
    })
    .catch(error => {
      console.error(error);
    });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_3() {
  // Using request library with SSL verification enabled
  // ok: javascript-always-verify-ssl-certificates
  request({
    url: 'https://api.example.com/data',
    method: 'GET',
    strictSSL: true
  }, (error, response, body) => {
    if (!error && response.statusCode === 200) {
      console.log(body);
    }
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_4() {
  // Using node-fetch with default secure settings
  // ok: javascript-always-verify-ssl-certificates
  fetch('https://api.example.com/data')
    .then(response => response.json())
    .then(data => console.log(data))
    .catch(error => console.error(error));
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_5() {
  // Using TLS connect with proper certificate validation
  const options = {
    host: 'api.example.com',
    port: 443,
    // ok: javascript-always-verify-ssl-certificates
    checkServerIdentity: tls.checkServerIdentity // Using the default validation
  };
  
  const socket = tls.connect(options, () => {
    console.log('Connection established');
    socket.write('GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n');
  });
  
  socket.on('data', (data) => {
    console.log(data.toString());
    socket.end();
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_6() {
  // Using AWS SDK with SSL enabled
  // ok: javascript-always-verify-ssl-certificates
  const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: 'us-west-2',
    sslEnabled: true // Default is true, but explicitly set for clarity
  });
  
  s3.getObject({
    Bucket: 'example-bucket',
    Key: 'example-file.txt'
  }, (err, data) => {
    if (err) console.error(err);
    else console.log(data.Body.toString());
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_7() {
  // Using MySQL connection with proper SSL verification
  const connection = mysql.createConnection({
    host: 'db.example.com',
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: 'mydb',
    ssl: {
      // ok: javascript-always-verify-ssl-certificates
      rejectUnauthorized: true,
      ca: fs.readFileSync('/path/to/ca-cert.pem')
    }
  });
  
  connection.connect();
  connection.query('SELECT * FROM users', (error, results) => {
    if (error) throw error;
    console.log(results);
  });
  connection.end();
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_8() {
  // Using superagent with default secure settings
  // ok: javascript-always-verify-ssl-certificates
  superagent
    .get('https://api.example.com/data')
    .end((err, res) => {
      if (err) console.error(err);
      else console.log(res.body);
    });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_9() {
  // Using got with default secure settings
  // ok: javascript-always-verify-ssl-certificates
  got('https://api.example.com/data')
    .then(response => {
      console.log(response.body);
    })
    .catch(error => {
      console.error(error);
    });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_10() {
  // Using needle with SSL verification enabled
  // ok: javascript-always-verify-ssl-certificates
  needle.get('https://api.example.com/data', { 
    secure: true 
  }, (error, response) => {
    if (!error && response.statusCode === 200) {
      console.log(response.body);
    }
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_11() {
  // Using https module with a custom agent that enforces certificate validation
  const agent = new https.Agent({
    // ok: javascript-always-verify-ssl-certificates
    rejectUnauthorized: true,
    keepAlive: true
  });
  
  https.get({
    hostname: 'api.example.com',
    path: '/data',
    agent: agent
  }, (res) => {
    let data = '';
    res.on('data', (chunk) => {
      data += chunk;
    });
    res.on('end', () => {
      console.log(JSON.parse(data));
    });
  }).on('error', (e) => {
    console.error(e);
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_12() {
  // Using axios with custom CA certificate
  const httpsAgent = new https.Agent({
    // ok: javascript-always-verify-ssl-certificates
    ca: fs.readFileSync('/path/to/ca-certificate.pem')
  });
  
  axios.get('https://api.example.com/data', { httpsAgent })
    .then(response => {
      console.log(response.data);
    })
    .catch(error => {
      console.error(error);
    });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_13() {
  // Using request with environment-based configuration but secure default
  const isTestEnv = process.env.NODE_ENV === 'test';
  const certPath = isTestEnv ? '/test/certs/ca.pem' : '/prod/certs/ca.pem';
  
  // ok: javascript-always-verify-ssl-certificates
  request({
    url: 'https://api.example.com/data',
    method: 'GET',
    strictSSL: true,
    ca: fs.readFileSync(certPath)
  }, (error, response, body) => {
    if (!error && response.statusCode === 200) {
      console.log(body);
    }
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_14() {
  // Using https.request with a function that returns secure options
  function getSecureRequestOptions(endpoint) {
    return {
      hostname: 'api.example.com',
      port: 443,
      path: endpoint,
      method: 'GET',
      // ok: javascript-always-verify-ssl-certificates
      rejectUnauthorized: true,
      ca: [fs.readFileSync('/path/to/ca-cert.pem')]
    };
  }
  
  const req = https.request(getSecureRequestOptions('/data'), (res) => {
    let data = '';
    res.on('data', (chunk) => {
      data += chunk;
    });
    res.on('end', () => {
      console.log(data);
    });
  });
  
  req.end();
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_15() {
  // Using TLS connect with a proper certificate verification function
  const options = {
    host: 'api.example.com',
    port: 443,
    // ok: javascript-always-verify-ssl-certificates
    checkServerIdentity: (host, cert) => {
      // Perform proper certificate validation
      const result = tls.checkServerIdentity(host, cert);
      if (result) {
        throw result; // Certificate validation failed
      }
      // Additional custom validation if needed
      if (cert.subject.CN !== 'api.example.com') {
        throw new Error('Certificate CN does not match expected hostname');
      }
      return undefined; // Certificate is valid
    }
  };
  
  const socket = tls.connect(options, () => {
    console.log('Connection established');
    socket.write('GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n');
  });
  
  socket.on('data', (data) => {
    console.log(data.toString());
    socket.end();
  });
}
// {/fact}