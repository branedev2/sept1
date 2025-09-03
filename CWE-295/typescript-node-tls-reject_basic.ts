// File: tls_reject_test_cases.ts
import * as https from 'https';
import * as http from 'http';
import * as request from 'request';
import axios from 'axios';
import * as tls from 'tls';
import * as fs from 'fs';
import * as dotenv from 'dotenv';
import { Agent } from 'https';

// TRUE POSITIVES (Vulnerable Code)

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_1() {
  // Setting NODE_TLS_REJECT_UNAUTHORIZED globally to 0
  // ruleid: typescript-node-tls-reject
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  
  https.get('https://example.com', (res) => {
    let data = '';
    res.on('data', (chunk) => {
      data += chunk;
    });
    res.on('end', () => {
      console.log(data);
    });
  }).on('error', (err) => {
    console.error(err);
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_2() {
  // Setting NODE_TLS_REJECT_UNAUTHORIZED to false
  // ruleid: typescript-node-tls-reject
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = 'false';
  
  const options = {
    hostname: 'example.com',
    port: 443,
    path: '/api/data',
    method: 'GET'
  };
  
  const req = https.request(options, (res) => {
    res.on('data', (data) => {
      console.log(data.toString());
    });
  });
  
  req.end();
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_3() {
  // Using request library with SSL_VERIFYPEER set to false
  // ruleid: typescript-node-tls-reject
  const options = {
    url: 'https://example.com',
    method: 'GET',
    rejectUnauthorized: false
  };
  
  request(options, (error, response, body) => {
    if (!error && response.statusCode === 200) {
      console.log(body);
    }
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_4() {
  // Using axios with rejectUnauthorized set to false
  // ruleid: typescript-node-tls-reject
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  
  axios.get('https://example.com')
    .then(response => {
      console.log(response.data);
    })
    .catch(error => {
      console.error(error);
    });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_5() {
  // Setting NODE_TLS_REJECT_UNAUTHORIZED in a conditional block
  if (process.env.NODE_ENV === 'development') {
    // ruleid: typescript-node-tls-reject
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  }
  
  https.get('https://example.com', (res) => {
    console.log(res.statusCode);
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_6() {
  // Using https.Agent with rejectUnauthorized: false
  const agent = new https.Agent({
    // ruleid: typescript-node-tls-reject
    rejectUnauthorized: false
  });
  
  https.get({
    hostname: 'example.com',
    path: '/',
    agent: agent
  }, (res) => {
    console.log(res.statusCode);
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_7() {
  // Using tls.connect with rejectUnauthorized: false
  // ruleid: typescript-node-tls-reject
  const options = {
    host: 'example.com',
    port: 443,
    rejectUnauthorized: false
  };
  
  const socket = tls.connect(options, () => {
    console.log('Connection established');
    socket.write('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n');
  });
  
  socket.on('data', (data) => {
    console.log(data.toString());
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_8() {
  // Setting NODE_TLS_REJECT_UNAUTHORIZED to 0 in a try-catch block
  try {
    // ruleid: typescript-node-tls-reject
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    
    https.get('https://example.com', (res) => {
      console.log(res.statusCode);
    });
  } catch (error) {
    console.error(error);
  }
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_9() {
  // Using request with SSL_VERIFYPEER set to 0
  const options = {
    url: 'https://example.com',
    method: 'GET',
    // ruleid: typescript-node-tls-reject
    ssl: {
      verifypeer: 0
    }
  };
  
  request(options, (error, response, body) => {
    if (!error) {
      console.log(body);
    }
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_10() {
  // Setting NODE_TLS_REJECT_UNAUTHORIZED to false in a function
  function makeRequest() {
    // ruleid: typescript-node-tls-reject
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = 'false';
    
    return https.get('https://example.com', (res) => {
      console.log(res.statusCode);
    });
  }
  
  makeRequest();
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_11() {
  // Using https.request with rejectUnauthorized: false in options
  const options = {
    hostname: 'example.com',
    port: 443,
    path: '/',
    method: 'GET',
    // ruleid: typescript-node-tls-reject
    rejectUnauthorized: false
  };
  
  const req = https.request(options, (res) => {
    console.log(res.statusCode);
  });
  
  req.end();
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_12() {
  // Setting NODE_TLS_REJECT_UNAUTHORIZED to 0 for a specific API call
  const originalValue = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  
  // ruleid: typescript-node-tls-reject
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  
  https.get('https://example.com', (res) => {
    console.log(res.statusCode);
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = originalValue;
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_13() {
  // Using axios with https agent that has rejectUnauthorized: false
  const httpsAgent = new https.Agent({
    // ruleid: typescript-node-tls-reject
    rejectUnauthorized: false
  });
  
  axios.get('https://example.com', { httpsAgent })
    .then(response => {
      console.log(response.data);
    })
    .catch(error => {
      console.error(error);
    });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_14() {
  // Setting NODE_TLS_REJECT_UNAUTHORIZED based on environment variable
  const disableTlsCheck = process.env.DISABLE_TLS_CHECK || 'false';
  
  if (disableTlsCheck === 'true') {
    // ruleid: typescript-node-tls-reject
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  }
  
  https.get('https://example.com', (res) => {
    console.log(res.statusCode);
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_15() {
  // Using a variable to set rejectUnauthorized to false
  const verifyTls = false;
  
  const options = {
    hostname: 'example.com',
    port: 443,
    path: '/',
    method: 'GET',
    // ruleid: typescript-node-tls-reject
    rejectUnauthorized: verifyTls
  };
  
  https.request(options, (res) => {
    console.log(res.statusCode);
  }).end();
}
// {/fact}

// TRUE NEGATIVES (Secure Code)

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_1() {
  // Using default TLS verification (not disabling it)
  // ok: typescript-node-tls-reject
  https.get('https://example.com', (res) => {
    let data = '';
    res.on('data', (chunk) => {
      data += chunk;
    });
    res.on('end', () => {
      console.log(data);
    });
  }).on('error', (err) => {
    console.error(err);
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_2() {
  // Explicitly setting rejectUnauthorized to true
  const options = {
    hostname: 'example.com',
    port: 443,
    path: '/api/data',
    method: 'GET',
    // ok: typescript-node-tls-reject
    rejectUnauthorized: true
  };
  
  const req = https.request(options, (res) => {
    res.on('data', (data) => {
      console.log(data.toString());
    });
  });
  
  req.end();
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_3() {
  // Using request library with proper TLS verification
  const options = {
    url: 'https://example.com',
    method: 'GET',
    // ok: typescript-node-tls-reject
    rejectUnauthorized: true
  };
  
  request(options, (error, response, body) => {
    if (!error && response.statusCode === 200) {
      console.log(body);
    }
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_4() {
  // Using axios with default TLS verification
  // ok: typescript-node-tls-reject
  axios.get('https://example.com')
    .then(response => {
      console.log(response.data);
    })
    .catch(error => {
      console.error(error);
    });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_5() {
  // Using custom certificates but still verifying
  const options = {
    hostname: 'example.com',
    port: 443,
    path: '/',
    method: 'GET',
    // ok: typescript-node-tls-reject
    ca: fs.readFileSync('custom-ca.pem'),
    rejectUnauthorized: true
  };
  
  https.request(options, (res) => {
    console.log(res.statusCode);
  }).end();
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_6() {
  // Using https.Agent with proper TLS verification
  const agent = new https.Agent({
    // ok: typescript-node-tls-reject
    rejectUnauthorized: true
  });
  
  https.get({
    hostname: 'example.com',
    path: '/',
    agent: agent
  }, (res) => {
    console.log(res.statusCode);
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_7() {
  // Using tls.connect with proper TLS verification
  // ok: typescript-node-tls-reject
  const options = {
    host: 'example.com',
    port: 443,
    rejectUnauthorized: true
  };
  
  const socket = tls.connect(options, () => {
    console.log('Connection established');
    socket.write('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n');
  });
  
  socket.on('data', (data) => {
    console.log(data.toString());
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_8() {
  // Setting NODE_TLS_REJECT_UNAUTHORIZED to '1' (secure)
  // ok: typescript-node-tls-reject
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';
  
  https.get('https://example.com', (res) => {
    console.log(res.statusCode);
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_9() {
  // Using request with proper SSL verification
  const options = {
    url: 'https://example.com',
    method: 'GET',
    // ok: typescript-node-tls-reject
    ssl: {
      verifypeer: 1
    }
  };
  
  request(options, (error, response, body) => {
    if (!error) {
      console.log(body);
    }
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_10() {
  // Using a custom HTTPS agent with proper verification
  const agent = new Agent({
    // ok: typescript-node-tls-reject
    rejectUnauthorized: true,
    ca: fs.readFileSync('custom-ca.pem')
  });
  
  https.get({
    hostname: 'example.com',
    path: '/',
    agent: agent
  }, (res) => {
    console.log(res.statusCode);
  });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_11() {
  // Loading configuration from environment but ensuring TLS verification
  dotenv.config();
  
  const options = {
    hostname: 'example.com',
    port: 443,
    path: '/',
    method: 'GET',
    // ok: typescript-node-tls-reject
    rejectUnauthorized: true
  };
  
  https.request(options, (res) => {
    console.log(res.statusCode);
  }).end();
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_12() {
  // Using axios with custom https agent that has proper verification
  const httpsAgent = new https.Agent({
    // ok: typescript-node-tls-reject
    rejectUnauthorized: true
  });
  
  axios.get('https://example.com', { httpsAgent })
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
  // Using a variable to set rejectUnauthorized to true
  const verifyTls = true;
  
  const options = {
    hostname: 'example.com',
    port: 443,
    path: '/',
    method: 'GET',
    // ok: typescript-node-tls-reject
    rejectUnauthorized: verifyTls
  };
  
  https.request(options, (res) => {
    console.log(res.statusCode);
  }).end();
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_14() {
  // Using proper TLS verification in development and production
  const isDev = process.env.NODE_ENV === 'development';
  
  const options = {
    hostname: 'example.com',
    port: 443,
    path: '/',
    method: 'GET',
    // ok: typescript-node-tls-reject
    rejectUnauthorized: true // Always verify TLS
  };
  
  https.request(options, (res) => {
    console.log(res.statusCode);
  }).end();
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_15() {
  // Using a custom certificate but still enforcing verification
  const options = {
    hostname: 'example.com',
    port: 443,
    path: '/',
    method: 'GET',
    // ok: typescript-node-tls-reject
    ca: [fs.readFileSync('ca1.pem'), fs.readFileSync('ca2.pem')],
    rejectUnauthorized: true
  };
  
  https.request(options, (res) => {
    console.log(res.statusCode);
  }).end();
}
// {/fact}