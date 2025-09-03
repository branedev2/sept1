const http = require('http');
const https = require('https');
const axios = require('axios');
const request = require('request');
const fetch = require('node-fetch');

// True Positive Examples (Vulnerable Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1() {
  // Creating an HTTP agent with default settings
  // ruleid: javascript-https-connection-pool
  const agent = new http.Agent({
    keepAlive: true,
    maxSockets: 10
  });
  
  http.get('http://api.example.com/data', { agent }, (res) => {
    let data = '';
    res.on('data', (chunk) => {
      data += chunk;
    });
    res.on('end', () => {
      console.log(JSON.parse(data));
    });
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2() {
  // Using http.Agent with custom timeout
  // ruleid: javascript-https-connection-pool
  const agent = new http.Agent({
    keepAlive: true,
    timeout: 5000
  });
  
  const options = {
    hostname: 'api.example.com',
    path: '/users',
    method: 'GET',
    agent: agent
  };
  
  const req = http.request(options, (res) => {
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

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3() {
  // Using http.Agent with axios
  // ruleid: javascript-https-connection-pool
  const agent = new http.Agent({ 
    keepAlive: true,
    maxSockets: 50
  });
  
  axios.get('http://api.example.com/products', { 
    httpAgent: agent 
  })
  .then(response => {
    console.log(response.data);
  })
  .catch(error => {
    console.error('Error:', error);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4() {
  // Creating a global http agent and using it
  // ruleid: javascript-https-connection-pool
  const globalAgent = new http.Agent({
    keepAlive: true,
    maxFreeSockets: 10
  });
  
  function fetchUserData(userId) {
    const options = {
      hostname: 'api.example.com',
      path: `/users/${userId}`,
      method: 'GET',
      agent: globalAgent
    };
    
    return new Promise((resolve, reject) => {
      const req = http.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          resolve(JSON.parse(data));
        });
      });
      
      req.on('error', (e) => {
        reject(e);
      });
      
      req.end();
    });
  }
  
  fetchUserData(123).then(data => console.log(data));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5() {
  // Using http.Agent with socket reuse
  // ruleid: javascript-https-connection-pool
  const agent = new http.Agent({
    keepAlive: true,
    keepAliveMsecs: 1000,
    maxSockets: 5,
    maxFreeSockets: 5
  });
  
  for (let i = 0; i < 10; i++) {
    http.get(`http://api.example.com/items/${i}`, { agent }, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        console.log(`Item ${i}:`, JSON.parse(data));
      });
    });
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6() {
  // Using http.Agent with request library
  // ruleid: javascript-https-connection-pool
  const agent = new http.Agent({
    keepAlive: true
  });
  
  request({
    url: 'http://api.example.com/data',
    method: 'GET',
    agent: agent,
    json: true
  }, (error, response, body) => {
    if (!error && response.statusCode === 200) {
      console.log(body);
    } else {
      console.error('Error:', error);
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7() {
  // Using http.Agent with specific family (IPv4)
  // ruleid: javascript-https-connection-pool
  const agent = new http.Agent({
    keepAlive: true,
    family: 4
  });
  
  const options = {
    hostname: 'api.example.com',
    path: '/data',
    method: 'POST',
    agent: agent,
    headers: {
      'Content-Type': 'application/json'
    }
  };
  
  const req = http.request(options, (res) => {
    let data = '';
    res.on('data', (chunk) => {
      data += chunk;
    });
    res.on('end', () => {
      console.log(JSON.parse(data));
    });
  });
  
  req.write(JSON.stringify({ key: 'value' }));
  req.end();
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8() {
  // Using http.Agent with node-fetch
  // ruleid: javascript-https-connection-pool
  const agent = new http.Agent({
    keepAlive: true
  });
  
  fetch('http://api.example.com/data', { agent })
    .then(response => response.json())
    .then(data => console.log(data))
    .catch(error => console.error('Error:', error));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9() {
  // Using http.Agent with custom certificate handling
  // ruleid: javascript-https-connection-pool
  const agent = new http.Agent({
    keepAlive: true,
    rejectUnauthorized: false
  });
  
  const options = {
    hostname: 'api.example.com',
    path: '/secure-data',
    method: 'GET',
    agent: agent
  };
  
  const req = http.request(options, (res) => {
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

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10() {
  // Using http.Agent with connection timeout
  // ruleid: javascript-https-connection-pool
  const agent = new http.Agent({
    keepAlive: true,
    timeout: 10000
  });
  
  function makeRequest() {
    return new Promise((resolve, reject) => {
      const req = http.get('http://api.example.com/data', { agent }, (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          resolve(JSON.parse(data));
        });
      });
      
      req.on('error', (e) => {
        reject(e);
      });
      
      req.on('timeout', () => {
        req.abort();
        reject(new Error('Request timed out'));
      });
    });
  }
  
  makeRequest()
    .then(data => console.log(data))
    .catch(error => console.error('Error:', error));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11() {
  // Using http.Agent with multiple concurrent requests
  // ruleid: javascript-https-connection-pool
  const agent = new http.Agent({
    keepAlive: true,
    maxSockets: 20
  });
  
  const endpoints = [
    '/users',
    '/products',
    '/orders',
    '/payments'
  ];
  
  const requests = endpoints.map(endpoint => {
    return new Promise((resolve, reject) => {
      http.get(`http://api.example.com${endpoint}`, { agent }, (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          resolve({ endpoint, data: JSON.parse(data) });
        });
      }).on('error', reject);
    });
  });
  
  Promise.all(requests)
    .then(results => console.log(results))
    .catch(error => console.error('Error:', error));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12() {
  // Using http.Agent with custom headers
  // ruleid: javascript-https-connection-pool
  const agent = new http.Agent({
    keepAlive: true
  });
  
  const options = {
    hostname: 'api.example.com',
    path: '/data',
    method: 'GET',
    agent: agent,
    headers: {
      'Authorization': 'Bearer token123',
      'User-Agent': 'CustomClient/1.0',
      'Accept': 'application/json'
    }
  };
  
  const req = http.request(options, (res) => {
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

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13() {
  // Using http.Agent with proxy configuration
  // ruleid: javascript-https-connection-pool
  const agent = new http.Agent({
    keepAlive: true,
    proxy: 'http://proxy.example.com:8080'
  });
  
  http.get('http://api.example.com/data', { agent }, (res) => {
    let data = '';
    res.on('data', (chunk) => {
      data += chunk;
    });
    res.on('end', () => {
      console.log(JSON.parse(data));
    });
  }).on('error', (e) => {
    console.error('Error:', e);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14() {
  // Using http.Agent with custom socket options
  // ruleid: javascript-https-connection-pool
  const agent = new http.Agent({
    keepAlive: true,
    socketOptions: {
      noDelay: true,
      keepAlive: true,
      keepAliveInitialDelay: 1000
    }
  });
  
  const options = {
    hostname: 'api.example.com',
    path: '/stream-data',
    method: 'GET',
    agent: agent
  };
  
  const req = http.request(options, (res) => {
    res.on('data', (chunk) => {
      console.log(chunk.toString());
    });
    res.on('end', () => {
      console.log('No more data');
    });
  });
  
  req.end();
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15() {
  // Using http.Agent with error handling
  // ruleid: javascript-https-connection-pool
  const agent = new http.Agent({
    keepAlive: true,
    maxSockets: 10
  });
  
  function fetchWithRetry(url, retries = 3) {
    return new Promise((resolve, reject) => {
      const makeRequest = (attemptsLeft) => {
        http.get(url, { agent }, (res) => {
          let data = '';
          res.on('data', (chunk) => {
            data += chunk;
          });
          res.on('end', () => {
            try {
              resolve(JSON.parse(data));
            } catch (e) {
              if (attemptsLeft > 0) {
                makeRequest(attemptsLeft - 1);
              } else {
                reject(new Error('Failed to parse response after multiple attempts'));
              }
            }
          });
        }).on('error', (err) => {
          if (attemptsLeft > 0) {
            makeRequest(attemptsLeft - 1);
          } else {
            reject(err);
          }
        });
      };
      
      makeRequest(retries);
    });
  }
  
  fetchWithRetry('http://api.example.com/data')
    .then(data => console.log(data))
    .catch(error => console.error('Error:', error));
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1() {
  // Using https.Agent instead of http.Agent
  // ok: javascript-https-connection-pool
  const agent = new https.Agent({
    keepAlive: true,
    maxSockets: 10
  });
  
  https.get('https://api.example.com/data', { agent }, (res) => {
    let data = '';
    res.on('data', (chunk) => {
      data += chunk;
    });
    res.on('end', () => {
      console.log(JSON.parse(data));
    });
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2() {
  // Using https.Agent with custom timeout
  // ok: javascript-https-connection-pool
  const agent = new https.Agent({
    keepAlive: true,
    timeout: 5000
  });
  
  const options = {
    hostname: 'api.example.com',
    path: '/users',
    method: 'GET',
    agent: agent
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

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3() {
  // Using https.Agent with axios
  // ok: javascript-https-connection-pool
  const agent = new https.Agent({ 
    keepAlive: true,
    maxSockets: 50
  });
  
  axios.get('https://api.example.com/products', { 
    httpsAgent: agent 
  })
  .then(response => {
    console.log(response.data);
  })
  .catch(error => {
    console.error('Error:', error);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4() {
  // Creating a global https agent and using it
  // ok: javascript-https-connection-pool
  const globalAgent = new https.Agent({
    keepAlive: true,
    maxFreeSockets: 10
  });
  
  function fetchUserData(userId) {
    const options = {
      hostname: 'api.example.com',
      path: `/users/${userId}`,
      method: 'GET',
      agent: globalAgent
    };
    
    return new Promise((resolve, reject) => {
      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          resolve(JSON.parse(data));
        });
      });
      
      req.on('error', (e) => {
        reject(e);
      });
      
      req.end();
    });
  }
  
  fetchUserData(123).then(data => console.log(data));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5() {
  // Using https.Agent with socket reuse
  // ok: javascript-https-connection-pool
  const agent = new https.Agent({
    keepAlive: true,
    keepAliveMsecs: 1000,
    maxSockets: 5,
    maxFreeSockets: 5
  });
  
  for (let i = 0; i < 10; i++) {
    https.get(`https://api.example.com/items/${i}`, { agent }, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        console.log(`Item ${i}:`, JSON.parse(data));
      });
    });
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6() {
  // Using https.Agent with request library
  // ok: javascript-https-connection-pool
  const agent = new https.Agent({
    keepAlive: true
  });
  
  request({
    url: 'https://api.example.com/data',
    method: 'GET',
    agent: agent,
    json: true
  }, (error, response, body) => {
    if (!error && response.statusCode === 200) {
      console.log(body);
    } else {
      console.error('Error:', error);
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7() {
  // Using https.Agent with specific family (IPv4)
  // ok: javascript-https-connection-pool
  const agent = new https.Agent({
    keepAlive: true,
    family: 4
  });
  
  const options = {
    hostname: 'api.example.com',
    path: '/data',
    method: 'POST',
    agent: agent,
    headers: {
      'Content-Type': 'application/json'
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
  
  req.write(JSON.stringify({ key: 'value' }));
  req.end();
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8() {
  // Using https.Agent with node-fetch
  // ok: javascript-https-connection-pool
  const agent = new https.Agent({
    keepAlive: true
  });
  
  fetch('https://api.example.com/data', { agent })
    .then(response => response.json())
    .then(data => console.log(data))
    .catch(error => console.error('Error:', error));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9() {
  // Using https.Agent with custom certificate handling
  // ok: javascript-https-connection-pool
  const agent = new https.Agent({
    keepAlive: true,
    ca: [/* certificate authority */],
    cert: [/* client certificate */],
    key: [/* client key */],
    rejectUnauthorized: true
  });
  
  const options = {
    hostname: 'api.example.com',
    path: '/secure-data',
    method: 'GET',
    agent: agent
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

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10() {
  // Using https.Agent with connection timeout
  // ok: javascript-https-connection-pool
  const agent = new https.Agent({
    keepAlive: true,
    timeout: 10000
  });
  
  function makeRequest() {
    return new Promise((resolve, reject) => {
      const req = https.get('https://api.example.com/data', { agent }, (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          resolve(JSON.parse(data));
        });
      });
      
      req.on('error', (e) => {
        reject(e);
      });
      
      req.on('timeout', () => {
        req.abort();
        reject(new Error('Request timed out'));
      });
    });
  }
  
  makeRequest()
    .then(data => console.log(data))
    .catch(error => console.error('Error:', error));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11() {
  // Using https.Agent with multiple concurrent requests
  // ok: javascript-https-connection-pool
  const agent = new https.Agent({
    keepAlive: true,
    maxSockets: 20
  });
  
  const endpoints = [
    '/users',
    '/products',
    '/orders',
    '/payments'
  ];
  
  const requests = endpoints.map(endpoint => {
    return new Promise((resolve, reject) => {
      https.get(`https://api.example.com${endpoint}`, { agent }, (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          resolve({ endpoint, data: JSON.parse(data) });
        });
      }).on('error', reject);
    });
  });
  
  Promise.all(requests)
    .then(results => console.log(results))
    .catch(error => console.error('Error:', error));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12() {
  // Using https.Agent with custom headers
  // ok: javascript-https-connection-pool
  const agent = new https.Agent({
    keepAlive: true
  });
  
  const options = {
    hostname: 'api.example.com',
    path: '/data',
    method: 'GET',
    agent: agent,
    headers: {
      'Authorization': 'Bearer token123',
      'User-Agent': 'CustomClient/1.0',
      'Accept': 'application/json'
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

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13() {
  // Using https.Agent with proxy configuration
  // ok: javascript-https-connection-pool
  const agent = new https.Agent({
    keepAlive: true,
    proxy: 'https://proxy.example.com:8080'
  });
  
  https.get('https://api.example.com/data', { agent }, (res) => {
    let data = '';
    res.on('data', (chunk) => {
      data += chunk;
    });
    res.on('end', () => {
      console.log(JSON.parse(data));
    });
  }).on('error', (e) => {
    console.error('Error:', e);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14() {
  // Using https.Agent with custom socket options
  // ok: javascript-https-connection-pool
  const agent = new https.Agent({
    keepAlive: true,
    socketOptions: {
      noDelay: true,
      keepAlive: true,
      keepAliveInitialDelay: 1000
    }
  });
  
  const options = {
    hostname: 'api.example.com',
    path: '/stream-data',
    method: 'GET',
    agent: agent
  };
  
  const req = https.request(options, (res) => {
    res.on('data', (chunk) => {
      console.log(chunk.toString());
    });
    res.on('end', () => {
      console.log('No more data');
    });
  });
  
  req.end();
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15() {
  // Using https.Agent with error handling
  // ok: javascript-https-connection-pool
  const agent = new https.Agent({
    keepAlive: true,
    maxSockets: 10
  });
  
  function fetchWithRetry(url, retries = 3) {
    return new Promise((resolve, reject) => {
      const makeRequest = (attemptsLeft) => {
        https.get(url, { agent }, (res) => {
          let data = '';
          res.on('data', (chunk) => {
            data += chunk;
          });
          res.on('end', () => {
            try {
              resolve(JSON.parse(data));
            } catch (e) {
              if (attemptsLeft > 0) {
                makeRequest(attemptsLeft - 1);
              } else {
                reject(new Error('Failed to parse response after multiple attempts'));
              }
            }
          });
        }).on('error', (err) => {
          if (attemptsLeft > 0) {
            makeRequest(attemptsLeft - 1);
          } else {
            reject(err);
          }
        });
      };
      
      makeRequest(retries);
    });
  }
  
  fetchWithRetry('https://api.example.com/data')
    .then(data => console.log(data))
    .catch(error => console.error('Error:', error));
}
// {/fact}