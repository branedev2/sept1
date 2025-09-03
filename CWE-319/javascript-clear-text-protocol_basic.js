const http = require('http');
const https = require('https');
const axios = require('axios');
const fetch = require('node-fetch');
const request = require('request');
const superagent = require('superagent');
const got = require('got');
const net = require('net');
const tls = require('tls');
const ftp = require('ftp');
const ftps = require('ftps');
const telnet = require('telnet-client');
const ssh2 = require('ssh2');
const WebSocket = require('ws');
const mqtt = require('mqtt');
const nodemailer = require('nodemailer');

// True Positives (Vulnerable Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1() {
  // Using HTTP to send sensitive data
  // ruleid: javascript-clear-text-protocol
  const client = http.request({
    hostname: 'api.example.com',
    port: 80,
    path: '/users/authenticate',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    }
  }, (res) => {
    let data = '';
    res.on('data', (chunk) => {
      data += chunk;
    });
    res.on('end', () => {
      console.log(JSON.parse(data));
    });
  });
  
  client.write(JSON.stringify({
    username: 'admin',
    password: 'secret123'
  }));
  client.end();
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2() {
  // Using axios with HTTP protocol for API calls
  // ruleid: javascript-clear-text-protocol
  axios.post('http://payment-gateway.com/process', {
    cardNumber: '4111111111111111',
    expiryDate: '12/25',
    cvv: '123',
    amount: 100.00
  })
  .then(response => {
    console.log('Payment processed:', response.data);
  })
  .catch(error => {
    console.error('Error:', error);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3() {
  // Using fetch with HTTP for user data
  // ruleid: javascript-clear-text-protocol
  fetch('http://userdb.internal.com/api/users', {
    method: 'GET',
    headers: {
      'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
    }
  })
  .then(response => response.json())
  .then(data => {
    for (const user of data.users) {
      console.log(`User: ${user.name}, Email: ${user.email}`);
    }
  })
  .catch(error => console.error('Error fetching users:', error));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4() {
  // Using FTP for file transfer (clear text protocol)
  const client = new ftp();
  
  client.on('ready', function() {
    // ruleid: javascript-clear-text-protocol
    client.put('local-file.txt', 'remote-file.txt', function(err) {
      if (err) throw err;
      client.end();
    });
  });
  
  client.connect({
    host: 'ftp.example.com',
    user: 'username',
    password: 'password'
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5() {
  // Using telnet (clear text protocol)
  const connection = new telnet();
  
  const params = {
    host: 'server.example.com',
    port: 23,
    shellPrompt: '/ # ',
    timeout: 1500
  };
  
  // ruleid: javascript-clear-text-protocol
  connection.connect(params)
  .then(() => {
    return connection.exec('ls -la');
  })
  .then((response) => {
    console.log('Response:', response);
    connection.end();
  })
  .catch((error) => {
    console.log('Error:', error);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6() {
  // Using WebSocket without TLS
  // ruleid: javascript-clear-text-protocol
  const socket = new WebSocket('ws://realtime.example.com/socket');
  
  socket.onopen = function(e) {
    console.log('Connection established');
    socket.send(JSON.stringify({
      type: 'subscribe',
      channel: 'private-user-123',
      auth: 'token-xyz'
    }));
  };
  
  socket.onmessage = function(event) {
    console.log('Data received:', event.data);
  };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7() {
  // Using MQTT without TLS
  // ruleid: javascript-clear-text-protocol
  const client = mqtt.connect('mqtt://broker.example.com', {
    clientId: 'device-123',
    username: 'device',
    password: 'secret-token'
  });
  
  client.on('connect', function() {
    client.subscribe('sensors/temperature');
    client.publish('device/status', JSON.stringify({
      deviceId: 'device-123',
      status: 'online'
    }));
  });
  
  client.on('message', function(topic, message) {
    console.log(`Received message on ${topic}: ${message.toString()}`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8() {
  // Using request library with HTTP
  // ruleid: javascript-clear-text-protocol
  request.post({
    url: 'http://auth.example.com/login',
    form: {
      username: 'admin',
      password: 'admin123'
    }
  }, function(error, response, body) {
    if (error) {
      console.error('Error:', error);
      return;
    }
    console.log('Login response:', body);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9() {
  // Using superagent with HTTP
  // ruleid: javascript-clear-text-protocol
  superagent
    .post('http://api.example.com/users')
    .send({ name: 'John', email: 'john@example.com', ssn: '123-45-6789' })
    .set('accept', 'json')
    .end((err, res) => {
      if (err) {
        console.error(err);
        return;
      }
      console.log('User created:', res.body);
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10() {
  // Using got with HTTP
  async function fetchData() {
    try {
      // ruleid: javascript-clear-text-protocol
      const response = await got('http://financial-data.example.com/transactions', {
        headers: {
          'Authorization': 'Bearer token123'
        }
      });
      console.log('Data:', response.body);
    } catch (error) {
      console.error('Error:', error);
    }
  }
  
  fetchData();
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11() {
  // Using nodemailer with non-TLS SMTP
  // ruleid: javascript-clear-text-protocol
  const transporter = nodemailer.createTransport({
    host: 'smtp.example.com',
    port: 25, // Non-TLS port
    secure: false, // No TLS
    auth: {
      user: 'user@example.com',
      pass: 'password123'
    }
  });
  
  transporter.sendMail({
    from: 'sender@example.com',
    to: 'recipient@example.com',
    subject: 'Confidential Information',
    text: 'This email contains sensitive information...'
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12() {
  // Creating a raw TCP socket for data transfer
  // ruleid: javascript-clear-text-protocol
  const client = net.createConnection({ port: 9000, host: 'dataserver.example.com' }, () => {
    console.log('Connected to server!');
    client.write(JSON.stringify({
      action: 'STORE',
      data: {
        userId: 12345,
        creditCard: '4111111111111111'
      }
    }));
  });
  
  client.on('data', (data) => {
    console.log('Received:', data.toString());
    client.end();
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13() {
  // Using HTTP URL in browser environment
  function submitForm() {
    const userData = {
      username: document.getElementById('username').value,
      password: document.getElementById('password').value
    };
    
    // ruleid: javascript-clear-text-protocol
    fetch('http://auth.example.com/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(userData)
    })
    .then(response => response.json())
    .then(data => {
      localStorage.setItem('authToken', data.token);
      window.location.href = '/dashboard';
    })
    .catch(error => console.error('Login failed:', error));
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14() {
  // Using XMLHttpRequest with HTTP
  function getUserData() {
    const xhr = new XMLHttpRequest();
    // ruleid: javascript-clear-text-protocol
    xhr.open('GET', 'http://api.example.com/user/profile', true);
    xhr.setRequestHeader('Authorization', 'Bearer ' + localStorage.getItem('token'));
    
    xhr.onreadystatechange = function() {
      if (xhr.readyState === 4 && xhr.status === 200) {
        const userData = JSON.parse(xhr.responseText);
        displayUserProfile(userData);
      }
    };
    
    xhr.send();
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15() {
  // Hardcoded HTTP URL in configuration
  const config = {
    // ruleid: javascript-clear-text-protocol
    apiEndpoint: 'http://api.internal.company.com/v2',
    authService: 'http://auth.internal.company.com',
    dataWarehouse: 'http://data.internal.company.com'
  };
  
  function initialize() {
    fetch(`${config.apiEndpoint}/initialize`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${getToken()}`
      }
    })
    .then(response => response.json())
    .then(data => console.log('System initialized:', data))
    .catch(error => console.error('Initialization failed:', error));
  }
  
  function getToken() {
    // Get authentication token
    return 'sample-token-123';
  }
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1() {
  // Using HTTPS to send sensitive data
  // ok: javascript-clear-text-protocol
  const client = https.request({
    hostname: 'api.example.com',
    port: 443,
    path: '/users/authenticate',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    }
  }, (res) => {
    let data = '';
    res.on('data', (chunk) => {
      data += chunk;
    });
    res.on('end', () => {
      console.log(JSON.parse(data));
    });
  });
  
  client.write(JSON.stringify({
    username: 'admin',
    password: 'secret123'
  }));
  client.end();
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2() {
  // Using axios with HTTPS protocol for API calls
  // ok: javascript-clear-text-protocol
  axios.post('https://payment-gateway.com/process', {
    cardNumber: '4111111111111111',
    expiryDate: '12/25',
    cvv: '123',
    amount: 100.00
  })
  .then(response => {
    console.log('Payment processed:', response.data);
  })
  .catch(error => {
    console.error('Error:', error);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3() {
  // Using fetch with HTTPS for user data
  // ok: javascript-clear-text-protocol
  fetch('https://userdb.internal.com/api/users', {
    method: 'GET',
    headers: {
      'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
    }
  })
  .then(response => response.json())
  .then(data => {
    for (const user of data.users) {
      console.log(`User: ${user.name}, Email: ${user.email}`);
    }
  })
  .catch(error => console.error('Error fetching users:', error));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4() {
  // Using SFTP instead of FTP for secure file transfer
  const Client = require('ssh2-sftp-client');
  const sftp = new Client();
  
  // ok: javascript-clear-text-protocol
  sftp.connect({
    host: 'sftp.example.com',
    port: 22,
    username: 'username',
    password: 'password'
  })
  .then(() => {
    return sftp.put('local-file.txt', 'remote-file.txt');
  })
  .then(() => {
    console.log('File transferred successfully');
    return sftp.end();
  })
  .catch(err => {
    console.error('Error:', err);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5() {
  // Using SSH instead of telnet
  const Client = require('ssh2').Client;
  const conn = new Client();
  
  // ok: javascript-clear-text-protocol
  conn.on('ready', function() {
    console.log('Connection established');
    conn.exec('ls -la', function(err, stream) {
      if (err) throw err;
      stream.on('close', function(code, signal) {
        console.log('Stream closed');
        conn.end();
      }).on('data', function(data) {
        console.log('STDOUT: ' + data);
      }).stderr.on('data', function(data) {
        console.log('STDERR: ' + data);
      });
    });
  }).connect({
    host: 'server.example.com',
    port: 22,
    username: 'username',
    password: 'password'
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6() {
  // Using WebSocket with TLS (WSS)
  // ok: javascript-clear-text-protocol
  const socket = new WebSocket('wss://realtime.example.com/socket');
  
  socket.onopen = function(e) {
    console.log('Connection established');
    socket.send(JSON.stringify({
      type: 'subscribe',
      channel: 'private-user-123',
      auth: 'token-xyz'
    }));
  };
  
  socket.onmessage = function(event) {
    console.log('Data received:', event.data);
  };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7() {
  // Using MQTT with TLS
  // ok: javascript-clear-text-protocol
  const client = mqtt.connect('mqtts://broker.example.com', {
    clientId: 'device-123',
    username: 'device',
    password: 'secret-token'
  });
  
  client.on('connect', function() {
    client.subscribe('sensors/temperature');
    client.publish('device/status', JSON.stringify({
      deviceId: 'device-123',
      status: 'online'
    }));
  });
  
  client.on('message', function(topic, message) {
    console.log(`Received message on ${topic}: ${message.toString()}`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8() {
  // Using request library with HTTPS
  // ok: javascript-clear-text-protocol
  request.post({
    url: 'https://auth.example.com/login',
    form: {
      username: 'admin',
      password: 'admin123'
    }
  }, function(error, response, body) {
    if (error) {
      console.error('Error:', error);
      return;
    }
    console.log('Login response:', body);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9() {
  // Using superagent with HTTPS
  // ok: javascript-clear-text-protocol
  superagent
    .post('https://api.example.com/users')
    .send({ name: 'John', email: 'john@example.com', ssn: '123-45-6789' })
    .set('accept', 'json')
    .end((err, res) => {
      if (err) {
        console.error(err);
        return;
      }
      console.log('User created:', res.body);
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10() {
  // Using got with HTTPS
  async function fetchData() {
    try {
      // ok: javascript-clear-text-protocol
      const response = await got('https://financial-data.example.com/transactions', {
        headers: {
          'Authorization': 'Bearer token123'
        }
      });
      console.log('Data:', response.body);
    } catch (error) {
      console.error('Error:', error);
    }
  }
  
  fetchData();
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11() {
  // Using nodemailer with TLS SMTP
  // ok: javascript-clear-text-protocol
  const transporter = nodemailer.createTransport({
    host: 'smtp.example.com',
    port: 465, // TLS port
    secure: true, // Use TLS
    auth: {
      user: 'user@example.com',
      pass: 'password123'
    }
  });
  
  transporter.sendMail({
    from: 'sender@example.com',
    to: 'recipient@example.com',
    subject: 'Confidential Information',
    text: 'This email contains sensitive information...'
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12() {
  // Using TLS socket instead of raw TCP
  // ok: javascript-clear-text-protocol
  const client = tls.connect({
    port: 9000,
    host: 'dataserver.example.com',
    rejectUnauthorized: true
  }, () => {
    console.log('Connected to server!');
    client.write(JSON.stringify({
      action: 'STORE',
      data: {
        userId: 12345,
        creditCard: '4111111111111111'
      }
    }));
  });
  
  client.on('data', (data) => {
    console.log('Received:', data.toString());
    client.end();
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13() {
  // Using HTTPS URL in browser environment
  function submitForm() {
    const userData = {
      username: document.getElementById('username').value,
      password: document.getElementById('password').value
    };
    
    // ok: javascript-clear-text-protocol
    fetch('https://auth.example.com/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(userData)
    })
    .then(response => response.json())
    .then(data => {
      localStorage.setItem('authToken', data.token);
      window.location.href = '/dashboard';
    })
    .catch(error => console.error('Login failed:', error));
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14() {
  // Using XMLHttpRequest with HTTPS
  function getUserData() {
    const xhr = new XMLHttpRequest();
    // ok: javascript-clear-text-protocol
    xhr.open('GET', 'https://api.example.com/user/profile', true);
    xhr.setRequestHeader('Authorization', 'Bearer ' + localStorage.getItem('token'));
    
    xhr.onreadystatechange = function() {
      if (xhr.readyState === 4 && xhr.status === 200) {
        const userData = JSON.parse(xhr.responseText);
        displayUserProfile(userData);
      }
    };
    
    xhr.send();
  }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15() {
  // Using HTTPS URLs in configuration
  const config = {
    // ok: javascript-clear-text-protocol
    apiEndpoint: 'https://api.internal.company.com/v2',
    authService: 'https://auth.internal.company.com',
    dataWarehouse: 'https://data.internal.company.com'
  };
  
  function initialize() {
    fetch(`${config.apiEndpoint}/initialize`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${getToken()}`
      }
    })
    .then(response => response.json())
    .then(data => console.log('System initialized:', data))
    .catch(error => console.error('Initialization failed:', error));
  }
  
  function getToken() {
    // Get authentication token
    return 'sample-token-123';
  }
}
// {/fact}