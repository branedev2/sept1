// File: cleartext_protocol_tests.ts

import * as http from 'http';
import * as https from 'https';
import * as net from 'net';
import * as tls from 'tls';
import * as fs from 'fs';
import * as ftp from 'ftp';
import * as ssh2 from 'ssh2';
import * as nodemailer from 'nodemailer';
import axios from 'axios';
import { MongoClient } from 'mongodb';
import { Client } from 'pg';
import * as mysql from 'mysql';
import * as redis from 'redis';
import * as mqtt from 'mqtt';
import * as ldap from 'ldapjs';
import * as amqp from 'amqplib';
import * as WebSocket from 'ws';

// True Positive Examples (Insecure/Vulnerable Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1() {
  // Using HTTP protocol to fetch sensitive data
  // ruleid: typescript-clear-text-protocol
  const client = http.get('http://api.example.com/users', (response) => {
    let data = '';
    response.on('data', (chunk) => {
      data += chunk;
    });
    response.on('end', () => {
      const users = JSON.parse(data);
      console.log('User data retrieved:', users);
    });
  });
  
  client.on('error', (err) => {
    console.error('Error fetching user data:', err);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2() {
  // Using axios with HTTP protocol for API authentication
  const apiKey = 'secret-api-key-12345';
  
  // ruleid: typescript-clear-text-protocol
  axios.post('http://api.payment-gateway.com/process', {
    amount: 100.50,
    cardNumber: '4111111111111111',
    expiryDate: '12/25',
    cvv: '123'
  }, {
    headers: {
      'Authorization': `Bearer ${apiKey}`
    }
  })
  .then(response => {
    console.log('Payment processed:', response.data);
  })
  .catch(error => {
    console.error('Payment failed:', error);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3() {
  // Using FTP to transfer sensitive files
  const client = new ftp();
  
  // ruleid: typescript-clear-text-protocol
  client.connect({
    host: 'ftp.example.com',
    user: 'username',
    password: 'password123'
  });
  
  client.on('ready', () => {
    client.put('local-financial-report.xlsx', 'financial-report.xlsx', (err) => {
      if (err) throw err;
      console.log('File transferred successfully');
      client.end();
    });
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4() {
  // Using telnet for server administration
  const socket = new net.Socket();
  
  // ruleid: typescript-clear-text-protocol
  socket.connect(23, 'server.example.com', () => {
    console.log('Connected to server');
    socket.write('admin\n');
    socket.write('supersecretpassword\n');
    socket.write('show system status\n');
  });
  
  socket.on('data', (data) => {
    console.log('Received:', data.toString());
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5() {
  // Creating an HTTP server to handle sensitive data
  // ruleid: typescript-clear-text-protocol
  const server = http.createServer((req, res) => {
    if (req.url === '/api/login' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => {
        body += chunk.toString();
      });
      req.on('end', () => {
        const { username, password } = JSON.parse(body);
        // Process login
        res.end(JSON.stringify({ token: 'user-auth-token-123' }));
      });
    }
  });
  
  server.listen(8080, () => {
    console.log('Server running on port 8080');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6() {
  // Using MongoDB with non-TLS connection
  // ruleid: typescript-clear-text-protocol
  const url = 'mongodb://username:password@mongodb.example.com:27017/admin';
  
  MongoClient.connect(url, (err, client) => {
    if (err) throw err;
    const db = client.db('users');
    db.collection('credentials').find({}).toArray((err, result) => {
      if (err) throw err;
      console.log('Retrieved user credentials:', result);
      client.close();
    });
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7() {
  // Using PostgreSQL without SSL
  const config = {
    host: 'db.example.com',
    port: 5432,
    database: 'financial',
    user: 'admin',
    password: 'dbpassword',
    // No SSL configuration
  };
  
  const client = new Client(config);
  
  // ruleid: typescript-clear-text-protocol
  client.connect()
    .then(() => {
      return client.query('SELECT * FROM customer_data');
    })
    .then(res => {
      console.log('Customer data:', res.rows);
      client.end();
    })
    .catch(err => {
      console.error('Database error:', err);
      client.end();
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8() {
  // Using MQTT without TLS
  // ruleid: typescript-clear-text-protocol
  const client = mqtt.connect('mqtt://broker.example.com:1883', {
    username: 'iotdevice',
    password: 'iot-secret-key'
  });
  
  client.on('connect', () => {
    console.log('Connected to MQTT broker');
    client.subscribe('sensors/data');
    client.publish('sensors/command', JSON.stringify({ action: 'read' }));
  });
  
  client.on('message', (topic, message) => {
    console.log(`Received message on ${topic}: ${message.toString()}`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9() {
  // Using LDAP without TLS
  // ruleid: typescript-clear-text-protocol
  const client = ldap.createClient({
    url: 'ldap://directory.example.com:389'
  });
  
  client.bind('cn=admin,dc=example,dc=com', 'admin-password', (err) => {
    if (err) {
      console.error('LDAP bind error:', err);
      return;
    }
    
    const opts = {
      filter: '(objectClass=user)',
      scope: 'sub',
      attributes: ['cn', 'mail']
    };
    
    client.search('dc=example,dc=com', opts, (err, res) => {
      if (err) {
        console.error('LDAP search error:', err);
        return;
      }
      
      res.on('searchEntry', (entry) => {
        console.log('User found:', entry.object);
      });
    });
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10() {
  // Using Redis without TLS
  // ruleid: typescript-clear-text-protocol
  const client = redis.createClient({
    host: 'cache.example.com',
    port: 6379,
    password: 'redis-password'
  });
  
  client.on('connect', () => {
    console.log('Connected to Redis');
    client.set('session:user123', JSON.stringify({ isAdmin: true, token: 'secret-token' }));
    client.get('session:user123', (err, reply) => {
      if (err) throw err;
      console.log('Session data:', reply);
    });
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11() {
  // Using RabbitMQ/AMQP without TLS
  // ruleid: typescript-clear-text-protocol
  amqp.connect('amqp://user:password@rabbitmq.example.com:5672')
    .then(connection => {
      return connection.createChannel();
    })
    .then(channel => {
      const queue = 'payment_processing';
      channel.assertQueue(queue, { durable: true });
      
      const paymentData = JSON.stringify({
        cardNumber: '4111111111111111',
        expiryDate: '12/25',
        cvv: '123',
        amount: 500
      });
      
      channel.sendToQueue(queue, Buffer.from(paymentData));
      console.log('Payment data sent to queue');
    })
    .catch(err => {
      console.error('RabbitMQ error:', err);
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12() {
  // Using WebSocket without TLS
  // ruleid: typescript-clear-text-protocol
  const ws = new WebSocket('ws://realtime.example.com/socket');
  
  ws.on('open', () => {
    console.log('Connected to WebSocket server');
    ws.send(JSON.stringify({
      type: 'auth',
      token: 'user-auth-token-123'
    }));
  });
  
  ws.on('message', (data) => {
    const message = JSON.parse(data.toString());
    console.log('Received message:', message);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13() {
  // Using MySQL without SSL
  // ruleid: typescript-clear-text-protocol
  const connection = mysql.createConnection({
    host: 'db.example.com',
    user: 'dbuser',
    password: 'dbpassword',
    database: 'customer_data'
  });
  
  connection.connect();
  
  connection.query('SELECT * FROM payment_methods', (error, results) => {
    if (error) throw error;
    console.log('Payment methods:', results);
    connection.end();
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14() {
  // Using SMTP without TLS
  // ruleid: typescript-clear-text-protocol
  const transporter = nodemailer.createTransport({
    host: 'smtp.example.com',
    port: 25, // Standard SMTP port (non-encrypted)
    secure: false,
    auth: {
      user: 'notifications@example.com',
      pass: 'email-password'
    }
  });
  
  const mailOptions = {
    from: 'notifications@example.com',
    to: 'user@example.com',
    subject: 'Your account information',
    text: 'Your username is user123 and temporary password is temp123'
  };
  
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error('Email error:', error);
    } else {
      console.log('Email sent:', info.response);
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15() {
  // Creating a custom HTTP client for API calls
  const options = {
    hostname: 'api.example.com',
    port: 80,
    path: '/users/authenticate',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    }
  };
  
  const userData = JSON.stringify({
    username: 'admin',
    password: 'super-secret-password'
  });
  
  // ruleid: typescript-clear-text-protocol
  const req = http.request(options, (res) => {
    let data = '';
    res.on('data', (chunk) => {
      data += chunk;
    });
    res.on('end', () => {
      console.log('Authentication response:', JSON.parse(data));
    });
  });
  
  req.on('error', (error) => {
    console.error('Request error:', error);
  });
  
  req.write(userData);
  req.end();
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1() {
  // Using HTTPS protocol to fetch sensitive data
  // ok: typescript-clear-text-protocol
  const client = https.get('https://api.example.com/users', (response) => {
    let data = '';
    response.on('data', (chunk) => {
      data += chunk;
    });
    response.on('end', () => {
      const users = JSON.parse(data);
      console.log('User data retrieved:', users);
    });
  });
  
  client.on('error', (err) => {
    console.error('Error fetching user data:', err);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2() {
  // Using axios with HTTPS protocol for API authentication
  const apiKey = 'secret-api-key-12345';
  
  // ok: typescript-clear-text-protocol
  axios.post('https://api.payment-gateway.com/process', {
    amount: 100.50,
    cardNumber: '4111111111111111',
    expiryDate: '12/25',
    cvv: '123'
  }, {
    headers: {
      'Authorization': `Bearer ${apiKey}`
    }
  })
  .then(response => {
    console.log('Payment processed:', response.data);
  })
  .catch(error => {
    console.error('Payment failed:', error);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3() {
  // Using SFTP to transfer sensitive files
  const Client = require('ssh2-sftp-client');
  const sftp = new Client();
  
  // ok: typescript-clear-text-protocol
  sftp.connect({
    host: 'sftp.example.com',
    port: 22,
    username: 'username',
    password: 'password123'
  })
  .then(() => {
    return sftp.put('local-financial-report.xlsx', 'financial-report.xlsx');
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
function good_case_4() {
  // Using SSH for server administration
  const conn = new ssh2.Client();
  
  // ok: typescript-clear-text-protocol
  conn.on('ready', () => {
    console.log('Connected to server');
    conn.exec('show system status', (err, stream) => {
      if (err) throw err;
      stream.on('data', (data) => {
        console.log('Output:', data.toString());
      });
      stream.on('close', () => {
        conn.end();
      });
    });
  }).connect({
    host: 'server.example.com',
    port: 22,
    username: 'admin',
    password: 'supersecretpassword'
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5() {
  // Creating an HTTPS server to handle sensitive data
  const options = {
    key: fs.readFileSync('server-key.pem'),
    cert: fs.readFileSync('server-cert.pem')
  };
  
  // ok: typescript-clear-text-protocol
  const server = https.createServer(options, (req, res) => {
    if (req.url === '/api/login' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => {
        body += chunk.toString();
      });
      req.on('end', () => {
        const { username, password } = JSON.parse(body);
        // Process login
        res.end(JSON.stringify({ token: 'user-auth-token-123' }));
      });
    }
  });
  
  server.listen(8443, () => {
    console.log('Secure server running on port 8443');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6() {
  // Using MongoDB with TLS connection
  // ok: typescript-clear-text-protocol
  const url = 'mongodb+srv://username:password@mongodb.example.com/admin?ssl=true';
  
  MongoClient.connect(url, (err, client) => {
    if (err) throw err;
    const db = client.db('users');
    db.collection('credentials').find({}).toArray((err, result) => {
      if (err) throw err;
      console.log('Retrieved user credentials:', result);
      client.close();
    });
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7() {
  // Using PostgreSQL with SSL
  const config = {
    host: 'db.example.com',
    port: 5432,
    database: 'financial',
    user: 'admin',
    password: 'dbpassword',
    // ok: typescript-clear-text-protocol
    ssl: {
      rejectUnauthorized: true,
      ca: fs.readFileSync('server-ca.pem').toString(),
      key: fs.readFileSync('client-key.pem').toString(),
      cert: fs.readFileSync('client-cert.pem').toString(),
    }
  };
  
  const client = new Client(config);
  
  client.connect()
    .then(() => {
      return client.query('SELECT * FROM customer_data');
    })
    .then(res => {
      console.log('Customer data:', res.rows);
      client.end();
    })
    .catch(err => {
      console.error('Database error:', err);
      client.end();
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8() {
  // Using MQTT with TLS
  // ok: typescript-clear-text-protocol
  const client = mqtt.connect('mqtts://broker.example.com:8883', {
    username: 'iotdevice',
    password: 'iot-secret-key',
    rejectUnauthorized: true,
    ca: fs.readFileSync('ca.pem')
  });
  
  client.on('connect', () => {
    console.log('Connected to MQTT broker securely');
    client.subscribe('sensors/data');
    client.publish('sensors/command', JSON.stringify({ action: 'read' }));
  });
  
  client.on('message', (topic, message) => {
    console.log(`Received message on ${topic}: ${message.toString()}`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9() {
  // Using LDAP with TLS
  // ok: typescript-clear-text-protocol
  const client = ldap.createClient({
    url: 'ldaps://directory.example.com:636',
    tlsOptions: {
      rejectUnauthorized: true,
      ca: [fs.readFileSync('ca.pem')]
    }
  });
  
  client.bind('cn=admin,dc=example,dc=com', 'admin-password', (err) => {
    if (err) {
      console.error('LDAP bind error:', err);
      return;
    }
    
    const opts = {
      filter: '(objectClass=user)',
      scope: 'sub',
      attributes: ['cn', 'mail']
    };
    
    client.search('dc=example,dc=com', opts, (err, res) => {
      if (err) {
        console.error('LDAP search error:', err);
        return;
      }
      
      res.on('searchEntry', (entry) => {
        console.log('User found:', entry.object);
      });
    });
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10() {
  // Using Redis with TLS
  // ok: typescript-clear-text-protocol
  const client = redis.createClient({
    host: 'cache.example.com',
    port: 6380,
    password: 'redis-password',
    tls: {
      rejectUnauthorized: true,
      ca: fs.readFileSync('ca.pem')
    }
  });
  
  client.on('connect', () => {
    console.log('Connected to Redis securely');
    client.set('session:user123', JSON.stringify({ isAdmin: true, token: 'secret-token' }));
    client.get('session:user123', (err, reply) => {
      if (err) throw err;
      console.log('Session data:', reply);
    });
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11() {
  // Using RabbitMQ/AMQP with TLS
  // ok: typescript-clear-text-protocol
  amqp.connect('amqps://user:password@rabbitmq.example.com:5671', {
    ca: [fs.readFileSync('ca.pem')],
    cert: fs.readFileSync('client-cert.pem'),
    key: fs.readFileSync('client-key.pem'),
    rejectUnauthorized: true
  })
    .then(connection => {
      return connection.createChannel();
    })
    .then(channel => {
      const queue = 'payment_processing';
      channel.assertQueue(queue, { durable: true });
      
      const paymentData = JSON.stringify({
        cardNumber: '4111111111111111',
        expiryDate: '12/25',
        cvv: '123',
        amount: 500
      });
      
      channel.sendToQueue(queue, Buffer.from(paymentData));
      console.log('Payment data sent to queue securely');
    })
    .catch(err => {
      console.error('RabbitMQ error:', err);
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12() {
  // Using WebSocket with TLS
  // ok: typescript-clear-text-protocol
  const ws = new WebSocket('wss://realtime.example.com/socket');
  
  ws.on('open', () => {
    console.log('Connected to WebSocket server securely');
    ws.send(JSON.stringify({
      type: 'auth',
      token: 'user-auth-token-123'
    }));
  });
  
  ws.on('message', (data) => {
    const message = JSON.parse(data.toString());
    console.log('Received message:', message);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13() {
  // Using MySQL with SSL
  // ok: typescript-clear-text-protocol
  const connection = mysql.createConnection({
    host: 'db.example.com',
    user: 'dbuser',
    password: 'dbpassword',
    database: 'customer_data',
    ssl: {
      ca: fs.readFileSync('ca.pem'),
      key: fs.readFileSync('client-key.pem'),
      cert: fs.readFileSync('client-cert.pem')
    }
  });
  
  connection.connect();
  
  connection.query('SELECT * FROM payment_methods', (error, results) => {
    if (error) throw error;
    console.log('Payment methods:', results);
    connection.end();
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14() {
  // Using SMTP with TLS
  // ok: typescript-clear-text-protocol
  const transporter = nodemailer.createTransport({
    host: 'smtp.example.com',
    port: 465, // Secure SMTP port
    secure: true, // Use TLS
    auth: {
      user: 'notifications@example.com',
      pass: 'email-password'
    }
  });
  
  const mailOptions = {
    from: 'notifications@example.com',
    to: 'user@example.com',
    subject: 'Your account information',
    text: 'Your username is user123 and temporary password is temp123'
  };
  
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error('Email error:', error);
    } else {
      console.log('Email sent:', info.response);
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15() {
  // Creating a custom HTTPS client for API calls
  const options = {
    hostname: 'api.example.com',
    port: 443,
    path: '/users/authenticate',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    }
  };
  
  const userData = JSON.stringify({
    username: 'admin',
    password: 'super-secret-password'
  });
  
  // ok: typescript-clear-text-protocol
  const req = https.request(options, (res) => {
    let data = '';
    res.on('data', (chunk) => {
      data += chunk;
    });
    res.on('end', () => {
      console.log('Authentication response:', JSON.parse(data));
    });
  });
  
  req.on('error', (error) => {
    console.error('Request error:', error);
  });
  
  req.write(userData);
  req.end();
}
// {/fact}