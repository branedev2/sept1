// File: socket_binding_test_cases.js

const net = require('net');
const http = require('http');
const dgram = require('dgram');
const tls = require('tls');
const fs = require('fs');
const os = require('os');
const path = require('path');
const dotenv = require('dotenv');

// TRUE POSITIVES (Vulnerable cases)

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1() {
  // Creating a TCP server that binds to all interfaces by using empty string
  const server = net.createServer();
  
  // ruleid: javascript-all-interfaces-socket-binding
  server.listen(8080, '', () => {
    console.log('Server listening on all interfaces on port 8080');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2() {
  // Creating a TCP server that explicitly binds to 0.0.0.0
  const server = net.createServer();
  
  // ruleid: javascript-all-interfaces-socket-binding
  server.listen(8080, '0.0.0.0', () => {
    console.log('Server listening on all interfaces on port 8080');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3() {
  // Creating an HTTP server that binds to all interfaces with empty string
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Hello World\n');
  });
  
  // ruleid: javascript-all-interfaces-socket-binding
  server.listen(8080, '', () => {
    console.log('HTTP server listening on all interfaces on port 8080');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4() {
  // Creating an HTTP server that explicitly binds to 0.0.0.0
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Hello World\n');
  });
  
  // ruleid: javascript-all-interfaces-socket-binding
  server.listen(8080, '0.0.0.0', () => {
    console.log('HTTP server listening on all interfaces on port 8080');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5() {
  // Creating a UDP socket that binds to all interfaces with empty string
  const socket = dgram.createSocket('udp4');
  
  // ruleid: javascript-all-interfaces-socket-binding
  socket.bind(8080, '');
  
  socket.on('listening', () => {
    console.log('UDP server listening on all interfaces on port 8080');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6() {
  // Creating a UDP socket that explicitly binds to 0.0.0.0
  const socket = dgram.createSocket('udp4');
  
  // ruleid: javascript-all-interfaces-socket-binding
  socket.bind(8080, '0.0.0.0');
  
  socket.on('listening', () => {
    console.log('UDP server listening on all interfaces on port 8080');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7() {
  // Creating a TLS server that binds to all interfaces with empty string
  const options = {
    key: fs.readFileSync('server-key.pem'),
    cert: fs.readFileSync('server-cert.pem')
  };
  
  const server = tls.createServer(options, (socket) => {
    console.log('server connected', socket.authorized ? 'authorized' : 'unauthorized');
    socket.write('welcome!\n');
    socket.setEncoding('utf8');
    socket.pipe(socket);
  });
  
  // ruleid: javascript-all-interfaces-socket-binding
  server.listen(8443, '', () => {
    console.log('TLS server listening on all interfaces on port 8443');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8() {
  // Creating a TLS server that explicitly binds to 0.0.0.0
  const options = {
    key: fs.readFileSync('server-key.pem'),
    cert: fs.readFileSync('server-cert.pem')
  };
  
  const server = tls.createServer(options, (socket) => {
    console.log('server connected', socket.authorized ? 'authorized' : 'unauthorized');
    socket.write('welcome!\n');
    socket.setEncoding('utf8');
    socket.pipe(socket);
  });
  
  // ruleid: javascript-all-interfaces-socket-binding
  server.listen(8443, '0.0.0.0', () => {
    console.log('TLS server listening on all interfaces on port 8443');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9() {
  // Creating a TCP server with options object that binds to all interfaces
  const server = net.createServer();
  
  // ruleid: javascript-all-interfaces-socket-binding
  server.listen({
    port: 8080,
    host: '',
    backlog: 511
  }, () => {
    console.log('Server listening on all interfaces on port 8080');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10() {
  // Creating a TCP server with options object that explicitly binds to 0.0.0.0
  const server = net.createServer();
  
  // ruleid: javascript-all-interfaces-socket-binding
  server.listen({
    port: 8080,
    host: '0.0.0.0',
    backlog: 511
  }, () => {
    console.log('Server listening on all interfaces on port 8080');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11() {
  // Creating an HTTP server with variable that binds to all interfaces
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Hello World\n');
  });
  
  const host = '';
  
  // ruleid: javascript-all-interfaces-socket-binding
  server.listen(8080, host, () => {
    console.log(`HTTP server listening on ${host || 'all interfaces'} on port 8080`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12() {
  // Creating an HTTP server with variable that explicitly binds to 0.0.0.0
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Hello World\n');
  });
  
  const host = '0.0.0.0';
  
  // ruleid: javascript-all-interfaces-socket-binding
  server.listen(8080, host, () => {
    console.log(`HTTP server listening on ${host} on port 8080`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13() {
  // Creating a UDP socket with variable that binds to all interfaces
  const socket = dgram.createSocket('udp4');
  
  const host = '';
  
  // ruleid: javascript-all-interfaces-socket-binding
  socket.bind(8080, host);
  
  socket.on('listening', () => {
    console.log(`UDP server listening on ${host || 'all interfaces'} on port 8080`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14() {
  // Creating a UDP socket with variable that explicitly binds to 0.0.0.0
  const socket = dgram.createSocket('udp4');
  
  const host = '0.0.0.0';
  
  // ruleid: javascript-all-interfaces-socket-binding
  socket.bind(8080, host);
  
  socket.on('listening', () => {
    console.log(`UDP server listening on ${host} on port 8080`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15() {
  // Creating a TCP server with conditional that binds to all interfaces
  const server = net.createServer();
  
  const isProduction = process.env.NODE_ENV === 'production';
  const host = isProduction ? '' : 'localhost';
  
  // ruleid: javascript-all-interfaces-socket-binding
  server.listen(8080, host, () => {
    console.log(`Server listening on ${host || 'all interfaces'} on port 8080`);
  });
}
// {/fact}

// TRUE NEGATIVES (Safe cases)

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1() {
  // Creating a TCP server that binds to localhost
  const server = net.createServer();
  
  // ok: javascript-all-interfaces-socket-binding
  server.listen(8080, 'localhost', () => {
    console.log('Server listening on localhost on port 8080');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2() {
  // Creating a TCP server that binds to 127.0.0.1
  const server = net.createServer();
  
  // ok: javascript-all-interfaces-socket-binding
  server.listen(8080, '127.0.0.1', () => {
    console.log('Server listening on 127.0.0.1 on port 8080');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3() {
  // Creating an HTTP server that binds to localhost
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Hello World\n');
  });
  
  // ok: javascript-all-interfaces-socket-binding
  server.listen(8080, 'localhost', () => {
    console.log('HTTP server listening on localhost on port 8080');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4() {
  // Creating an HTTP server that binds to 127.0.0.1
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Hello World\n');
  });
  
  // ok: javascript-all-interfaces-socket-binding
  server.listen(8080, '127.0.0.1', () => {
    console.log('HTTP server listening on 127.0.0.1 on port 8080');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5() {
  // Creating a UDP socket that binds to localhost
  const socket = dgram.createSocket('udp4');
  
  // ok: javascript-all-interfaces-socket-binding
  socket.bind(8080, 'localhost');
  
  socket.on('listening', () => {
    console.log('UDP server listening on localhost on port 8080');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6() {
  // Creating a UDP socket that binds to 127.0.0.1
  const socket = dgram.createSocket('udp4');
  
  // ok: javascript-all-interfaces-socket-binding
  socket.bind(8080, '127.0.0.1');
  
  socket.on('listening', () => {
    console.log('UDP server listening on 127.0.0.1 on port 8080');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7() {
  // Creating a TLS server that binds to localhost
  const options = {
    key: fs.readFileSync('server-key.pem'),
    cert: fs.readFileSync('server-cert.pem')
  };
  
  const server = tls.createServer(options, (socket) => {
    console.log('server connected', socket.authorized ? 'authorized' : 'unauthorized');
    socket.write('welcome!\n');
    socket.setEncoding('utf8');
    socket.pipe(socket);
  });
  
  // ok: javascript-all-interfaces-socket-binding
  server.listen(8443, 'localhost', () => {
    console.log('TLS server listening on localhost on port 8443');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8() {
  // Creating a TLS server that binds to 127.0.0.1
  const options = {
    key: fs.readFileSync('server-key.pem'),
    cert: fs.readFileSync('server-cert.pem')
  };
  
  const server = tls.createServer(options, (socket) => {
    console.log('server connected', socket.authorized ? 'authorized' : 'unauthorized');
    socket.write('welcome!\n');
    socket.setEncoding('utf8');
    socket.pipe(socket);
  });
  
  // ok: javascript-all-interfaces-socket-binding
  server.listen(8443, '127.0.0.1', () => {
    console.log('TLS server listening on 127.0.0.1 on port 8443');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9() {
  // Creating a TCP server with options object that binds to localhost
  const server = net.createServer();
  
  // ok: javascript-all-interfaces-socket-binding
  server.listen({
    port: 8080,
    host: 'localhost',
    backlog: 511
  }, () => {
    console.log('Server listening on localhost on port 8080');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10() {
  // Creating a TCP server with options object that binds to 127.0.0.1
  const server = net.createServer();
  
  // ok: javascript-all-interfaces-socket-binding
  server.listen({
    port: 8080,
    host: '127.0.0.1',
    backlog: 511
  }, () => {
    console.log('Server listening on 127.0.0.1 on port 8080');
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11() {
  // Creating an HTTP server with variable that binds to localhost
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Hello World\n');
  });
  
  const host = 'localhost';
  
  // ok: javascript-all-interfaces-socket-binding
  server.listen(8080, host, () => {
    console.log(`HTTP server listening on ${host} on port 8080`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12() {
  // Creating an HTTP server with variable that binds to 127.0.0.1
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Hello World\n');
  });
  
  const host = '127.0.0.1';
  
  // ok: javascript-all-interfaces-socket-binding
  server.listen(8080, host, () => {
    console.log(`HTTP server listening on ${host} on port 8080`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13() {
  // Creating a UDP socket with variable that binds to localhost
  const socket = dgram.createSocket('udp4');
  
  const host = 'localhost';
  
  // ok: javascript-all-interfaces-socket-binding
  socket.bind(8080, host);
  
  socket.on('listening', () => {
    console.log(`UDP server listening on ${host} on port 8080`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14() {
  // Creating a UDP socket with variable that binds to 127.0.0.1
  const socket = dgram.createSocket('udp4');
  
  const host = '127.0.0.1';
  
  // ok: javascript-all-interfaces-socket-binding
  socket.bind(8080, host);
  
  socket.on('listening', () => {
    console.log(`UDP server listening on ${host} on port 8080`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15() {
  // Creating a TCP server with environment variable for host
  const server = net.createServer();
  
  // Load environment variables
  dotenv.config();
  
  // Use environment variable or default to localhost
  const host = process.env.SERVER_HOST || 'localhost';
  
  // ok: javascript-all-interfaces-socket-binding
  server.listen(8080, host, () => {
    console.log(`Server listening on ${host} on port 8080`);
  });
}
// {/fact}