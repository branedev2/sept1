import * as net from 'net';
import * as http from 'http';
import * as dgram from 'dgram';
import * as os from 'os';
import * as dns from 'dns';
import { promises as fsPromises } from 'fs';

// TRUE POSITIVES (Vulnerable code)

// Example 1: TCP server with empty IP address
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1() {
    const server = net.createServer((socket) => {
        socket.write('Hello client!\n');
        socket.end();
    });
    
    // ruleid: typescript-all-interfaces-socket-binding
    server.listen(3000, '', () => {
        console.log('Server listening on port 3000');
    });
}
// {/fact}

// Example 2: HTTP server with empty IP address
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2() {
    const server = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('Hello World\n');
    });
    
    // ruleid: typescript-all-interfaces-socket-binding
    server.listen(8080, '', () => {
        console.log('HTTP server running on port 8080');
    });
}
// {/fact}

// Example 3: UDP socket with empty IP address
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3() {
    const socket = dgram.createSocket('udp4');
    
    // ruleid: typescript-all-interfaces-socket-binding
    socket.bind(5000, '');
    
    socket.on('message', (msg, rinfo) => {
        console.log(`Received message from ${rinfo.address}:${rinfo.port}`);
    });
}
// {/fact}

// Example 4: TCP server with undefined IP address
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4() {
    const server = net.createServer((socket) => {
        socket.write('Connected to server\n');
        socket.end();
    });
    
    const host = undefined;
    // ruleid: typescript-all-interfaces-socket-binding
    server.listen(3001, host, () => {
        console.log('Server started');
    });
}
// {/fact}

// Example 5: HTTP server with null IP address
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5() {
    const server = http.createServer((req, res) => {
        res.writeHead(200);
        res.end('Response from server');
    });
    
    const host = null;
    // ruleid: typescript-all-interfaces-socket-binding
    server.listen(8081, host, () => {
        console.log('HTTP server started');
    });
}
// {/fact}

// Example 6: TCP server with empty string from configuration
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6() {
    const config = {
        port: 3002,
        host: ''
    };
    
    const server = net.createServer();
    // ruleid: typescript-all-interfaces-socket-binding
    server.listen(config.port, config.host, () => {
        console.log(`Server listening on port ${config.port}`);
    });
}
// {/fact}

// Example 7: HTTP server with empty string from environment variable
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7() {
    const server = http.createServer();
    const port = 8082;
    const host = process.env.HOST || '';
    
    // ruleid: typescript-all-interfaces-socket-binding
    server.listen(port, host, () => {
        console.log(`HTTP server running on ${host}:${port}`);
    });
}
// {/fact}

// Example 8: UDP socket with empty string from function
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8() {
    function getBindAddress() {
        return '';
    }
    
    const socket = dgram.createSocket('udp4');
    // ruleid: typescript-all-interfaces-socket-binding
    socket.bind(5001, getBindAddress());
    
    socket.on('listening', () => {
        console.log('UDP server listening');
    });
}
// {/fact}

// Example 9: TCP server with empty string in options object
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9() {
    const server = net.createServer();
    const options = {
        port: 3003,
        host: ''
    };
    
    // ruleid: typescript-all-interfaces-socket-binding
    server.listen(options);
}
// {/fact}

// Example 10: HTTP server with empty host in complex options
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10() {
    const server = http.createServer();
    const options = {
        port: 8083,
        host: '',
        backlog: 511
    };
    
    // ruleid: typescript-all-interfaces-socket-binding
    server.listen(options);
}
// {/fact}

// Example 11: TCP server with empty host from async function
// {fact rule=insecure-cookie@v1.0 defects=1}
async function bad_case_11() {
    const server = net.createServer();
    
    async function getConfig() {
        return { host: '', port: 3004 };
    }
    
    const config = await getConfig();
    // ruleid: typescript-all-interfaces-socket-binding
    server.listen(config.port, config.host);
}
// {/fact}

// Example 12: HTTP server with empty host in ternary operation
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12() {
    const server = http.createServer();
    const useLocalhost = false;
    
    // ruleid: typescript-all-interfaces-socket-binding
    server.listen(8084, useLocalhost ? 'localhost' : '');
}
// {/fact}

// Example 13: UDP socket with empty host from conditional
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13() {
    const socket = dgram.createSocket('udp4');
    const config = { restrictAccess: false };
    
    const host = config.restrictAccess ? '127.0.0.1' : '';
    // ruleid: typescript-all-interfaces-socket-binding
    socket.bind(5002, host);
}
// {/fact}

// Example 14: TCP server with empty string from template literal
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14() {
    const server = net.createServer();
    const hostPrefix = '';
    const hostSuffix = '';
    
    // ruleid: typescript-all-interfaces-socket-binding
    server.listen(3005, `${hostPrefix}${hostSuffix}`);
}
// {/fact}

// Example 15: HTTP server with empty string from string concatenation
// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15() {
    const server = http.createServer();
    const part1 = '';
    const part2 = '';
    
    // ruleid: typescript-all-interfaces-socket-binding
    server.listen(8085, part1 + part2);
}
// {/fact}

// TRUE NEGATIVES (Safe code)

// Example 1: TCP server with specific IP address
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1() {
    const server = net.createServer((socket) => {
        socket.write('Hello client!\n');
        socket.end();
    });
    
    // ok: typescript-all-interfaces-socket-binding
    server.listen(3000, '127.0.0.1', () => {
        console.log('Server listening on 127.0.0.1:3000');
    });
}
// {/fact}

// Example 2: HTTP server with localhost
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2() {
    const server = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('Hello World\n');
    });
    
    // ok: typescript-all-interfaces-socket-binding
    server.listen(8080, 'localhost', () => {
        console.log('HTTP server running on localhost:8080');
    });
}
// {/fact}

// Example 3: UDP socket with specific IP address
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3() {
    const socket = dgram.createSocket('udp4');
    
    // ok: typescript-all-interfaces-socket-binding
    socket.bind(5000, '192.168.1.100');
    
    socket.on('message', (msg, rinfo) => {
        console.log(`Received message from ${rinfo.address}:${rinfo.port}`);
    });
}
// {/fact}

// Example 4: TCP server with IPv6 loopback address
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4() {
    const server = net.createServer((socket) => {
        socket.write('Connected to server\n');
        socket.end();
    });
    
    // ok: typescript-all-interfaces-socket-binding
    server.listen(3001, '::1', () => {
        console.log('Server started on IPv6 loopback');
    });
}
// {/fact}

// Example 5: HTTP server with specific IP from configuration
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5() {
    const server = http.createServer((req, res) => {
        res.writeHead(200);
        res.end('Response from server');
    });
    
    const config = {
        host: '10.0.0.5',
        port: 8081
    };
    
    // ok: typescript-all-interfaces-socket-binding
    server.listen(config.port, config.host, () => {
        console.log(`HTTP server started on ${config.host}:${config.port}`);
    });
}
// {/fact}

// Example 6: TCP server with IP from environment variable with default
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6() {
    const server = net.createServer();
    const host = process.env.HOST || '127.0.0.1';
    
    // ok: typescript-all-interfaces-socket-binding
    server.listen(3002, host, () => {
        console.log(`Server listening on ${host}:3002`);
    });
}
// {/fact}

// Example 7: HTTP server with specific IP from function
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7() {
    function getBindAddress() {
        return '127.0.0.1';
    }
    
    const server = http.createServer();
    // ok: typescript-all-interfaces-socket-binding
    server.listen(8082, getBindAddress(), () => {
        console.log('HTTP server running');
    });
}
// {/fact}

// Example 8: UDP socket with specific IP in options object
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8() {
    const socket = dgram.createSocket('udp4');
    const options = {
        port: 5001,
        address: '192.168.0.10'
    };
    
    // ok: typescript-all-interfaces-socket-binding
    socket.bind(options);
    
    socket.on('listening', () => {
        console.log('UDP server listening');
    });
}
// {/fact}

// Example 9: TCP server with specific IP from network interface
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9() {
    const server = net.createServer();
    const networkInterfaces = os.networkInterfaces();
    let bindAddress = '127.0.0.1'; // Default fallback
    
    // Get the first IPv4 address that's not internal
    for (const [name, interfaces] of Object.entries(networkInterfaces)) {
        if (interfaces) {
            for (const iface of interfaces) {
                if (iface.family === 'IPv4' && !iface.internal) {
                    bindAddress = iface.address;
                    break;
                }
            }
        }
    }
    
    // ok: typescript-all-interfaces-socket-binding
    server.listen(3003, bindAddress);
}
// {/fact}

// Example 10: HTTP server with specific IP from async function
// {fact rule=insecure-cookie@v1.0 defects=0}
async function good_case_10() {
    const server = http.createServer();
    
    async function getConfig() {
        return { host: '127.0.0.1', port: 8083 };
    }
    
    const config = await getConfig();
    // ok: typescript-all-interfaces-socket-binding
    server.listen(config.port, config.host);
}
// {/fact}

// Example 11: TCP server with specific IP from DNS lookup
// {fact rule=insecure-cookie@v1.0 defects=0}
async function good_case_11() {
    const server = net.createServer();
    
    function lookupHostname(hostname: string): Promise<string> {
        return new Promise((resolve, reject) => {
            dns.lookup(hostname, (err, address) => {
                if (err) reject(err);
                else resolve(address);
            });
        });
    }
    
    try {
        const address = await lookupHostname('localhost');
        // ok: typescript-all-interfaces-socket-binding
        server.listen(3004, address);
    } catch (error) {
        console.error('DNS lookup failed:', error);
        // Fallback to loopback address
        server.listen(3004, '127.0.0.1');
    }
}
// {/fact}

// Example 12: HTTP server with specific IP from configuration file
// {fact rule=insecure-cookie@v1.0 defects=0}
async function good_case_12() {
    const server = http.createServer();
    
    try {
        const configData = await fsPromises.readFile('config.json', 'utf8');
        const config = JSON.parse(configData);
        // ok: typescript-all-interfaces-socket-binding
        server.listen(config.port, config.host || '127.0.0.1');
    } catch (error) {
        console.error('Failed to read config:', error);
        // Fallback to safe default
        server.listen(8084, '127.0.0.1');
    }
}
// {/fact}

// Example 13: UDP socket with specific IP from ternary operation
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13() {
    const socket = dgram.createSocket('udp4');
    const isProduction = process.env.NODE_ENV === 'production';
    
    // ok: typescript-all-interfaces-socket-binding
    socket.bind(5002, isProduction ? '10.0.0.1' : '127.0.0.1');
}
// {/fact}

// Example 14: TCP server with specific IP from template literal
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14() {
    const server = net.createServer();
    const subnet = '192.168.1';
    const host = `${subnet}.10`;
    
    // ok: typescript-all-interfaces-socket-binding
    server.listen(3005, host);
}
// {/fact}

// Example 15: HTTP server with port only (no host specified)
// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15() {
    const server = http.createServer();
    
    // ok: typescript-all-interfaces-socket-binding
    server.listen(8085, () => {
        console.log('Server started on port 8085');
    });
}
// {/fact}