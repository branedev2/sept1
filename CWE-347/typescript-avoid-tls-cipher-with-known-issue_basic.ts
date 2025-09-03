// File: tls_cipher_test_cases.ts
import * as https from 'https';
import * as tls from 'tls';
import * as fs from 'fs';
import * as crypto from 'crypto';
import * as constants from 'constants';

// True Positive Examples (Vulnerable Code)

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_1() {
    const options = {
        key: fs.readFileSync('server.key'),
        cert: fs.readFileSync('server.crt'),
        // ruleid: typescript-avoid-tls-cipher-with-known-issue
        ciphers: 'RC4-SHA:RC4:ECDHE-RSA-RC4-SHA'
    };
    
    https.createServer(options, (req, res) => {
        res.writeHead(200);
        res.end('Hello World\n');
    }).listen(8000);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_2() {
    const tlsOptions = {
        // ruleid: typescript-avoid-tls-cipher-with-known-issue
        ciphers: 'DES-CBC3-SHA',
        key: fs.readFileSync('client.key'),
        cert: fs.readFileSync('client.crt')
    };
    
    const socket = tls.connect(443, 'example.com', tlsOptions, () => {
        console.log('Connection established');
    });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_3() {
    const server = tls.createServer({
        key: fs.readFileSync('server.key'),
        cert: fs.readFileSync('server.crt'),
        // ruleid: typescript-avoid-tls-cipher-with-known-issue
        ciphers: 'AES128-SHA:AES256-SHA:RC4-SHA:DES-CBC3-SHA'
    });
    
    server.listen(8000, () => {
        console.log('Server listening');
    });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_4() {
    // Using Node.js constants for ciphers
    const options = {
        key: fs.readFileSync('server.key'),
        cert: fs.readFileSync('server.crt'),
        // ruleid: typescript-avoid-tls-cipher-with-known-issue
        ciphers: 'ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA'
    };
    
    https.createServer(options, (req, res) => {
        res.writeHead(200);
        res.end('Secure server\n');
    }).listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_5() {
    const config = {
        // ruleid: typescript-avoid-tls-cipher-with-known-issue
        cipherSuites: 'TLS_RSA_WITH_RC4_128_SHA',
        key: fs.readFileSync('private.key'),
        cert: fs.readFileSync('certificate.crt')
    };
    
    const server = https.createServer(config);
    server.listen(443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_6() {
    class SecureConnection {
        constructor() {
            this.options = {
                // ruleid: typescript-avoid-tls-cipher-with-known-issue
                ciphers: 'ECDHE-RSA-RC4-SHA:RC4-SHA:RC4-MD5',
                key: fs.readFileSync('key.pem'),
                cert: fs.readFileSync('cert.pem')
            };
        }
        
        connect() {
            return tls.connect(443, 'secure.example.com', this.options);
        }
    }
    
    const connection = new SecureConnection();
    connection.connect();
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_7() {
    const httpsOptions = {
        key: fs.readFileSync('key.pem'),
        cert: fs.readFileSync('cert.pem'),
        // ruleid: typescript-avoid-tls-cipher-with-known-issue
        ciphers: 'ECDHE-RSA-AES128-SHA:AES128-SHA:DES-CBC3-SHA'
    };
    
    const server = https.createServer(httpsOptions);
    server.listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_8() {
    function setupTlsServer() {
        const serverOptions = {
            // ruleid: typescript-avoid-tls-cipher-with-known-issue
            ciphers: 'ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:RC4:HIGH:!MD5:!aNULL',
            key: fs.readFileSync('server.key'),
            cert: fs.readFileSync('server.cert')
        };
        
        return tls.createServer(serverOptions, (socket) => {
            socket.write('Welcome!\n');
            socket.pipe(socket);
        });
    }
    
    const server = setupTlsServer();
    server.listen(8000);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_9() {
    const options = {
        hostname: 'api.example.com',
        port: 443,
        path: '/data',
        method: 'GET',
        key: fs.readFileSync('client.key'),
        cert: fs.readFileSync('client.cert'),
        // ruleid: typescript-avoid-tls-cipher-with-known-issue
        ciphers: 'AES256-SHA:RC4-SHA:DES-CBC3-SHA'
    };
    
    const req = https.request(options, (res) => {
        console.log('statusCode:', res.statusCode);
    });
    req.end();
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_10() {
    const tlsConnectionParams = {
        host: 'secure.example.org',
        port: 443,
        // ruleid: typescript-avoid-tls-cipher-with-known-issue
        ciphers: 'ECDHE-RSA-AES128-SHA256:AES128-GCM-SHA256:RC4:ECDHE-RSA-RC4-SHA:DES-CBC3-SHA'
    };
    
    const socket = tls.connect(tlsConnectionParams, () => {
        console.log('Connection established using cipher:', socket.getCipher());
    });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_11() {
    const secureContextOptions = {
        // ruleid: typescript-avoid-tls-cipher-with-known-issue
        ciphers: 'ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:RC4-SHA',
        key: fs.readFileSync('key.pem'),
        cert: fs.readFileSync('cert.pem')
    };
    
    const secureContext = tls.createSecureContext(secureContextOptions);
    const server = tls.createServer({
        secureContext: secureContext
    });
    server.listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_12() {
    class ApiClient {
        constructor() {
            this.httpsAgent = new https.Agent({
                // ruleid: typescript-avoid-tls-cipher-with-known-issue
                ciphers: 'AES128-GCM-SHA256:AES256-GCM-SHA384:ECDHE-RSA-RC4-SHA',
                key: fs.readFileSync('client.key'),
                cert: fs.readFileSync('client.cert')
            });
        }
        
        makeRequest() {
            return https.get('https://api.example.com', { agent: this.httpsAgent });
        }
    }
    
    const client = new ApiClient();
    client.makeRequest();
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_13() {
    const serverConfig = {
        // ruleid: typescript-avoid-tls-cipher-with-known-issue
        cipherSuites: 'TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_RC4_128_SHA',
        key: fs.readFileSync('server.key'),
        cert: fs.readFileSync('server.cert')
    };
    
    const server = https.createServer(serverConfig);
    server.listen(443, () => {
        console.log('Server running');
    });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_14() {
    const options = {
        // ruleid: typescript-avoid-tls-cipher-with-known-issue
        ciphers: 'ECDHE-RSA-AES128-SHA:AES128-SHA:DES-CBC3-SHA:ADH-AES256-SHA',
        secureProtocol: 'TLSv1_2_method',
        key: fs.readFileSync('key.pem'),
        cert: fs.readFileSync('cert.pem')
    };
    
    const server = tls.createServer(options, (socket) => {
        socket.write('welcome!\n');
        socket.pipe(socket);
    });
    server.listen(8000);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_15() {
    const tlsOptions = {
        key: fs.readFileSync('client.key'),
        cert: fs.readFileSync('client.cert'),
        // ruleid: typescript-avoid-tls-cipher-with-known-issue
        ciphers: 'ECDHE-RSA-AES256-SHA:AES256-SHA:RC4-SHA:DHE-RSA-AES128-SHA:EDH-RSA-DES-CBC3-SHA'
    };
    
    const socket = tls.connect(443, 'api.example.com', tlsOptions, () => {
        console.log('Connected');
        socket.write('GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n');
    });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_1() {
    const options = {
        key: fs.readFileSync('server.key'),
        cert: fs.readFileSync('server.crt'),
        // ok: typescript-avoid-tls-cipher-with-known-issue
        ciphers: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
    };
    
    https.createServer(options, (req, res) => {
        res.writeHead(200);
        res.end('Hello World\n');
    }).listen(8000);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_2() {
    const tlsOptions = {
        // ok: typescript-avoid-tls-cipher-with-known-issue
        ciphers: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        key: fs.readFileSync('client.key'),
        cert: fs.readFileSync('client.crt')
    };
    
    const socket = tls.connect(443, 'example.com', tlsOptions, () => {
        console.log('Connection established');
    });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_3() {
    const server = tls.createServer({
        key: fs.readFileSync('server.key'),
        cert: fs.readFileSync('server.crt'),
        // ok: typescript-avoid-tls-cipher-with-known-issue
        ciphers: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256'
    });
    
    server.listen(8000, () => {
        console.log('Server listening');
    });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_4() {
    const options = {
        key: fs.readFileSync('server.key'),
        cert: fs.readFileSync('server.crt'),
        // ok: typescript-avoid-tls-cipher-with-known-issue
        ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384'
    };
    
    https.createServer(options, (req, res) => {
        res.writeHead(200);
        res.end('Secure server\n');
    }).listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_5() {
    const config = {
        // ok: typescript-avoid-tls-cipher-with-known-issue
        cipherSuites: 'TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256',
        key: fs.readFileSync('private.key'),
        cert: fs.readFileSync('certificate.crt')
    };
    
    const server = https.createServer(config);
    server.listen(443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_6() {
    class SecureConnection {
        constructor() {
            this.options = {
                // ok: typescript-avoid-tls-cipher-with-known-issue
                ciphers: 'TLS_AES_128_CCM_8_SHA256:TLS_AES_128_GCM_SHA256',
                key: fs.readFileSync('key.pem'),
                cert: fs.readFileSync('cert.pem')
            };
        }
        
        connect() {
            return tls.connect(443, 'secure.example.com', this.options);
        }
    }
    
    const connection = new SecureConnection();
    connection.connect();
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_7() {
    const httpsOptions = {
        key: fs.readFileSync('key.pem'),
        cert: fs.readFileSync('cert.pem'),
        // ok: typescript-avoid-tls-cipher-with-known-issue
        ciphers: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'
    };
    
    const server = https.createServer(httpsOptions);
    server.listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_8() {
    function setupTlsServer() {
        const serverOptions = {
            // ok: typescript-avoid-tls-cipher-with-known-issue
            ciphers: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
            key: fs.readFileSync('server.key'),
            cert: fs.readFileSync('server.cert')
        };
        
        return tls.createServer(serverOptions, (socket) => {
            socket.write('Welcome!\n');
            socket.pipe(socket);
        });
    }
    
    const server = setupTlsServer();
    server.listen(8000);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_9() {
    const options = {
        hostname: 'api.example.com',
        port: 443,
        path: '/data',
        method: 'GET',
        key: fs.readFileSync('client.key'),
        cert: fs.readFileSync('client.cert'),
        // ok: typescript-avoid-tls-cipher-with-known-issue
        ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256'
    };
    
    const req = https.request(options, (res) => {
        console.log('statusCode:', res.statusCode);
    });
    req.end();
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_10() {
    const tlsConnectionParams = {
        host: 'secure.example.org',
        port: 443,
        // ok: typescript-avoid-tls-cipher-with-known-issue
        ciphers: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
    };
    
    const socket = tls.connect(tlsConnectionParams, () => {
        console.log('Connection established using cipher:', socket.getCipher());
    });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_11() {
    const secureContextOptions = {
        // ok: typescript-avoid-tls-cipher-with-known-issue
        ciphers: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
        key: fs.readFileSync('key.pem'),
        cert: fs.readFileSync('cert.pem')
    };
    
    const secureContext = tls.createSecureContext(secureContextOptions);
    const server = tls.createServer({
        secureContext: secureContext
    });
    server.listen(8443);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_12() {
    class ApiClient {
        constructor() {
            this.httpsAgent = new https.Agent({
                // ok: typescript-avoid-tls-cipher-with-known-issue
                ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
                key: fs.readFileSync('client.key'),
                cert: fs.readFileSync('client.cert')
            });
        }
        
        makeRequest() {
            return https.get('https://api.example.com', { agent: this.httpsAgent });
        }
    }
    
    const client = new ApiClient();
    client.makeRequest();
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_13() {
    // Using recommended TLS 1.3 ciphers
    const serverConfig = {
        // ok: typescript-avoid-tls-cipher-with-known-issue
        cipherSuites: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
        key: fs.readFileSync('server.key'),
        cert: fs.readFileSync('server.cert')
    };
    
    const server = https.createServer(serverConfig);
    server.listen(443, () => {
        console.log('Server running');
    });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_14() {
    const options = {
        // ok: typescript-avoid-tls-cipher-with-known-issue
        ciphers: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        secureProtocol: 'TLSv1_2_method',
        key: fs.readFileSync('key.pem'),
        cert: fs.readFileSync('cert.pem')
    };
    
    const server = tls.createServer(options, (socket) => {
        socket.write('welcome!\n');
        socket.pipe(socket);
    });
    server.listen(8000);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_15() {
    // Using Node.js crypto module to create a secure context with recommended ciphers
    const tlsOptions = {
        key: fs.readFileSync('client.key'),
        cert: fs.readFileSync('client.cert'),
        // ok: typescript-avoid-tls-cipher-with-known-issue
        ciphers: 'TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
    };
    
    const socket = tls.connect(443, 'api.example.com', tlsOptions, () => {
        console.log('Connected');
        socket.write('GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n');
    });
}
// {/fact}