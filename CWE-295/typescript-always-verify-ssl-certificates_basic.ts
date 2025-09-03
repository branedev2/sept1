import * as https from 'https';
import * as tls from 'tls';
import * as fs from 'fs';
import axios from 'axios';
import * as request from 'request';
import fetch from 'node-fetch';
import * as http from 'http';
import * as aws from 'aws-sdk';
import { Agent } from 'https';
import * as needle from 'needle';
import * as got from 'got';
import * as superagent from 'superagent';

// True Positives (Vulnerable Code)

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_1() {
    // Using Node.js https module with rejectUnauthorized: false
    const options = {
        hostname: 'example.com',
        port: 443,
        path: '/api/data',
        method: 'GET',
        // ruleid: typescript-always-verify-ssl-certificates
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
    axios.get('https://api.example.com/data', {
        // ruleid: typescript-always-verify-ssl-certificates
        httpsAgent: new https.Agent({ rejectUnauthorized: false })
    }).then(response => {
        console.log(response.data);
    }).catch(error => {
        console.error(error);
    });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_3() {
    // Using request library with SSL verification disabled
    request.get({
        url: 'https://api.example.com/data',
        // ruleid: typescript-always-verify-ssl-certificates
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
    // Using node-fetch with SSL verification disabled
    const agent = new https.Agent({
        // ruleid: typescript-always-verify-ssl-certificates
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
    // Using TLS with checkServerIdentity disabled
    const options = {
        host: 'api.example.com',
        port: 443,
        // ruleid: typescript-always-verify-ssl-certificates
        checkServerIdentity: () => undefined
    };
    
    const socket = tls.connect(options, () => {
        console.log('Connected');
        socket.write('GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n');
    });
    
    socket.on('data', (data) => {
        console.log(data.toString());
    });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_6() {
    // Using request library with insecure parameter
    const options = {
        url: 'https://api.example.com/data',
        method: 'GET',
        // ruleid: typescript-always-verify-ssl-certificates
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
function bad_case_7() {
    // Using AWS SDK with SSL disabled
    const s3 = new aws.S3({
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        region: 'us-west-2',
        // ruleid: typescript-always-verify-ssl-certificates
        sslEnabled: false
    });
    
    s3.getObject({ Bucket: 'example-bucket', Key: 'example-key' }, (err, data) => {
        if (err) console.log(err);
        else console.log(data);
    });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_8() {
    // Using needle with SSL verification disabled
    needle.get('https://api.example.com/data', {
        // ruleid: typescript-always-verify-ssl-certificates
        rejectUnauthorized: false
    }, (error, response) => {
        if (!error) {
            console.log(response.body);
        }
    });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_9() {
    // Using got with SSL verification disabled
    (async () => {
        try {
            const response = await got('https://api.example.com/data', {
                // ruleid: typescript-always-verify-ssl-certificates
                https: { rejectUnauthorized: false }
            });
            console.log(response.body);
        } catch (error) {
            console.error(error);
        }
    })();
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_10() {
    // Using superagent with SSL verification disabled
    superagent
        .get('https://api.example.com/data')
        // ruleid: typescript-always-verify-ssl-certificates
        .disableTLSCerts()
        .end((err, res) => {
            if (!err) {
                console.log(res.body);
            }
        });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_11() {
    // Using https.request with a function that returns an agent with disabled SSL verification
    function getInsecureAgent() {
        // ruleid: typescript-always-verify-ssl-certificates
        return new https.Agent({ rejectUnauthorized: false });
    }
    
    const req = https.request({
        hostname: 'example.com',
        port: 443,
        path: '/api/data',
        method: 'GET',
        agent: getInsecureAgent()
    }, (res) => {
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
function bad_case_12() {
    // Using axios with a conditional that always disables SSL verification
    const shouldVerify = false;
    
    axios.get('https://api.example.com/data', {
        // ruleid: typescript-always-verify-ssl-certificates
        httpsAgent: new https.Agent({ rejectUnauthorized: shouldVerify })
    }).then(response => {
        console.log(response.data);
    }).catch(error => {
        console.error(error);
    });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_13() {
    // Using TLS with a custom secureContext that has SSL verification disabled
    const options = {
        secureContext: tls.createSecureContext({
            // ruleid: typescript-always-verify-ssl-certificates
            rejectUnauthorized: false
        }),
        host: 'api.example.com',
        port: 443
    };
    
    const socket = tls.connect(options, () => {
        console.log('Connected');
        socket.write('GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n');
    });
    
    socket.on('data', (data) => {
        console.log(data.toString());
    });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=1}
function bad_case_14() {
    // Using https module with a custom agent that has SSL verification disabled
    class CustomAgent extends https.Agent {
        constructor() {
            // ruleid: typescript-always-verify-ssl-certificates
            super({ rejectUnauthorized: false });
        }
    }
    
    const agent = new CustomAgent();
    
    const req = https.request({
        hostname: 'example.com',
        port: 443,
        path: '/api/data',
        method: 'GET',
        agent: agent
    }, (res) => {
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
    // Using request with a complex options object that includes SSL verification disabled
    const requestOptions = {
        url: 'https://api.example.com/data',
        method: 'GET',
        headers: {
            'User-Agent': 'MyApp/1.0'
        },
        timeout: 5000,
        // ruleid: typescript-always-verify-ssl-certificates
        agentOptions: {
            rejectUnauthorized: false
        }
    };
    
    request(requestOptions, (error, response, body) => {
        if (!error && response.statusCode === 200) {
            console.log(body);
        }
    });
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_1() {
    // Using Node.js https module with default SSL verification (enabled)
    const options = {
        hostname: 'example.com',
        port: 443,
        path: '/api/data',
        method: 'GET'
        // ok: typescript-always-verify-ssl-certificates
        // No rejectUnauthorized parameter, defaults to true
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
    // Using axios with explicitly enabled SSL verification
    axios.get('https://api.example.com/data', {
        // ok: typescript-always-verify-ssl-certificates
        httpsAgent: new https.Agent({ rejectUnauthorized: true })
    }).then(response => {
        console.log(response.data);
    }).catch(error => {
        console.error(error);
    });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_3() {
    // Using request library with SSL verification explicitly enabled
    request.get({
        url: 'https://api.example.com/data',
        // ok: typescript-always-verify-ssl-certificates
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
    // Using node-fetch with default SSL verification
    // ok: typescript-always-verify-ssl-certificates
    fetch('https://api.example.com/data')
        .then(response => response.json())
        .then(data => console.log(data))
        .catch(error => console.error(error));
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_5() {
    // Using TLS with proper certificate validation
    const options = {
        host: 'api.example.com',
        port: 443,
        // ok: typescript-always-verify-ssl-certificates
        ca: fs.readFileSync('trusted-ca.pem')
    };
    
    const socket = tls.connect(options, () => {
        console.log('Connected securely');
        socket.write('GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n');
    });
    
    socket.on('data', (data) => {
        console.log(data.toString());
    });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_6() {
    // Using request library with explicit secure configuration
    const options = {
        url: 'https://api.example.com/data',
        method: 'GET',
        // ok: typescript-always-verify-ssl-certificates
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
function good_case_7() {
    // Using AWS SDK with SSL enabled (default)
    // ok: typescript-always-verify-ssl-certificates
    const s3 = new aws.S3({
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
        region: 'us-west-2'
    });
    
    s3.getObject({ Bucket: 'example-bucket', Key: 'example-key' }, (err, data) => {
        if (err) console.log(err);
        else console.log(data);
    });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_8() {
    // Using needle with SSL verification enabled
    // ok: typescript-always-verify-ssl-certificates
    needle.get('https://api.example.com/data', (error, response) => {
        if (!error) {
            console.log(response.body);
        }
    });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_9() {
    // Using got with default SSL verification
    (async () => {
        try {
            // ok: typescript-always-verify-ssl-certificates
            const response = await got('https://api.example.com/data');
            console.log(response.body);
        } catch (error) {
            console.error(error);
        }
    })();
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_10() {
    // Using superagent with default SSL verification
    // ok: typescript-always-verify-ssl-certificates
    superagent
        .get('https://api.example.com/data')
        .end((err, res) => {
            if (!err) {
                console.log(res.body);
            }
        });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_11() {
    // Using https.request with a custom certificate authority
    const options = {
        hostname: 'example.com',
        port: 443,
        path: '/api/data',
        method: 'GET',
        // ok: typescript-always-verify-ssl-certificates
        ca: fs.readFileSync('custom-ca.pem')
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
function good_case_12() {
    // Using axios with a custom certificate authority
    axios.get('https://api.example.com/data', {
        // ok: typescript-always-verify-ssl-certificates
        httpsAgent: new https.Agent({
            ca: fs.readFileSync('custom-ca.pem')
        })
    }).then(response => {
        console.log(response.data);
    }).catch(error => {
        console.error(error);
    });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_13() {
    // Using TLS with a custom secureContext that has proper SSL verification
    const options = {
        // ok: typescript-always-verify-ssl-certificates
        secureContext: tls.createSecureContext({
            ca: fs.readFileSync('custom-ca.pem')
        }),
        host: 'api.example.com',
        port: 443
    };
    
    const socket = tls.connect(options, () => {
        console.log('Connected securely');
        socket.write('GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n');
    });
    
    socket.on('data', (data) => {
        console.log(data.toString());
    });
}
// {/fact}

// {fact rule=improper-certificate-validation@v1.0 defects=0}
function good_case_14() {
    // Using https module with a custom agent that has proper SSL verification
    class CustomAgent extends https.Agent {
        constructor() {
            // ok: typescript-always-verify-ssl-certificates
            super({
                rejectUnauthorized: true,
                ca: fs.readFileSync('custom-ca.pem')
            });
        }
    }
    
    const agent = new CustomAgent();
    
    const req = https.request({
        hostname: 'example.com',
        port: 443,
        path: '/api/data',
        method: 'GET',
        agent: agent
    }, (res) => {
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
    // Using request with a complex options object that includes proper SSL verification
    const requestOptions = {
        url: 'https://api.example.com/data',
        method: 'GET',
        headers: {
            'User-Agent': 'MyApp/1.0'
        },
        timeout: 5000,
        // ok: typescript-always-verify-ssl-certificates
        agentOptions: {
            ca: fs.readFileSync('custom-ca.pem')
        }
    };
    
    request(requestOptions, (error, response, body) => {
        if (!error && response.statusCode === 200) {
            console.log(body);
        }
    });
}
// {/fact}