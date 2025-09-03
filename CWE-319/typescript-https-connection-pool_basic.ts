import * as http from 'http';
import * as https from 'https';
import * as axios from 'axios';
import * as request from 'request';
import * as fetch from 'node-fetch';

// True Positive Examples (Vulnerable Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1() {
    // Using http.Agent directly for a connection
    // ruleid: typescript-https-connection-pool
    const agent = new http.Agent({ keepAlive: true });
    
    http.get('http://example.com', { agent }, (res) => {
        let data = '';
        res.on('data', (chunk) => {
            data += chunk;
        });
        res.on('end', () => {
            console.log(data);
        });
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2() {
    // Using http.Agent with custom options
    // ruleid: typescript-https-connection-pool
    const agent = new http.Agent({
        keepAlive: true,
        maxSockets: 10,
        timeout: 60000
    });
    
    const options = {
        hostname: 'example.com',
        port: 80,
        path: '/api/data',
        method: 'GET',
        agent: agent
    };
    
    const req = http.request(options, (res) => {
        console.log(`STATUS: ${res.statusCode}`);
    });
    
    req.end();
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3() {
    // Using http.Agent with axios
    // ruleid: typescript-https-connection-pool
    const httpAgent = new http.Agent({ keepAlive: true });
    
    axios.default.get('http://example.com', {
        httpAgent: httpAgent
    }).then(response => {
        console.log(response.data);
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4() {
    // Using http.Agent in a function that processes sensitive data
    function processUserCredentials(username: string, password: string) {
        // ruleid: typescript-https-connection-pool
        const agent = new http.Agent({ keepAlive: true });
        
        const options = {
            hostname: 'auth.example.com',
            path: '/login',
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
                console.log('Authentication complete');
            });
        });
        
        req.write(JSON.stringify({ username, password }));
        req.end();
    }
    
    processUserCredentials('user123', 'password123');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5() {
    // Using http.Agent with a variable name that suggests security
    // ruleid: typescript-https-connection-pool
    const secureAgent = new http.Agent({ keepAlive: true });
    
    http.get('http://api.example.com/secure-data', { agent: secureAgent }, (res) => {
        console.log(`Status: ${res.statusCode}`);
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6() {
    // Using http.Agent in a class for API communication
    class ApiClient {
        private agent: http.Agent;
        
        constructor() {
            // ruleid: typescript-https-connection-pool
            this.agent = new http.Agent({
                keepAlive: true,
                maxSockets: 5
            });
        }
        
        fetchData(endpoint: string) {
            const options = {
                hostname: 'api.example.com',
                path: endpoint,
                method: 'GET',
                agent: this.agent
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
                
                req.on('error', (err) => {
                    reject(err);
                });
                
                req.end();
            });
        }
    }
    
    const client = new ApiClient();
    client.fetchData('/users');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7() {
    // Using http.Agent with conditional creation
    const useSecure = false;
    let agent;
    
    if (useSecure) {
        agent = new https.Agent({ keepAlive: true });
    } else {
        // ruleid: typescript-https-connection-pool
        agent = new http.Agent({ keepAlive: true });
    }
    
    http.get('http://example.com', { agent }, (res) => {
        console.log(`Status: ${res.statusCode}`);
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8() {
    // Using http.Agent with request library
    // ruleid: typescript-https-connection-pool
    const agent = new http.Agent({ keepAlive: true });
    
    request({
        url: 'http://api.example.com/data',
        method: 'GET',
        agent: agent
    }, (error, response, body) => {
        if (!error && response.statusCode === 200) {
            console.log(body);
        }
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9() {
    // Using http.Agent with fetch API
    // ruleid: typescript-https-connection-pool
    const agent = new http.Agent({ keepAlive: true });
    
    const fetchOptions = {
        method: 'GET',
        agent: agent
    };
    
    fetch('http://api.example.com/data', fetchOptions)
        .then(response => response.json())
        .then(data => console.log(data));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10() {
    // Using http.Agent with a factory function
    function createAgent(options: any) {
        // ruleid: typescript-https-connection-pool
        return new http.Agent(options);
    }
    
    const agent = createAgent({ keepAlive: true });
    
    http.get('http://example.com', { agent }, (res) => {
        console.log(`Status: ${res.statusCode}`);
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11() {
    // Using http.Agent with destructuring assignment
    // ruleid: typescript-https-connection-pool
    const { Agent } = http;
    const agent = new Agent({ keepAlive: true });
    
    http.get('http://example.com', { agent }, (res) => {
        console.log(`Status: ${res.statusCode}`);
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12() {
    // Using http.Agent with a renamed import
    // ruleid: typescript-https-connection-pool
    const httpAgent = new http.Agent({ keepAlive: true });
    
    const options = {
        hostname: 'example.com',
        path: '/api/data',
        method: 'GET',
        agent: httpAgent
    };
    
    http.request(options, (res) => {
        console.log(`STATUS: ${res.statusCode}`);
    }).end();
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13() {
    // Using http.Agent in an async function
    async function fetchData() {
        // ruleid: typescript-https-connection-pool
        const agent = new http.Agent({ keepAlive: true });
        
        return new Promise((resolve, reject) => {
            http.get('http://api.example.com/data', { agent }, (res) => {
                let data = '';
                res.on('data', (chunk) => {
                    data += chunk;
                });
                res.on('end', () => {
                    resolve(JSON.parse(data));
                });
                res.on('error', (err) => {
                    reject(err);
                });
            });
        });
    }
    
    fetchData().then(data => console.log(data));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14() {
    // Using http.Agent with a custom timeout
    // ruleid: typescript-https-connection-pool
    const agent = new http.Agent({
        keepAlive: true,
        timeout: 5000
    });
    
    const req = http.request({
        hostname: 'example.com',
        path: '/api/data',
        method: 'GET',
        agent: agent,
        timeout: 3000
    }, (res) => {
        console.log(`STATUS: ${res.statusCode}`);
    });
    
    req.end();
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15() {
    // Using http.Agent with a map of agents
    const agents = {
        default: null as any,
        secure: null as any
    };
    
    // ruleid: typescript-https-connection-pool
    agents.default = new http.Agent({ keepAlive: true });
    agents.secure = new https.Agent({ keepAlive: true });
    
    function makeRequest(url: string, isSecure: boolean) {
        const agent = isSecure ? agents.secure : agents.default;
        const protocol = isSecure ? https : http;
        
        protocol.get(url, { agent }, (res) => {
            console.log(`STATUS: ${res.statusCode}`);
        });
    }
    
    makeRequest('http://example.com', false);
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1() {
    // Using https.Agent for secure connections
    // ok: typescript-https-connection-pool
    const agent = new https.Agent({ keepAlive: true });
    
    https.get('https://example.com', { agent }, (res) => {
        let data = '';
        res.on('data', (chunk) => {
            data += chunk;
        });
        res.on('end', () => {
            console.log(data);
        });
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2() {
    // Using https.Agent with custom options
    // ok: typescript-https-connection-pool
    const agent = new https.Agent({
        keepAlive: true,
        maxSockets: 10,
        timeout: 60000
    });
    
    const options = {
        hostname: 'example.com',
        port: 443,
        path: '/api/data',
        method: 'GET',
        agent: agent
    };
    
    const req = https.request(options, (res) => {
        console.log(`STATUS: ${res.statusCode}`);
    });
    
    req.end();
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3() {
    // Using https.Agent with axios
    // ok: typescript-https-connection-pool
    const httpsAgent = new https.Agent({ keepAlive: true });
    
    axios.default.get('https://example.com', {
        httpsAgent: httpsAgent
    }).then(response => {
        console.log(response.data);
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4() {
    // Using https.Agent in a function that processes sensitive data
    function processUserCredentials(username: string, password: string) {
        // ok: typescript-https-connection-pool
        const agent = new https.Agent({ keepAlive: true });
        
        const options = {
            hostname: 'auth.example.com',
            path: '/login',
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
                console.log('Authentication complete');
            });
        });
        
        req.write(JSON.stringify({ username, password }));
        req.end();
    }
    
    processUserCredentials('user123', 'password123');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5() {
    // Using https.Agent with a variable name that suggests security
    // ok: typescript-https-connection-pool
    const secureAgent = new https.Agent({ keepAlive: true });
    
    https.get('https://api.example.com/secure-data', { agent: secureAgent }, (res) => {
        console.log(`Status: ${res.statusCode}`);
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6() {
    // Using https.Agent in a class for API communication
    class ApiClient {
        private agent: https.Agent;
        
        constructor() {
            // ok: typescript-https-connection-pool
            this.agent = new https.Agent({
                keepAlive: true,
                maxSockets: 5
            });
        }
        
        fetchData(endpoint: string) {
            const options = {
                hostname: 'api.example.com',
                path: endpoint,
                method: 'GET',
                agent: this.agent
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
                
                req.on('error', (err) => {
                    reject(err);
                });
                
                req.end();
            });
        }
    }
    
    const client = new ApiClient();
    client.fetchData('/users');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7() {
    // Using https.Agent with conditional creation
    const useSecure = true;
    let agent;
    
    if (useSecure) {
        // ok: typescript-https-connection-pool
        agent = new https.Agent({ keepAlive: true });
    } else {
        agent = new http.Agent({ keepAlive: true });
    }
    
    https.get('https://example.com', { agent }, (res) => {
        console.log(`Status: ${res.statusCode}`);
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8() {
    // Using https.Agent with request library
    // ok: typescript-https-connection-pool
    const agent = new https.Agent({ keepAlive: true });
    
    request({
        url: 'https://api.example.com/data',
        method: 'GET',
        agent: agent
    }, (error, response, body) => {
        if (!error && response.statusCode === 200) {
            console.log(body);
        }
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9() {
    // Using https.Agent with fetch API
    // ok: typescript-https-connection-pool
    const agent = new https.Agent({ keepAlive: true });
    
    const fetchOptions = {
        method: 'GET',
        agent: agent
    };
    
    fetch('https://api.example.com/data', fetchOptions)
        .then(response => response.json())
        .then(data => console.log(data));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10() {
    // Using https.Agent with a factory function
    function createSecureAgent(options: any) {
        // ok: typescript-https-connection-pool
        return new https.Agent(options);
    }
    
    const agent = createSecureAgent({ keepAlive: true });
    
    https.get('https://example.com', { agent }, (res) => {
        console.log(`Status: ${res.statusCode}`);
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11() {
    // Using https.Agent with destructuring assignment
    // ok: typescript-https-connection-pool
    const { Agent } = https;
    const agent = new Agent({ keepAlive: true });
    
    https.get('https://example.com', { agent }, (res) => {
        console.log(`Status: ${res.statusCode}`);
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12() {
    // Using https.Agent with a renamed import
    // ok: typescript-https-connection-pool
    const httpsAgent = new https.Agent({ keepAlive: true });
    
    const options = {
        hostname: 'example.com',
        path: '/api/data',
        method: 'GET',
        agent: httpsAgent
    };
    
    https.request(options, (res) => {
        console.log(`STATUS: ${res.statusCode}`);
    }).end();
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13() {
    // Using https.Agent in an async function
    async function fetchSecureData() {
        // ok: typescript-https-connection-pool
        const agent = new https.Agent({ keepAlive: true });
        
        return new Promise((resolve, reject) => {
            https.get('https://api.example.com/data', { agent }, (res) => {
                let data = '';
                res.on('data', (chunk) => {
                    data += chunk;
                });
                res.on('end', () => {
                    resolve(JSON.parse(data));
                });
                res.on('error', (err) => {
                    reject(err);
                });
            });
        });
    }
    
    fetchSecureData().then(data => console.log(data));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14() {
    // Using https.Agent with a custom timeout
    // ok: typescript-https-connection-pool
    const agent = new https.Agent({
        keepAlive: true,
        timeout: 5000
    });
    
    const req = https.request({
        hostname: 'example.com',
        path: '/api/data',
        method: 'GET',
        agent: agent,
        timeout: 3000
    }, (res) => {
        console.log(`STATUS: ${res.statusCode}`);
    });
    
    req.end();
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15() {
    // Using only https.Agent in a map of agents
    const agents = {
        default: null as any,
        custom: null as any
    };
    
    // ok: typescript-https-connection-pool
    agents.default = new https.Agent({ keepAlive: true });
    agents.custom = new https.Agent({ keepAlive: true, maxSockets: 10 });
    
    function makeRequest(url: string, useCustom: boolean) {
        const agent = useCustom ? agents.custom : agents.default;
        
        https.get(url, { agent }, (res) => {
            console.log(`STATUS: ${res.statusCode}`);
        });
    }
    
    makeRequest('https://example.com', false);
}
// {/fact}