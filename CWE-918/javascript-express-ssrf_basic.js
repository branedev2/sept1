const express = require('express');
const axios = require('axios');
const fetch = require('node-fetch');
const request = require('request');
const http = require('http');
const https = require('https');
const url = require('url');
const validator = require('validator');
const isUrl = require('is-url');
const { URL } = require('url');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// True Positive Examples (Vulnerable Code)

// Example 1: Basic SSRF with axios
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_1(req, res) {
    const targetUrl = req.query.url;
    
    // ruleid: javascript-express-ssrf
    axios.get(targetUrl)
        .then(response => {
            res.send(response.data);
        })
        .catch(error => {
            res.status(500).send('Error fetching URL');
        });
}
// {/fact}

// Example 2: SSRF with fetch API
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_2(req, res) {
    const targetUrl = req.body.target;
    
    // ruleid: javascript-express-ssrf
    fetch(targetUrl)
        .then(response => response.text())
        .then(data => {
            res.send(data);
        })
        .catch(err => {
            res.status(500).send('Error fetching URL');
        });
}
// {/fact}

// Example 3: SSRF with request library
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_3(req, res) {
    const targetUrl = req.params.url;
    
    // ruleid: javascript-express-ssrf
    request(targetUrl, (error, response, body) => {
        if (error) {
            return res.status(500).send('Error fetching URL');
        }
        res.send(body);
    });
}
// {/fact}

// Example 4: SSRF with http.get
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_4(req, res) {
    const targetUrl = req.query.api;
    
    // ruleid: javascript-express-ssrf
    http.get(targetUrl, (response) => {
        let data = '';
        
        response.on('data', (chunk) => {
            data += chunk;
        });
        
        response.on('end', () => {
            res.send(JSON.parse(data));
        });
    }).on('error', (err) => {
        res.status(500).send('Error fetching URL');
    });
}
// {/fact}

// Example 5: SSRF with https.get
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_5(req, res) {
    const targetUrl = req.headers['x-target-url'];
    
    // ruleid: javascript-express-ssrf
    https.get(targetUrl, (response) => {
        let data = '';
        
        response.on('data', (chunk) => {
            data += chunk;
        });
        
        response.on('end', () => {
            res.send(data);
        });
    }).on('error', (err) => {
        res.status(500).send('Error fetching URL');
    });
}
// {/fact}

// Example 6: SSRF with axios and template literals
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_6(req, res) {
    const baseUrl = 'https://api.example.com';
    const endpoint = req.query.endpoint;
    const fullUrl = `${baseUrl}/${endpoint}`;
    
    // ruleid: javascript-express-ssrf
    axios.get(fullUrl)
        .then(response => {
            res.json(response.data);
        })
        .catch(error => {
            res.status(500).send('Error fetching URL');
        });
}
// {/fact}

// Example 7: SSRF with axios.post
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_7(req, res) {
    const targetUrl = req.body.webhook;
    const data = { message: 'Notification' };
    
    // ruleid: javascript-express-ssrf
    axios.post(targetUrl, data)
        .then(response => {
            res.send('Notification sent');
        })
        .catch(error => {
            res.status(500).send('Error sending notification');
        });
}
// {/fact}

// Example 8: SSRF with URL object
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_8(req, res) {
    const targetUrl = req.query.url;
    const parsedUrl = new URL(targetUrl);
    
    // ruleid: javascript-express-ssrf
    fetch(parsedUrl.toString())
        .then(response => response.json())
        .then(data => {
            res.json(data);
        })
        .catch(err => {
            res.status(500).send('Error fetching URL');
        });
}
// {/fact}

// Example 9: SSRF with request library and options object
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_9(req, res) {
    const targetUrl = req.query.target;
    const options = {
        url: targetUrl,
        method: 'GET',
        headers: {
            'User-Agent': 'Custom User Agent'
        }
    };
    
    // ruleid: javascript-express-ssrf
    request(options, (error, response, body) => {
        if (error) {
            return res.status(500).send('Error fetching URL');
        }
        res.send(body);
    });
}
// {/fact}

// Example 10: SSRF with axios and complex path construction
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_10(req, res) {
    const apiHost = req.query.host || 'api.default.com';
    const apiPath = req.query.path || '/data';
    const apiUrl = `https://${apiHost}${apiPath}`;
    
    // ruleid: javascript-express-ssrf
    axios.get(apiUrl)
        .then(response => {
            res.json(response.data);
        })
        .catch(error => {
            res.status(500).send('Error fetching API');
        });
}
// {/fact}

// Example 11: SSRF with fetch and dynamic protocol
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_11(req, res) {
    const protocol = req.query.protocol || 'https';
    const host = req.query.host;
    const targetUrl = `${protocol}://${host}/api/data`;
    
    // ruleid: javascript-express-ssrf
    fetch(targetUrl)
        .then(response => response.json())
        .then(data => {
            res.json(data);
        })
        .catch(err => {
            res.status(500).send('Error fetching data');
        });
}
// {/fact}

// Example 12: SSRF with axios and URL from cookie
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_12(req, res) {
    const targetUrl = req.cookies.apiUrl;
    
    // ruleid: javascript-express-ssrf
    axios.get(targetUrl)
        .then(response => {
            res.send(response.data);
        })
        .catch(error => {
            res.status(500).send('Error fetching URL');
        });
}
// {/fact}

// Example 13: SSRF with http.request
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_13(req, res) {
    const targetUrl = req.query.url;
    const parsedUrl = url.parse(targetUrl);
    
    const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || 80,
        path: parsedUrl.path,
        method: 'GET'
    };
    
    // ruleid: javascript-express-ssrf
    const request = http.request(options, (response) => {
        let data = '';
        
        response.on('data', (chunk) => {
            data += chunk;
        });
        
        response.on('end', () => {
            res.send(data);
        });
    });
    
    request.on('error', (e) => {
        res.status(500).send('Error fetching URL');
    });
    
    request.end();
}
// {/fact}

// Example 14: SSRF with axios and partial URL validation
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_14(req, res) {
    let targetUrl = req.query.url;
    
    // Incomplete validation - only checks if it starts with http
    if (targetUrl.startsWith('http')) {
        // ruleid: javascript-express-ssrf
        axios.get(targetUrl)
            .then(response => {
                res.send(response.data);
            })
            .catch(error => {
                res.status(500).send('Error fetching URL');
            });
    } else {
        res.status(400).send('Invalid URL');
    }
}
// {/fact}

// Example 15: SSRF with fetch and URL from JSON body
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_15(req, res) {
    const data = req.body;
    const targetUrl = data.config.apiEndpoint;
    
    // ruleid: javascript-express-ssrf
    fetch(targetUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ query: data.query })
    })
    .then(response => response.json())
    .then(result => {
        res.json(result);
    })
    .catch(err => {
        res.status(500).send('Error querying API');
    });
}
// {/fact}

// True Negative Examples (Secure Code)

// Example 1: Whitelist validation with axios
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_1(req, res) {
    const targetUrl = req.query.url;
    const allowedDomains = ['api.trusted.com', 'data.trusted.com'];
    
    try {
        const parsedUrl = new URL(targetUrl);
        
        // ok: javascript-express-ssrf
        if (allowedDomains.includes(parsedUrl.hostname)) {
            axios.get(targetUrl)
                .then(response => {
                    res.send(response.data);
                })
                .catch(error => {
                    res.status(500).send('Error fetching URL');
                });
        } else {
            res.status(403).send('Domain not allowed');
        }
    } catch (error) {
        res.status(400).send('Invalid URL');
    }
}
// {/fact}

// Example 2: Using predefined URLs instead of user input
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_2(req, res) {
    const apiEndpoints = {
        'users': 'https://api.trusted.com/users',
        'products': 'https://api.trusted.com/products',
        'orders': 'https://api.trusted.com/orders'
    };
    
    const endpoint = req.query.endpoint;
    
    // ok: javascript-express-ssrf
    if (apiEndpoints[endpoint]) {
        axios.get(apiEndpoints[endpoint])
            .then(response => {
                res.json(response.data);
            })
            .catch(error => {
                res.status(500).send('Error fetching data');
            });
    } else {
        res.status(400).send('Invalid endpoint');
    }
}
// {/fact}

// Example 3: URL validation with validator library
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_3(req, res) {
    const targetUrl = req.query.url;
    
    // ok: javascript-express-ssrf
    if (validator.isURL(targetUrl, {
        protocols: ['http', 'https'],
        require_protocol: true,
        require_host: true,
        host_whitelist: ['api.trusted.com', 'data.trusted.com']
    })) {
        fetch(targetUrl)
            .then(response => response.json())
            .then(data => {
                res.json(data);
            })
            .catch(err => {
                res.status(500).send('Error fetching URL');
            });
    } else {
        res.status(403).send('URL not allowed');
    }
}
// {/fact}

// Example 4: Regex validation for domain
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_4(req, res) {
    const targetUrl = req.query.url;
    const trustedDomainRegex = /^https:\/\/([\w-]+\.)*trusted\.com\//i;
    
    // ok: javascript-express-ssrf
    if (trustedDomainRegex.test(targetUrl)) {
        axios.get(targetUrl)
            .then(response => {
                res.send(response.data);
            })
            .catch(error => {
                res.status(500).send('Error fetching URL');
            });
    } else {
        res.status(403).send('Domain not allowed');
    }
}
// {/fact}

// Example 5: Using URL path only and prepending trusted domain
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_5(req, res) {
    const path = req.query.path;
    const pathRegex = /^[\/\w-]+$/; // Only allow paths with letters, numbers, underscores, hyphens, and slashes
    
    // ok: javascript-express-ssrf
    if (pathRegex.test(path)) {
        const trustedUrl = `https://api.trusted.com${path}`;
        
        fetch(trustedUrl)
            .then(response => response.text())
            .then(data => {
                res.send(data);
            })
            .catch(err => {
                res.status(500).send('Error fetching URL');
            });
    } else {
        res.status(400).send('Invalid path');
    }
}
// {/fact}

// Example 6: Using URL constructor and hostname validation
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_6(req, res) {
    const targetUrl = req.query.url;
    
    try {
        const parsedUrl = new URL(targetUrl);
        
        // ok: javascript-express-ssrf
        if (parsedUrl.hostname === 'api.trusted.com' || parsedUrl.hostname.endsWith('.trusted.com')) {
            http.get(targetUrl, (response) => {
                let data = '';
                
                response.on('data', (chunk) => {
                    data += chunk;
                });
                
                response.on('end', () => {
                    res.send(data);
                });
            }).on('error', (err) => {
                res.status(500).send('Error fetching URL');
            });
        } else {
            res.status(403).send('Domain not allowed');
        }
    } catch (error) {
        res.status(400).send('Invalid URL');
    }
}
// {/fact}

// Example 7: Using a proxy service to restrict URLs
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_7(req, res) {
    const targetUrl = req.query.url;
    
    // ok: javascript-express-ssrf
    // Using internal proxy service that validates URLs
    axios.post('https://internal-proxy.company.com/fetch', {
        url: targetUrl,
        token: process.env.PROXY_API_KEY
    })
    .then(response => {
        res.send(response.data);
    })
    .catch(error => {
        res.status(500).send('Error fetching URL');
    });
}
// {/fact}

// Example 8: Using is-url library and IP address check
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_8(req, res) {
    const targetUrl = req.query.url;
    
    // ok: javascript-express-ssrf
    if (isUrl(targetUrl)) {
        try {
            const parsedUrl = new URL(targetUrl);
            const hostname = parsedUrl.hostname;
            
            // Check if hostname is an IP address
            const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
            
            if (ipRegex.test(hostname)) {
                // Block requests to IP addresses
                return res.status(403).send('Direct IP addresses not allowed');
            }
            
            // Check against whitelist
            const allowedDomains = ['api.trusted.com', 'data.trusted.com'];
            if (allowedDomains.includes(hostname)) {
                axios.get(targetUrl)
                    .then(response => {
                        res.send(response.data);
                    })
                    .catch(error => {
                        res.status(500).send('Error fetching URL');
                    });
            } else {
                res.status(403).send('Domain not allowed');
            }
        } catch (error) {
            res.status(400).send('Invalid URL');
        }
    } else {
        res.status(400).send('Invalid URL format');
    }
}
// {/fact}

// Example 9: Using URL parameters instead of full URL
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_9(req, res) {
    const resourceId = req.query.id;
    const resourceType = req.query.type;
    
    // Validate input
    if (!resourceId || !resourceType) {
        return res.status(400).send('Missing required parameters');
    }
    
    const validTypes = ['users', 'products', 'orders'];
    
    // ok: javascript-express-ssrf
    if (validTypes.includes(resourceType) && /^\w+$/.test(resourceId)) {
        const apiUrl = `https://api.trusted.com/${resourceType}/${resourceId}`;
        
        axios.get(apiUrl)
            .then(response => {
                res.json(response.data);
            })
            .catch(error => {
                res.status(500).send('Error fetching resource');
            });
    } else {
        res.status(400).send('Invalid resource type or ID');
    }
}
// {/fact}

// Example 10: Using a configuration map for allowed endpoints
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_10(req, res) {
    const endpoint = req.query.endpoint;
    
    const endpointConfig = {
        'userProfile': {
            baseUrl: 'https://api.trusted.com/users',
            requiresId: true
        },
        'productList': {
            baseUrl: 'https://api.trusted.com/products',
            requiresId: false
        },
        'orderStatus': {
            baseUrl: 'https://api.trusted.com/orders',
            requiresId: true
        }
    };
    
    // ok: javascript-express-ssrf
    if (endpointConfig[endpoint]) {
        let apiUrl = endpointConfig[endpoint].baseUrl;
        
        if (endpointConfig[endpoint].requiresId) {
            const id = req.query.id;
            if (!id || !/^\w+$/.test(id)) {
                return res.status(400).send('Invalid or missing ID');
            }
            apiUrl += `/${id}`;
        }
        
        fetch(apiUrl)
            .then(response => response.json())
            .then(data => {
                res.json(data);
            })
            .catch(err => {
                res.status(500).send('Error fetching data');
            });
    } else {
        res.status(400).send('Invalid endpoint');
    }
}
// {/fact}

// Example 11: Using a service class with predefined endpoints
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_11(req, res) {
    class ApiService {
        constructor() {
            this.baseUrl = 'https://api.trusted.com';
            this.endpoints = {
                'users': '/users',
                'products': '/products',
                'orders': '/orders'
            };
        }
        
        getUrl(endpoint) {
            if (this.endpoints[endpoint]) {
                return `${this.baseUrl}${this.endpoints[endpoint]}`;
            }
            return null;
        }
    }
    
    const apiService = new ApiService();
    const endpoint = req.query.endpoint;
    
    // ok: javascript-express-ssrf
    const apiUrl = apiService.getUrl(endpoint);
    
    if (apiUrl) {
        axios.get(apiUrl)
            .then(response => {
                res.json(response.data);
            })
            .catch(error => {
                res.status(500).send('Error fetching data');
            });
    } else {
        res.status(400).send('Invalid endpoint');
    }
}
// {/fact}

// Example 12: Using URL validation with protocol and hostname check
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_12(req, res) {
    const targetUrl = req.query.url;
    
    try {
        const parsedUrl = new URL(targetUrl);
        
        // ok: javascript-express-ssrf
        // Check protocol
        if (parsedUrl.protocol !== 'https:') {
            return res.status(403).send('Only HTTPS protocol is allowed');
        }
        
        // Check hostname
        const trustedDomains = ['api.trusted.com', 'data.trusted.com', 'cdn.trusted.com'];
        if (!trustedDomains.includes(parsedUrl.hostname)) {
            return res.status(403).send('Domain not allowed');
        }
        
        // If all checks pass, make the request
        request(targetUrl, (error, response, body) => {
            if (error) {
                return res.status(500).send('Error fetching URL');
            }
            res.send(body);
        });
    } catch (error) {
        res.status(400).send('Invalid URL');
    }
}
// {/fact}

// Example 13: Using environment variables for API endpoints
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_13(req, res) {
    const apiType = req.query.type;
    
    const apiEndpoints = {
        'users': process.env.USERS_API_URL,
        'products': process.env.PRODUCTS_API_URL,
        'orders': process.env.ORDERS_API_URL
    };
    
    // ok: javascript-express-ssrf
    if (apiEndpoints[apiType]) {
        axios.get(apiEndpoints[apiType])
            .then(response => {
                res.json(response.data);
            })
            .catch(error => {
                res.status(500).send('Error fetching data');
            });
    } else {
        res.status(400).send('Invalid API type');
    }
}
// {/fact}

// Example 14: Using a function to validate URL against multiple criteria
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_14(req, res) {
    const targetUrl = req.query.url;
    
    function isUrlSafe(url) {
        try {
            const parsedUrl = new URL(url);
            
            // Check protocol
            if (parsedUrl.protocol !== 'https:') {
                return false;
            }
            
            // Check hostname
            const trustedDomains = ['api.trusted.com', 'data.trusted.com'];
            if (!trustedDomains.includes(parsedUrl.hostname)) {
                return false;
            }
            
            // Check for private IP ranges
            const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
            if (ipRegex.test(parsedUrl.hostname)) {
                return false;
            }
            
            // Check path for traversal attempts
            if (parsedUrl.pathname.includes('..')) {
                return false;
            }
            
            return true;
        } catch (error) {
            return false;
        }
    }
    
    // ok: javascript-express-ssrf
    if (isUrlSafe(targetUrl)) {
        fetch(targetUrl)
            .then(response => response.json())
            .then(data => {
                res.json(data);
            })
            .catch(err => {
                res.status(500).send('Error fetching URL');
            });
    } else {
        res.status(403).send('URL not allowed');
    }
}
// {/fact}

// Example 15: Using a dedicated API gateway
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_15(req, res) {
    const resourcePath = req.query.path;
    
    // Validate path format
    if (!resourcePath || !/^[\w\/\-]+$/.test(resourcePath)) {
        return res.status(400).send('Invalid resource path');
    }
    
    // ok: javascript-express-ssrf
    // Using API gateway with fixed base URL
    const apiGatewayUrl = process.env.API_GATEWAY_URL || 'https://api-gateway.company.com';
    const apiUrl = `${apiGatewayUrl}/${resourcePath}`;
    
    axios.get(apiUrl, {
        headers: {
            'X-API-Key': process.env.API_GATEWAY_KEY,
            'X-Request-ID': req.headers['x-request-id'] || 'unknown'
        }
    })
    .then(response => {
        res.json(response.data);
    })
    .catch(error => {
        res.status(error.response?.status || 500).send('Error fetching resource');
    });
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});