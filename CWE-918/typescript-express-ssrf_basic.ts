import express from 'express';
import axios from 'axios';
import fetch from 'node-fetch';
import request from 'request';
import http from 'http';
import https from 'https';
import got from 'got';
import superagent from 'superagent';
import { URL } from 'url';
import * as validator from 'validator';
import { isURL } from 'validator';

const app = express();
app.use(express.json());

// True Positive Examples (Vulnerable Code)

// Example 1: Basic SSRF with axios
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_1() {
  app.get('/fetch-url', async (req, res) => {
    const url = req.query.url as string;
    try {
      // ruleid: typescript-express-ssrf
      const response = await axios.get(url);
      res.send(response.data);
    } catch (error) {
      res.status(500).send('Error fetching URL');
    }
  });
}
// {/fact}

// Example 2: SSRF with node-fetch
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_2() {
  app.post('/proxy', async (req, res) => {
    const targetUrl = req.body.url;
    try {
      // ruleid: typescript-express-ssrf
      const response = await fetch(targetUrl);
      const data = await response.text();
      res.send(data);
    } catch (error) {
      res.status(500).send('Error proxying request');
    }
  });
}
// {/fact}

// Example 3: SSRF with request library
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_3() {
  app.get('/api/proxy', (req, res) => {
    const targetUrl = req.query.target as string;
    // ruleid: typescript-express-ssrf
    request(targetUrl, (error, response, body) => {
      if (error) {
        return res.status(500).send('Error occurred');
      }
      res.send(body);
    });
  });
}
// {/fact}

// Example 4: SSRF with http.get
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_4() {
  app.get('/fetch-data', (req, res) => {
    const url = req.query.source as string;
    // ruleid: typescript-express-ssrf
    http.get(url, (response) => {
      let data = '';
      response.on('data', (chunk) => {
        data += chunk;
      });
      response.on('end', () => {
        res.send(data);
      });
    }).on('error', (err) => {
      res.status(500).send('Error fetching data');
    });
  });
}
// {/fact}

// Example 5: SSRF with https.request
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_5() {
  app.post('/external-api', (req, res) => {
    const apiUrl = req.body.apiEndpoint;
    const options = {
      method: 'GET',
    };
    
    // ruleid: typescript-express-ssrf
    const request = https.request(apiUrl, options, (response) => {
      let data = '';
      response.on('data', (chunk) => {
        data += chunk;
      });
      response.on('end', () => {
        res.json(JSON.parse(data));
      });
    });
    
    request.on('error', (error) => {
      res.status(500).send('Error occurred');
    });
    
    request.end();
  });
}
// {/fact}

// Example 6: SSRF with got library
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_6() {
  app.get('/fetch-content', async (req, res) => {
    const contentUrl = req.query.content as string;
    try {
      // ruleid: typescript-express-ssrf
      const response = await got(contentUrl);
      res.send(response.body);
    } catch (error) {
      res.status(500).send('Failed to fetch content');
    }
  });
}
// {/fact}

// Example 7: SSRF with superagent
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_7() {
  app.get('/proxy-api', async (req, res) => {
    const endpoint = req.query.endpoint as string;
    try {
      // ruleid: typescript-express-ssrf
      const response = await superagent.get(endpoint);
      res.json(response.body);
    } catch (error) {
      res.status(500).send('Error proxying API');
    }
  });
}
// {/fact}

// Example 8: SSRF with axios and headers
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_8() {
  app.post('/forward-request', async (req, res) => {
    const targetUrl = req.body.url;
    const headers = req.headers;
    
    try {
      // ruleid: typescript-express-ssrf
      const response = await axios.get(targetUrl, { headers });
      res.json(response.data);
    } catch (error) {
      res.status(500).send('Request forwarding failed');
    }
  });
}
// {/fact}

// Example 9: SSRF with template literals
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_9() {
  app.get('/image-proxy', async (req, res) => {
    const imageId = req.query.id as string;
    const imageServer = req.query.server as string;
    
    try {
      const url = `${imageServer}/images/${imageId}.jpg`;
      // ruleid: typescript-express-ssrf
      const response = await axios.get(url);
      res.set('Content-Type', 'image/jpeg');
      res.send(response.data);
    } catch (error) {
      res.status(404).send('Image not found');
    }
  });
}
// {/fact}

// Example 10: SSRF with URL concatenation
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_10() {
  app.get('/api-gateway', async (req, res) => {
    const baseUrl = req.query.baseUrl as string;
    const endpoint = req.query.endpoint as string;
    
    try {
      const fullUrl = baseUrl + '/' + endpoint;
      // ruleid: typescript-express-ssrf
      const response = await fetch(fullUrl);
      const data = await response.json();
      res.json(data);
    } catch (error) {
      res.status(500).send('Gateway error');
    }
  });
}
// {/fact}

// Example 11: SSRF with URL object
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_11() {
  app.get('/fetch-resource', async (req, res) => {
    const urlString = req.query.resource as string;
    
    try {
      const url = new URL(urlString);
      // ruleid: typescript-express-ssrf
      const response = await axios.get(url.toString());
      res.send(response.data);
    } catch (error) {
      res.status(500).send('Error fetching resource');
    }
  });
}
// {/fact}

// Example 12: SSRF with request options object
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_12() {
  app.get('/external-service', (req, res) => {
    const host = req.query.host as string;
    const path = req.query.path as string;
    
    const options = {
      hostname: host,
      path: path,
      method: 'GET'
    };
    
    // ruleid: typescript-express-ssrf
    const request = http.request(options, (response) => {
      let data = '';
      response.on('data', (chunk) => {
        data += chunk;
      });
      response.on('end', () => {
        res.send(data);
      });
    });
    
    request.on('error', (error) => {
      res.status(500).send('Service unavailable');
    });
    
    request.end();
  });
}
// {/fact}

// Example 13: SSRF with POST request
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_13() {
  app.post('/relay', async (req, res) => {
    const targetUrl = req.body.target;
    const payload = req.body.data;
    
    try {
      // ruleid: typescript-express-ssrf
      const response = await axios.post(targetUrl, payload);
      res.json(response.data);
    } catch (error) {
      res.status(500).send('Relay failed');
    }
  });
}
// {/fact}

// Example 14: SSRF with request headers from client
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_14() {
  app.get('/proxy-with-headers', async (req, res) => {
    const url = req.query.url as string;
    const customHeaders = {
      'User-Agent': req.headers['user-agent'],
      'Accept': req.headers['accept'],
      'Authorization': req.headers['authorization']
    };
    
    try {
      // ruleid: typescript-express-ssrf
      const response = await axios.get(url, { headers: customHeaders });
      res.send(response.data);
    } catch (error) {
      res.status(500).send('Proxy request failed');
    }
  });
}
// {/fact}

// Example 15: SSRF with dynamic protocol
// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_15() {
  app.get('/dynamic-fetch', async (req, res) => {
    const protocol = req.query.protocol as string;
    const host = req.query.host as string;
    const path = req.query.path as string;
    
    try {
      const url = `${protocol}://${host}/${path}`;
      // ruleid: typescript-express-ssrf
      const response = await fetch(url);
      const data = await response.text();
      res.send(data);
    } catch (error) {
      res.status(500).send('Request failed');
    }
  });
}
// {/fact}

// True Negative Examples (Safe Code)

// Example 1: Using a whitelist of allowed domains
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_1() {
  app.get('/safe-fetch', async (req, res) => {
    const url = req.query.url as string;
    const allowedDomains = ['api.example.com', 'data.example.org'];
    
    try {
      const urlObj = new URL(url);
      // ok: typescript-express-ssrf
      if (allowedDomains.includes(urlObj.hostname)) {
        const response = await axios.get(url);
        res.send(response.data);
      } else {
        res.status(403).send('Domain not allowed');
      }
    } catch (error) {
      res.status(500).send('Error fetching URL');
    }
  });
}
// {/fact}

// Example 2: Using fixed URLs with dynamic paths
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_2() {
  app.get('/api-proxy', async (req, res) => {
    const resourceId = req.query.id as string;
    
    try {
      // ok: typescript-express-ssrf
      const url = `https://api.trusted-domain.com/resources/${resourceId}`;
      const response = await fetch(url);
      const data = await response.json();
      res.json(data);
    } catch (error) {
      res.status(500).send('Error fetching resource');
    }
  });
}
// {/fact}

// Example 3: Using URL validation with validator
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_3() {
  app.get('/validated-fetch', async (req, res) => {
    const urlToFetch = req.query.url as string;
    
    try {
      // ok: typescript-express-ssrf
      if (validator.isURL(urlToFetch, { 
        protocols: ['https'],
        host_whitelist: ['api.trusted.com', 'data.trusted.com']
      })) {
        const response = await axios.get(urlToFetch);
        res.send(response.data);
      } else {
        res.status(400).send('Invalid or disallowed URL');
      }
    } catch (error) {
      res.status(500).send('Error occurred');
    }
  });
}
// {/fact}

// Example 4: Using a predefined API endpoint with dynamic parameters
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_4() {
  app.get('/weather', async (req, res) => {
    const city = req.query.city as string;
    
    try {
      // ok: typescript-express-ssrf
      const url = `https://weather-api.example.com/current?city=${encodeURIComponent(city)}`;
      const response = await axios.get(url);
      res.json(response.data);
    } catch (error) {
      res.status(500).send('Weather data unavailable');
    }
  });
}
// {/fact}

// Example 5: Using a fixed base URL with validated path
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_5() {
  app.get('/docs', async (req, res) => {
    const docPath = req.query.path as string;
    
    // Validate path to prevent directory traversal
    const pathRegex = /^[a-zA-Z0-9-_\/]+\.md$/;
    
    try {
      // ok: typescript-express-ssrf
      if (pathRegex.test(docPath)) {
        const url = `https://docs.example.org/${docPath}`;
        const response = await fetch(url);
        const content = await response.text();
        res.send(content);
      } else {
        res.status(400).send('Invalid document path');
      }
    } catch (error) {
      res.status(404).send('Document not found');
    }
  });
}
// {/fact}

// Example 6: Using an internal configuration for URLs
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_6() {
  const apiConfig = {
    userService: 'https://user-api.internal.com',
    productService: 'https://product-api.internal.com',
    orderService: 'https://order-api.internal.com'
  };
  
  app.get('/internal-api', async (req, res) => {
    const service = req.query.service as string;
    const endpoint = req.query.endpoint as string;
    
    try {
      // ok: typescript-express-ssrf
      if (service in apiConfig && typeof endpoint === 'string') {
        const url = `${apiConfig[service as keyof typeof apiConfig]}/${endpoint}`;
        const response = await axios.get(url);
        res.json(response.data);
      } else {
        res.status(400).send('Invalid service specified');
      }
    } catch (error) {
      res.status(500).send('API request failed');
    }
  });
}
// {/fact}

// Example 7: Using URL validation with custom function
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_7() {
  function isAllowedUrl(url: string): boolean {
    try {
      const parsedUrl = new URL(url);
      const allowedDomains = ['api.company.com', 'cdn.company.com'];
      return allowedDomains.includes(parsedUrl.hostname);
    } catch {
      return false;
    }
  }
  
  app.get('/safe-proxy', async (req, res) => {
    const targetUrl = req.query.url as string;
    
    try {
      // ok: typescript-express-ssrf
      if (isAllowedUrl(targetUrl)) {
        const response = await axios.get(targetUrl);
        res.send(response.data);
      } else {
        res.status(403).send('URL not allowed');
      }
    } catch (error) {
      res.status(500).send('Proxy request failed');
    }
  });
}
// {/fact}

// Example 8: Using a switch statement for predefined endpoints
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_8() {
  app.get('/service-proxy', async (req, res) => {
    const serviceType = req.query.type as string;
    const resourceId = req.query.id as string;
    
    let serviceUrl: string;
    
    // ok: typescript-express-ssrf
    switch (serviceType) {
      case 'users':
        serviceUrl = `https://users-api.example.com/users/${resourceId}`;
        break;
      case 'products':
        serviceUrl = `https://products-api.example.com/products/${resourceId}`;
        break;
      case 'orders':
        serviceUrl = `https://orders-api.example.com/orders/${resourceId}`;
        break;
      default:
        return res.status(400).send('Invalid service type');
    }
    
    try {
      const response = await fetch(serviceUrl);
      const data = await response.json();
      res.json(data);
    } catch (error) {
      res.status(500).send('Service unavailable');
    }
  });
}
// {/fact}

// Example 9: Using a mapping object for allowed endpoints
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_9() {
  app.get('/api-gateway', async (req, res) => {
    const endpoint = req.query.endpoint as string;
    
    const endpointMap: Record<string, string> = {
      'users': 'https://api.example.com/users',
      'products': 'https://api.example.com/products',
      'orders': 'https://api.example.com/orders'
    };
    
    try {
      // ok: typescript-express-ssrf
      if (endpoint in endpointMap) {
        const url = endpointMap[endpoint];
        const response = await axios.get(url);
        res.json(response.data);
      } else {
        res.status(400).send('Invalid endpoint');
      }
    } catch (error) {
      res.status(500).send('Gateway error');
    }
  });
}
// {/fact}

// Example 10: Using URL validation with protocol and hostname check
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_10() {
  app.get('/secure-fetch', async (req, res) => {
    const urlToFetch = req.query.url as string;
    
    try {
      const urlObj = new URL(urlToFetch);
      
      // ok: typescript-express-ssrf
      if (urlObj.protocol === 'https:' && 
          (urlObj.hostname === 'api.trusted.com' || 
           urlObj.hostname.endsWith('.trusted.com'))) {
        const response = await fetch(urlToFetch);
        const data = await response.json();
        res.json(data);
      } else {
        res.status(403).send('URL not allowed');
      }
    } catch (error) {
      res.status(400).send('Invalid URL');
    }
  });
}
// {/fact}

// Example 11: Using a URL builder with fixed components
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_11() {
  app.get('/resource', async (req, res) => {
    const resourceType = req.query.type as string;
    const resourceId = req.query.id as string;
    
    const allowedTypes = ['articles', 'images', 'documents'];
    
    try {
      // ok: typescript-express-ssrf
      if (allowedTypes.includes(resourceType) && /^\d+$/.test(resourceId)) {
        const url = `https://content.example.org/${resourceType}/${resourceId}`;
        const response = await axios.get(url);
        res.send(response.data);
      } else {
        res.status(400).send('Invalid resource request');
      }
    } catch (error) {
      res.status(500).send('Resource unavailable');
    }
  });
}
// {/fact}

// Example 12: Using environment variables for API endpoints
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_12() {
  const API_BASE_URL = process.env.API_BASE_URL || 'https://api.example.com';
  
  app.get('/env-api', async (req, res) => {
    const endpoint = req.query.endpoint as string;
    
    try {
      // ok: typescript-express-ssrf
      const url = `${API_BASE_URL}/${endpoint}`;
      const response = await fetch(url);
      const data = await response.json();
      res.json(data);
    } catch (error) {
      res.status(500).send('API request failed');
    }
  });
}
// {/fact}

// Example 13: Using a service class with predefined endpoints
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_13() {
  class ApiService {
    private baseUrl = 'https://api.trusted-service.com';
    
    async fetchUserData(userId: string) {
      return axios.get(`${this.baseUrl}/users/${userId}`);
    }
    
    async fetchProductData(productId: string) {
      return axios.get(`${this.baseUrl}/products/${productId}`);
    }
  }
  
  const apiService = new ApiService();
  
  app.get('/service-data', async (req, res) => {
    const dataType = req.query.type as string;
    const id = req.query.id as string;
    
    try {
      let response;
      
      // ok: typescript-express-ssrf
      if (dataType === 'user') {
        response = await apiService.fetchUserData(id);
      } else if (dataType === 'product') {
        response = await apiService.fetchProductData(id);
      } else {
        return res.status(400).send('Invalid data type');
      }
      
      res.json(response.data);
    } catch (error) {
      res.status(500).send('Error fetching data');
    }
  });
}
// {/fact}

// Example 14: Using URL validation with regex pattern
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_14() {
  app.get('/regex-validated', async (req, res) => {
    const url = req.query.url as string;
    
    // Validate URL against a specific pattern
    const urlPattern = /^https:\/\/(api|cdn)\.example\.com\/[a-zA-Z0-9\/_-]+$/;
    
    try {
      // ok: typescript-express-ssrf
      if (urlPattern.test(url)) {
        const response = await axios.get(url);
        res.send(response.data);
      } else {
        res.status(403).send('URL not allowed');
      }
    } catch (error) {
      res.status(500).send('Request failed');
    }
  });
}
// {/fact}

// Example 15: Using a configuration object with allowed hosts
// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_15() {
  const config = {
    allowedHosts: ['api.internal.com', 'cdn.internal.com', 'auth.internal.com'],
    maxRedirects: 3,
    timeout: 5000
  };
  
  app.get('/configured-request', async (req, res) => {
    const urlToFetch = req.query.url as string;
    
    try {
      const urlObj = new URL(urlToFetch);
      
      // ok: typescript-express-ssrf
      if (config.allowedHosts.includes(urlObj.hostname)) {
        const response = await axios.get(urlToFetch, {
          maxRedirects: config.maxRedirects,
          timeout: config.timeout
        });
        res.send(response.data);
      } else {
        res.status(403).send('Host not allowed');
      }
    } catch (error) {
      res.status(500).send('Request failed');
    }
  });
}
// {/fact}

export default app;