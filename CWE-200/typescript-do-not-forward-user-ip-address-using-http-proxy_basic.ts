import * as http from 'http';
import * as https from 'https';
import axios from 'axios';
import request from 'request';
import got from 'got';
import fetch from 'node-fetch';
import superagent from 'superagent';
import express from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';

// BAD CASES - Forwarding user IP addresses (vulnerable)

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  app.get('/proxy', (req, res) => {
    const options = {
      hostname: 'api.example.com',
      path: '/data',
      method: 'GET',
      headers: {
        // ruleid: typescript-do-not-forward-user-ip-address-using-http-proxy
        'X-Forwarded-For': req.ip
      }
    };
    
    const proxyReq = http.request(options, (proxyRes) => {
      proxyRes.pipe(res);
    });
    
    proxyReq.end();
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  app.get('/proxy', (req, res) => {
    const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    
    // ruleid: typescript-do-not-forward-user-ip-address-using-http-proxy
    axios.get('https://api.example.com/data', {
      headers: {
        'X-Forwarded-For': clientIp
      }
    }).then(response => {
      res.send(response.data);
    });
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  app.get('/proxy', (req, res) => {
    const clientIp = req.ip;
    
    // ruleid: typescript-do-not-forward-user-ip-address-using-http-proxy
    request({
      url: 'https://api.example.com/data',
      headers: {
        'X-Real-IP': clientIp
      }
    }, (error, response, body) => {
      res.send(body);
    });
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  app.get('/proxy', async (req, res) => {
    const clientIp = req.connection.remoteAddress;
    
    try {
      // ruleid: typescript-do-not-forward-user-ip-address-using-http-proxy
      const response = await got('https://api.example.com/data', {
        headers: {
          'Client-IP': clientIp
        }
      });
      res.send(response.body);
    } catch (error) {
      res.status(500).send('Error');
    }
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  app.get('/proxy', async (req, res) => {
    const clientIp = req.headers['x-forwarded-for'] || req.ip;
    
    try {
      // ruleid: typescript-do-not-forward-user-ip-address-using-http-proxy
      const response = await fetch('https://api.example.com/data', {
        headers: {
          'X-Forwarded-For': clientIp
        }
      });
      const data = await response.json();
      res.send(data);
    } catch (error) {
      res.status(500).send('Error');
    }
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  
  app.get('/proxy', (req, res) => {
    const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    
    // ruleid: typescript-do-not-forward-user-ip-address-using-http-proxy
    superagent
      .get('https://api.example.com/data')
      .set('X-Forwarded-For', clientIp)
      .end((err, response) => {
        if (err) {
          return res.status(500).send('Error');
        }
        res.send(response.body);
      });
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  // ruleid: typescript-do-not-forward-user-ip-address-using-http-proxy
  const apiProxy = createProxyMiddleware('/api', {
    target: 'https://api.example.com',
    changeOrigin: true,
    onProxyReq: (proxyReq, req, res) => {
      proxyReq.setHeader('X-Forwarded-For', req.ip);
    }
  });
  
  app.use(apiProxy);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  app.get('/proxy', (req, res) => {
    const options = {
      hostname: 'api.example.com',
      path: '/data',
      method: 'GET',
      headers: {}
    };
    
    if (req.headers['x-forwarded-for']) {
      // ruleid: typescript-do-not-forward-user-ip-address-using-http-proxy
      options.headers['X-Forwarded-For'] = req.headers['x-forwarded-for'];
    } else {
      // ruleid: typescript-do-not-forward-user-ip-address-using-http-proxy
      options.headers['X-Forwarded-For'] = req.connection.remoteAddress;
    }
    
    const proxyReq = https.request(options, (proxyRes) => {
      proxyRes.pipe(res);
    });
    
    proxyReq.end();
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  app.get('/proxy', (req, res) => {
    const userIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const headers = {
      'Content-Type': 'application/json',
      // ruleid: typescript-do-not-forward-user-ip-address-using-http-proxy
      'X-Client-IP': userIp
    };
    
    axios.post('https://api.example.com/data', { data: 'test' }, { headers })
      .then(response => {
        res.send(response.data);
      })
      .catch(error => {
        res.status(500).send('Error');
      });
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  app.get('/proxy', (req, res) => {
    const forwardedIps = req.headers['x-forwarded-for'] as string || '';
    const clientIp = forwardedIps.split(',')[0].trim() || req.connection.remoteAddress;
    
    // ruleid: typescript-do-not-forward-user-ip-address-using-http-proxy
    const proxyReq = http.request({
      hostname: 'api.example.com',
      path: '/data',
      method: 'GET',
      headers: {
        'X-Real-IP': clientIp
      }
    }, (proxyRes) => {
      proxyRes.pipe(res);
    });
    
    proxyReq.end();
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  app.get('/proxy', async (req, res) => {
    try {
      const ipAddress = req.ip;
      const requestHeaders = {
        'User-Agent': req.headers['user-agent'],
        // ruleid: typescript-do-not-forward-user-ip-address-using-http-proxy
        'X-Original-IP': ipAddress
      };
      
      const response = await axios.get('https://api.example.com/data', { headers: requestHeaders });
      res.send(response.data);
    } catch (error) {
      res.status(500).send('Error');
    }
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  app.use((req, res, next) => {
    req.clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    next();
  });
  
  app.get('/proxy', (req: any, res) => {
    // ruleid: typescript-do-not-forward-user-ip-address-using-http-proxy
    request.get({
      url: 'https://api.example.com/data',
      headers: {
        'X-Forwarded-For': req.clientIp
      }
    }).pipe(res);
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  app.get('/proxy', (req, res) => {
    const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const url = new URL('https://api.example.com/data');
    
    // ruleid: typescript-do-not-forward-user-ip-address-using-http-proxy
    const proxyReq = https.request({
      hostname: url.hostname,
      path: url.pathname,
      method: 'GET',
      headers: {
        'X-Client-IP': clientIp
      }
    }, (proxyRes) => {
      let data = '';
      proxyRes.on('data', (chunk) => {
        data += chunk;
      });
      proxyRes.on('end', () => {
        res.send(data);
      });
    });
    
    proxyReq.end();
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  app.get('/proxy', (req, res) => {
    const headers: Record<string, string> = {};
    
    if (req.headers['user-agent']) {
      headers['User-Agent'] = req.headers['user-agent'] as string;
    }
    
    // ruleid: typescript-do-not-forward-user-ip-address-using-http-proxy
    headers['X-Forwarded-For'] = req.ip;
    
    axios.get('https://api.example.com/data', { headers })
      .then(response => {
        res.send(response.data);
      })
      .catch(error => {
        res.status(500).send('Error');
      });
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  app.get('/proxy', (req, res) => {
    const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    
    const options = {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        // ruleid: typescript-do-not-forward-user-ip-address-using-http-proxy
        'X-Visitor-IP': clientIp
      }
    };
    
    const proxyReq = https.request('https://api.example.com/data', options, (proxyRes) => {
      let data = '';
      proxyRes.on('data', (chunk) => {
        data += chunk;
      });
      proxyRes.on('end', () => {
        res.send(JSON.parse(data));
      });
    });
    
    proxyReq.end();
  });
}
// {/fact}

// GOOD CASES - Not forwarding user IP addresses (secure)

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  app.get('/proxy', (req, res) => {
    const options = {
      hostname: 'api.example.com',
      path: '/data',
      method: 'GET',
      // ok: typescript-do-not-forward-user-ip-address-using-http-proxy
      headers: {
        'User-Agent': 'MyProxyServer/1.0'
      }
    };
    
    const proxyReq = http.request(options, (proxyRes) => {
      proxyRes.pipe(res);
    });
    
    proxyReq.end();
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  app.get('/proxy', (req, res) => {
    // ok: typescript-do-not-forward-user-ip-address-using-http-proxy
    axios.get('https://api.example.com/data', {
      headers: {
        'User-Agent': 'MyProxyServer/1.0'
      }
    }).then(response => {
      res.send(response.data);
    });
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  app.get('/proxy', (req, res) => {
    // ok: typescript-do-not-forward-user-ip-address-using-http-proxy
    request({
      url: 'https://api.example.com/data',
      headers: {
        'Accept': 'application/json'
      }
    }, (error, response, body) => {
      res.send(body);
    });
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  app.get('/proxy', async (req, res) => {
    try {
      // ok: typescript-do-not-forward-user-ip-address-using-http-proxy
      const response = await got('https://api.example.com/data', {
        headers: {
          'Accept-Language': 'en-US'
        }
      });
      res.send(response.body);
    } catch (error) {
      res.status(500).send('Error');
    }
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  app.get('/proxy', async (req, res) => {
    try {
      // ok: typescript-do-not-forward-user-ip-address-using-http-proxy
      const response = await fetch('https://api.example.com/data', {
        headers: {
          'Content-Type': 'application/json'
        }
      });
      const data = await response.json();
      res.send(data);
    } catch (error) {
      res.status(500).send('Error');
    }
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_6() {
  const app = express();
  
  app.get('/proxy', (req, res) => {
    // ok: typescript-do-not-forward-user-ip-address-using-http-proxy
    superagent
      .get('https://api.example.com/data')
      .set('Accept', 'application/json')
      .end((err, response) => {
        if (err) {
          return res.status(500).send('Error');
        }
        res.send(response.body);
      });
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  // ok: typescript-do-not-forward-user-ip-address-using-http-proxy
  const apiProxy = createProxyMiddleware('/api', {
    target: 'https://api.example.com',
    changeOrigin: true,
    onProxyReq: (proxyReq, req, res) => {
      proxyReq.setHeader('X-Proxy-ID', 'my-proxy-server');
    }
  });
  
  app.use(apiProxy);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  app.get('/proxy', (req, res) => {
    // ok: typescript-do-not-forward-user-ip-address-using-http-proxy
    const options = {
      hostname: 'api.example.com',
      path: '/data',
      method: 'GET',
      headers: {
        'Cache-Control': 'no-cache'
      }
    };
    
    const proxyReq = https.request(options, (proxyRes) => {
      proxyRes.pipe(res);
    });
    
    proxyReq.end();
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  app.get('/proxy', (req, res) => {
    // ok: typescript-do-not-forward-user-ip-address-using-http-proxy
    const headers = {
      'Content-Type': 'application/json',
      'X-Proxy-ID': 'my-proxy-server'
    };
    
    axios.post('https://api.example.com/data', { data: 'test' }, { headers })
      .then(response => {
        res.send(response.data);
      })
      .catch(error => {
        res.status(500).send('Error');
      });
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  app.get('/proxy', (req, res) => {
    // ok: typescript-do-not-forward-user-ip-address-using-http-proxy
    const proxyReq = http.request({
      hostname: 'api.example.com',
      path: '/data',
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'X-Proxy-Version': '1.0'
      }
    }, (proxyRes) => {
      proxyRes.pipe(res);
    });
    
    proxyReq.end();
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  app.get('/proxy', async (req, res) => {
    try {
      // ok: typescript-do-not-forward-user-ip-address-using-http-proxy
      const requestHeaders = {
        'User-Agent': 'MyProxyServer/1.0',
        'Accept-Language': 'en-US'
      };
      
      const response = await axios.get('https://api.example.com/data', { headers: requestHeaders });
      res.send(response.data);
    } catch (error) {
      res.status(500).send('Error');
    }
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  app.get('/proxy', (req, res) => {
    // ok: typescript-do-not-forward-user-ip-address-using-http-proxy
    request.get({
      url: 'https://api.example.com/data',
      headers: {
        'X-Proxy-ID': 'my-proxy-server'
      }
    }).pipe(res);
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  app.get('/proxy', (req, res) => {
    const url = new URL('https://api.example.com/data');
    
    // ok: typescript-do-not-forward-user-ip-address-using-http-proxy
    const proxyReq = https.request({
      hostname: url.hostname,
      path: url.pathname,
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'X-Proxy-ID': 'my-proxy-server'
      }
    }, (proxyRes) => {
      let data = '';
      proxyRes.on('data', (chunk) => {
        data += chunk;
      });
      proxyRes.on('end', () => {
        res.send(data);
      });
    });
    
    proxyReq.end();
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  app.get('/proxy', (req, res) => {
    // ok: typescript-do-not-forward-user-ip-address-using-http-proxy
    const headers: Record<string, string> = {
      'User-Agent': 'MyProxyServer/1.0',
      'Accept': 'application/json'
    };
    
    axios.get('https://api.example.com/data', { headers })
      .then(response => {
        res.send(response.data);
      })
      .catch(error => {
        res.status(500).send('Error');
      });
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  app.get('/proxy', (req, res) => {
    // ok: typescript-do-not-forward-user-ip-address-using-http-proxy
    const options = {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'X-Proxy-ID': 'my-proxy-server'
      }
    };
    
    const proxyReq = https.request('https://api.example.com/data', options, (proxyRes) => {
      let data = '';
      proxyRes.on('data', (chunk) => {
        data += chunk;
      });
      proxyRes.on('end', () => {
        res.send(JSON.parse(data));
      });
    });
    
    proxyReq.end();
  });
}
// {/fact}