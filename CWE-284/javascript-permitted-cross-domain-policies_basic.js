// Cross-Domain Policy Configuration Examples
// Rule ID: javascript-permitted-cross-domain-policies

// Import common libraries
const express = require('express');
const http = require('http');
const fs = require('fs');
const helmet = require('helmet');

// BAD EXAMPLES - Vulnerable cross-domain policies

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  app.use((req, res, next) => {
    // ruleid: javascript-permitted-cross-domain-policies
    res.header('X-Permitted-Cross-Domain-Policies', 'all');
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_2() {
  const server = http.createServer((req, res) => {
    // ruleid: javascript-permitted-cross-domain-policies
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'all');
    res.end('Hello World');
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  app.get('/api', (req, res) => {
    // ruleid: javascript-permitted-cross-domain-policies
    res.set({
      'Content-Type': 'application/json',
      'X-Permitted-Cross-Domain-Policies': 'all'
    });
    res.send({ data: 'sensitive information' });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_4() {
  const crossDomainXml = `<?xml version="1.0"?>
  <!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
  <!-- ruleid: javascript-permitted-cross-domain-policies -->
  <cross-domain-policy>
    <site-control permitted-cross-domain-policies="all"/>
    <allow-access-from domain="*" />
    <allow-http-request-headers-from domain="*" headers="*"/>
  </cross-domain-policy>`;
  
  fs.writeFileSync('crossdomain.xml', crossDomainXml);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  app.use((req, res, next) => {
    // ruleid: javascript-permitted-cross-domain-policies
    res.header('X-Permitted-Cross-Domain-Policies', 'master-only');
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_6() {
  const crossDomainXml = `<?xml version="1.0"?>
  <!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
  <!-- ruleid: javascript-permitted-cross-domain-policies -->
  <cross-domain-policy>
    <site-control permitted-cross-domain-policies="by-content-type"/>
    <allow-access-from domain="*" />
  </cross-domain-policy>`;
  
  fs.writeFileSync('/public/crossdomain.xml', crossDomainXml);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  const configureHeaders = (res) => {
    // ruleid: javascript-permitted-cross-domain-policies
    res.header('X-Permitted-Cross-Domain-Policies', 'by-ftp-filename');
    return res;
  };
  
  app.get('/data', (req, res) => {
    configureHeaders(res).send('Data');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  app.use((req, res, next) => {
    if (req.path.includes('api')) {
      // ruleid: javascript-permitted-cross-domain-policies
      res.header('X-Permitted-Cross-Domain-Policies', 'all');
    }
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_9() {
  const headers = {
    'Content-Type': 'application/json',
    // ruleid: javascript-permitted-cross-domain-policies
    'X-Permitted-Cross-Domain-Policies': 'all'
  };
  
  const server = http.createServer((req, res) => {
    Object.entries(headers).forEach(([key, value]) => {
      res.setHeader(key, value);
    });
    res.end(JSON.stringify({ status: 'success' }));
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_10() {
  const crossDomainPolicy = {
    // ruleid: javascript-permitted-cross-domain-policies
    'permitted-cross-domain-policies': 'all',
    'allow-access-from': '*'
  };
  
  const generateXml = () => {
    return `<?xml version="1.0"?>
    <!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
    <cross-domain-policy>
      <site-control permitted-cross-domain-policies="${crossDomainPolicy['permitted-cross-domain-policies']}"/>
      <allow-access-from domain="${crossDomainPolicy['allow-access-from']}" />
    </cross-domain-policy>`;
  };
  
  fs.writeFileSync('crossdomain.xml', generateXml());
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  const securityHeaders = new Map([
    ['X-Content-Type-Options', 'nosniff'],
    ['X-Frame-Options', 'DENY'],
    // ruleid: javascript-permitted-cross-domain-policies
    ['X-Permitted-Cross-Domain-Policies', 'all']
  ]);
  
  app.use((req, res, next) => {
    securityHeaders.forEach((value, key) => {
      res.setHeader(key, value);
    });
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_12() {
  const createCrossDomainXml = (policy) => {
    return `<?xml version="1.0"?>
    <!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
    <cross-domain-policy>
      <site-control permitted-cross-domain-policies="${policy}"/>
      <allow-access-from domain="*" />
    </cross-domain-policy>`;
  };
  
  // ruleid: javascript-permitted-cross-domain-policies
  const xml = createCrossDomainXml('all');
  fs.writeFileSync('crossdomain.xml', xml);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  const policyValue = process.env.CROSS_DOMAIN_POLICY || 'all';
  
  app.use((req, res, next) => {
    // ruleid: javascript-permitted-cross-domain-policies
    res.header('X-Permitted-Cross-Domain-Policies', policyValue);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_14() {
  const server = http.createServer((req, res) => {
    const headers = {};
    headers['Content-Type'] = 'text/html';
    headers['Cache-Control'] = 'no-cache';
    // ruleid: javascript-permitted-cross-domain-policies
    headers['X-Permitted-Cross-Domain-Policies'] = 'all';
    
    for (const [key, value] of Object.entries(headers)) {
      res.setHeader(key, value);
    }
    
    res.end('<html><body>Hello</body></html>');
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
function bad_case_15() {
  const crossDomainSettings = {
    // ruleid: javascript-permitted-cross-domain-policies
    siteControl: 'all',
    allowAccessFrom: ['*.example.com', '*.partner.com'],
    allowHttpRequestHeadersFrom: ['*.example.com', '*.partner.com']
  };
  
  const generateCrossDomainXml = () => {
    let xml = `<?xml version="1.0"?>
    <!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
    <cross-domain-policy>
      <site-control permitted-cross-domain-policies="${crossDomainSettings.siteControl}"/>`;
    
    crossDomainSettings.allowAccessFrom.forEach(domain => {
      xml += `\n      <allow-access-from domain="${domain}" />`;
    });
    
    crossDomainSettings.allowHttpRequestHeadersFrom.forEach(domain => {
      xml += `\n      <allow-http-request-headers-from domain="${domain}" headers="*"/>`;
    });
    
    xml += '\n    </cross-domain-policy>';
    return xml;
  };
  
  fs.writeFileSync('crossdomain.xml', generateCrossDomainXml());
}
// {/fact}

// GOOD EXAMPLES - Secure cross-domain policies

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  app.use((req, res, next) => {
    // ok: javascript-permitted-cross-domain-policies
    res.header('X-Permitted-Cross-Domain-Policies', 'none');
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_2() {
  const server = http.createServer((req, res) => {
    // ok: javascript-permitted-cross-domain-policies
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
    res.end('Hello World');
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  app.get('/api', (req, res) => {
    // ok: javascript-permitted-cross-domain-policies
    res.set({
      'Content-Type': 'application/json',
      'X-Permitted-Cross-Domain-Policies': 'none'
    });
    res.send({ data: 'sensitive information' });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_4() {
  const crossDomainXml = `<?xml version="1.0"?>
  <!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
  <!-- ok: javascript-permitted-cross-domain-policies -->
  <cross-domain-policy>
    <site-control permitted-cross-domain-policies="none"/>
  </cross-domain-policy>`;
  
  fs.writeFileSync('crossdomain.xml', crossDomainXml);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  // Using helmet to set secure headers including X-Permitted-Cross-Domain-Policies
  // ok: javascript-permitted-cross-domain-policies
  app.use(helmet.permittedCrossDomainPolicies({ permittedPolicies: 'none' }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_6() {
  const app = express();
  
  // Using helmet with default settings (which sets X-Permitted-Cross-Domain-Policies to 'none')
  // ok: javascript-permitted-cross-domain-policies
  app.use(helmet());
  
  app.listen(3000);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_7() {
  // Not creating a crossdomain.xml file at all is the most secure approach
  // ok: javascript-permitted-cross-domain-policies
  const server = http.createServer((req, res) => {
    if (req.url === '/crossdomain.xml') {
      res.statusCode = 404;
      res.end('Not found');
    } else {
      res.end('Hello World');
    }
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  const configureHeaders = (res) => {
    // ok: javascript-permitted-cross-domain-policies
    res.header('X-Permitted-Cross-Domain-Policies', 'none');
    return res;
  };
  
  app.get('/data', (req, res) => {
    configureHeaders(res).send('Data');
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_9() {
  const headers = {
    'Content-Type': 'application/json',
    // ok: javascript-permitted-cross-domain-policies
    'X-Permitted-Cross-Domain-Policies': 'none'
  };
  
  const server = http.createServer((req, res) => {
    Object.entries(headers).forEach(([key, value]) => {
      res.setHeader(key, value);
    });
    res.end(JSON.stringify({ status: 'success' }));
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_10() {
  // Explicitly block access with a minimal crossdomain.xml
  // ok: javascript-permitted-cross-domain-policies
  const blockingCrossDomainXml = `<?xml version="1.0"?>
  <!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
  <cross-domain-policy>
    <site-control permitted-cross-domain-policies="none"/>
  </cross-domain-policy>`;
  
  fs.writeFileSync('crossdomain.xml', blockingCrossDomainXml);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  const securityHeaders = new Map([
    ['X-Content-Type-Options', 'nosniff'],
    ['X-Frame-Options', 'DENY'],
    // ok: javascript-permitted-cross-domain-policies
    ['X-Permitted-Cross-Domain-Policies', 'none']
  ]);
  
  app.use((req, res, next) => {
    securityHeaders.forEach((value, key) => {
      res.setHeader(key, value);
    });
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  // Using environment variables with secure default
  const policyValue = process.env.CROSS_DOMAIN_POLICY === 'master-only' ? 
    'master-only' : 'none';
  
  app.use((req, res, next) => {
    // ok: javascript-permitted-cross-domain-policies
    res.header('X-Permitted-Cross-Domain-Policies', policyValue);
    next();
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_13() {
  const server = http.createServer((req, res) => {
    const headers = {};
    headers['Content-Type'] = 'text/html';
    headers['Cache-Control'] = 'no-cache';
    // ok: javascript-permitted-cross-domain-policies
    headers['X-Permitted-Cross-Domain-Policies'] = 'none';
    
    for (const [key, value] of Object.entries(headers)) {
      res.setHeader(key, value);
    }
    
    res.end('<html><body>Hello</body></html>');
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_14() {
  // Using a function to consistently apply secure headers
  const applySecureHeaders = (res) => {
    // ok: javascript-permitted-cross-domain-policies
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    return res;
  };
  
  const server = http.createServer((req, res) => {
    applySecureHeaders(res);
    res.end('Hello World');
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
function good_case_15() {
  // Using a restrictive cross-domain policy that only allows specific domains
  const app = express();
  
  // Implementing a middleware that serves a secure crossdomain.xml
  app.get('/crossdomain.xml', (req, res) => {
    // ok: javascript-permitted-cross-domain-policies
    const xml = `<?xml version="1.0"?>
    <!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
    <cross-domain-policy>
      <site-control permitted-cross-domain-policies="none"/>
    </cross-domain-policy>`;
    
    res.type('application/xml');
    res.send(xml);
  });
  
  app.listen(3000);
}
// {/fact}