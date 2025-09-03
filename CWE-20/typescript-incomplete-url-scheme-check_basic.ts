// File: url_scheme_validation_tests.ts

// Import common libraries for URL handling
import { URL } from 'url';
import * as http from 'http';
import * as express from 'express';
import axios from 'axios';

// TRUE POSITIVES (Vulnerable code that should be detected)

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_1() {
  const userProvidedUrl = "https://example.com";
  
  // Only checking for javascript: scheme but not others
  // ruleid: typescript-incomplete-url-scheme-check
  if (!userProvidedUrl.toLowerCase().startsWith('javascript:')) {
    window.location.href = userProvidedUrl;
  } else {
    console.log("Potentially malicious URL detected");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  app.get('/redirect', (req, res) => {
    const redirectUrl = req.query.url as string;
    
    // Incomplete check - only checks for javascript: scheme
    // ruleid: typescript-incomplete-url-scheme-check
    if (redirectUrl.indexOf('javascript:') === -1) {
      res.redirect(redirectUrl);
    } else {
      res.status(400).send('Invalid URL');
    }
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_3() {
  const userInput = document.getElementById('user-input') as HTMLInputElement;
  const url = userInput.value;
  
  // Checks only for javascript: using regex but misses other schemes
  // ruleid: typescript-incomplete-url-scheme-check
  if (!url.match(/^javascript:/i)) {
    document.location = url;
  } else {
    console.error("Potentially dangerous URL");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_4() {
  const server = http.createServer((req, res) => {
    const urlParam = new URL(req.url || '', `http://${req.headers.host}`).searchParams.get('redirect');
    
    if (urlParam) {
      // Only checking for javascript: in lowercase
      // ruleid: typescript-incomplete-url-scheme-check
      if (!urlParam.startsWith('javascript:')) {
        res.writeHead(302, { 'Location': urlParam });
        res.end();
      } else {
        res.writeHead(400);
        res.end('Invalid URL');
      }
    }
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_5() {
  function validateUrl(url: string): boolean {
    // Incomplete validation - only checks javascript: scheme
    // ruleid: typescript-incomplete-url-scheme-check
    return !url.toLowerCase().includes('javascript:');
  }
  
  const userUrl = "https://example.com";
  if (validateUrl(userUrl)) {
    window.open(userUrl, '_blank');
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_6() {
  class UrlValidator {
    static isSafe(url: string): boolean {
      // Only checks for javascript: scheme with case insensitivity
      // ruleid: typescript-incomplete-url-scheme-check
      return !/javascript:/i.test(url);
    }
  }
  
  const userUrl = "https://example.com";
  if (UrlValidator.isSafe(userUrl)) {
    location.assign(userUrl);
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_7() {
  const iframe = document.createElement('iframe');
  const userProvidedSrc = "https://example.com";
  
  // Incomplete check using String.search
  // ruleid: typescript-incomplete-url-scheme-check
  if (userProvidedSrc.toLowerCase().search('javascript:') === -1) {
    iframe.src = userProvidedSrc;
    document.body.appendChild(iframe);
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  app.post('/process-url', (req, res) => {
    const url = req.body.url;
    let isUrlSafe = true;
    
    // Only checking for javascript: with string comparison
    // ruleid: typescript-incomplete-url-scheme-check
    if (url.toLowerCase().indexOf('javascript:') >= 0) {
      isUrlSafe = false;
    }
    
    if (isUrlSafe) {
      res.send({ redirectUrl: url });
    } else {
      res.status(400).send({ error: 'Invalid URL' });
    }
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_9() {
  const sanitizeUrl = (url: string): string => {
    // Only removing javascript: scheme but not others
    // ruleid: typescript-incomplete-url-scheme-check
    if (url.toLowerCase().startsWith('javascript:')) {
      return '#';
    }
    return url;
  };
  
  const userUrl = "https://example.com";
  const anchor = document.createElement('a');
  anchor.href = sanitizeUrl(userUrl);
  document.body.appendChild(anchor);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_10() {
  function processUserInput() {
    const input = document.getElementById('url-input') as HTMLInputElement;
    const url = input.value;
    
    // Switch statement only checking for javascript:
    // ruleid: typescript-incomplete-url-scheme-check
    switch (true) {
      case url.toLowerCase().startsWith('javascript:'):
        console.error('JavaScript URLs are not allowed');
        break;
      default:
        window.location.replace(url);
        break;
    }
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_11() {
  const urlValidator = {
    dangerousSchemes: ['javascript:'],
    isUrlSafe(url: string): boolean {
      // Only checks for javascript: in the array
      // ruleid: typescript-incomplete-url-scheme-check
      return !this.dangerousSchemes.some(scheme => 
        url.toLowerCase().startsWith(scheme)
      );
    }
  };
  
  const userUrl = "https://example.com";
  if (urlValidator.isUrlSafe(userUrl)) {
    document.location.href = userUrl;
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_12() {
  async function fetchExternalContent(urlInput: string) {
    // Only checking for javascript: using a ternary operator
    // ruleid: typescript-incomplete-url-scheme-check
    const url = urlInput.toLowerCase().startsWith('javascript:') 
      ? 'https://safe-default.com' 
      : urlInput;
      
    const response = await axios.get(url);
    return response.data;
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  app.get('/proxy', (req, res) => {
    let targetUrl = req.query.url as string;
    
    // Only checking for javascript: with string replacement
    // ruleid: typescript-incomplete-url-scheme-check
    targetUrl = targetUrl.replace(/javascript:/gi, '');
    
    axios.get(targetUrl)
      .then(response => res.send(response.data))
      .catch(error => res.status(500).send(error.message));
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_14() {
  function createDynamicLink(href: string): HTMLAnchorElement {
    // Only checking for javascript: with conditional
    // ruleid: typescript-incomplete-url-scheme-check
    let safeHref = href;
    if (href.toLowerCase().includes('javascript:')) {
      safeHref = '#';
    }
    
    const link = document.createElement('a');
    link.href = safeHref;
    link.textContent = 'Click me';
    return link;
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_15() {
  const urlChecker = (url: string): boolean => {
    // Only checking for javascript: with multiple conditions
    // ruleid: typescript-incomplete-url-scheme-check
    if (url.toLowerCase().startsWith('javascript:') || 
        url.toLowerCase().includes('%0ajavascript:')) {
      return false;
    }
    return true;
  };
  
  const userUrl = "https://example.com";
  if (urlChecker(userUrl)) {
    window.open(userUrl);
  }
}
// {/fact}

// TRUE NEGATIVES (Safe code that should not be detected)

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_1() {
  const userProvidedUrl = "https://example.com";
  
  // Properly checking for multiple dangerous schemes
  // ok: typescript-incomplete-url-scheme-check
  if (!userProvidedUrl.toLowerCase().startsWith('javascript:') && 
      !userProvidedUrl.toLowerCase().startsWith('data:') && 
      !userProvidedUrl.toLowerCase().startsWith('vbscript:')) {
    window.location.href = userProvidedUrl;
  } else {
    console.log("Potentially malicious URL detected");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  app.get('/redirect', (req, res) => {
    const redirectUrl = req.query.url as string;
    
    // Complete check for all dangerous schemes
    // ok: typescript-incomplete-url-scheme-check
    if (redirectUrl.indexOf('javascript:') === -1 && 
        redirectUrl.indexOf('data:') === -1 && 
        redirectUrl.indexOf('vbscript:') === -1) {
      res.redirect(redirectUrl);
    } else {
      res.status(400).send('Invalid URL');
    }
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_3() {
  const userInput = document.getElementById('user-input') as HTMLInputElement;
  const url = userInput.value;
  
  // Comprehensive regex check for multiple schemes
  // ok: typescript-incomplete-url-scheme-check
  if (!url.match(/^(javascript|data|vbscript):/i)) {
    document.location = url;
  } else {
    console.error("Potentially dangerous URL");
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_4() {
  const server = http.createServer((req, res) => {
    const urlParam = new URL(req.url || '', `http://${req.headers.host}`).searchParams.get('redirect');
    
    if (urlParam) {
      // Checking for all dangerous schemes with array
      const dangerousSchemes = ['javascript:', 'data:', 'vbscript:'];
      // ok: typescript-incomplete-url-scheme-check
      const isUrlSafe = !dangerousSchemes.some(scheme => 
        urlParam.toLowerCase().startsWith(scheme)
      );
      
      if (isUrlSafe) {
        res.writeHead(302, { 'Location': urlParam });
        res.end();
      } else {
        res.writeHead(400);
        res.end('Invalid URL');
      }
    }
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_5() {
  function validateUrl(url: string): boolean {
    const lowerUrl = url.toLowerCase();
    // Complete validation checking all schemes
    // ok: typescript-incomplete-url-scheme-check
    return !lowerUrl.includes('javascript:') && 
           !lowerUrl.includes('data:') && 
           !lowerUrl.includes('vbscript:');
  }
  
  const userUrl = "https://example.com";
  if (validateUrl(userUrl)) {
    window.open(userUrl, '_blank');
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_6() {
  class UrlValidator {
    static isSafe(url: string): boolean {
      // Comprehensive regex test for all dangerous schemes
      // ok: typescript-incomplete-url-scheme-check
      return !/(?:javascript|data|vbscript):/i.test(url);
    }
  }
  
  const userUrl = "https://example.com";
  if (UrlValidator.isSafe(userUrl)) {
    location.assign(userUrl);
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_7() {
  // Using URL constructor to validate instead of string checks
  function isUrlSafe(urlString: string): boolean {
    try {
      const url = new URL(urlString);
      // ok: typescript-incomplete-url-scheme-check
      return url.protocol !== 'javascript:' && 
             url.protocol !== 'data:' && 
             url.protocol !== 'vbscript:';
    } catch {
      return false;
    }
  }
  
  const userUrl = "https://example.com";
  if (isUrlSafe(userUrl)) {
    window.location.href = userUrl;
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  app.post('/process-url', (req, res) => {
    const url = req.body.url;
    
    // Using a whitelist approach for allowed protocols
    try {
      const parsedUrl = new URL(url);
      const allowedProtocols = ['http:', 'https:'];
      // ok: typescript-incomplete-url-scheme-check
      if (allowedProtocols.includes(parsedUrl.protocol)) {
        res.send({ redirectUrl: url });
      } else {
        res.status(400).send({ error: 'Invalid URL protocol' });
      }
    } catch {
      res.status(400).send({ error: 'Invalid URL format' });
    }
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_9() {
  const sanitizeUrl = (url: string): string => {
    const lowerUrl = url.toLowerCase();
    // Checking and sanitizing all dangerous schemes
    // ok: typescript-incomplete-url-scheme-check
    if (lowerUrl.startsWith('javascript:') || 
        lowerUrl.startsWith('data:') || 
        lowerUrl.startsWith('vbscript:')) {
      return '#';
    }
    return url;
  };
  
  const userUrl = "https://example.com";
  const anchor = document.createElement('a');
  anchor.href = sanitizeUrl(userUrl);
  document.body.appendChild(anchor);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_10() {
  function processUserInput() {
    const input = document.getElementById('url-input') as HTMLInputElement;
    const url = input.value;
    
    // Switch statement checking all dangerous schemes
    const lowerUrl = url.toLowerCase();
    // ok: typescript-incomplete-url-scheme-check
    switch (true) {
      case lowerUrl.startsWith('javascript:'):
      case lowerUrl.startsWith('data:'):
      case lowerUrl.startsWith('vbscript:'):
        console.error('Potentially dangerous URL detected');
        break;
      default:
        window.location.replace(url);
        break;
    }
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_11() {
  const urlValidator = {
    dangerousSchemes: ['javascript:', 'data:', 'vbscript:'],
    isUrlSafe(url: string): boolean {
      // Checks for all dangerous schemes in the array
      // ok: typescript-incomplete-url-scheme-check
      return !this.dangerousSchemes.some(scheme => 
        url.toLowerCase().startsWith(scheme)
      );
    }
  };
  
  const userUrl = "https://example.com";
  if (urlValidator.isUrlSafe(userUrl)) {
    document.location.href = userUrl;
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_12() {
  // Using a dedicated URL validation library
  function validateUrlWithLib(url: string): boolean {
    // This is a mock of a URL validation library function
    function isValidUrl(url: string): boolean {
      try {
        const parsedUrl = new URL(url);
        // ok: typescript-incomplete-url-scheme-check
        const dangerousProtocols = ['javascript:', 'data:', 'vbscript:'];
        return !dangerousProtocols.includes(parsedUrl.protocol);
      } catch {
        return false;
      }
    }
    
    return isValidUrl(url);
  }
  
  const userUrl = "https://example.com";
  if (validateUrlWithLib(userUrl)) {
    location.href = userUrl;
  }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  app.get('/proxy', (req, res) => {
    let targetUrl = req.query.url as string;
    
    // Using regex to remove all dangerous schemes
    // ok: typescript-incomplete-url-scheme-check
    targetUrl = targetUrl.replace(/(?:javascript|data|vbscript):/gi, '');
    
    axios.get(targetUrl)
      .then(response => res.send(response.data))
      .catch(error => res.status(500).send(error.message));
  });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_14() {
  // Using a comprehensive URL sanitizer function
  function sanitizeUrl(url: string): string {
    if (!url) return '#';
    
    const urlLower = url.toLowerCase();
    const dangerousProtocols = [
      'javascript:',
      'data:',
      'vbscript:'
    ];
    
    // ok: typescript-incomplete-url-scheme-check
    for (const protocol of dangerousProtocols) {
      if (urlLower.startsWith(protocol)) {
        return '#';
      }
    }
    
    return url;
  }
  
  const userUrl = "https://example.com";
  window.location.href = sanitizeUrl(userUrl);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_15() {
  // Using a more complex validation with URL parsing
  function isUrlSafe(urlString: string): boolean {
    try {
      const url = new URL(urlString);
      
      // Whitelist approach combined with blacklist check
      const safeProtocols = ['http:', 'https:', 'ftp:', 'ftps:'];
      const dangerousProtocols = ['javascript:', 'data:', 'vbscript:'];
      
      // ok: typescript-incomplete-url-scheme-check
      return safeProtocols.includes(url.protocol) && 
             !dangerousProtocols.includes(url.protocol);
    } catch {
      return false;
    }
  }
  
  const userUrl = "https://example.com";
  if (isUrlSafe(userUrl)) {
    document.location.href = userUrl;
  }
}
// {/fact}