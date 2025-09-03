import { chromium, firefox, webkit, Browser, BrowserContext, Page } from 'playwright';
import express from 'express';
import http from 'http';
import https from 'https';
import { URL } from 'url';

// TRUE POSITIVES (Vulnerable Code)

// Case 1: Direct use of user input in goto method
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_1() {
  const app = express();
  app.get('/navigate', async (req, res) => {
    const url = req.query.url as string;
    const browser = await chromium.launch();
    const page = await browser.newPage();
    // ruleid: playwright-goto-injection-ts-rule
    await page.goto(url);
    const content = await page.content();
    await browser.close();
    res.send(content);
  });
}
// {/fact}

// Case 2: User input with minimal transformation
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_2() {
  const app = express();
  app.get('/screenshot', async (req, res) => {
    const targetUrl = req.query.site + '/homepage';
    const browser = await firefox.launch();
    const context = await browser.newContext();
    const page = await context.newPage();
    // ruleid: playwright-goto-injection-ts-rule
    await page.goto(targetUrl);
    const screenshot = await page.screenshot();
    await browser.close();
    res.contentType('image/png').send(screenshot);
  });
}
// {/fact}

// Case 3: User input from POST body
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_3() {
  const app = express();
  app.use(express.json());
  app.post('/render', async (req, res) => {
    const { targetUrl } = req.body;
    const browser = await webkit.launch();
    const page = await browser.newPage();
    // ruleid: playwright-goto-injection-ts-rule
    await page.goto(targetUrl);
    const pdf = await page.pdf();
    await browser.close();
    res.contentType('application/pdf').send(pdf);
  });
}
// {/fact}

// Case 4: User input from headers
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_4() {
  const app = express();
  app.get('/proxy', async (req, res) => {
    const referer = req.headers.referer as string;
    const browser = await chromium.launch();
    const page = await browser.newPage();
    // ruleid: playwright-goto-injection-ts-rule
    await page.goto(referer);
    const content = await page.content();
    await browser.close();
    res.send(content);
  });
}
// {/fact}

// Case 5: User input with string concatenation
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_5() {
  const app = express();
  app.get('/visit', async (req, res) => {
    const domain = req.query.domain as string;
    const protocol = req.query.protocol as string;
    const fullUrl = protocol + '://' + domain;
    
    const browser = await chromium.launch();
    const page = await browser.newPage();
    // ruleid: playwright-goto-injection-ts-rule
    await page.goto(fullUrl);
    const title = await page.title();
    await browser.close();
    res.send({ title });
  });
}
// {/fact}

// Case 6: User input in template literal
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_6() {
  const app = express();
  app.get('/preview', async (req, res) => {
    const subdomain = req.query.subdomain as string;
    const browser = await firefox.launch();
    const page = await browser.newPage();
    // ruleid: playwright-goto-injection-ts-rule
    await page.goto(`https://${subdomain}.example.com`);
    const screenshot = await page.screenshot();
    await browser.close();
    res.contentType('image/png').send(screenshot);
  });
}
// {/fact}

// Case 7: User input from cookies
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_7() {
  const app = express();
  app.get('/last-visited', async (req, res) => {
    const lastUrl = req.cookies.lastVisited;
    const browser = await webkit.launch();
    const page = await browser.newPage();
    // ruleid: playwright-goto-injection-ts-rule
    await page.goto(lastUrl);
    const content = await page.content();
    await browser.close();
    res.send(content);
  });
}
// {/fact}

// Case 8: User input with URL object
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_8() {
  const app = express();
  app.get('/fetch', async (req, res) => {
    const inputUrl = req.query.url as string;
    const urlObj = new URL(inputUrl);
    
    const browser = await chromium.launch();
    const page = await browser.newPage();
    // ruleid: playwright-goto-injection-ts-rule
    await page.goto(urlObj.toString());
    const content = await page.content();
    await browser.close();
    res.send(content);
  });
}
// {/fact}

// Case 9: User input through path parameters
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_9() {
  const app = express();
  app.get('/site/:domain', async (req, res) => {
    const domain = req.params.domain;
    const url = `https://${domain}`;
    
    const browser = await firefox.launch();
    const page = await browser.newPage();
    // ruleid: playwright-goto-injection-ts-rule
    await page.goto(url);
    const title = await page.title();
    await browser.close();
    res.send({ title });
  });
}
// {/fact}

// Case 10: User input with conditional logic
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_10() {
  const app = express();
  app.get('/conditional', async (req, res) => {
    const targetUrl = req.query.url as string;
    const useHttps = req.query.secure === 'true';
    
    let finalUrl = targetUrl;
    if (useHttps && !targetUrl.startsWith('https://')) {
      finalUrl = 'https://' + targetUrl;
    }
    
    const browser = await chromium.launch();
    const page = await browser.newPage();
    // ruleid: playwright-goto-injection-ts-rule
    await page.goto(finalUrl);
    const content = await page.content();
    await browser.close();
    res.send(content);
  });
}
// {/fact}

// Case 11: User input with array join
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_11() {
  const app = express();
  app.get('/complex-url', async (req, res) => {
    const parts = [
      req.query.protocol as string,
      '://',
      req.query.domain as string,
      '/',
      req.query.path as string
    ];
    const url = parts.join('');
    
    const browser = await webkit.launch();
    const page = await browser.newPage();
    // ruleid: playwright-goto-injection-ts-rule
    await page.goto(url);
    const content = await page.content();
    await browser.close();
    res.send(content);
  });
}
// {/fact}

// Case 12: User input with object destructuring
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_12() {
  const app = express();
  app.use(express.json());
  app.post('/navigate-complex', async (req, res) => {
    const { protocol, domain, path } = req.body;
    const url = `${protocol}://${domain}/${path}`;
    
    const browser = await chromium.launch();
    const page = await browser.newPage();
    // ruleid: playwright-goto-injection-ts-rule
    await page.goto(url);
    const content = await page.content();
    await browser.close();
    res.send(content);
  });
}
// {/fact}

// Case 13: User input with async processing
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_13() {
  const app = express();
  app.get('/delayed', async (req, res) => {
    const targetUrl = req.query.url as string;
    
    // Simulate some async processing
    const processUrl = async (url: string): Promise<string> => {
      return new Promise(resolve => {
        setTimeout(() => resolve(url), 100);
      });
    };
    
    const processedUrl = await processUrl(targetUrl);
    const browser = await firefox.launch();
    const page = await browser.newPage();
    // ruleid: playwright-goto-injection-ts-rule
    await page.goto(processedUrl);
    const content = await page.content();
    await browser.close();
    res.send(content);
  });
}
// {/fact}

// Case 14: User input with switch statement
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_14() {
  const app = express();
  app.get('/switch-case', async (req, res) => {
    const targetUrl = req.query.url as string;
    const mode = req.query.mode as string;
    
    let finalUrl: string;
    switch(mode) {
      case 'www':
        finalUrl = `https://www.${targetUrl}`;
        break;
      case 'mobile':
        finalUrl = `https://m.${targetUrl}`;
        break;
      default:
        finalUrl = `https://${targetUrl}`;
    }
    
    const browser = await chromium.launch();
    const page = await browser.newPage();
    // ruleid: playwright-goto-injection-ts-rule
    await page.goto(finalUrl);
    const content = await page.content();
    await browser.close();
    res.send(content);
  });
}
// {/fact}

// Case 15: User input with try-catch
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_15() {
  const app = express();
  app.get('/error-handling', async (req, res) => {
    const targetUrl = req.query.url as string;
    
    try {
      const browser = await webkit.launch();
      const page = await browser.newPage();
      // ruleid: playwright-goto-injection-ts-rule
      await page.goto(targetUrl);
      const content = await page.content();
      await browser.close();
      res.send(content);
    } catch (error) {
      res.status(500).send({ error: 'Failed to navigate' });
    }
  });
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// Case 1: Using hardcoded URL
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_1() {
  const app = express();
  app.get('/static', async (req, res) => {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    // ok: playwright-goto-injection-ts-rule
    await page.goto('https://example.com');
    const content = await page.content();
    await browser.close();
    res.send(content);
  });
}
// {/fact}

// Case 2: Validating URL against whitelist
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_2() {
  const app = express();
  app.get('/whitelist', async (req, res) => {
    const targetUrl = req.query.url as string;
    const allowedDomains = ['example.com', 'trusted-site.org', 'safe-domain.net'];
    
    const urlObj = new URL(targetUrl);
    const domain = urlObj.hostname;
    
    if (!allowedDomains.includes(domain)) {
      return res.status(403).send('Domain not allowed');
    }
    
    const browser = await firefox.launch();
    const page = await browser.newPage();
    // ok: playwright-goto-injection-ts-rule
    await page.goto(targetUrl);
    const content = await page.content();
    await browser.close();
    res.send(content);
  });
}
// {/fact}

// Case 3: Using URL pattern validation
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_3() {
  const app = express();
  app.get('/pattern', async (req, res) => {
    const targetUrl = req.query.url as string;
    
    // Validate URL format and domain
    const urlPattern = /^https:\/\/example\.com\/[a-zA-Z0-9\/_-]+$/;
    if (!urlPattern.test(targetUrl)) {
      return res.status(403).send('Invalid URL pattern');
    }
    
    const browser = await webkit.launch();
    const page = await browser.newPage();
    // ok: playwright-goto-injection-ts-rule
    await page.goto(targetUrl);
    const content = await page.content();
    await browser.close();
    res.send(content);
  });
}
// {/fact}

// Case 4: Using URL object to validate protocol and hostname
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_4() {
  const app = express();
  app.get('/validate-components', async (req, res) => {
    const targetUrl = req.query.url as string;
    
    try {
      const urlObj = new URL(targetUrl);
      
      // Validate protocol and hostname
      if (urlObj.protocol !== 'https:' || urlObj.hostname !== 'example.com') {
        return res.status(403).send('Only https://example.com URLs are allowed');
      }
      
      const browser = await chromium.launch();
      const page = await browser.newPage();
      // ok: playwright-goto-injection-ts-rule
      await page.goto(targetUrl);
      const content = await page.content();
      await browser.close();
      res.send(content);
    } catch (error) {
      res.status(400).send('Invalid URL');
    }
  });
}
// {/fact}

// Case 5: Using a predefined URL with user input only for the path
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_5() {
  const app = express();
  app.get('/safe-path', async (req, res) => {
    const path = req.query.path as string;
    
    // Validate path format
    if (!/^[a-zA-Z0-9\/_-]+$/.test(path)) {
      return res.status(400).send('Invalid path format');
    }
    
    const baseUrl = 'https://example.com/';
    const finalUrl = baseUrl + path;
    
    const browser = await firefox.launch();
    const page = await browser.newPage();
    // ok: playwright-goto-injection-ts-rule
    await page.goto(finalUrl);
    const content = await page.content();
    await browser.close();
    res.send(content);
  });
}
// {/fact}

// Case 6: Using environment variables for allowed domains
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_6() {
  const app = express();
  app.get('/env-whitelist', async (req, res) => {
    const targetUrl = req.query.url as string;
    
    // Assume ALLOWED_DOMAINS is set in environment as comma-separated list
    const allowedDomains = process.env.ALLOWED_DOMAINS?.split(',') || ['example.com'];
    
    try {
      const urlObj = new URL(targetUrl);
      if (!allowedDomains.includes(urlObj.hostname)) {
        return res.status(403).send('Domain not allowed');
      }
      
      const browser = await webkit.launch();
      const page = await browser.newPage();
      // ok: playwright-goto-injection-ts-rule
      await page.goto(targetUrl);
      const content = await page.content();
      await browser.close();
      res.send(content);
    } catch (error) {
      res.status(400).send('Invalid URL');
    }
  });
}
// {/fact}

// Case 7: Using a mapping of safe URLs
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_7() {
  const app = express();
  app.get('/mapped-urls', async (req, res) => {
    const urlKey = req.query.key as string;
    
    // Map of safe URLs
    const urlMap: Record<string, string> = {
      'home': 'https://example.com/',
      'about': 'https://example.com/about',
      'contact': 'https://example.com/contact',
      'products': 'https://example.com/products'
    };
    
    const targetUrl = urlMap[urlKey];
    if (!targetUrl) {
      return res.status(404).send('URL key not found');
    }
    
    const browser = await chromium.launch();
    const page = await browser.newPage();
    // ok: playwright-goto-injection-ts-rule
    await page.goto(targetUrl);
    const content = await page.content();
    await browser.close();
    res.send(content);
  });
}
// {/fact}

// Case 8: Using a URL builder function with validation
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_8() {
  const app = express();
  app.get('/builder', async (req, res) => {
    const section = req.query.section as string;
    const id = req.query.id as string;
    
    // Validate inputs
    if (!/^[a-zA-Z0-9_-]+$/.test(section) || !/^[0-9]+$/.test(id)) {
      return res.status(400).send('Invalid parameters');
    }
    
    // Build URL safely
    const buildSafeUrl = (section: string, id: string): string => {
      return `https://example.com/${section}/${id}`;
    };
    
    const targetUrl = buildSafeUrl(section, id);
    
    const browser = await firefox.launch();
    const page = await browser.newPage();
    // ok: playwright-goto-injection-ts-rule
    await page.goto(targetUrl);
    const content = await page.content();
    await browser.close();
    res.send(content);
  });
}
// {/fact}

// Case 9: Using a URL validator class
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_9() {
  class UrlValidator {
    private allowedDomains: string[];
    
    constructor(domains: string[]) {
      this.allowedDomains = domains;
    }
    
    validate(url: string): boolean {
      try {
        const urlObj = new URL(url);
        return urlObj.protocol === 'https:' && this.allowedDomains.includes(urlObj.hostname);
      } catch {
        return false;
      }
    }
  }
  
  const app = express();
  app.get('/validator-class', async (req, res) => {
    const targetUrl = req.query.url as string;
    const validator = new UrlValidator(['example.com', 'trusted-site.org']);
    
    if (!validator.validate(targetUrl)) {
      return res.status(403).send('URL not allowed');
    }
    
    const browser = await webkit.launch();
    const page = await browser.newPage();
    // ok: playwright-goto-injection-ts-rule
    await page.goto(targetUrl);
    const content = await page.content();
    await browser.close();
    res.send(content);
  });
}
// {/fact}

// Case 10: Using predefined URLs with query parameters
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_10() {
  const app = express();
  app.get('/safe-query', async (req, res) => {
    const productId = req.query.id as string;
    const category = req.query.category as string;
    
    // Validate inputs
    if (!/^[0-9]+$/.test(productId) || !/^[a-zA-Z0-9_-]+$/.test(category)) {
      return res.status(400).send('Invalid parameters');
    }
    
    // Construct URL with safe query parameters
    const baseUrl = 'https://example.com/products';
    const url = new URL(baseUrl);
    url.searchParams.append('id', productId);
    url.searchParams.append('category', category);
    
    const browser = await chromium.launch();
    const page = await browser.newPage();
    // ok: playwright-goto-injection-ts-rule
    await page.goto(url.toString());
    const content = await page.content();
    await browser.close();
    res.send(content);
  });
}
// {/fact}

// Case 11: Using a URL sanitizer function
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_11() {
  const app = express();
  app.get('/sanitized', async (req, res) => {
    const targetUrl = req.query.url as string;
    
    const sanitizeUrl = (url: string): string | null => {
      try {
        const urlObj = new URL(url);
        // Only allow specific domain and HTTPS
        if (urlObj.hostname === 'example.com' && urlObj.protocol === 'https:') {
          return urlObj.toString();
        }
        return null;
      } catch {
        return null;
      }
    };
    
    const safeUrl = sanitizeUrl(targetUrl);
    if (!safeUrl) {
      return res.status(403).send('URL not allowed');
    }
    
    const browser = await firefox.launch();
    const page = await browser.newPage();
    // ok: playwright-goto-injection-ts-rule
    await page.goto(safeUrl);
    const content = await page.content();
    await browser.close();
    res.send(content);
  });
}
// {/fact}

// Case 12: Using a configuration-based approach
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_12() {
  const app = express();
  app.get('/config-based', async (req, res) => {
    const pageKey = req.query.page as string;
    
    // Configuration object with predefined URLs
    const config = {
      pages: {
        'home': 'https://example.com/',
        'about': 'https://example.com/about',
        'contact': 'https://example.com/contact',
        'products': 'https://example.com/products'
      }
    };
    
    if (!pageKey || !config.pages[pageKey]) {
      return res.status(404).send('Page not found');
    }
    
    const targetUrl = config.pages[pageKey];
    
    const browser = await webkit.launch();
    const page = await browser.newPage();
    // ok: playwright-goto-injection-ts-rule
    await page.goto(targetUrl);
    const content = await page.content();
    await browser.close();
    res.send(content);
  });
}
// {/fact}

// Case 13: Using domain and path validation with regex
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_13() {
  const app = express();
  app.get('/regex-validation', async (req, res) => {
    const domain = req.query.domain as string;
    const path = req.query.path as string;
    
    // Strict validation with regex
    const domainRegex = /^(example\.com|trusted-site\.org)$/;
    const pathRegex = /^[a-zA-Z0-9\/_-]+$/;
    
    if (!domainRegex.test(domain) || !pathRegex.test(path)) {
      return res.status(403).send('Invalid domain or path');
    }
    
    const targetUrl = `https://${domain}/${path}`;
    
    const browser = await chromium.launch();
    const page = await browser.newPage();
    // ok: playwright-goto-injection-ts-rule
    await page.goto(targetUrl);
    const content = await page.content();
    await browser.close();
    res.send(content);
  });
}
// {/fact}

// Case 14: Using a URL builder with type checking
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_14() {
  const app = express();
  app.get('/typed-builder', async (req, res) => {
    type AllowedSection = 'products' | 'services' | 'blog';
    
    const section = req.query.section as string;
    const id = req.query.id as string;
    
    // Validate section is one of allowed values
    if (!['products', 'services', 'blog'].includes(section)) {
      return res.status(400).send('Invalid section');
    }
    
    // Validate ID is numeric
    if (!/^[0-9]+$/.test(id)) {
      return res.status(400).send('Invalid ID');
    }
    
    // Type-safe section
    const typedSection = section as AllowedSection;
    const targetUrl = `https://example.com/${typedSection}/${id}`;
    
    const browser = await firefox.launch();
    const page = await browser.newPage();
    // ok: playwright-goto-injection-ts-rule
    await page.goto(targetUrl);
    const content = await page.content();
    await browser.close();
    res.send(content);
  });
}
// {/fact}

// Case 15: Using a URL builder with comprehensive validation
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_15() {
  const app = express();
  app.get('/comprehensive', async (req, res) => {
    const targetUrl = req.query.url as string;
    
    // Comprehensive URL validation
    const validateUrl = (url: string): boolean => {
      try {
        const urlObj = new URL(url);
        
        // Check protocol
        if (urlObj.protocol !== 'https:') {
          return false;
        }
        
        // Check domain
        const allowedDomains = ['example.com', 'trusted-site.org'];
        if (!allowedDomains.includes(urlObj.hostname)) {
          return false;
        }
        
        // Check path
        if (!/^\/[a-zA-Z0-9\/_-]*$/.test(urlObj.pathname)) {
          return false;
        }
        
        // Check for suspicious query parameters
        const suspiciousParams = ['file', 'exec', 'cmd', 'script'];
        for (const param of suspiciousParams) {
          if (urlObj.searchParams.has(param)) {
            return false;
          }
        }
        
        return true;
      } catch {
        return false;
      }
    };
    
    if (!validateUrl(targetUrl)) {
      return res.status(403).send('URL validation failed');
    }
    
    const browser = await webkit.launch();
    const page = await browser.newPage();
    // ok: playwright-goto-injection-ts-rule
    await page.goto(targetUrl);
    const content = await page.content();
    await browser.close();
    res.send(content);
  });
}
// {/fact}