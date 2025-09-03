import express from 'express';
import puppeteer from 'puppeteer';
import { Request, Response } from 'express';
import * as url from 'url';
import * as validator from 'validator';
import * as crypto from 'crypto';

// TRUE POSITIVES (Vulnerable Code)

// Case 1: Direct use of query parameter in goto method
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_1(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  const userUrl = req.query.url as string;
  
  try {
    // ruleid: express-puppeteer-injection-ts-rule
    await page.goto(userUrl);
    const content = await page.content();
    res.send(content);
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 2: Using request body parameter in goto method
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_2(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  const targetUrl = req.body.targetUrl;
  
  try {
    // ruleid: express-puppeteer-injection-ts-rule
    await page.goto(targetUrl);
    const title = await page.title();
    res.send(`Page title: ${title}`);
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 3: Using URL from request header in goto method
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_3(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  const referer = req.headers.referer as string;
  
  try {
    // ruleid: express-puppeteer-injection-ts-rule
    await page.goto(referer);
    const metrics = await page.metrics();
    res.json(metrics);
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 4: Using request parameter in setContent method
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_4(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  const htmlContent = req.query.html as string;
  
  try {
    // ruleid: express-puppeteer-injection-ts-rule
    await page.setContent(htmlContent);
    const screenshot = await page.screenshot();
    res.type('image/png').send(screenshot);
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 5: Using request parameter in evaluate method
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_5(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  const script = req.query.script as string;
  
  try {
    await page.goto('https://example.com');
    // ruleid: express-puppeteer-injection-ts-rule
    const result = await page.evaluate(script);
    res.json({ result });
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 6: Using cookie value in goto method
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_6(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  const targetUrl = req.cookies.savedUrl;
  
  try {
    // ruleid: express-puppeteer-injection-ts-rule
    await page.goto(targetUrl);
    const content = await page.content();
    res.send(content);
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 7: Using request parameter with string concatenation
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_7(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  const domain = req.query.domain as string;
  const path = 'https://' + domain + '/index.html';
  
  try {
    // ruleid: express-puppeteer-injection-ts-rule
    await page.goto(path);
    const content = await page.content();
    res.send(content);
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 8: Using request parameter in setExtraHTTPHeaders
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_8(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  const userAgent = req.query.userAgent as string;
  
  try {
    // ruleid: express-puppeteer-injection-ts-rule
    await page.setExtraHTTPHeaders({
      'User-Agent': userAgent
    });
    await page.goto('https://example.com');
    const content = await page.content();
    res.send(content);
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 9: Using request parameter in pdf method options
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_9(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  const footerTemplate = req.query.footer as string;
  
  try {
    await page.goto('https://example.com');
    // ruleid: express-puppeteer-injection-ts-rule
    const pdf = await page.pdf({ footerTemplate });
    res.type('application/pdf').send(pdf);
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 10: Using request parameter in addScriptTag method
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_10(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  const scriptUrl = req.query.scriptUrl as string;
  
  try {
    await page.goto('https://example.com');
    // ruleid: express-puppeteer-injection-ts-rule
    await page.addScriptTag({ url: scriptUrl });
    const content = await page.content();
    res.send(content);
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 11: Using request parameter in addStyleTag method
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_11(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  const styleContent = req.body.style;
  
  try {
    await page.goto('https://example.com');
    // ruleid: express-puppeteer-injection-ts-rule
    await page.addStyleTag({ content: styleContent });
    const screenshot = await page.screenshot();
    res.type('image/png').send(screenshot);
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 12: Using request parameter in waitForRequest method
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_12(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  const urlPattern = req.query.pattern as string;
  
  try {
    await page.goto('https://example.com');
    // ruleid: express-puppeteer-injection-ts-rule
    const request = await page.waitForRequest(urlPattern);
    res.json({ url: request.url() });
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 13: Using request parameter in waitForResponse method
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_13(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  const urlPattern = req.query.pattern as string;
  
  try {
    await page.goto('https://example.com');
    // ruleid: express-puppeteer-injection-ts-rule
    const response = await page.waitForResponse(urlPattern);
    res.json({ status: response.status() });
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 14: Using request parameter in type method
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_14(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  const userInput = req.query.input as string;
  
  try {
    await page.goto('https://example.com');
    // ruleid: express-puppeteer-injection-ts-rule
    await page.type('input[name="search"]', userInput);
    const screenshot = await page.screenshot();
    res.type('image/png').send(screenshot);
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 15: Using request parameter in evaluateHandle method
// {fact rule=server-side-request-forgery@v1.0 defects=1}
async function bad_case_15(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  const script = req.query.script as string;
  
  try {
    await page.goto('https://example.com');
    // ruleid: express-puppeteer-injection-ts-rule
    const jsHandle = await page.evaluateHandle(script);
    const properties = await jsHandle.getProperties();
    const result = Array.from(properties.entries()).map(([key, value]) => key);
    res.json({ properties: result });
  } finally {
    await browser.close();
  }
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// Case 1: Using hardcoded URL in goto method
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_1(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  
  try {
    // ok: express-puppeteer-injection-ts-rule
    await page.goto('https://example.com');
    const content = await page.content();
    res.send(content);
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 2: Validating URL before using in goto method
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_2(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  const userUrl = req.query.url as string;
  
  try {
    // Validate URL against whitelist
    const allowedDomains = ['example.com', 'trusted-site.com'];
    const parsedUrl = new url.URL(userUrl);
    
    if (allowedDomains.includes(parsedUrl.hostname)) {
      // ok: express-puppeteer-injection-ts-rule
      await page.goto(userUrl);
      const content = await page.content();
      res.send(content);
    } else {
      res.status(403).send('Domain not allowed');
    }
  } catch (error) {
    res.status(400).send('Invalid URL');
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 3: Using URL validation library
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_3(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  const userUrl = req.query.url as string;
  
  try {
    if (validator.isURL(userUrl, { protocols: ['https'], require_protocol: true })) {
      // ok: express-puppeteer-injection-ts-rule
      await page.goto(userUrl);
      const content = await page.content();
      res.send(content);
    } else {
      res.status(400).send('Invalid URL');
    }
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 4: Using a fixed set of URLs
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_4(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  const urlId = req.query.id as string;
  
  const urlMap: {[key: string]: string} = {
    'example': 'https://example.com',
    'google': 'https://google.com',
    'github': 'https://github.com'
  };
  
  try {
    if (urlId in urlMap) {
      // ok: express-puppeteer-injection-ts-rule
      await page.goto(urlMap[urlId]);
      const content = await page.content();
      res.send(content);
    } else {
      res.status(400).send('Invalid URL ID');
    }
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 5: Using hardcoded content in setContent method
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_5(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  
  try {
    // ok: express-puppeteer-injection-ts-rule
    await page.setContent('<html><body><h1>Hello World</h1></body></html>');
    const screenshot = await page.screenshot();
    res.type('image/png').send(screenshot);
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 6: Using sanitized HTML content
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_6(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  const userHtml = req.query.html as string;
  
  // Simple HTML sanitization (in a real app, use a proper sanitizer library)
  const sanitizedHtml = userHtml
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/on\w+="[^"]*"/g, '')
    .replace(/on\w+='[^']*'/g, '');
  
  try {
    // ok: express-puppeteer-injection-ts-rule
    await page.setContent(sanitizedHtml);
    const screenshot = await page.screenshot();
    res.type('image/png').send(screenshot);
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 7: Using hardcoded function in evaluate method
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_7(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  
  try {
    await page.goto('https://example.com');
    // ok: express-puppeteer-injection-ts-rule
    const dimensions = await page.evaluate(() => {
      return {
        width: document.documentElement.clientWidth,
        height: document.documentElement.clientHeight,
        deviceScaleFactor: window.devicePixelRatio
      };
    });
    res.json(dimensions);
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 8: Using a safe function with user input as parameter
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_8(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  const searchTerm = req.query.q as string;
  
  try {
    await page.goto('https://example.com');
    // ok: express-puppeteer-injection-ts-rule
    const results = await page.evaluate((term) => {
      // The function itself is safe, only the parameter is user-controlled
      return document.querySelectorAll(`a:contains("${term}")`).length;
    }, searchTerm);
    res.json({ count: results });
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 9: Using environment variables for configuration
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_9(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  
  try {
    // ok: express-puppeteer-injection-ts-rule
    await page.goto(process.env.TARGET_URL || 'https://example.com');
    const content = await page.content();
    res.send(content);
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 10: Using hardcoded HTTP headers
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_10(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  
  try {
    // ok: express-puppeteer-injection-ts-rule
    await page.setExtraHTTPHeaders({
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      'Accept-Language': 'en-US,en;q=0.9'
    });
    await page.goto('https://example.com');
    const content = await page.content();
    res.send(content);
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 11: Using hardcoded PDF options
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_11(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  
  try {
    await page.goto('https://example.com');
    // ok: express-puppeteer-injection-ts-rule
    const pdf = await page.pdf({
      format: 'A4',
      margin: { top: '1cm', right: '1cm', bottom: '1cm', left: '1cm' },
      printBackground: true,
      footerTemplate: '<div style="text-align: center;"><span class="pageNumber"></span></div>'
    });
    res.type('application/pdf').send(pdf);
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 12: Using a safe script tag
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_12(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  
  try {
    await page.goto('https://example.com');
    // ok: express-puppeteer-injection-ts-rule
    await page.addScriptTag({ url: 'https://code.jquery.com/jquery-3.6.0.min.js' });
    const content = await page.content();
    res.send(content);
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 13: Using a safe style tag
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_13(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  
  try {
    await page.goto('https://example.com');
    // ok: express-puppeteer-injection-ts-rule
    await page.addStyleTag({ content: 'body { background-color: lightblue; }' });
    const screenshot = await page.screenshot();
    res.type('image/png').send(screenshot);
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 14: Using a regex pattern for waitForRequest
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_14(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  
  try {
    await page.goto('https://example.com');
    // ok: express-puppeteer-injection-ts-rule
    const request = await page.waitForRequest(/\.png$/);
    res.json({ url: request.url() });
  } finally {
    await browser.close();
  }
}
// {/fact}

// Case 15: Using hardcoded input in type method
// {fact rule=server-side-request-forgery@v1.0 defects=0}
async function good_case_15(req: Request, res: Response) {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  
  try {
    await page.goto('https://example.com');
    // ok: express-puppeteer-injection-ts-rule
    await page.type('input[name="search"]', 'puppeteer');
    const screenshot = await page.screenshot();
    res.type('image/png').send(screenshot);
  } finally {
    await browser.close();
  }
}
// {/fact}

// Set up Express app
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes for testing
app.get('/bad1', bad_case_1);
app.post('/bad2', bad_case_2);
app.get('/bad3', bad_case_3);
// ... add routes for other cases

app.listen(3000, () => {
  console.log('Server running on port 3000');
});