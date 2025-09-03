import * as http from 'http';
import * as https from 'https';
import * as express from 'express';
import * as url from 'url';
import * as nodemailer from 'nodemailer';
import axios from 'axios';
import { Request, Response } from 'express';

// True Positive Examples (Vulnerable Code)

// Example 1: Using host header directly in redirect
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_1(req: express.Request, res: express.Response) {
  const host = req.headers.host;
  // ruleid: typescript-host-header-injection
  res.redirect(`https://${host}/login`);
}
// {/fact}

// Example 2: Using host header in constructing URLs for email
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_2(req: express.Request, res: express.Response) {
  const host = req.headers.host;
  const resetToken = "abc123";
  
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'example@gmail.com',
      pass: 'password'
    }
  });
  
  // ruleid: typescript-host-header-injection
  const resetLink = `https://${host}/reset-password?token=${resetToken}`;
  
  const mailOptions = {
    from: 'security@example.com',
    to: 'user@example.com',
    subject: 'Password Reset',
    html: `Click <a href="${resetLink}">here</a> to reset your password.`
  };
  
  transporter.sendMail(mailOptions);
  res.send('Password reset email sent');
}
// {/fact}

// Example 3: Using host header in constructing absolute URLs
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_3(req: express.Request, res: express.Response) {
  const host = req.headers.host;
  const userId = "12345";
  
  // ruleid: typescript-host-header-injection
  const profileUrl = `https://${host}/profile/${userId}`;
  
  res.send(`Your profile is available at: ${profileUrl}`);
}
// {/fact}

// Example 4: Using host header in proxy request
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_4(req: express.Request, res: express.Response) {
  const host = req.headers.host;
  const path = req.path;
  
  // ruleid: typescript-host-header-injection
  const apiUrl = `https://${host}/api${path}`;
  
  axios.get(apiUrl)
    .then(response => {
      res.json(response.data);
    })
    .catch(error => {
      res.status(500).send('Error fetching data');
    });
}
// {/fact}

// Example 5: Using host header in webhook URL construction
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_5(req: express.Request, res: express.Response) {
  const host = req.headers.host;
  const webhookId = "webhook123";
  
  // ruleid: typescript-host-header-injection
  const webhookUrl = `https://${host}/webhooks/${webhookId}/callback`;
  
  // Store the webhook URL for later use
  storeWebhookUrl(webhookId, webhookUrl);
  
  res.send(`Webhook registered at: ${webhookUrl}`);
  
  function storeWebhookUrl(id: string, url: string) {
    // Mock function to store webhook URL
    console.log(`Storing webhook ${id} at ${url}`);
  }
}
// {/fact}

// Example 6: Using host header in constructing OAuth callback URL
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_6(req: express.Request, res: express.Response) {
  const host = req.headers.host;
  
  // ruleid: typescript-host-header-injection
  const callbackUrl = `https://${host}/auth/callback`;
  
  const authUrl = `https://oauth-provider.com/authorize?client_id=client123&redirect_uri=${encodeURIComponent(callbackUrl)}`;
  
  res.redirect(authUrl);
}
// {/fact}

// Example 7: Using host header in CSP header
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_7(req: express.Request, res: express.Response) {
  const host = req.headers.host;
  
  // ruleid: typescript-host-header-injection
  res.setHeader('Content-Security-Policy', `default-src 'self' https://${host}`);
  
  res.send('Page with CSP');
}
// {/fact}

// Example 8: Using host header in CORS configuration
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_8(req: express.Request, res: express.Response) {
  const host = req.headers.host;
  
  // ruleid: typescript-host-header-injection
  res.setHeader('Access-Control-Allow-Origin', `https://${host}`);
  
  res.json({ message: 'API response' });
}
// {/fact}

// Example 9: Using host header in dynamic script loading
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_9(req: express.Request, res: express.Response) {
  const host = req.headers.host;
  
  // ruleid: typescript-host-header-injection
  const scriptUrl = `https://${host}/assets/script.js`;
  
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <script src="${scriptUrl}"></script>
      </head>
      <body>
        <h1>Welcome</h1>
      </body>
    </html>
  `);
}
// {/fact}

// Example 10: Using host header in WebSocket connection
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_10(req: express.Request, res: express.Response) {
  const host = req.headers.host;
  
  // ruleid: typescript-host-header-injection
  const wsUrl = `wss://${host}/socket`;
  
  res.send(`
    <script>
      const socket = new WebSocket('${wsUrl}');
      socket.onmessage = function(event) {
        console.log(event.data);
      };
    </script>
  `);
}
// {/fact}

// Example 11: Using host header in constructing canonical URL
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_11(req: express.Request, res: express.Response) {
  const host = req.headers.host;
  const path = req.path;
  
  // ruleid: typescript-host-header-injection
  const canonicalUrl = `https://${host}${path}`;
  
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <link rel="canonical" href="${canonicalUrl}" />
      </head>
      <body>
        <h1>Page Content</h1>
      </body>
    </html>
  `);
}
// {/fact}

// Example 12: Using host header in API endpoint construction
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_12(req: express.Request, res: express.Response) {
  const host = req.headers.host;
  const apiVersion = "v1";
  
  // ruleid: typescript-host-header-injection
  const apiBaseUrl = `https://${host}/api/${apiVersion}`;
  
  res.json({
    api: {
      users: `${apiBaseUrl}/users`,
      products: `${apiBaseUrl}/products`,
      orders: `${apiBaseUrl}/orders`
    }
  });
}
// {/fact}

// Example 13: Using host header in sitemap generation
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_13(req: express.Request, res: express.Response) {
  const host = req.headers.host;
  const pages = ["about", "products", "contact"];
  
  let sitemap = '<?xml version="1.0" encoding="UTF-8"?>\n';
  sitemap += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';
  
  for (const page of pages) {
    // ruleid: typescript-host-header-injection
    sitemap += `  <url><loc>https://${host}/${page}</loc></url>\n`;
  }
  
  sitemap += '</urlset>';
  
  res.header('Content-Type', 'application/xml');
  res.send(sitemap);
}
// {/fact}

// Example 14: Using host header in JSON-LD structured data
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_14(req: express.Request, res: express.Response) {
  const host = req.headers.host;
  
  // ruleid: typescript-host-header-injection
  const structuredData = {
    "@context": "https://schema.org",
    "@type": "Organization",
    "name": "Example Company",
    "url": `https://${host}`,
    "logo": `https://${host}/logo.png`
  };
  
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <script type="application/ld+json">
          ${JSON.stringify(structuredData)}
        </script>
      </head>
      <body>
        <h1>Company Page</h1>
      </body>
    </html>
  `);
}
// {/fact}

// Example 15: Using host header in iframe source
// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_15(req: express.Request, res: express.Response) {
  const host = req.headers.host;
  const widgetId = "widget123";
  
  // ruleid: typescript-host-header-injection
  const widgetUrl = `https://${host}/widgets/${widgetId}`;
  
  res.send(`
    <!DOCTYPE html>
    <html>
      <body>
        <h1>Widget Demo</h1>
        <iframe src="${widgetUrl}" width="500" height="300"></iframe>
      </body>
    </html>
  `);
}
// {/fact}

// True Negative Examples (Secure Code)

// Example 1: Using hardcoded domain for redirect
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_1(req: express.Request, res: express.Response) {
  // ok: typescript-host-header-injection
  const trustedDomain = 'example.com';
  res.redirect(`https://${trustedDomain}/login`);
}
// {/fact}

// Example 2: Using environment variable for domain in email links
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_2(req: express.Request, res: express.Response) {
  const resetToken = "abc123";
  
  // ok: typescript-host-header-injection
  const trustedDomain = process.env.APP_DOMAIN || 'example.com';
  
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'example@gmail.com',
      pass: 'password'
    }
  });
  
  const resetLink = `https://${trustedDomain}/reset-password?token=${resetToken}`;
  
  const mailOptions = {
    from: 'security@example.com',
    to: 'user@example.com',
    subject: 'Password Reset',
    html: `Click <a href="${resetLink}">here</a> to reset your password.`
  };
  
  transporter.sendMail(mailOptions);
  res.send('Password reset email sent');
}
// {/fact}

// Example 3: Using whitelist validation for host header
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_3(req: express.Request, res: express.Response) {
  const host = req.headers.host;
  const userId = "12345";
  
  const allowedHosts = ['example.com', 'www.example.com', 'app.example.com'];
  
  // ok: typescript-host-header-injection
  if (host && allowedHosts.includes(host)) {
    const profileUrl = `https://${host}/profile/${userId}`;
    res.send(`Your profile is available at: ${profileUrl}`);
  } else {
    const defaultHost = 'example.com';
    const profileUrl = `https://${defaultHost}/profile/${userId}`;
    res.send(`Your profile is available at: ${profileUrl}`);
  }
}
// {/fact}

// Example 4: Using configuration for API URL instead of host header
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_4(req: express.Request, res: express.Response) {
  const path = req.path;
  
  // ok: typescript-host-header-injection
  const apiHost = process.env.API_HOST || 'api.example.com';
  const apiUrl = `https://${apiHost}/api${path}`;
  
  axios.get(apiUrl)
    .then(response => {
      res.json(response.data);
    })
    .catch(error => {
      res.status(500).send('Error fetching data');
    });
}
// {/fact}

// Example 5: Using configuration for webhook URL
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_5(req: express.Request, res: express.Response) {
  const webhookId = "webhook123";
  
  // ok: typescript-host-header-injection
  const webhookDomain = process.env.WEBHOOK_DOMAIN || 'webhooks.example.com';
  const webhookUrl = `https://${webhookDomain}/webhooks/${webhookId}/callback`;
  
  // Store the webhook URL for later use
  storeWebhookUrl(webhookId, webhookUrl);
  
  res.send(`Webhook registered at: ${webhookUrl}`);
  
  function storeWebhookUrl(id: string, url: string) {
    // Mock function to store webhook URL
    console.log(`Storing webhook ${id} at ${url}`);
  }
}
// {/fact}

// Example 6: Using configuration for OAuth callback URL
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_6(req: express.Request, res: express.Response) {
  // ok: typescript-host-header-injection
  const callbackDomain = process.env.AUTH_DOMAIN || 'auth.example.com';
  const callbackUrl = `https://${callbackDomain}/auth/callback`;
  
  const authUrl = `https://oauth-provider.com/authorize?client_id=client123&redirect_uri=${encodeURIComponent(callbackUrl)}`;
  
  res.redirect(authUrl);
}
// {/fact}

// Example 7: Using hardcoded domain in CSP header
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_7(req: express.Request, res: express.Response) {
  // ok: typescript-host-header-injection
  const trustedDomain = 'cdn.example.com';
  res.setHeader('Content-Security-Policy', `default-src 'self' https://${trustedDomain}`);
  
  res.send('Page with CSP');
}
// {/fact}

// Example 8: Using environment configuration for CORS
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_8(req: express.Request, res: express.Response) {
  // ok: typescript-host-header-injection
  const allowedOrigins = process.env.CORS_ORIGINS?.split(',') || ['example.com', 'app.example.com'];
  const origin = req.headers.origin;
  
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else {
    res.setHeader('Access-Control-Allow-Origin', 'https://example.com');
  }
  
  res.json({ message: 'API response' });
}
// {/fact}

// Example 9: Using static asset URL
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_9(req: express.Request, res: express.Response) {
  // ok: typescript-host-header-injection
  const scriptUrl = '/assets/script.js';  // Relative URL
  
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <script src="${scriptUrl}"></script>
      </head>
      <body>
        <h1>Welcome</h1>
      </body>
    </html>
  `);
}
// {/fact}

// Example 10: Using configuration for WebSocket URL
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_10(req: express.Request, res: express.Response) {
  // ok: typescript-host-header-injection
  const wsHost = process.env.WS_HOST || 'ws.example.com';
  const wsUrl = `wss://${wsHost}/socket`;
  
  res.send(`
    <script>
      const socket = new WebSocket('${wsUrl}');
      socket.onmessage = function(event) {
        console.log(event.data);
      };
    </script>
  `);
}
// {/fact}

// Example 11: Using configuration for canonical URL
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_11(req: express.Request, res: express.Response) {
  const path = req.path;
  
  // ok: typescript-host-header-injection
  const canonicalDomain = process.env.CANONICAL_DOMAIN || 'www.example.com';
  const canonicalUrl = `https://${canonicalDomain}${path}`;
  
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <link rel="canonical" href="${canonicalUrl}" />
      </head>
      <body>
        <h1>Page Content</h1>
      </body>
    </html>
  `);
}
// {/fact}

// Example 12: Using configuration for API endpoint URLs
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_12(req: express.Request, res: express.Response) {
  const apiVersion = "v1";
  
  // ok: typescript-host-header-injection
  const apiDomain = process.env.API_DOMAIN || 'api.example.com';
  const apiBaseUrl = `https://${apiDomain}/api/${apiVersion}`;
  
  res.json({
    api: {
      users: `${apiBaseUrl}/users`,
      products: `${apiBaseUrl}/products`,
      orders: `${apiBaseUrl}/orders`
    }
  });
}
// {/fact}

// Example 13: Using configuration for sitemap generation
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_13(req: express.Request, res: express.Response) {
  const pages = ["about", "products", "contact"];
  
  // ok: typescript-host-header-injection
  const sitemapDomain = process.env.SITE_DOMAIN || 'www.example.com';
  
  let sitemap = '<?xml version="1.0" encoding="UTF-8"?>\n';
  sitemap += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';
  
  for (const page of pages) {
    sitemap += `  <url><loc>https://${sitemapDomain}/${page}</loc></url>\n`;
  }
  
  sitemap += '</urlset>';
  
  res.header('Content-Type', 'application/xml');
  res.send(sitemap);
}
// {/fact}

// Example 14: Using configuration for JSON-LD structured data
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_14(req: express.Request, res: express.Response) {
  // ok: typescript-host-header-injection
  const companyDomain = process.env.COMPANY_DOMAIN || 'example.com';
  
  const structuredData = {
    "@context": "https://schema.org",
    "@type": "Organization",
    "name": "Example Company",
    "url": `https://${companyDomain}`,
    "logo": `https://${companyDomain}/logo.png`
  };
  
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <script type="application/ld+json">
          ${JSON.stringify(structuredData)}
        </script>
      </head>
      <body>
        <h1>Company Page</h1>
      </body>
    </html>
  `);
}
// {/fact}

// Example 15: Using relative URL for iframe source
// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_15(req: express.Request, res: express.Response) {
  const widgetId = "widget123";
  
  // ok: typescript-host-header-injection
  const widgetUrl = `/widgets/${widgetId}`;  // Relative URL
  
  res.send(`
    <!DOCTYPE html>
    <html>
      <body>
        <h1>Widget Demo</h1>
        <iframe src="${widgetUrl}" width="500" height="300"></iframe>
      </body>
    </html>
  `);
}
// {/fact}