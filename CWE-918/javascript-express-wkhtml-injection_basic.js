const express = require('express');
const wkhtmltopdf = require('wkhtmltopdf');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const puppeteer = require('puppeteer');
const { URL } = require('url');
const validator = require('validator');
const sanitizeUrl = require('@braintree/sanitize-url').sanitizeUrl;

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// True positives (vulnerable code)

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_1() {
  app.get('/generate-pdf', (req, res) => {
    const url = req.query.url;
    // ruleid: javascript-express-wkhtml-injection
    wkhtmltopdf(url, { output: 'report.pdf' });
    res.download('report.pdf');
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_2() {
  app.post('/create-pdf', (req, res) => {
    const userUrl = req.body.targetUrl;
    // ruleid: javascript-express-wkhtml-injection
    wkhtmltopdf(userUrl, (err, stream) => {
      res.setHeader('Content-Type', 'application/pdf');
      stream.pipe(res);
    });
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_3() {
  app.get('/pdf-from-header', (req, res) => {
    const sourceUrl = req.headers['x-source-url'];
    // ruleid: javascript-express-wkhtml-injection
    exec(`wkhtmltopdf ${sourceUrl} output.pdf`, (error) => {
      if (!error) {
        res.download('output.pdf');
      } else {
        res.status(500).send('Error generating PDF');
      }
    });
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_4() {
  app.get('/pdf-with-options', (req, res) => {
    const url = req.query.url;
    const options = {
      pageSize: 'A4',
      orientation: 'portrait',
      marginTop: '1cm'
    };
    
    // ruleid: javascript-express-wkhtml-injection
    wkhtmltopdf(url, options, (err, stream) => {
      if (err) return res.status(500).send('Error');
      res.setHeader('Content-Type', 'application/pdf');
      stream.pipe(res);
    });
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_5() {
  app.post('/batch-pdf', (req, res) => {
    const urls = req.body.urls;
    if (Array.isArray(urls) && urls.length > 0) {
      const url = urls[0]; // Just process the first URL for this example
      // ruleid: javascript-express-wkhtml-injection
      wkhtmltopdf(url, { output: `batch-${Date.now()}.pdf` });
      res.send('PDF generation started');
    }
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_6() {
  app.get('/pdf-from-cookie', (req, res) => {
    const url = req.cookies.pdfSource;
    // ruleid: javascript-express-wkhtml-injection
    exec(`wkhtmltopdf ${url} ${req.query.filename || 'output.pdf'}`, (error) => {
      if (!error) {
        res.send('PDF generated');
      } else {
        res.status(500).send('Error');
      }
    });
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_7() {
  app.post('/complex-pdf', (req, res) => {
    let url = '';
    if (req.body.type === 'direct') {
      url = req.body.directUrl;
    } else {
      url = req.body.indirectUrl;
    }
    
    // ruleid: javascript-express-wkhtml-injection
    wkhtmltopdf(url, { 
      output: 'complex.pdf',
      enableJavascript: true,
      javascriptDelay: 1000
    });
    res.send('PDF generation in progress');
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_8() {
  app.get('/pdf-template', (req, res) => {
    const template = req.query.template;
    const baseUrl = req.query.baseUrl;
    const fullUrl = `${baseUrl}/${template}`;
    
    // ruleid: javascript-express-wkhtml-injection
    wkhtmltopdf(fullUrl, (err, stream) => {
      if (err) return res.status(500).send('Error');
      stream.pipe(res);
    });
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_9() {
  app.post('/pdf-with-auth', (req, res) => {
    const targetUrl = req.body.url;
    const options = {
      username: req.body.username,
      password: req.body.password
    };
    
    // ruleid: javascript-express-wkhtml-injection
    wkhtmltopdf(targetUrl, options, (err, stream) => {
      if (err) return res.status(500).send('Error');
      res.setHeader('Content-Type', 'application/pdf');
      stream.pipe(res);
    });
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_10() {
  app.get('/dynamic-pdf', (req, res) => {
    const params = new URLSearchParams(req.query);
    const url = params.get('source');
    
    // ruleid: javascript-express-wkhtml-injection
    exec(`wkhtmltopdf "${url}" dynamic-${Date.now()}.pdf`, (error) => {
      if (!error) {
        res.send('PDF created');
      } else {
        res.status(500).send('Error');
      }
    });
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_11() {
  app.post('/pdf-from-json', (req, res) => {
    const data = JSON.parse(req.body.data);
    const url = data.url;
    
    // ruleid: javascript-express-wkhtml-injection
    wkhtmltopdf(url, { output: 'from-json.pdf' });
    res.send('Processing');
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_12() {
  app.get('/pdf-multiple-params', (req, res) => {
    const protocol = req.query.protocol || 'https';
    const domain = req.query.domain;
    const path = req.query.path || '';
    const url = `${protocol}://${domain}/${path}`;
    
    // ruleid: javascript-express-wkhtml-injection
    wkhtmltopdf(url, (err, stream) => {
      if (err) return res.status(500).send('Error');
      stream.pipe(res);
    });
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_13() {
  app.post('/pdf-conditional', (req, res) => {
    let url;
    if (req.body.isExternal === 'true') {
      url = req.body.externalUrl;
    } else {
      url = `https://internal.example.com/${req.body.page}`;
    }
    
    // ruleid: javascript-express-wkhtml-injection
    wkhtmltopdf(url, { output: 'conditional.pdf' });
    res.send('PDF generation started');
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_14() {
  app.get('/pdf-with-transform', (req, res) => {
    let url = req.query.url;
    // Simple transformation that doesn't sanitize
    url = url.replace(/\s+/g, '%20');
    
    // ruleid: javascript-express-wkhtml-injection
    wkhtmltopdf(url, { output: 'transformed.pdf' });
    res.download('transformed.pdf');
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_15() {
  app.post('/pdf-with-fragments', (req, res) => {
    const baseUrl = req.body.baseUrl;
    const fragment = req.body.fragment ? `#${req.body.fragment}` : '';
    const fullUrl = `${baseUrl}${fragment}`;
    
    // ruleid: javascript-express-wkhtml-injection
    wkhtmltopdf(fullUrl, (err, stream) => {
      if (err) return res.status(500).send('Error');
      stream.pipe(res);
    });
  });
}
// {/fact}

// True negatives (secure code)

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_1() {
  app.get('/safe-pdf', (req, res) => {
    // Hardcoded URL, not user input
    // ok: javascript-express-wkhtml-injection
    wkhtmltopdf('https://example.com/static-page', { output: 'safe.pdf' });
    res.download('safe.pdf');
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_2() {
  app.post('/validated-pdf', (req, res) => {
    const userUrl = req.body.targetUrl;
    
    // Validate URL against whitelist
    const allowedDomains = ['example.com', 'trusted-site.org'];
    try {
      const parsedUrl = new URL(userUrl);
      const isDomainAllowed = allowedDomains.some(domain => parsedUrl.hostname === domain || 
                                                 parsedUrl.hostname.endsWith(`.${domain}`));
      
      if (isDomainAllowed) {
        // ok: javascript-express-wkhtml-injection
        wkhtmltopdf(userUrl, (err, stream) => {
          if (err) return res.status(500).send('Error');
          res.setHeader('Content-Type', 'application/pdf');
          stream.pipe(res);
        });
      } else {
        res.status(403).send('Domain not allowed');
      }
    } catch (error) {
      res.status(400).send('Invalid URL');
    }
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_3() {
  app.get('/internal-pdf', (req, res) => {
    const pageId = req.query.pageId;
    // Using the page ID to construct an internal URL, not using external URLs
    const internalUrl = `https://internal.example.com/pages/${pageId}`;
    
    // ok: javascript-express-wkhtml-injection
    wkhtmltopdf(internalUrl, { output: 'internal.pdf' });
    res.download('internal.pdf');
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_4() {
  app.post('/sanitized-pdf', (req, res) => {
    const userUrl = req.body.url;
    
    // Sanitize URL to prevent SSRF
    const sanitized = sanitizeUrl(userUrl);
    
    // Validate that it's an HTTP or HTTPS URL
    if (sanitized.startsWith('http://') || sanitized.startsWith('https://')) {
      // ok: javascript-express-wkhtml-injection
      wkhtmltopdf(sanitized, (err, stream) => {
        if (err) return res.status(500).send('Error');
        stream.pipe(res);
      });
    } else {
      res.status(400).send('Invalid URL protocol');
    }
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_5() {
  app.get('/pdf-from-template', (req, res) => {
    const templateName = req.query.template;
    // Using a template name to select from predefined templates
    const templates = {
      'invoice': 'templates/invoice.html',
      'report': 'templates/report.html',
      'receipt': 'templates/receipt.html'
    };
    
    const templatePath = templates[templateName];
    if (templatePath) {
      // ok: javascript-express-wkhtml-injection
      wkhtmltopdf(fs.readFileSync(templatePath, 'utf8'), { output: 'template.pdf' });
      res.download('template.pdf');
    } else {
      res.status(404).send('Template not found');
    }
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_6() {
  app.post('/pdf-with-validation', (req, res) => {
    const url = req.body.url;
    
    if (validator.isURL(url, { 
      protocols: ['http', 'https'],
      require_protocol: true,
      host_whitelist: ['example.com', 'trusted-domain.com']
    })) {
      // ok: javascript-express-wkhtml-injection
      wkhtmltopdf(url, { output: 'validated.pdf' });
      res.send('PDF generation started');
    } else {
      res.status(400).send('Invalid or disallowed URL');
    }
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_7() {
  app.get('/pdf-from-html', (req, res) => {
    // Generate PDF from HTML content, not from URL
    const htmlContent = `
      <html>
        <head><title>Generated PDF</title></head>
        <body>
          <h1>Hello ${req.query.name || 'User'}</h1>
          <p>This is a safe PDF generated from HTML content.</p>
        </body>
      </html>
    `;
    
    // ok: javascript-express-wkhtml-injection
    wkhtmltopdf(htmlContent, (err, stream) => {
      if (err) return res.status(500).send('Error');
      res.setHeader('Content-Type', 'application/pdf');
      stream.pipe(res);
    });
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_8() {
  app.post('/pdf-from-id', (req, res) => {
    const documentId = req.body.documentId;
    
    // Validate that documentId is a number
    if (/^\d+$/.test(documentId)) {
      // Construct internal URL based on ID
      const internalUrl = `https://internal.example.com/documents/${documentId}`;
      
      // ok: javascript-express-wkhtml-injection
      wkhtmltopdf(internalUrl, { output: `document-${documentId}.pdf` });
      res.send('PDF generation started');
    } else {
      res.status(400).send('Invalid document ID');
    }
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_9() {
  app.get('/safe-exec-pdf', (req, res) => {
    const templateId = req.query.templateId;
    
    // Validate template ID format
    if (/^[a-zA-Z0-9_-]+$/.test(templateId)) {
      const templatePath = path.join(__dirname, 'templates', `${templateId}.html`);
      
      // Check if template exists
      if (fs.existsSync(templatePath)) {
        // ok: javascript-express-wkhtml-injection
        exec(`wkhtmltopdf ${templatePath} output-${templateId}.pdf`, (error) => {
          if (!error) {
            res.download(`output-${templateId}.pdf`);
          } else {
            res.status(500).send('Error generating PDF');
          }
        });
      } else {
        res.status(404).send('Template not found');
      }
    } else {
      res.status(400).send('Invalid template ID');
    }
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_10() {
  app.post('/puppeteer-pdf', async (req, res) => {
    // Using Puppeteer instead of wkhtmltopdf for better security
    try {
      const browser = await puppeteer.launch({ 
        args: ['--no-sandbox', '--disable-setuid-sandbox'] 
      });
      const page = await browser.newPage();
      
      // Using a fixed internal URL, not user input
      // ok: javascript-express-wkhtml-injection
      await page.goto('https://internal.example.com/report', { waitUntil: 'networkidle2' });
      
      const pdfBuffer = await page.pdf({ format: 'A4' });
      await browser.close();
      
      res.setHeader('Content-Type', 'application/pdf');
      res.send(pdfBuffer);
    } catch (error) {
      res.status(500).send('Error generating PDF');
    }
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_11() {
  app.get('/enum-pdf', (req, res) => {
    const reportType = req.query.type;
    
    // Using an enumeration of allowed values
    const allowedReports = {
      'financial': 'https://internal.example.com/reports/financial',
      'quarterly': 'https://internal.example.com/reports/quarterly',
      'annual': 'https://internal.example.com/reports/annual'
    };
    
    const reportUrl = allowedReports[reportType];
    if (reportUrl) {
      // ok: javascript-express-wkhtml-injection
      wkhtmltopdf(reportUrl, { output: `${reportType}-report.pdf` });
      res.download(`${reportType}-report.pdf`);
    } else {
      res.status(400).send('Invalid report type');
    }
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_12() {
  app.post('/safe-dynamic-pdf', (req, res) => {
    const userId = req.body.userId;
    const reportDate = req.body.date;
    
    // Validate inputs
    if (/^\d+$/.test(userId) && /^\d{4}-\d{2}-\d{2}$/.test(reportDate)) {
      // Construct internal URL with validated parameters
      const internalUrl = `https://reports.internal.example.com/user/${userId}/date/${reportDate}`;
      
      // ok: javascript-express-wkhtml-injection
      wkhtmltopdf(internalUrl, (err, stream) => {
        if (err) return res.status(500).send('Error');
        res.setHeader('Content-Type', 'application/pdf');
        stream.pipe(res);
      });
    } else {
      res.status(400).send('Invalid parameters');
    }
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_13() {
  app.get('/proxy-pdf', (req, res) => {
    const targetUrl = req.query.url;
    
    try {
      const url = new URL(targetUrl);
      
      // Check if URL is internal by validating hostname
      if (url.hostname === 'internal.example.com' || url.hostname.endsWith('.internal.example.com')) {
        // ok: javascript-express-wkhtml-injection
        wkhtmltopdf(targetUrl, { output: 'internal-proxy.pdf' });
        res.download('internal-proxy.pdf');
      } else {
        res.status(403).send('Only internal URLs are allowed');
      }
    } catch (error) {
      res.status(400).send('Invalid URL');
    }
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_14() {
  app.post('/pdf-with-hash', (req, res) => {
    const documentHash = req.body.hash;
    
    // Validate hash format (e.g., SHA-256)
    if (/^[a-f0-9]{64}$/.test(documentHash)) {
      // Look up document by hash in database (simplified example)
      const documentUrl = `https://documents.internal.example.com/by-hash/${documentHash}`;
      
      // ok: javascript-express-wkhtml-injection
      wkhtmltopdf(documentUrl, { output: `document-${documentHash.substring(0, 8)}.pdf` });
      res.send('PDF generation started');
    } else {
      res.status(400).send('Invalid document hash');
    }
  });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_15() {
  app.get('/safe-template-pdf', (req, res) => {
    const templateName = req.query.template;
    const userData = {
      name: req.query.name || 'User',
      date: new Date().toLocaleDateString()
    };
    
    // Validate template name
    if (/^[a-zA-Z0-9_-]+$/.test(templateName)) {
      try {
        // Read template from filesystem
        const templatePath = path.join(__dirname, 'templates', `${templateName}.html`);
        if (fs.existsSync(templatePath)) {
          let templateContent = fs.readFileSync(templatePath, 'utf8');
          
          // Simple template substitution
          templateContent = templateContent
            .replace('{{name}}', userData.name)
            .replace('{{date}}', userData.date);
          
          // ok: javascript-express-wkhtml-injection
          wkhtmltopdf(templateContent, (err, stream) => {
            if (err) return res.status(500).send('Error');
            res.setHeader('Content-Type', 'application/pdf');
            stream.pipe(res);
          });
        } else {
          res.status(404).send('Template not found');
        }
      } catch (error) {
        res.status(500).send('Error processing template');
      }
    } else {
      res.status(400).send('Invalid template name');
    }
  });
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});