import express from 'express';
import { Request, Response } from 'express';
import * as wkhtmltopdf from 'wkhtmltopdf';
import * as child_process from 'child_process';
import * as url from 'url';
import * as validator from 'validator';
import { URL } from 'url';
import * as fs from 'fs';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// True Positive Cases (Vulnerable Code)

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_1(req: Request, res: Response) {
    const userUrl = req.query.url as string;
    
    // ruleid: typescript-express-wkhtml-injection
    wkhtmltopdf(userUrl, { output: 'output.pdf' });
    
    res.send('PDF generated');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_2(req: Request, res: Response) {
    const userUrl = req.body.targetSite;
    
    // ruleid: typescript-express-wkhtml-injection
    wkhtmltopdf(userUrl, (err, stream) => {
        if (err) return res.status(500).send('Error generating PDF');
        stream.pipe(res);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_3(req: Request, res: Response) {
    const pageUrl = req.params.page;
    const options = {
        pageSize: 'letter',
        orientation: 'portrait'
    };
    
    // ruleid: typescript-express-wkhtml-injection
    wkhtmltopdf.command(pageUrl, options, (err, result) => {
        if (err) return res.status(500).send('Error');
        res.download(result);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_4(req: Request, res: Response) {
    const targetUrl = req.headers['x-target-url'] as string;
    
    // ruleid: typescript-express-wkhtml-injection
    const cmd = `wkhtmltopdf ${targetUrl} output.pdf`;
    child_process.exec(cmd, (err) => {
        if (err) return res.status(500).send('Error');
        res.download('output.pdf');
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_5(req: Request, res: Response) {
    const userInput = req.query.site as string;
    const urlWithProtocol = userInput.startsWith('http') ? userInput : `http://${userInput}`;
    
    // ruleid: typescript-express-wkhtml-injection
    wkhtmltopdf(urlWithProtocol, { output: 'result.pdf' });
    res.send('PDF created');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_6(req: Request, res: Response) {
    const urls = req.body.urls as string[];
    
    urls.forEach(userUrl => {
        // ruleid: typescript-express-wkhtml-injection
        wkhtmltopdf(userUrl, { output: `${Date.now()}.pdf` });
    });
    
    res.send('PDFs generated');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_7(req: Request, res: Response) {
    const { url: targetUrl } = req.body;
    
    if (typeof targetUrl === 'string') {
        // ruleid: typescript-express-wkhtml-injection
        const pdfProcess = child_process.spawn('wkhtmltopdf', [targetUrl, 'output.pdf']);
        pdfProcess.on('close', () => {
            res.download('output.pdf');
        });
    }
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_8(req: Request, res: Response) {
    const siteUrl = req.query.url as string || 'https://example.com';
    
    // ruleid: typescript-express-wkhtml-injection
    wkhtmltopdf(siteUrl, { 
        output: 'report.pdf',
        pageSize: 'A4',
        lowquality: true
    });
    
    res.send('Report generated');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_9(req: Request, res: Response) {
    let userUrl = req.body.url;
    
    // Simple transformation doesn't make it safe
    userUrl = userUrl.replace(/^https?:\/\//, '');
    userUrl = `https://${userUrl}`;
    
    // ruleid: typescript-express-wkhtml-injection
    wkhtmltopdf(userUrl, (err, stream) => {
        stream.pipe(res);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_10(req: Request, res: Response) {
    const targetSite = req.query.target as string;
    const options = JSON.parse(req.body.options || '{}');
    
    // ruleid: typescript-express-wkhtml-injection
    wkhtmltopdf(targetSite, options, (err, stream) => {
        if (err) return res.status(500).send('Error');
        res.setHeader('Content-Type', 'application/pdf');
        stream.pipe(res);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_11(req: Request, res: Response) {
    const baseUrl = 'https://';
    const domain = req.query.domain as string;
    const fullUrl = baseUrl + domain;
    
    // ruleid: typescript-express-wkhtml-injection
    wkhtmltopdf(fullUrl, { output: 'domain.pdf' });
    res.download('domain.pdf');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_12(req: Request, res: Response) {
    const userInput = req.body.url;
    let finalUrl;
    
    try {
        // This doesn't validate if the URL is safe, just if it's valid
        new URL(userInput);
        finalUrl = userInput;
    } catch {
        finalUrl = 'https://example.com';
    }
    
    // ruleid: typescript-express-wkhtml-injection
    wkhtmltopdf(finalUrl, { output: 'output.pdf' });
    res.send('PDF created');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_13(req: Request, res: Response) {
    const path = req.query.path as string;
    const protocol = req.query.protocol as string || 'https';
    const fullUrl = `${protocol}://${path}`;
    
    // ruleid: typescript-express-wkhtml-injection
    wkhtmltopdf(fullUrl, (err, stream) => {
        if (err) return res.status(500).send('Error');
        stream.pipe(res);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_14(req: Request, res: Response) {
    const { site } = req.params;
    
    // Insufficient validation - only checks for http/https
    if (!/^https?:\/\//i.test(site)) {
        return res.status(400).send('Invalid URL');
    }
    
    // ruleid: typescript-express-wkhtml-injection
    wkhtmltopdf(site, { output: 'site.pdf' });
    res.download('site.pdf');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=1}
function bad_case_15(req: Request, res: Response) {
    const userUrl = req.cookies.savedUrl;
    
    // ruleid: typescript-express-wkhtml-injection
    const cmd = `wkhtmltopdf "${userUrl}" output.pdf`;
    child_process.execSync(cmd);
    
    res.sendFile('output.pdf');
}
// {/fact}

// True Negative Cases (Safe Code)

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_1(req: Request, res: Response) {
    const userUrl = req.query.url as string;
    
    // Only allow specific whitelisted domains
    const allowedDomains = ['example.com', 'trusted-site.org'];
    const parsedUrl = new URL(userUrl);
    
    if (!allowedDomains.includes(parsedUrl.hostname)) {
        return res.status(403).send('Domain not allowed');
    }
    
    // ok: typescript-express-wkhtml-injection
    wkhtmltopdf(userUrl, { output: 'output.pdf' });
    
    res.send('PDF generated');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_2(req: Request, res: Response) {
    // Use a fixed URL instead of user input
    const fixedUrl = 'https://example.com/report';
    
    // ok: typescript-express-wkhtml-injection
    wkhtmltopdf(fixedUrl, (err, stream) => {
        if (err) return res.status(500).send('Error generating PDF');
        stream.pipe(res);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_3(req: Request, res: Response) {
    // Use a predefined template with user data inserted safely
    const userName = req.body.name;
    const htmlContent = `
        <html>
            <body>
                <h1>Report for ${userName}</h1>
                <p>This is a safe report.</p>
            </body>
        </html>
    `;
    
    // ok: typescript-express-wkhtml-injection
    wkhtmltopdf(htmlContent, { output: 'report.pdf' });
    
    res.download('report.pdf');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_4(req: Request, res: Response) {
    const reportId = req.params.id;
    
    // Validate that reportId is numeric
    if (!/^\d+$/.test(reportId)) {
        return res.status(400).send('Invalid report ID');
    }
    
    // Use the validated ID to generate a safe URL
    const reportUrl = `https://internal-reports.example.com/report/${reportId}`;
    
    // ok: typescript-express-wkhtml-injection
    wkhtmltopdf(reportUrl, { output: 'report.pdf' });
    
    res.download('report.pdf');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_5(req: Request, res: Response) {
    // Use a predefined list of options
    const reportType = req.query.type as string;
    const allowedReports = {
        'financial': 'https://reports.example.com/financial',
        'sales': 'https://reports.example.com/sales',
        'inventory': 'https://reports.example.com/inventory'
    };
    
    const reportUrl = allowedReports[reportType];
    if (!reportUrl) {
        return res.status(400).send('Invalid report type');
    }
    
    // ok: typescript-express-wkhtml-injection
    wkhtmltopdf(reportUrl, { output: 'report.pdf' });
    
    res.download('report.pdf');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_6(req: Request, res: Response) {
    const userUrl = req.query.url as string;
    
    // Validate URL is from allowed domain and has https protocol
    if (!validator.isURL(userUrl, { 
        protocols: ['https'], 
        host_whitelist: ['example.com', 'subdomain.example.com']
    })) {
        return res.status(403).send('URL not allowed');
    }
    
    // ok: typescript-express-wkhtml-injection
    wkhtmltopdf(userUrl, { output: 'output.pdf' });
    
    res.send('PDF generated');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_7(req: Request, res: Response) {
    // Generate HTML content server-side with user data
    const userData = req.body.userData;
    
    // Create HTML content with the user data
    const htmlContent = `
        <html>
            <head><title>User Report</title></head>
            <body>
                <h1>User: ${userData.name}</h1>
                <p>Email: ${userData.email}</p>
            </body>
        </html>
    `;
    
    // Write HTML to a temporary file
    fs.writeFileSync('temp.html', htmlContent);
    
    // ok: typescript-express-wkhtml-injection
    wkhtmltopdf('temp.html', { output: 'user_report.pdf' });
    
    res.download('user_report.pdf');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_8(req: Request, res: Response) {
    const pageNumber = parseInt(req.query.page as string, 10) || 1;
    
    // Use the validated page number in a fixed URL pattern
    const safeUrl = `https://internal-docs.example.com/report/page/${pageNumber}`;
    
    // ok: typescript-express-wkhtml-injection
    wkhtmltopdf(safeUrl, (err, stream) => {
        if (err) return res.status(500).send('Error');
        stream.pipe(res);
    });
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_9(req: Request, res: Response) {
    // Use environment variables for trusted URLs
    const apiBaseUrl = process.env.API_BASE_URL || 'https://api.example.com';
    const reportPath = '/generate-report';
    const reportUrl = `${apiBaseUrl}${reportPath}`;
    
    // ok: typescript-express-wkhtml-injection
    wkhtmltopdf(reportUrl, { output: 'api_report.pdf' });
    
    res.download('api_report.pdf');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_10(req: Request, res: Response) {
    // Use a UUID to fetch a specific resource from a trusted domain
    const reportId = req.params.id;
    
    if (!validator.isUUID(reportId)) {
        return res.status(400).send('Invalid report ID');
    }
    
    const reportUrl = `https://reports.example.com/fetch/${reportId}`;
    
    // ok: typescript-express-wkhtml-injection
    wkhtmltopdf(reportUrl, { output: 'uuid_report.pdf' });
    
    res.download('uuid_report.pdf');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_11(req: Request, res: Response) {
    // Use a fixed template and insert user data via wkhtmltopdf options
    const userName = req.body.name;
    const userEmail = req.body.email;
    
    const templatePath = 'templates/report_template.html';
    
    // ok: typescript-express-wkhtml-injection
    wkhtmltopdf(templatePath, { 
        output: 'user_report.pdf',
        replacements: {
            '{{name}}': userName,
            '{{email}}': userEmail
        }
    });
    
    res.download('user_report.pdf');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_12(req: Request, res: Response) {
    // Use a fixed URL with query parameters
    const startDate = req.query.start as string;
    const endDate = req.query.end as string;
    
    // Validate dates
    if (!validator.isDate(startDate) || !validator.isDate(endDate)) {
        return res.status(400).send('Invalid date format');
    }
    
    const reportUrl = `https://reports.example.com/generate?start=${encodeURIComponent(startDate)}&end=${encodeURIComponent(endDate)}`;
    
    // ok: typescript-express-wkhtml-injection
    wkhtmltopdf(reportUrl, { output: 'date_report.pdf' });
    
    res.download('date_report.pdf');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_13(req: Request, res: Response) {
    // Use a hash map to map user input to safe URLs
    const reportType = req.query.type as string;
    
    const reportUrlMap: Record<string, string> = {
        'sales': 'https://reports.example.com/sales',
        'inventory': 'https://reports.example.com/inventory',
        'customers': 'https://reports.example.com/customers'
    };
    
    const reportUrl = reportUrlMap[reportType];
    if (!reportUrl) {
        return res.status(400).send('Invalid report type');
    }
    
    // ok: typescript-express-wkhtml-injection
    wkhtmltopdf(reportUrl, { output: 'mapped_report.pdf' });
    
    res.download('mapped_report.pdf');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_14(req: Request, res: Response) {
    // Generate HTML content directly instead of using a URL
    const productId = parseInt(req.params.id, 10);
    
    if (isNaN(productId)) {
        return res.status(400).send('Invalid product ID');
    }
    
    // Fetch product data from database (simulated)
    const product = { id: productId, name: 'Sample Product', price: 99.99 };
    
    const htmlContent = `
        <html>
            <body>
                <h1>${product.name}</h1>
                <p>ID: ${product.id}</p>
                <p>Price: $${product.price}</p>
            </body>
        </html>
    `;
    
    // ok: typescript-express-wkhtml-injection
    wkhtmltopdf(htmlContent, { output: 'product.pdf' });
    
    res.download('product.pdf');
}
// {/fact}

// {fact rule=server-side-request-forgery@v1.0 defects=0}
function good_case_15(req: Request, res: Response) {
    // Use a fixed file path instead of a URL
    const templateFile = 'templates/invoice_template.html';
    
    // Ensure the file exists
    if (!fs.existsSync(templateFile)) {
        return res.status(500).send('Template not found');
    }
    
    // ok: typescript-express-wkhtml-injection
    wkhtmltopdf(templateFile, { 
        output: 'invoice.pdf',
        pageSize: 'A4'
    });
    
    res.download('invoice.pdf');
}
// {/fact}

export { app };