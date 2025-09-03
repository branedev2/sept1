import express from 'express';
import { Request, Response } from 'express';
import * as xml2js from 'xml2js';
import * as fs from 'fs';
import { DOMParser } from 'xmldom';
import { xml2json } from 'xml-js';
import * as libxmljs from 'libxmljs';

const app = express();
app.use(express.json());
app.use(express.text());
app.use(express.raw({ type: 'application/xml' }));

// TRUE POSITIVES (VULNERABLE CASES)

// Case 1: Basic XML parsing with xml2js from request body
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_1() {
    app.post('/api/parse-xml', (req: Request, res: Response) => {
        const xmlData = req.body;
        
        // ruleid: express-xml2json-xxe-event-ts-rule
        xml2js.parseString(xmlData, (err, result) => {
            if (err) {
                return res.status(400).json({ error: 'Invalid XML' });
            }
            res.json(result);
        });
    });
}
// {/fact}

// Case 2: XML parsing with xml-js from request body
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_2() {
    app.post('/api/convert-xml', (req: Request, res: Response) => {
        const xmlData = req.body;
        
        try {
            // ruleid: express-xml2json-xxe-event-ts-rule
            const jsonData = xml2json(xmlData, { compact: true });
            res.json(JSON.parse(jsonData));
        } catch (error) {
            res.status(400).json({ error: 'Failed to parse XML' });
        }
    });
}
// {/fact}

// Case 3: XML parsing with DOMParser from query parameter
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_3() {
    app.get('/api/parse-xml-from-url', (req: Request, res: Response) => {
        const xmlData = req.query.xml as string;
        
        try {
            const parser = new DOMParser();
            // ruleid: express-xml2json-xxe-event-ts-rule
            const xmlDoc = parser.parseFromString(xmlData, 'text/xml');
            res.send('XML parsed successfully');
        } catch (error) {
            res.status(400).send('Failed to parse XML');
        }
    });
}
// {/fact}

// Case 4: XML parsing with libxmljs from request header
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_4() {
    app.post('/api/process-xml-header', (req: Request, res: Response) => {
        const xmlData = req.headers['x-xml-data'] as string;
        
        try {
            // ruleid: express-xml2json-xxe-event-ts-rule
            const xmlDoc = libxmljs.parseXml(xmlData);
            res.send('XML processed successfully');
        } catch (error) {
            res.status(400).send('Failed to process XML');
        }
    });
}
// {/fact}

// Case 5: XML parsing with xml2js in PUT request
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_5() {
    app.put('/api/update-xml', (req: Request, res: Response) => {
        const xmlData = req.body;
        
        // ruleid: express-xml2json-xxe-event-ts-rule
        xml2js.parseString(xmlData, { explicitArray: false }, (err, result) => {
            if (err) {
                return res.status(400).json({ error: 'Invalid XML' });
            }
            res.json(result);
        });
    });
}
// {/fact}

// Case 6: XML parsing with xml2js in PATCH request
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_6() {
    app.patch('/api/patch-xml', (req: Request, res: Response) => {
        const xmlData = req.body;
        
        const parser = new xml2js.Parser();
        // ruleid: express-xml2json-xxe-event-ts-rule
        parser.parseString(xmlData, (err, result) => {
            if (err) {
                return res.status(400).json({ error: 'Invalid XML' });
            }
            res.json(result);
        });
    });
}
// {/fact}

// Case 7: XML parsing with xml-js in nested route handler
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_7() {
    app.use('/api/documents', (req: Request, res: Response, next) => {
        if (req.headers['content-type'] === 'application/xml') {
            // ruleid: express-xml2json-xxe-event-ts-rule
            const jsonData = xml2json(req.body, { compact: false });
            req.body = JSON.parse(jsonData);
        }
        next();
    });
}
// {/fact}

// Case 8: XML parsing with xml2js in route with parameters
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_8() {
    app.post('/api/users/:userId/xml-data', (req: Request, res: Response) => {
        const userId = req.params.userId;
        const xmlData = req.body;
        
        // ruleid: express-xml2json-xxe-event-ts-rule
        xml2js.parseString(xmlData, (err, result) => {
            if (err) {
                return res.status(400).json({ error: 'Invalid XML' });
            }
            res.json({ userId, data: result });
        });
    });
}
// {/fact}

// Case 9: XML parsing with DOMParser in async route handler
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_9() {
    app.post('/api/async-xml-parse', async (req: Request, res: Response) => {
        try {
            const xmlData = req.body;
            const parser = new DOMParser();
            
            // ruleid: express-xml2json-xxe-event-ts-rule
            const xmlDoc = parser.parseFromString(xmlData, 'text/xml');
            res.send('XML parsed successfully');
        } catch (error) {
            res.status(500).send('Server error');
        }
    });
}
// {/fact}

// Case 10: XML parsing with xml2js in error handler
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_10() {
    app.post('/api/xml-with-error-handling', (req: Request, res: Response) => {
        try {
            const xmlData = req.body;
            
            // ruleid: express-xml2json-xxe-event-ts-rule
            xml2js.parseString(xmlData, { explicitArray: false }, (err, result) => {
                if (err) throw new Error('XML parsing failed');
                res.json(result);
            });
        } catch (error) {
            res.status(500).json({ error: 'Internal server error' });
        }
    });
}
// {/fact}

// Case 11: XML parsing with libxmljs in conditional block
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_11() {
    app.post('/api/conditional-xml-parse', (req: Request, res: Response) => {
        const contentType = req.headers['content-type'];
        
        if (contentType && contentType.includes('application/xml')) {
            const xmlData = req.body;
            try {
                // ruleid: express-xml2json-xxe-event-ts-rule
                const xmlDoc = libxmljs.parseXml(xmlData);
                return res.json({ success: true });
            } catch (error) {
                return res.status(400).json({ error: 'Invalid XML' });
            }
        }
        
        res.status(415).json({ error: 'Unsupported Media Type' });
    });
}
// {/fact}

// Case 12: XML parsing with xml2js in middleware chain
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_12() {
    const validateXml = (req: Request, res: Response, next: Function) => {
        const xmlData = req.body;
        
        // ruleid: express-xml2json-xxe-event-ts-rule
        xml2js.parseString(xmlData, (err, result) => {
            if (err) {
                return res.status(400).json({ error: 'Invalid XML' });
            }
            req.body = result;
            next();
        });
    };
    
    app.post('/api/xml-middleware', validateXml, (req: Request, res: Response) => {
        res.json(req.body);
    });
}
// {/fact}

// Case 13: XML parsing with xml-js from base64 encoded request data
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_13() {
    app.post('/api/base64-xml', (req: Request, res: Response) => {
        const base64XmlData = req.body.data;
        const xmlData = Buffer.from(base64XmlData, 'base64').toString('utf-8');
        
        try {
            // ruleid: express-xml2json-xxe-event-ts-rule
            const jsonData = xml2json(xmlData, { compact: true });
            res.json(JSON.parse(jsonData));
        } catch (error) {
            res.status(400).json({ error: 'Failed to parse XML' });
        }
    });
}
// {/fact}

// Case 14: XML parsing with xml2js from URL encoded form data
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_14() {
    app.use(express.urlencoded({ extended: true }));
    
    app.post('/api/form-xml', (req: Request, res: Response) => {
        const xmlData = req.body.xmlContent;
        
        // ruleid: express-xml2json-xxe-event-ts-rule
        xml2js.parseString(xmlData, (err, result) => {
            if (err) {
                return res.status(400).json({ error: 'Invalid XML' });
            }
            res.json(result);
        });
    });
}
// {/fact}

// Case 15: XML parsing with DOMParser from cookie data
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_15() {
    app.get('/api/cookie-xml', (req: Request, res: Response) => {
        const xmlData = req.cookies.xmlData;
        
        try {
            const parser = new DOMParser();
            // ruleid: express-xml2json-xxe-event-ts-rule
            const xmlDoc = parser.parseFromString(xmlData, 'text/xml');
            res.send('XML parsed successfully');
        } catch (error) {
            res.status(400).send('Failed to parse XML');
        }
    });
}
// {/fact}

// TRUE NEGATIVES (SECURE CASES)

// Case 1: Secure XML parsing with xml2js using disableDtd option
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_1() {
    app.post('/api/secure-parse-xml', (req: Request, res: Response) => {
        const xmlData = req.body;
        
        // ok: express-xml2json-xxe-event-ts-rule
        xml2js.parseString(xmlData, { 
            explicitArray: false,
            normalizeTags: true,
            explicitRoot: false,
            xmlns: true,
            explicitCharkey: true,
            charkey: 'text',
            emptyTag: '',
            attrkey: 'attr',
            explicitChildren: false,
            childkey: 'children',
            charsAsChildren: false,
            includeWhiteChars: false,
            async: false,
            strict: true,
            attrNameProcessors: null,
            attrValueProcessors: null,
            tagNameProcessors: null,
            valueProcessors: null,
            validator: null,
            trim: false,
            normalize: false,
            normalizeTags: false,
            mergeAttrs: false,
            ignoreAttrs: false,
            explicitRoot: true,
            explicitArray: true,
            ignoreXmlns: false,
            explicitCharkey: false,
            charkey: '_',
            explicitChildren: false,
            childkey: '$$',
            charsAsChildren: false,
            includeWhiteChars: false,
            async: false,
            strict: true,
            attrNameProcessors: null,
            attrValueProcessors: null,
            tagNameProcessors: null,
            valueProcessors: null,
            validator: null,
            xmlns: false,
            xmlnskey: 'xmlns',
            attrNameProcessors: null,
            attrValueProcessors: null,
            tagNameProcessors: null,
            valueProcessors: null,
            validator: null,
            explicitRoot: true,
            trim: false,
            normalize: false,
            normalizeTags: false,
            mergeAttrs: false,
            ignoreAttrs: false,
            explicitArray: true,
            ignoreXmlns: false,
            explicitCharkey: false,
            charkey: '_',
            explicitChildren: false,
            preserveChildrenOrder: false,
            childkey: '$$',
            charsAsChildren: false,
            includeWhiteChars: false,
            async: false,
            strict: true,
            attrkey: '$',
            rootName: 'root',
            xmldec: {
                'version': '1.0',
                'encoding': 'UTF-8',
                'standalone': true
            },
            doctype: null,
            renderOpts: {
                'pretty': true,
                'indent': '  ',
                'newline': '\n'
            },
            headless: false,
            chunkSize: 10000,
            emptyTag: '',
            cdata: false,
            disableDtd: true  // This option disables DTD processing, preventing XXE
        }, (err, result) => {
            if (err) {
                return res.status(400).json({ error: 'Invalid XML' });
            }
            res.json(result);
        });
    });
}
// {/fact}

// Case 2: Secure XML parsing with libxmljs using nonet option
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_2() {
    app.post('/api/secure-libxmljs', (req: Request, res: Response) => {
        const xmlData = req.body;
        
        try {
            // ok: express-xml2json-xxe-event-ts-rule
            const xmlDoc = libxmljs.parseXml(xmlData, { 
                nonet: true,  // Prevents network access during parsing
                noblanks: true,
                noent: false, // Do not substitute entities
                dtdload: false, // Do not load DTDs
                dtdvalid: false, // Do not validate with DTDs
                dtdattr: false, // Do not apply DTD attributes
                xinclude: false // Do not process XInclude directives
            });
            res.send('XML processed securely');
        } catch (error) {
            res.status(400).send('Failed to process XML');
        }
    });
}
// {/fact}

// Case 3: Using a custom XML parser with XXE protections
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_3() {
    app.post('/api/custom-secure-parser', (req: Request, res: Response) => {
        const xmlData = req.body;
        
        // Custom function that uses secure parsing options
        function secureXmlParse(xml: string) {
            // ok: express-xml2json-xxe-event-ts-rule
            return xml2js.parseStringPromise(xml, {
                disableDtd: true, // Disable DTD processing
                xmlns: false,
                normalizeTags: true,
                explicitArray: false
            });
        }
        
        secureXmlParse(xmlData)
            .then(result => res.json(result))
            .catch(err => res.status(400).json({ error: 'Invalid XML' }));
    });
}
// {/fact}

// Case 4: Using XML validation before parsing
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_4() {
    app.post('/api/validate-then-parse', (req: Request, res: Response) => {
        const xmlData = req.body;
        
        // First validate XML for security
        function isXmlSafe(xml: string): boolean {
            // Check for DOCTYPE declarations which could lead to XXE
            if (xml.includes('<!DOCTYPE') || xml.includes('<!ENTITY')) {
                return false;
            }
            return true;
        }
        
        if (!isXmlSafe(xmlData)) {
            return res.status(400).json({ error: 'XML contains potentially unsafe content' });
        }
        
        // Now parse with secure options
        // ok: express-xml2json-xxe-event-ts-rule
        xml2js.parseString(xmlData, { 
            disableDtd: true,
            explicitArray: false 
        }, (err, result) => {
            if (err) {
                return res.status(400).json({ error: 'Invalid XML' });
            }
            res.json(result);
        });
    });
}
// {/fact}

// Case 5: Using a sanitized XML string
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_5() {
    app.post('/api/sanitized-xml', (req: Request, res: Response) => {
        let xmlData = req.body;
        
        // Sanitize XML by removing potentially dangerous elements
        function sanitizeXml(xml: string): string {
            // Remove DOCTYPE declarations
            xml = xml.replace(/<!DOCTYPE[^>]*>/g, '');
            // Remove ENTITY declarations
            xml = xml.replace(/<!ENTITY[^>]*>/g, '');
            return xml;
        }
        
        const sanitizedXml = sanitizeXml(xmlData);
        
        // ok: express-xml2json-xxe-event-ts-rule
        xml2js.parseString(sanitizedXml, (err, result) => {
            if (err) {
                return res.status(400).json({ error: 'Invalid XML' });
            }
            res.json(result);
        });
    });
}
// {/fact}

// Case 6: Using a secure XML parser library wrapper
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_6() {
    app.post('/api/secure-parser-wrapper', (req: Request, res: Response) => {
        const xmlData = req.body;
        
        // Secure parser wrapper
        const secureParser = {
            parse: function(xml: string) {
                // ok: express-xml2json-xxe-event-ts-rule
                return xml2js.parseStringPromise(xml, {
                    disableDtd: true,
                    explicitArray: false,
                    ignoreAttrs: true
                });
            }
        };
        
        secureParser.parse(xmlData)
            .then(result => res.json(result))
            .catch(err => res.status(400).json({ error: 'Invalid XML' }));
    });
}
// {/fact}

// Case 7: Using a non-XML parser for JSON data
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_7() {
    app.post('/api/json-data', (req: Request, res: Response) => {
        // This endpoint handles JSON, not XML, so no XXE risk
        const jsonData = req.body;
        
        // ok: express-xml2json-xxe-event-ts-rule
        try {
            // Process JSON data
            const processedData = { ...jsonData, processed: true };
            res.json(processedData);
        } catch (error) {
            res.status(400).json({ error: 'Invalid JSON' });
        }
    });
}
// {/fact}

// Case 8: Using a predefined XML template instead of user input
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_8() {
    app.post('/api/template-xml', (req: Request, res: Response) => {
        // Using a safe, predefined XML template instead of user input
        const safeXmlTemplate = `
            <root>
                <item>
                    <name>${req.body.name}</name>
                    <value>${req.body.value}</value>
                </item>
            </root>
        `;
        
        // ok: express-xml2json-xxe-event-ts-rule
        xml2js.parseString(safeXmlTemplate, { 
            disableDtd: true 
        }, (err, result) => {
            if (err) {
                return res.status(400).json({ error: 'Error processing data' });
            }
            res.json(result);
        });
    });
}
// {/fact}

// Case 9: Using a secure XML builder instead of parser
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_9() {
    app.post('/api/build-xml', (req: Request, res: Response) => {
        const userData = req.body;
        
        // Create XML from JSON instead of parsing XML
        // ok: express-xml2json-xxe-event-ts-rule
        const builder = new xml2js.Builder({
            rootName: 'root',
            headless: true,
            renderOpts: {
                pretty: true,
                indent: '  ',
                newline: '\n'
            }
        });
        
        try {
            const xml = builder.buildObject(userData);
            res.type('application/xml').send(xml);
        } catch (error) {
            res.status(400).json({ error: 'Failed to build XML' });
        }
    });
}
// {/fact}

// Case 10: Using XML parsing on server-generated content
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_10() {
    app.get('/api/server-xml', (req: Request, res: Response) => {
        // XML is generated on the server, not from user input
        const serverGeneratedXml = `
            <data>
                <item id="1">First item</item>
                <item id="2">Second item</item>
                <item id="3">Third item</item>
            </data>
        `;
        
        // ok: express-xml2json-xxe-event-ts-rule
        xml2js.parseString(serverGeneratedXml, (err, result) => {
            if (err) {
                return res.status(500).json({ error: 'Server error' });
            }
            res.json(result);
        });
    });
}
// {/fact}

// Case 11: Using a secure XML parser with proper error handling
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_11() {
    app.post('/api/robust-xml-parsing', (req: Request, res: Response) => {
        const xmlData = req.body;
        
        // ok: express-xml2json-xxe-event-ts-rule
        const parser = new xml2js.Parser({
            disableDtd: true,
            explicitArray: false,
            normalizeTags: true
        });
        
        parser.parseString(xmlData, (err, result) => {
            if (err) {
                console.error('XML parsing error:', err);
                return res.status(400).json({ 
                    error: 'Invalid XML format',
                    details: err.message
                });
            }
            
            try {
                // Additional validation of parsed content
                if (!result || !result.root) {
                    throw new Error('Missing required XML structure');
                }
                
                res.json(result);
            } catch (validationError) {
                res.status(400).json({ 
                    error: 'XML validation failed',
                    details: validationError.message
                });
            }
        });
    });
}
// {/fact}

// Case 12: Using XML parsing in a controlled environment
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_12() {
    // This function processes an XML file from a trusted source
    app.get('/api/process-trusted-xml', (req: Request, res: Response) => {
        const trustedXmlPath = './trusted-data.xml';
        
        fs.readFile(trustedXmlPath, 'utf8', (err, xmlData) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to read XML file' });
            }
            
            // ok: express-xml2json-xxe-event-ts-rule
            xml2js.parseString(xmlData, {
                disableDtd: true,
                explicitArray: false
            }, (parseErr, result) => {
                if (parseErr) {
                    return res.status(500).json({ error: 'Failed to parse XML' });
                }
                res.json(result);
            });
        });
    });
}
// {/fact}

// Case 13: Using a secure XML parser with validation
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_13() {
    app.post('/api/validated-xml', (req: Request, res: Response) => {
        const xmlData = req.body;
        
        // Validate XML structure before parsing
        function validateXmlStructure(xml: string): boolean {
            // Simple validation - check for well-formed XML
            try {
                // Use a simple check without enabling external entities
                const tempParser = new DOMParser();
                tempParser.parseFromString(xml, 'text/xml');
                return true;
            } catch (e) {
                return false;
            }
        }
        
        if (!validateXmlStructure(xmlData)) {
            return res.status(400).json({ error: 'Invalid XML structure' });
        }
        
        // ok: express-xml2json-xxe-event-ts-rule
        xml2js.parseString(xmlData, {
            disableDtd: true,
            explicitArray: false,
            async: true
        }, (err, result) => {
            if (err) {
                return res.status(400).json({ error: 'XML parsing failed' });
            }
            res.json(result);
        });
    });
}
// {/fact}

// Case 14: Using XML parsing with content verification
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_14() {
    app.post('/api/verified-xml-content', (req: Request, res: Response) => {
        const xmlData = req.body;
        
        // Verify XML content doesn't contain suspicious patterns
        function verifyXmlContent(xml: string): boolean {
            const suspiciousPatterns = [
                '<!DOCTYPE',
                '<!ENTITY',
                'SYSTEM',
                'PUBLIC'
            ];
            
            return !suspiciousPatterns.some(pattern => xml.includes(pattern));
        }
        
        if (!verifyXmlContent(xmlData)) {
            return res.status(403).json({ error: 'XML contains potentially malicious content' });
        }
        
        // ok: express-xml2json-xxe-event-ts-rule
        xml2js.parseString(xmlData, {
            disableDtd: true,
            explicitArray: false
        }, (err, result) => {
            if (err) {
                return res.status(400).json({ error: 'XML parsing failed' });
            }
            res.json(result);
        });
    });
}
// {/fact}

// Case 15: Using a secure XML parser with schema validation
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_15() {
    app.post('/api/schema-validated-xml', (req: Request, res: Response) => {
        const xmlData = req.body;
        
        // Define a schema validator function
        function validateAgainstSchema(parsedXml: any): boolean {
            // In a real application, this would validate the parsed XML against a schema
            // For this example, we'll do a simple check
            return parsedXml && parsedXml.root && typeof parsedXml.root === 'object';
        }
        
        // ok: express-xml2json-xxe-event-ts-rule
        xml2js.parseString(xmlData, {
            disableDtd: true,
            explicitArray: false,
            validator: (xpath: string, currentValue: any, newValue: any) => {
                // Additional validation during parsing
                if (typeof newValue === 'string' && newValue.length > 1000) {
                    throw new Error('String value too long');
                }
                return newValue;
            }
        }, (err, result) => {
            if (err) {
                return res.status(400).json({ error: 'XML parsing or validation failed' });
            }
            
            if (!validateAgainstSchema(result)) {
                return res.status(400).json({ error: 'XML does not match required schema' });
            }
            
            res.json(result);
        });
    });
}
// {/fact}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});