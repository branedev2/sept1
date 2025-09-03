import * as express from 'express';
import * as libxmljs from 'libxmljs';
import * as fs from 'fs';
import * as DOMParser from 'xmldom';
import * as xpath from 'xpath';
import { parseString } from 'xml2js';
import * as http from 'http';
import * as https from 'https';
import { JSDOM } from 'jsdom';

// True Positive Examples (Vulnerable Code)

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_1() {
    const app = express();
    
    app.post('/parse-xml', (req, res) => {
        const xmlData = req.body.xml;
        
        // ruleid: typescript-xxe-injection
        const xmlDoc = libxmljs.parseXml(xmlData, { noent: true });
        
        const result = xmlDoc.get('//data').text();
        res.send(`Parsed data: ${result}`);
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_2() {
    const app = express();
    
    app.get('/process-xml', (req, res) => {
        const xmlInput = req.query.xml as string;
        
        // ruleid: typescript-xxe-injection
        const parser = new DOMParser.DOMParser({
            errorHandler: {warning: () => {}, error: () => {}, fatalError: () => {}},
        });
        const doc = parser.parseFromString(xmlInput, 'text/xml');
        
        const nodes = xpath.select('//user/name', doc);
        res.send(`Found ${nodes.length} users`);
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_3() {
    const app = express();
    
    app.post('/convert-xml', (req, res) => {
        const xmlContent = req.body.content;
        
        // ruleid: typescript-xxe-injection
        parseString(xmlContent, { explicitArray: false }, (err, result) => {
            if (err) {
                return res.status(400).send('Invalid XML');
            }
            res.json(result);
        });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_4() {
    const app = express();
    
    app.post('/xml-config', (req, res) => {
        const configXml = req.body.config;
        
        try {
            // ruleid: typescript-xxe-injection
            const doc = new DOMParser.DOMParser().parseFromString(configXml, 'application/xml');
            const serverName = xpath.select1('//server/name', doc).textContent;
            res.send(`Server name: ${serverName}`);
        } catch (e) {
            res.status(500).send('Error parsing XML');
        }
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_5() {
    const app = express();
    
    app.get('/xml-feed', (req, res) => {
        const feedUrl = req.query.url as string;
        
        https.get(feedUrl, (response) => {
            let data = '';
            response.on('data', (chunk) => {
                data += chunk;
            });
            
            response.on('end', () => {
                // ruleid: typescript-xxe-injection
                const xmlDoc = libxmljs.parseXml(data);
                const items = xmlDoc.find('//item');
                res.json({ itemCount: items.length });
            });
        });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_6() {
    const app = express();
    
    app.post('/xml-transform', (req, res) => {
        const userXml = req.body.xml;
        const options = {
            noent: true,
            dtdload: true,
            dtdvalid: true
        };
        
        // ruleid: typescript-xxe-injection
        const doc = libxmljs.parseXml(userXml, options);
        const result = doc.toString();
        res.send(result);
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_7() {
    const app = express();
    
    app.post('/process-form', (req, res) => {
        const formData = req.body.formXml;
        
        // ruleid: typescript-xxe-injection
        const dom = new JSDOM(formData, {
            contentType: "text/xml",
            runScripts: "dangerously"
        });
        
        const fields = dom.window.document.querySelectorAll('field');
        res.send(`Processed ${fields.length} fields`);
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_8() {
    const app = express();
    
    app.get('/xml-api', (req, res) => {
        const apiEndpoint = req.query.endpoint as string;
        
        http.get(apiEndpoint, (response) => {
            let xmlData = '';
            response.on('data', (chunk) => {
                xmlData += chunk;
            });
            
            response.on('end', () => {
                // ruleid: typescript-xxe-injection
                const parser = new DOMParser.DOMParser();
                const xmlDoc = parser.parseFromString(xmlData, 'text/xml');
                const status = xpath.select('//status/text()', xmlDoc).toString();
                res.send(`API Status: ${status}`);
            });
        });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_9() {
    const app = express();
    
    app.post('/import-data', (req, res) => {
        const importXml = req.body.importData;
        
        try {
            // ruleid: typescript-xxe-injection
            libxmljs.parseXmlString(importXml, { noblanks: true, noent: true }, (err, doc) => {
                if (err) {
                    return res.status(400).send('Invalid XML');
                }
                const records = doc.find('//record');
                res.send(`Imported ${records.length} records`);
            });
        } catch (e) {
            res.status(500).send('Import failed');
        }
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_10() {
    const app = express();
    
    app.post('/validate-xml', (req, res) => {
        const xmlContent = req.body.xml;
        const schemaContent = req.body.schema;
        
        try {
            // ruleid: typescript-xxe-injection
            const doc = libxmljs.parseXml(xmlContent);
            const schema = libxmljs.parseXml(schemaContent);
            
            const isValid = doc.validate(schema);
            res.json({ valid: isValid });
        } catch (e) {
            res.status(500).send('Validation error');
        }
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_11() {
    const app = express();
    
    app.post('/extract-data', (req, res) => {
        const xmlPayload = req.headers['x-xml-data'] as string;
        
        // ruleid: typescript-xxe-injection
        const parser = new DOMParser.DOMParser({
            locator: {},
            errorHandler: { warning: () => {}, error: () => {}, fatalError: () => {} }
        });
        
        const doc = parser.parseFromString(xmlPayload, 'application/xml');
        const dataPoints = xpath.select('//dataPoint', doc);
        
        res.json({ count: dataPoints.length });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_12() {
    const app = express();
    
    app.get('/rss-reader', (req, res) => {
        const rssFeed = req.query.feed as string;
        
        https.get(rssFeed, (response) => {
            let data = '';
            response.on('data', (chunk) => {
                data += chunk;
            });
            
            response.on('end', () => {
                // ruleid: typescript-xxe-injection
                parseString(data, (err, result) => {
                    if (err) {
                        return res.status(400).send('Invalid RSS feed');
                    }
                    
                    const items = result.rss.channel[0].item || [];
                    res.json({ items: items.length });
                });
            });
        });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_13() {
    const app = express();
    
    app.post('/svg-processor', (req, res) => {
        const svgContent = req.body.svg;
        
        // ruleid: typescript-xxe-injection
        const parser = new DOMParser.DOMParser();
        const svgDoc = parser.parseFromString(svgContent, 'image/svg+xml');
        
        const elements = svgDoc.getElementsByTagName('*');
        res.send(`Processed SVG with ${elements.length} elements`);
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_14() {
    const app = express();
    
    app.post('/xml-search', (req, res) => {
        const searchXml = req.body.searchDoc;
        const searchTerm = req.query.term as string;
        
        // ruleid: typescript-xxe-injection
        const doc = libxmljs.parseXml(searchXml);
        const nodes = doc.find(`//*[contains(text(),'${searchTerm}')]`);
        
        res.json({ matches: nodes.length });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_15() {
    const app = express();
    
    app.post('/xml-upload', (req, res) => {
        const uploadedXml = req.body.fileContent;
        
        try {
            // ruleid: typescript-xxe-injection
            const options = { noblanks: true };
            const xmlDoc = libxmljs.parseXml(uploadedXml, options);
            
            const rootName = xmlDoc.root().name();
            res.send(`Uploaded XML with root element: ${rootName}`);
        } catch (e) {
            res.status(400).send('Invalid XML file');
        }
    });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_1() {
    const app = express();
    
    app.post('/parse-xml-safe', (req, res) => {
        const xmlData = req.body.xml;
        
        // ok: typescript-xxe-injection
        const xmlDoc = libxmljs.parseXml(xmlData, { noent: false });
        
        const result = xmlDoc.get('//data').text();
        res.send(`Parsed data: ${result}`);
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_2() {
    const app = express();
    
    app.get('/process-xml-safe', (req, res) => {
        const xmlInput = req.query.xml as string;
        
        // ok: typescript-xxe-injection
        const parser = new DOMParser.DOMParser({
            errorHandler: {warning: () => {}, error: () => {}, fatalError: () => {}},
            entityParser: DOMParser.EntityParser.ENTITIES_NEVER
        });
        const doc = parser.parseFromString(xmlInput, 'text/xml');
        
        const nodes = xpath.select('//user/name', doc);
        res.send(`Found ${nodes.length} users`);
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_3() {
    const app = express();
    
    app.post('/convert-xml-safe', (req, res) => {
        const xmlContent = req.body.content;
        
        // ok: typescript-xxe-injection
        parseString(xmlContent, { 
            explicitArray: false,
            ignoreAttrs: true,
            explicitCharkey: true,
            xmlns: true,
            explicitRoot: true,
            normalizeTags: true,
            normalize: true,
            explicitChildren: true,
            preserveChildrenOrder: true,
            charsAsChildren: true,
            includeWhiteChars: true,
            async: true,
            strict: true,
            attrNameProcessors: [],
            attrValueProcessors: [],
            tagNameProcessors: [],
            valueProcessors: []
        }, (err, result) => {
            if (err) {
                return res.status(400).send('Invalid XML');
            }
            res.json(result);
        });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_4() {
    const app = express();
    
    app.post('/xml-config-safe', (req, res) => {
        const configXml = req.body.config;
        
        try {
            // ok: typescript-xxe-injection
            const parser = new DOMParser.DOMParser({
                locator: {},
                errorHandler: { warning: () => {}, error: () => {}, fatalError: () => {} },
                entityParser: DOMParser.EntityParser.ENTITIES_NEVER
            });
            const doc = parser.parseFromString(configXml, 'application/xml');
            const serverName = xpath.select1('//server/name', doc).textContent;
            res.send(`Server name: ${serverName}`);
        } catch (e) {
            res.status(500).send('Error parsing XML');
        }
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_5() {
    const app = express();
    
    app.get('/xml-feed-safe', (req, res) => {
        const feedUrl = req.query.url as string;
        
        https.get(feedUrl, (response) => {
            let data = '';
            response.on('data', (chunk) => {
                data += chunk;
            });
            
            response.on('end', () => {
                // ok: typescript-xxe-injection
                const xmlDoc = libxmljs.parseXml(data, { noent: false, dtdload: false });
                const items = xmlDoc.find('//item');
                res.json({ itemCount: items.length });
            });
        });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_6() {
    const app = express();
    
    app.post('/xml-transform-safe', (req, res) => {
        const userXml = req.body.xml;
        const options = {
            noent: false,
            dtdload: false,
            dtdvalid: false
        };
        
        // ok: typescript-xxe-injection
        const doc = libxmljs.parseXml(userXml, options);
        const result = doc.toString();
        res.send(result);
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_7() {
    const app = express();
    
    app.post('/process-form-safe', (req, res) => {
        const formData = req.body.formXml;
        
        // Sanitize XML by removing DOCTYPE declarations
        const sanitizedXml = formData.replace(/<!DOCTYPE[^>]*>/i, '');
        
        // ok: typescript-xxe-injection
        const dom = new JSDOM(sanitizedXml, {
            contentType: "text/xml",
            runScripts: "outside-only"
        });
        
        const fields = dom.window.document.querySelectorAll('field');
        res.send(`Processed ${fields.length} fields`);
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_8() {
    const app = express();
    
    app.get('/xml-api-safe', (req, res) => {
        const apiEndpoint = req.query.endpoint as string;
        
        http.get(apiEndpoint, (response) => {
            let xmlData = '';
            response.on('data', (chunk) => {
                xmlData += chunk;
            });
            
            response.on('end', () => {
                // Remove any DOCTYPE declarations
                const sanitizedXml = xmlData.replace(/<!DOCTYPE[^>]*>/i, '');
                
                // ok: typescript-xxe-injection
                const parser = new DOMParser.DOMParser({
                    entityParser: DOMParser.EntityParser.ENTITIES_NEVER
                });
                const xmlDoc = parser.parseFromString(sanitizedXml, 'text/xml');
                const status = xpath.select('//status/text()', xmlDoc).toString();
                res.send(`API Status: ${status}`);
            });
        });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_9() {
    const app = express();
    
    app.post('/import-data-safe', (req, res) => {
        const importXml = req.body.importData;
        
        try {
            // ok: typescript-xxe-injection
            const options = { 
                noblanks: true, 
                noent: false, 
                dtdload: false, 
                dtdvalid: false 
            };
            
            libxmljs.parseXml(importXml, options, (err, doc) => {
                if (err) {
                    return res.status(400).send('Invalid XML');
                }
                const records = doc.find('//record');
                res.send(`Imported ${records.length} records`);
            });
        } catch (e) {
            res.status(500).send('Import failed');
        }
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_10() {
    const app = express();
    
    app.post('/validate-xml-safe', (req, res) => {
        const xmlContent = req.body.xml;
        const schemaContent = req.body.schema;
        
        try {
            // ok: typescript-xxe-injection
            const safeOptions = { noent: false, dtdload: false };
            const doc = libxmljs.parseXml(xmlContent, safeOptions);
            const schema = libxmljs.parseXml(schemaContent, safeOptions);
            
            const isValid = doc.validate(schema);
            res.json({ valid: isValid });
        } catch (e) {
            res.status(500).send('Validation error');
        }
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_11() {
    const app = express();
    
    app.post('/extract-data-safe', (req, res) => {
        const xmlPayload = req.headers['x-xml-data'] as string;
        
        // Remove DOCTYPE declarations as a first line of defense
        const sanitizedXml = xmlPayload.replace(/<!DOCTYPE[^>]*>/i, '');
        
        // ok: typescript-xxe-injection
        const parser = new DOMParser.DOMParser({
            locator: {},
            errorHandler: { warning: () => {}, error: () => {}, fatalError: () => {} },
            entityParser: DOMParser.EntityParser.ENTITIES_NEVER
        });
        
        const doc = parser.parseFromString(sanitizedXml, 'application/xml');
        const dataPoints = xpath.select('//dataPoint', doc);
        
        res.json({ count: dataPoints.length });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_12() {
    const app = express();
    
    app.get('/rss-reader-safe', (req, res) => {
        const rssFeed = req.query.feed as string;
        
        https.get(rssFeed, (response) => {
            let data = '';
            response.on('data', (chunk) => {
                data += chunk;
            });
            
            response.on('end', () => {
                // ok: typescript-xxe-injection
                parseString(data, { 
                    explicitArray: true,
                    normalizeTags: true,
                    explicitRoot: true,
                    xmlns: true
                }, (err, result) => {
                    if (err) {
                        return res.status(400).send('Invalid RSS feed');
                    }
                    
                    const items = result.rss.channel[0].item || [];
                    res.json({ items: items.length });
                });
            });
        });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_13() {
    const app = express();
    
    app.post('/svg-processor-safe', (req, res) => {
        const svgContent = req.body.svg;
        
        // Remove DOCTYPE declarations
        const sanitizedSvg = svgContent.replace(/<!DOCTYPE[^>]*>/i, '');
        
        // ok: typescript-xxe-injection
        const parser = new DOMParser.DOMParser({
            entityParser: DOMParser.EntityParser.ENTITIES_NEVER
        });
        const svgDoc = parser.parseFromString(sanitizedSvg, 'image/svg+xml');
        
        const elements = svgDoc.getElementsByTagName('*');
        res.send(`Processed SVG with ${elements.length} elements`);
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_14() {
    const app = express();
    
    app.post('/xml-search-safe', (req, res) => {
        const searchXml = req.body.searchDoc;
        const searchTerm = req.query.term as string;
        
        // ok: typescript-xxe-injection
        const doc = libxmljs.parseXml(searchXml, { 
            noent: false, 
            dtdload: false 
        });
        
        // Use a safer approach to search
        const nodes = doc.find('//element');
        const matches = nodes.filter(node => 
            node.text().includes(searchTerm)
        );
        
        res.json({ matches: matches.length });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_15() {
    const app = express();
    
    app.post('/xml-upload-safe', (req, res) => {
        const uploadedXml = req.body.fileContent;
        
        try {
            // ok: typescript-xxe-injection
            const options = { 
                noblanks: true,
                noent: false,
                dtdload: false,
                dtdvalid: false,
                nocdata: false,
                recover: true
            };
            
            const xmlDoc = libxmljs.parseXml(uploadedXml, options);
            
            const rootName = xmlDoc.root().name();
            res.send(`Uploaded XML with root element: ${rootName}`);
        } catch (e) {
            res.status(400).send('Invalid XML file');
        }
    });
}
// {/fact}