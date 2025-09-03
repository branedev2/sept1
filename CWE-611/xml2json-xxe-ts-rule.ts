import * as express from 'express';
import { Request, Response } from 'express';
import * as xml2js from 'xml2js';
import * as fs from 'fs';
import * as https from 'https';
import * as http from 'http';
import { DOMParser } from 'xmldom';
import * as fastXml from 'fast-xml-parser';
import { XMLParser } from 'fast-xml-parser';
import * as bodyParser from 'body-parser';
import { libxmljs } from 'libxmljs';
import * as dotenv from 'dotenv';

// True Positives (Vulnerable Code)

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_1() {
    const app = express();
    app.use(express.text({ type: 'application/xml' }));
    
    app.post('/parse-xml', (req: Request, res: Response) => {
        const xmlData = req.body;
        
        // ruleid: xml2json-xxe-ts-rule
        xml2js.parseString(xmlData, (err, result) => {
            if (err) {
                return res.status(400).send('Invalid XML');
            }
            res.json(result);
        });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_2() {
    const app = express();
    app.use(express.text({ type: 'application/xml' }));
    
    app.post('/convert', (req: Request, res: Response) => {
        const xmlContent = req.body;
        const parser = new xml2js.Parser();
        
        // ruleid: xml2json-xxe-ts-rule
        parser.parseString(xmlContent, (err, result) => {
            if (err) {
                return res.status(400).json({ error: 'Failed to parse XML' });
            }
            res.json(result);
        });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_3() {
    const app = express();
    app.use(express.text());
    
    app.post('/process-xml', (req: Request, res: Response) => {
        const userXml = req.body;
        
        try {
            // ruleid: xml2json-xxe-ts-rule
            const parser = new DOMParser({
                errorHandler: {
                    warning: () => {},
                    error: () => {},
                    fatalError: () => {}
                }
            });
            const doc = parser.parseFromString(userXml, 'text/xml');
            res.send('XML processed successfully');
        } catch (error) {
            res.status(400).send('Error processing XML');
        }
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_4() {
    const app = express();
    app.use(bodyParser.text({ type: 'application/xml' }));
    
    app.post('/xml-endpoint', (req: Request, res: Response) => {
        const xmlInput = req.body;
        
        // ruleid: xml2json-xxe-ts-rule
        const options = {};
        const parser = new fastXml.XMLParser(options);
        const jsonObj = parser.parse(xmlInput);
        
        res.json(jsonObj);
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_5() {
    const app = express();
    
    app.get('/fetch-and-parse', (req: Request, res: Response) => {
        const xmlUrl = req.query.url as string;
        
        https.get(xmlUrl, (response) => {
            let data = '';
            response.on('data', (chunk) => {
                data += chunk;
            });
            
            response.on('end', () => {
                // ruleid: xml2json-xxe-ts-rule
                const parser = new XMLParser();
                const result = parser.parse(data);
                res.json(result);
            });
        });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_6() {
    const app = express();
    app.use(express.text({ type: 'application/xml' }));
    
    app.post('/upload-xml', (req: Request, res: Response) => {
        const xmlContent = req.body;
        
        try {
            // ruleid: xml2json-xxe-ts-rule
            const xmlDoc = libxmljs.parseXml(xmlContent);
            const result = { success: true, nodes: xmlDoc.childNodes().length };
            res.json(result);
        } catch (error) {
            res.status(400).json({ error: 'Failed to parse XML' });
        }
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_7() {
    const app = express();
    
    app.post('/process-xml-file', (req: Request, res: Response) => {
        const filePath = req.body.filePath;
        
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                return res.status(400).send('Error reading file');
            }
            
            // ruleid: xml2json-xxe-ts-rule
            xml2js.parseString(data, (parseErr, result) => {
                if (parseErr) {
                    return res.status(400).send('Error parsing XML');
                }
                res.json(result);
            });
        });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_8() {
    const app = express();
    app.use(express.text({ type: 'application/xml' }));
    
    app.post('/xml-to-json', (req: Request, res: Response) => {
        const xmlData = req.body;
        const options = {
            trim: true,
            explicitArray: false
        };
        
        // ruleid: xml2json-xxe-ts-rule
        xml2js.parseString(xmlData, options, (err, result) => {
            if (err) {
                return res.status(400).send('Invalid XML');
            }
            res.json(result);
        });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_9() {
    const app = express();
    
    app.post('/parse-xml-header', (req: Request, res: Response) => {
        const xmlContent = req.headers['x-xml-data'] as string;
        
        if (!xmlContent) {
            return res.status(400).send('No XML data provided');
        }
        
        // ruleid: xml2json-xxe-ts-rule
        const parser = new xml2js.Parser();
        parser.parseString(xmlContent, (err, result) => {
            if (err) {
                return res.status(400).send('Invalid XML');
            }
            res.json(result);
        });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_10() {
    const app = express();
    app.use(express.urlencoded({ extended: true }));
    
    app.post('/form-xml', (req: Request, res: Response) => {
        const xmlData = req.body.xmlData;
        
        // ruleid: xml2json-xxe-ts-rule
        const parser = new DOMParser();
        const xmlDoc = parser.parseFromString(xmlData, 'text/xml');
        
        const result = {
            rootNode: xmlDoc.documentElement.nodeName,
            childCount: xmlDoc.documentElement.childNodes.length
        };
        
        res.json(result);
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_11() {
    const app = express();
    
    app.get('/proxy-xml', (req: Request, res: Response) => {
        const url = req.query.url as string;
        
        http.get(url, (response) => {
            let xmlData = '';
            
            response.on('data', (chunk) => {
                xmlData += chunk;
            });
            
            response.on('end', () => {
                // ruleid: xml2json-xxe-ts-rule
                const options = { ignoreAttributes: false };
                const parser = new XMLParser(options);
                const result = parser.parse(xmlData);
                
                res.json(result);
            });
        });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_12() {
    const app = express();
    app.use(express.json());
    
    app.post('/convert-base64-xml', (req: Request, res: Response) => {
        const base64XmlData = req.body.base64Data;
        const xmlData = Buffer.from(base64XmlData, 'base64').toString('utf8');
        
        // ruleid: xml2json-xxe-ts-rule
        const parser = new xml2js.Parser();
        parser.parseString(xmlData, (err, result) => {
            if (err) {
                return res.status(400).send('Invalid XML data');
            }
            res.json(result);
        });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_13() {
    const app = express();
    
    app.post('/batch-process', (req: Request, res: Response) => {
        const xmlFiles = req.body.files as string[];
        const results: any[] = [];
        
        xmlFiles.forEach(file => {
            const xmlContent = fs.readFileSync(file, 'utf8');
            
            // ruleid: xml2json-xxe-ts-rule
            const parser = new XMLParser();
            const result = parser.parse(xmlContent);
            results.push(result);
        });
        
        res.json(results);
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_14() {
    const app = express();
    app.use(express.text({ type: 'application/xml' }));
    
    app.post('/validate-xml', (req: Request, res: Response) => {
        const xmlData = req.body;
        
        try {
            // ruleid: xml2json-xxe-ts-rule
            const xmlDoc = libxmljs.parseXml(xmlData, { noent: true });
            res.json({ valid: true, elements: xmlDoc.root().childNodes().length });
        } catch (error) {
            res.status(400).json({ valid: false, error: error.message });
        }
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_15() {
    const app = express();
    
    app.post('/xml-config', (req: Request, res: Response) => {
        const configXml = req.body.config;
        
        if (!configXml) {
            return res.status(400).send('No configuration provided');
        }
        
        // ruleid: xml2json-xxe-ts-rule
        const options = {
            explicitArray: false,
            normalizeTags: true
        };
        
        xml2js.parseString(configXml, options, (err, result) => {
            if (err) {
                return res.status(400).send('Invalid configuration format');
            }
            
            // Process configuration
            res.json({ status: 'Configuration applied', config: result });
        });
    });
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_1() {
    const app = express();
    app.use(express.text({ type: 'application/xml' }));
    
    app.post('/parse-xml', (req: Request, res: Response) => {
        const xmlData = req.body;
        
        // ok: xml2json-xxe-ts-rule
        const parser = new xml2js.Parser({
            explicitCharkey: true,
            explicitArray: false,
            xmlnskey: '_xmlns',
            normalizeTags: true,
            explicitRoot: true,
            ignoreAttrs: true,
            async: true,
            attrNameProcessors: [],
            attrValueProcessors: [],
            tagNameProcessors: [],
            valueProcessors: [],
            charsAsChildren: false,
            includeWhiteChars: false,
            xmlns: false,
            mergeAttrs: false,
            validator: null,
            trim: true,
            normalize: true,
            strict: true,
            headless: false,
            explicitChildren: false,
            childkey: '_children',
            preserveChildrenOrder: false,
            emptyTag: '',
            cdata: false
        });
        
        parser.parseString(xmlData, (err, result) => {
            if (err) {
                return res.status(400).send('Invalid XML');
            }
            res.json(result);
        });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_2() {
    const app = express();
    app.use(express.text({ type: 'application/xml' }));
    
    app.post('/convert', (req: Request, res: Response) => {
        const xmlContent = req.body;
        
        // ok: xml2json-xxe-ts-rule
        const parserOptions = {
            explicitArray: false,
            normalizeTags: true,
            explicitRoot: true,
        };
        
        const parser = new xml2js.Parser(parserOptions);
        parser.parseString(xmlContent, (err, result) => {
            if (err) {
                return res.status(400).json({ error: 'Failed to parse XML' });
            }
            res.json(result);
        });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_3() {
    const app = express();
    app.use(express.text());
    
    app.post('/process-xml', (req: Request, res: Response) => {
        const userXml = req.body;
        
        try {
            // ok: xml2json-xxe-ts-rule
            const parser = new DOMParser({
                errorHandler: {
                    warning: () => {},
                    error: () => {},
                    fatalError: () => {}
                },
                locator: {},
                entityResolver: (publicId: string, systemId: string) => {
                    // Prevent XXE by not resolving external entities
                    return '';
                }
            });
            
            const doc = parser.parseFromString(userXml, 'text/xml');
            res.send('XML processed successfully');
        } catch (error) {
            res.status(400).send('Error processing XML');
        }
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_4() {
    const app = express();
    app.use(bodyParser.text({ type: 'application/xml' }));
    
    app.post('/xml-endpoint', (req: Request, res: Response) => {
        const xmlInput = req.body;
        
        // ok: xml2json-xxe-ts-rule
        const options = {
            ignoreAttributes: false,
            isArray: (name: string, jpath: string) => {
                return name === 'item';
            },
            attributeNamePrefix: '@_',
            textNodeName: '#text',
            ignoreNameSpace: false,
            allowBooleanAttributes: false,
            parseNodeValue: true,
            parseAttributeValue: false,
            trimValues: true,
            cdataTagName: '__cdata',
            cdataPositionChar: '\\c',
            parseTrueNumberOnly: false,
            arrayMode: false,
            stopNodes: ['parse-me-as-string'],
            // Disable entity expansion to prevent XXE
            processEntities: false,
            htmlEntities: false,
            alwaysCreateTextNode: false,
        };
        
        const parser = new fastXml.XMLParser(options);
        const jsonObj = parser.parse(xmlInput);
        
        res.json(jsonObj);
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_5() {
    const app = express();
    
    app.get('/fetch-and-parse', (req: Request, res: Response) => {
        const xmlUrl = req.query.url as string;
        
        https.get(xmlUrl, (response) => {
            let data = '';
            response.on('data', (chunk) => {
                data += chunk;
            });
            
            response.on('end', () => {
                // ok: xml2json-xxe-ts-rule
                const options = {
                    ignoreAttributes: false,
                    // Disable entity expansion to prevent XXE
                    processEntities: false,
                    htmlEntities: false
                };
                
                const parser = new XMLParser(options);
                const result = parser.parse(data);
                res.json(result);
            });
        });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_6() {
    const app = express();
    app.use(express.text({ type: 'application/xml' }));
    
    app.post('/upload-xml', (req: Request, res: Response) => {
        const xmlContent = req.body;
        
        try {
            // ok: xml2json-xxe-ts-rule
            const xmlDoc = libxmljs.parseXml(xmlContent, { noent: false, noblanks: true });
            const result = { success: true, nodes: xmlDoc.childNodes().length };
            res.json(result);
        } catch (error) {
            res.status(400).json({ error: 'Failed to parse XML' });
        }
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_7() {
    const app = express();
    
    app.post('/process-xml-file', (req: Request, res: Response) => {
        const filePath = req.body.filePath;
        
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                return res.status(400).send('Error reading file');
            }
            
            // ok: xml2json-xxe-ts-rule
            const parserOptions = {
                explicitArray: false,
                normalizeTags: true,
                explicitRoot: true,
                // Disable entity expansion to prevent XXE
                entityResolver: () => ''
            };
            
            xml2js.parseString(data, parserOptions, (parseErr, result) => {
                if (parseErr) {
                    return res.status(400).send('Error parsing XML');
                }
                res.json(result);
            });
        });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_8() {
    const app = express();
    app.use(express.text({ type: 'application/xml' }));
    
    app.post('/xml-to-json', (req: Request, res: Response) => {
        const xmlData = req.body;
        
        // ok: xml2json-xxe-ts-rule
        const options = {
            trim: true,
            explicitArray: false,
            // Disable entity expansion to prevent XXE
            entityResolver: function(publicId: string, systemId: string) {
                return '';
            }
        };
        
        xml2js.parseString(xmlData, options, (err, result) => {
            if (err) {
                return res.status(400).send('Invalid XML');
            }
            res.json(result);
        });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_9() {
    const app = express();
    
    app.post('/parse-xml-header', (req: Request, res: Response) => {
        const xmlContent = req.headers['x-xml-data'] as string;
        
        if (!xmlContent) {
            return res.status(400).send('No XML data provided');
        }
        
        // ok: xml2json-xxe-ts-rule
        const parser = new xml2js.Parser({
            explicitArray: false,
            // Disable entity expansion to prevent XXE
            resolveEntities: false
        });
        
        parser.parseString(xmlContent, (err, result) => {
            if (err) {
                return res.status(400).send('Invalid XML');
            }
            res.json(result);
        });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_10() {
    const app = express();
    app.use(express.urlencoded({ extended: true }));
    
    app.post('/form-xml', (req: Request, res: Response) => {
        const xmlData = req.body.xmlData;
        
        // ok: xml2json-xxe-ts-rule
        const parser = new DOMParser({
            locator: {},
            errorHandler: {
                warning: () => {},
                error: () => {},
                fatalError: () => {}
            },
            // Prevent XXE by not resolving external entities
            entityResolver: () => {
                return '';
            }
        });
        
        const xmlDoc = parser.parseFromString(xmlData, 'text/xml');
        
        const result = {
            rootNode: xmlDoc.documentElement.nodeName,
            childCount: xmlDoc.documentElement.childNodes.length
        };
        
        res.json(result);
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_11() {
    const app = express();
    
    app.get('/proxy-xml', (req: Request, res: Response) => {
        const url = req.query.url as string;
        
        http.get(url, (response) => {
            let xmlData = '';
            
            response.on('data', (chunk) => {
                xmlData += chunk;
            });
            
            response.on('end', () => {
                // ok: xml2json-xxe-ts-rule
                const options = {
                    ignoreAttributes: false,
                    isArray: (name: string) => ['item', 'entry'].includes(name),
                    attributeNamePrefix: '@_',
                    // Disable entity expansion to prevent XXE
                    processEntities: false,
                    htmlEntities: false
                };
                
                const parser = new XMLParser(options);
                const result = parser.parse(xmlData);
                
                res.json(result);
            });
        });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_12() {
    const app = express();
    app.use(express.json());
    
    app.post('/convert-base64-xml', (req: Request, res: Response) => {
        const base64XmlData = req.body.base64Data;
        const xmlData = Buffer.from(base64XmlData, 'base64').toString('utf8');
        
        // ok: xml2json-xxe-ts-rule
        const parser = new xml2js.Parser({
            explicitArray: false,
            normalizeTags: true,
            // Disable entity expansion to prevent XXE
            resolveEntities: false
        });
        
        parser.parseString(xmlData, (err, result) => {
            if (err) {
                return res.status(400).send('Invalid XML data');
            }
            res.json(result);
        });
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_13() {
    const app = express();
    
    app.post('/batch-process', (req: Request, res: Response) => {
        const xmlFiles = req.body.files as string[];
        const results: any[] = [];
        
        xmlFiles.forEach(file => {
            const xmlContent = fs.readFileSync(file, 'utf8');
            
            // ok: xml2json-xxe-ts-rule
            const options = {
                ignoreAttributes: false,
                attributeNamePrefix: '@_',
                // Disable entity expansion to prevent XXE
                processEntities: false,
                htmlEntities: false
            };
            
            const parser = new XMLParser(options);
            const result = parser.parse(xmlContent);
            results.push(result);
        });
        
        res.json(results);
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_14() {
    const app = express();
    app.use(express.text({ type: 'application/xml' }));
    
    app.post('/validate-xml', (req: Request, res: Response) => {
        const xmlData = req.body;
        
        try {
            // ok: xml2json-xxe-ts-rule
            // Set noent to false to disable entity expansion
            const xmlDoc = libxmljs.parseXml(xmlData, { noent: false });
            res.json({ valid: true, elements: xmlDoc.root().childNodes().length });
        } catch (error) {
            res.status(400).json({ valid: false, error: error.message });
        }
    });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_15() {
    const app = express();
    
    app.post('/xml-config', (req: Request, res: Response) => {
        const configXml = req.body.config;
        
        if (!configXml) {
            return res.status(400).send('No configuration provided');
        }
        
        // ok: xml2json-xxe-ts-rule
        const options = {
            explicitArray: false,
            normalizeTags: true,
            // Disable entity expansion to prevent XXE
            resolveEntities: false,
            entityResolver: () => {
                return '';
            }
        };
        
        xml2js.parseString(configXml, options, (err, result) => {
            if (err) {
                return res.status(400).send('Invalid configuration format');
            }
            
            // Process configuration
            res.json({ status: 'Configuration applied', config: result });
        });
    });
}
// {/fact}