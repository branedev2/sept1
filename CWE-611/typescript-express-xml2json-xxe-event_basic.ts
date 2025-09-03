import express from 'express';
import { Request, Response } from 'express';
import * as xml2js from 'xml2js';
import * as fastXml from 'fast-xml-parser';
import * as libxmljs from 'libxmljs';
import { DOMParser } from 'xmldom';
import { parseString } from 'xml2js';
import { XMLParser } from 'fast-xml-parser';
import * as fs from 'fs';
import * as path from 'path';

// TRUE POSITIVES - Vulnerable code examples

// Bad case 1: Using xml2js.parseString with user input directly
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  app.post('/parse-xml', (req: Request, res: Response) => {
    const xmlData = req.body.xml;
    
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

// Bad case 2: Using fast-xml-parser with user input directly
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  app.post('/parse-xml', (req: Request, res: Response) => {
    const xmlData = req.body.xmlContent;
    const parser = new fastXml.XMLParser();
    
    try {
      // ruleid: express-xml2json-xxe-event-ts-rule
      const result = parser.parse(xmlData);
      res.json(result);
    } catch (error) {
      res.status(400).json({ error: 'Failed to parse XML' });
    }
  });
}
// {/fact}

// Bad case 3: Using libxmljs with user input directly
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  app.post('/parse-xml', (req: Request, res: Response) => {
    const xmlData = req.body.data;
    
    try {
      // ruleid: express-xml2json-xxe-event-ts-rule
      const xmlDoc = libxmljs.parseXml(xmlData);
      const result = { root: xmlDoc.root().name() };
      res.json(result);
    } catch (error) {
      res.status(400).json({ error: 'Failed to parse XML' });
    }
  });
}
// {/fact}

// Bad case 4: Using xmldom with user input directly
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  app.post('/parse-xml', (req: Request, res: Response) => {
    const xmlData = req.body.xml;
    const parser = new DOMParser();
    
    try {
      // ruleid: express-xml2json-xxe-event-ts-rule
      const doc = parser.parseFromString(xmlData, 'text/xml');
      const elements = doc.getElementsByTagName('*');
      const result = { count: elements.length };
      res.json(result);
    } catch (error) {
      res.status(400).json({ error: 'Failed to parse XML' });
    }
  });
}
// {/fact}

// Bad case 5: Using xml2js with user input from URL parameter
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  app.get('/parse-xml/:encodedXml', (req: Request, res: Response) => {
    const xmlData = Buffer.from(req.params.encodedXml, 'base64').toString();
    
    // ruleid: express-xml2json-xxe-event-ts-rule
    parseString(xmlData, (err, result) => {
      if (err) {
        return res.status(400).json({ error: 'Invalid XML' });
      }
      res.json(result);
    });
  });
}
// {/fact}

// Bad case 6: Using fast-xml-parser with user input from query parameter
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  
  app.get('/parse-xml', (req: Request, res: Response) => {
    const xmlData = req.query.xml as string;
    const parser = new XMLParser();
    
    try {
      // ruleid: express-xml2json-xxe-event-ts-rule
      const result = parser.parse(xmlData);
      res.json(result);
    } catch (error) {
      res.status(400).json({ error: 'Failed to parse XML' });
    }
  });
}
// {/fact}

// Bad case 7: Using xml2js with user input from headers
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  app.post('/parse-xml-header', (req: Request, res: Response) => {
    const xmlData = req.headers['x-xml-data'] as string;
    
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

// Bad case 8: Using xml2js with user input from cookies
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  app.get('/parse-xml-cookie', (req: Request, res: Response) => {
    const xmlData = req.cookies.xmlData;
    
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

// Bad case 9: Using xml2js with minimal processing of user input
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  app.post('/parse-xml', (req: Request, res: Response) => {
    let xmlData = req.body.xml;
    xmlData = xmlData.trim(); // Minimal processing
    
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

// Bad case 10: Using fast-xml-parser with user input in a complex route handler
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  app.post('/process-data', (req: Request, res: Response) => {
    const { type, content } = req.body;
    
    if (type === 'xml') {
      const parser = new XMLParser();
      try {
        // ruleid: express-xml2json-xxe-event-ts-rule
        const result = parser.parse(content);
        return res.json({ processed: true, data: result });
      } catch (error) {
        return res.status(400).json({ error: 'Failed to parse XML' });
      }
    }
    
    res.status(400).json({ error: 'Unsupported type' });
  });
}
// {/fact}

// Bad case 11: Using xml2js with user input in an async route handler
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  app.post('/async-parse', async (req: Request, res: Response) => {
    const xmlData = req.body.xml;
    
    try {
      // ruleid: express-xml2json-xxe-event-ts-rule
      const result = await new Promise((resolve, reject) => {
        xml2js.parseString(xmlData, (err, result) => {
          if (err) reject(err);
          else resolve(result);
        });
      });
      
      res.json(result);
    } catch (error) {
      res.status(400).json({ error: 'Failed to parse XML' });
    }
  });
}
// {/fact}

// Bad case 12: Using libxmljs with user input from a file upload
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  app.post('/upload-xml', (req: Request, res: Response) => {
    const xmlContent = req.body.fileContent;
    
    try {
      // ruleid: express-xml2json-xxe-event-ts-rule
      const xmlDoc = libxmljs.parseXml(xmlContent);
      const result = { rootName: xmlDoc.root().name() };
      res.json(result);
    } catch (error) {
      res.status(400).json({ error: 'Failed to parse XML' });
    }
  });
}
// {/fact}

// Bad case 13: Using xml2js with user input in a middleware
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  const xmlMiddleware = (req: Request, res: Response, next: Function) => {
    if (req.body.xml) {
      // ruleid: express-xml2json-xxe-event-ts-rule
      xml2js.parseString(req.body.xml, (err, result) => {
        if (err) {
          return res.status(400).json({ error: 'Invalid XML' });
        }
        req.body.parsedXml = result;
        next();
      });
    } else {
      next();
    }
  };
  
  app.post('/process', xmlMiddleware, (req: Request, res: Response) => {
    res.json(req.body.parsedXml);
  });
}
// {/fact}

// Bad case 14: Using DOMParser with user input in a complex flow
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  app.post('/complex-parse', (req: Request, res: Response) => {
    const { format, data } = req.body;
    
    if (format === 'xml') {
      const parser = new DOMParser();
      try {
        // ruleid: express-xml2json-xxe-event-ts-rule
        const doc = parser.parseFromString(data, 'text/xml');
        const elements = doc.getElementsByTagName('item');
        const items = [];
        
        for (let i = 0; i < elements.length; i++) {
          items.push(elements[i].textContent);
        }
        
        return res.json({ items });
      } catch (error) {
        return res.status(400).json({ error: 'Failed to parse XML' });
      }
    }
    
    res.status(400).json({ error: 'Unsupported format' });
  });
}
// {/fact}

// Bad case 15: Using fast-xml-parser with user input in error handling
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  app.post('/parse-with-error-handling', (req: Request, res: Response) => {
    const xmlData = req.body.xml;
    const parser = new XMLParser();
    
    try {
      // ruleid: express-xml2json-xxe-event-ts-rule
      const result = parser.parse(xmlData);
      res.json(result);
    } catch (error) {
      console.error('XML parsing error:', error);
      // Try to extract partial data if possible
      try {
        const cleanedXml = xmlData.replace(/[^\x20-\x7E]/g, '');
        const partialResult = parser.parse(cleanedXml);
        res.status(206).json({ partial: true, data: partialResult });
      } catch (innerError) {
        res.status(400).json({ error: 'Failed to parse XML' });
      }
    }
  });
}
// {/fact}

// TRUE NEGATIVES - Secure code examples

// Good case 1: Using xml2js with secure options
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  app.post('/parse-xml', (req: Request, res: Response) => {
    const xmlData = req.body.xml;
    
    const parserOptions = {
      // ok: express-xml2json-xxe-event-ts-rule
      explicitCharkey: true,
      explicitArray: false,
      xmlnskey: '_xmlns',
      normalizeTags: true,
      explicitRoot: false,
      charsAsChildren: false,
      includeWhiteChars: false,
      async: true,
      strict: true,
      attrkey: '_attr',
      charkey: '_content',
      trim: true,
      normalize: true,
      normalizeTags: true,
      explicitChildren: false,
      preserveChildrenOrder: false,
      mergeAttrs: false,
      validator: null,
      xmlns: false,
      emptyTag: '',
      childkey: '_children',
      valuekey: '_value',
      attrNameProcessors: null,
      attrValueProcessors: null,
      tagNameProcessors: null,
      valueProcessors: null,
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
      cdata: false
    };
    
    xml2js.parseString(xmlData, parserOptions, (err, result) => {
      if (err) {
        return res.status(400).json({ error: 'Invalid XML' });
      }
      res.json(result);
    });
  });
}
// {/fact}

// Good case 2: Using fast-xml-parser with secure options
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  app.post('/parse-xml', (req: Request, res: Response) => {
    const xmlData = req.body.xmlContent;
    
    // ok: express-xml2json-xxe-event-ts-rule
    const options = {
      ignoreAttributes: false,
      attributeNamePrefix: "@_",
      allowBooleanAttributes: false,
      parseAttributeValue: false,
      parseNodeValue: true,
      trimValues: true,
      cdataTagName: "__cdata",
      cdataPositionChar: "\\c",
      parseTrueNumberOnly: false,
      arrayMode: false,
      stopNodes: ["parse-me-as-string"],
      isArray: (name, jpath, isLeafNode, isAttribute) => { return false; },
      processEntities: false,
      htmlEntities: false,
      ignoreDeclaration: false,
      ignorePiTags: false,
      alwaysCreateTextNode: false,
      preserveOrder: false,
      unpairedTags: [],
      default: {
        attributeNamePrefix: "@_",
        attributesGroupName: false,
        textNodeName: "#text",
        ignoreAttributes: true,
        cdataTagName: false,
        cdataPositionChar: "\\c",
        format: false,
        indentBy: "  ",
        supressEmptyNode: false,
        tagValueProcessor: a => a,
        attrValueProcessor: a => a,
        stopNodes: [],
        alwaysCreateTextNode: false
      }
    };
    
    const parser = new fastXml.XMLParser(options);
    
    try {
      const result = parser.parse(xmlData);
      res.json(result);
    } catch (error) {
      res.status(400).json({ error: 'Failed to parse XML' });
    }
  });
}
// {/fact}

// Good case 3: Using libxmljs with secure options
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  app.post('/parse-xml', (req: Request, res: Response) => {
    const xmlData = req.body.data;
    
    try {
      // ok: express-xml2json-xxe-event-ts-rule
      const xmlDoc = libxmljs.parseXml(xmlData, {
        noent: false,
        noblanks: true,
        nonet: true,
        xinclude: false,
        dtdload: false,
        dtdvalid: false,
        dtdattr: false,
        dtdload: false,
        noerror: true,
        nowarning: true,
        pedantic: false,
        recover: true,
        nodict: true,
        nsclean: true,
        nocdata: false
      });
      
      const result = { root: xmlDoc.root().name() };
      res.json(result);
    } catch (error) {
      res.status(400).json({ error: 'Failed to parse XML' });
    }
  });
}
// {/fact}

// Good case 4: Using pre-validated XML data
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  app.post('/parse-xml', (req: Request, res: Response) => {
    const xmlData = req.body.xml;
    
    // ok: express-xml2json-xxe-event-ts-rule
    // Validate the XML structure before parsing
    const validateXml = (xml: string): boolean => {
      // Simple validation to check for DOCTYPE declarations
      if (xml.includes('<!DOCTYPE') || xml.includes('<!ENTITY')) {
        return false;
      }
      
      // Check for other potentially dangerous patterns
      if (xml.includes('file://') || xml.includes('http://') || xml.includes('https://')) {
        return false;
      }
      
      return true;
    };
    
    if (!validateXml(xmlData)) {
      return res.status(400).json({ error: 'Invalid or potentially dangerous XML' });
    }
    
    xml2js.parseString(xmlData, (err, result) => {
      if (err) {
        return res.status(400).json({ error: 'Invalid XML' });
      }
      res.json(result);
    });
  });
}
// {/fact}

// Good case 5: Using a sanitized XML string
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  app.post('/parse-xml', (req: Request, res: Response) => {
    const xmlData = req.body.xml;
    
    // ok: express-xml2json-xxe-event-ts-rule
    // Sanitize XML by removing DOCTYPE and ENTITY declarations
    const sanitizeXml = (xml: string): string => {
      // Remove DOCTYPE declarations
      let sanitized = xml.replace(/<!DOCTYPE[^>]*>/g, '');
      // Remove ENTITY declarations
      sanitized = sanitized.replace(/<!ENTITY[^>]*>/g, '');
      return sanitized;
    };
    
    const sanitizedXml = sanitizeXml(xmlData);
    
    xml2js.parseString(sanitizedXml, (err, result) => {
      if (err) {
        return res.status(400).json({ error: 'Invalid XML' });
      }
      res.json(result);
    });
  });
}
// {/fact}

// Good case 6: Using static XML data
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_6() {
  const app = express();
  
  app.get('/static-xml', (req: Request, res: Response) => {
    // ok: express-xml2json-xxe-event-ts-rule
    const staticXml = `
      <root>
        <item>Static Item 1</item>
        <item>Static Item 2</item>
        <item>Static Item 3</item>
      </root>
    `;
    
    xml2js.parseString(staticXml, (err, result) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to parse static XML' });
      }
      res.json(result);
    });
  });
}
// {/fact}

// Good case 7: Using XML from a trusted file
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  app.get('/trusted-xml', (req: Request, res: Response) => {
    // ok: express-xml2json-xxe-event-ts-rule
    const trustedXmlPath = path.join(__dirname, 'trusted-data.xml');
    
    fs.readFile(trustedXmlPath, 'utf8', (err, xmlData) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to read XML file' });
      }
      
      xml2js.parseString(xmlData, (err, result) => {
        if (err) {
          return res.status(500).json({ error: 'Failed to parse XML' });
        }
        res.json(result);
      });
    });
  });
}
// {/fact}

// Good case 8: Using XML parser in a non-request context
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  // ok: express-xml2json-xxe-event-ts-rule
  const processStaticXml = () => {
    const staticXml = `
      <config>
        <setting name="timeout" value="30" />
        <setting name="retries" value="3" />
      </config>
    `;
    
    let config: any = {};
    
    xml2js.parseString(staticXml, (err, result) => {
      if (!err && result && result.config && result.config.setting) {
        result.config.setting.forEach((setting: any) => {
          if (setting.$.name && setting.$.value) {
            config[setting.$.name] = setting.$.value;
          }
        });
      }
    });
    
    return config;
  };
  
  app.get('/config', (req: Request, res: Response) => {
    const config = processStaticXml();
    res.json(config);
  });
}
// {/fact}

// Good case 9: Using XML parser with hardcoded templates and user data
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  app.post('/generate-xml', (req: Request, res: Response) => {
    const { name, email } = req.body;
    
    // ok: express-xml2json-xxe-event-ts-rule
    // Create XML using template with user data
    const xmlTemplate = `
      <user>
        <name>${name}</name>
        <email>${email}</email>
        <created>${new Date().toISOString()}</created>
      </user>
    `;
    
    // Parse the generated XML (not user-provided XML)
    xml2js.parseString(xmlTemplate, (err, result) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to process XML' });
      }
      res.json(result);
    });
  });
}
// {/fact}

// Good case 10: Using XML parser with server-generated XML
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  app.get('/generate-report/:type', (req: Request, res: Response) => {
    const reportType = req.params.type;
    
    // ok: express-xml2json-xxe-event-ts-rule
    // Generate XML based on report type
    let reportXml = '<report>';
    
    if (reportType === 'sales') {
      reportXml += '<type>Sales Report</type>';
      reportXml += '<data><item>Product A: 100</item><item>Product B: 150</item></data>';
    } else if (reportType === 'inventory') {
      reportXml += '<type>Inventory Report</type>';
      reportXml += '<data><item>Product A: 50 in stock</item><item>Product B: 75 in stock</item></data>';
    } else {
      reportXml += '<type>Unknown Report</type>';
      reportXml += '<data><item>No data available</item></data>';
    }
    
    reportXml += '</report>';
    
    xml2js.parseString(reportXml, (err, result) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to process report' });
      }
      res.json(result);
    });
  });
}
// {/fact}

// Good case 11: Using XML parser with validated schema
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  app.post('/validate-xml', (req: Request, res: Response) => {
    const xmlData = req.body.xml;
    
    // ok: express-xml2json-xxe-event-ts-rule
    // Define allowed XML schema
    const validateAgainstSchema = (xml: string): boolean => {
      // Simple schema validation
      if (!xml.includes('<root>')) return false;
      if (xml.includes('<!DOCTYPE')) return false;
      if (xml.includes('<!ENTITY')) return false;
      
      // Check for required elements
      if (!xml.includes('<name>')) return false;
      if (!xml.includes('<value>')) return false;
      
      return true;
    };
    
    if (!validateAgainstSchema(xmlData)) {
      return res.status(400).json({ error: 'XML does not match required schema' });
    }
    
    xml2js.parseString(xmlData, { explicitArray: false }, (err, result) => {
      if (err) {
        return res.status(400).json({ error: 'Invalid XML' });
      }
      res.json(result);
    });
  });
}
// {/fact}

// Good case 12: Using XML parser with content verification
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  app.post('/process-order', (req: Request, res: Response) => {
    const xmlData = req.body.orderXml;
    
    // ok: express-xml2json-xxe-event-ts-rule
    // Verify XML content before parsing
    const verifyOrderXml = (xml: string): boolean => {
      // Check for required order structure
      if (!xml.includes('<order>')) return false;
      if (!xml.includes('<items>')) return false;
      
      // Disallow external entities
      if (xml.includes('<!DOCTYPE')) return false;
      if (xml.includes('<!ENTITY')) return false;
      if (xml.includes('SYSTEM')) return false;
      if (xml.includes('PUBLIC')) return false;
      
      return true;
    };
    
    if (!verifyOrderXml(xmlData)) {
      return res.status(400).json({ error: 'Invalid order XML format' });
    }
    
    xml2js.parseString(xmlData, (err, result) => {
      if (err) {
        return res.status(400).json({ error: 'Failed to parse order' });
      }
      res.json({ orderProcessed: true, orderId: Date.now() });
    });
  });
}
// {/fact}

// Good case 13: Using XML parser with regex filtering
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  app.post('/filter-xml', (req: Request, res: Response) => {
    let xmlData = req.body.xml;
    
    // ok: express-xml2json-xxe-event-ts-rule
    // Apply comprehensive filtering
    const filterXml = (xml: string): string => {
      // Remove DOCTYPE declarations
      let filtered = xml.replace(/<!DOCTYPE[^>]*>/g, '');
      // Remove ENTITY declarations
      filtered = filtered.replace(/<!ENTITY[^>]*>/g, '');
      // Remove processing instructions
      filtered = filtered.replace(/<\?[^>]*\?>/g, '');
      // Remove comments
      filtered = filtered.replace(/<!--[\s\S]*?-->/g, '');
      // Remove CDATA sections
      filtered = filtered.replace(/<!\[CDATA\[[\s\S]*?\]\]>/g, '');
      // Remove any external references
      filtered = filtered.replace(/SYSTEM\s+["'][^"']*["']/g, '');
      filtered = filtered.replace(/PUBLIC\s+["'][^"']*["']\s+["'][^"']*["']/g, '');
      
      return filtered;
    };
    
    xmlData = filterXml(xmlData);
    
    xml2js.parseString(xmlData, (err, result) => {
      if (err) {
        return res.status(400).json({ error: 'Invalid XML after filtering' });
      }
      res.json(result);
    });
  });
}
// {/fact}

// Good case 14: Using XML parser with whitelist approach
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  app.post('/whitelist-xml', (req: Request, res: Response) => {
    const xmlData = req.body.xml;
    
    // ok: express-xml2json-xxe-event-ts-rule
    // Whitelist approach - only allow specific XML structure
    const extractSafeXml = (xml: string): string => {
      const allowedTags = ['user', 'name', 'email', 'role', 'department'];
      
      // Simple extraction of allowed elements (in real scenarios, use a proper XML parser for this)
      let safeXml = '<root>';
      
      for (const tag of allowedTags) {
        const regex = new RegExp(`<${tag}[^>]*>(.*?)<\/${tag}>`, 'g');
        const matches = xml.match(regex);
        
        if (matches) {
          for (const match of matches) {
            safeXml += match;
          }
        }
      }
      
      safeXml += '</root>';
      return safeXml;
    };
    
    const safeXml = extractSafeXml(xmlData);
    
    xml2js.parseString(safeXml, (err, result) => {
      if (err) {
        return res.status(400).json({ error: 'Failed to parse XML' });
      }
      res.json(result);
    });
  });
}
// {/fact}

// Good case 15: Using XML parser with custom entity resolver
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  app.post('/custom-entity-resolver', (req: Request, res: Response) => {
    const xmlData = req.body.xml;
    
    // ok: express-xml2json-xxe-event-ts-rule
    // Custom entity resolver that blocks external entities
    const customEntityResolver = {
      resolveEntity: function(publicId: string, systemId: string) {
        // Block all external entity references
        return '';
      }
    };
    
    // Using a hypothetical secure XML parser with entity resolver
    // In a real scenario, you would use a library that supports this feature
    const secureParser = {
      parse: function(xml: string) {
        // This is a simplified example - in reality, you would use a proper XML parser
        // that supports custom entity resolvers
        
        // Check for potentially dangerous content
        if (xml.includes('<!DOCTYPE') || xml.includes('<!ENTITY')) {
          throw new Error('Potentially dangerous XML detected');
        }
        
        // Parse XML safely
        return xml2js.parseStringPromise(xml, { 
          explicitArray: false,
          ignoreAttrs: false
        });
      }
    };
    
    secureParser.parse(xmlData)
      .then(result => {
        res.json(result);
      })
      .catch(error => {
        res.status(400).json({ error: 'Failed to parse XML securely' });
      });
  });
}
// {/fact}