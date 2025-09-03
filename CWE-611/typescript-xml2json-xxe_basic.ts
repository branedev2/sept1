import express from 'express';
import { Parser } from 'xml2json';
import * as fs from 'fs';
import * as http from 'http';
import { DOMParser } from 'xmldom';
import { parseString } from 'xml2js';
import { XMLParser } from 'fast-xml-parser';
import libxmljs from 'libxmljs';

// TRUE POSITIVES (VULNERABLE CODE)

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  app.post('/convert', (req, res) => {
    const xmlData = req.body.xml;
    
    // ruleid: xml2json-xxe-ts-rule
    const parser = new Parser();
    const json = parser.parse(xmlData);
    
    res.json(json);
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  app.get('/process-xml', (req, res) => {
    const xmlContent = req.query.xml as string;
    
    // ruleid: xml2json-xxe-ts-rule
    const parser = new Parser();
    const result = parser.parse(xmlContent);
    
    res.send(result);
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  app.post('/api/parse', (req, res) => {
    const userXml = req.body.content;
    
    try {
      // ruleid: xml2json-xxe-ts-rule
      parseString(userXml, (err, result) => {
        if (err) {
          res.status(400).send('Invalid XML');
        } else {
          res.json(result);
        }
      });
    } catch (error) {
      res.status(500).send('Server error');
    }
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  app.post('/xml-to-json', (req, res) => {
    const xmlInput = req.headers['x-xml-content'] as string;
    
    // ruleid: xml2json-xxe-ts-rule
    const parser = new DOMParser();
    const doc = parser.parseFromString(xmlInput, 'text/xml');
    
    // Convert DOM to JSON (simplified)
    const result = { root: doc.documentElement.nodeName };
    res.json(result);
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  app.post('/convert-xml', (req, res) => {
    const xmlData = req.body.data;
    
    // ruleid: xml2json-xxe-ts-rule
    const parser = new XMLParser();
    const jsonObj = parser.parse(xmlData);
    
    res.json(jsonObj);
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  
  app.post('/process', (req, res) => {
    let xmlData = '';
    
    req.on('data', (chunk) => {
      xmlData += chunk.toString();
    });
    
    req.on('end', () => {
      // ruleid: xml2json-xxe-ts-rule
      const parser = new Parser();
      const json = parser.parse(xmlData);
      
      res.json(json);
    });
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  app.post('/upload-xml', (req, res) => {
    const xmlContent = req.body.xmlString;
    let result;
    
    try {
      // ruleid: xml2json-xxe-ts-rule
      const xmlDoc = libxmljs.parseXml(xmlContent);
      result = { rootName: xmlDoc.root().name() };
    } catch (error) {
      result = { error: 'Failed to parse XML' };
    }
    
    res.json(result);
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  app.post('/transform', (req, res) => {
    const userXml = req.body.xml;
    
    // ruleid: xml2json-xxe-ts-rule
    const parser = new Parser({ reversible: true });
    const jsonOutput = parser.parse(userXml);
    
    res.send(jsonOutput);
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  app.get('/fetch-and-parse', async (req, res) => {
    const url = req.query.url as string;
    
    try {
      const response = await fetch(url);
      const xmlData = await response.text();
      
      // ruleid: xml2json-xxe-ts-rule
      const parser = new Parser();
      const jsonData = parser.parse(xmlData);
      
      res.json(jsonData);
    } catch (error) {
      res.status(500).send('Error processing XML');
    }
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  app.post('/validate-xml', (req, res) => {
    const xmlInput = req.body.xml;
    
    try {
      // ruleid: xml2json-xxe-ts-rule
      const doc = new DOMParser().parseFromString(xmlInput, 'application/xml');
      const isValid = doc.documentElement.nodeName !== 'parsererror';
      
      res.json({ valid: isValid });
    } catch (error) {
      res.status(400).json({ valid: false, error: error.message });
    }
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  app.post('/process-form', (req, res) => {
    const formData = req.body.formXml;
    
    // ruleid: xml2json-xxe-ts-rule
    parseString(formData, { explicitArray: false }, (err, result) => {
      if (err) {
        return res.status(400).send('Invalid XML format');
      }
      
      res.json(result);
    });
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  app.post('/api/import', (req, res) => {
    const importData = req.body.importXml;
    
    // ruleid: xml2json-xxe-ts-rule
    const parser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: "@_"
    });
    const result = parser.parse(importData);
    
    res.json({ success: true, data: result });
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  app.post('/parse-config', (req, res) => {
    const configXml = req.body.config;
    let config;
    
    try {
      // ruleid: xml2json-xxe-ts-rule
      const xmlDoc = libxmljs.parseXml(configXml, { noent: true });
      config = { name: xmlDoc.get('//name')?.text() };
    } catch (error) {
      return res.status(400).send('Invalid configuration');
    }
    
    res.json(config);
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  app.post('/convert-data', (req, res) => {
    const xmlContent = req.body.content;
    
    // ruleid: xml2json-xxe-ts-rule
    const parser = new Parser({ trim: true, coerce: true });
    const jsonData = parser.parse(xmlContent);
    
    res.json(jsonData);
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  app.post('/api/xml-rpc', (req, res) => {
    let data = '';
    
    req.on('data', chunk => {
      data += chunk;
    });
    
    req.on('end', () => {
      try {
        // ruleid: xml2json-xxe-ts-rule
        const parser = new DOMParser();
        const xmlDoc = parser.parseFromString(data, 'text/xml');
        const methodName = xmlDoc.getElementsByTagName('methodName')[0].textContent;
        
        res.json({ method: methodName });
      } catch (error) {
        res.status(400).send('Invalid XML-RPC request');
      }
    });
  });
}
// {/fact}

// TRUE NEGATIVES (SECURE CODE)

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  app.post('/convert', (req, res) => {
    const xmlData = req.body.xml;
    
    // ok: xml2json-xxe-ts-rule
    const parser = new Parser({ strict: true });
    const options = { 
      entityExpansion: false,
      resolveEntities: false
    };
    const json = parser.parse(xmlData, options);
    
    res.json(json);
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  app.get('/process-xml', (req, res) => {
    const xmlContent = req.query.xml as string;
    
    // ok: xml2json-xxe-ts-rule
    const parser = new XMLParser({
      isEnabledXmlEntities: false,
      allowBooleanAttributes: true
    });
    const result = parser.parse(xmlContent);
    
    res.send(result);
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  app.post('/api/parse', (req, res) => {
    const userXml = req.body.content;
    
    try {
      // ok: xml2json-xxe-ts-rule
      parseString(userXml, { 
        explicitArray: false, 
        explicitRoot: false,
        xmlns: true,
        explicitCharkey: true,
        normalizeTags: false,
        attrkey: 'attributes',
        charkey: 'content',
        explicitChildren: false,
        charsAsChildren: false,
        includeWhiteChars: false,
        async: true,
        strict: true,
        trim: true,
        normalize: true,
        normalizeTags: false,
        attrNameProcessors: [],
        attrValueProcessors: [],
        tagNameProcessors: [],
        valueProcessors: [],
        xmlnskey: 'xmlns'
      }, (err, result) => {
        if (err) {
          res.status(400).send('Invalid XML');
        } else {
          res.json(result);
        }
      });
    } catch (error) {
      res.status(500).send('Server error');
    }
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  app.post('/xml-to-json', (req, res) => {
    const xmlInput = req.headers['x-xml-content'] as string;
    
    // ok: xml2json-xxe-ts-rule
    const parser = new DOMParser({
      locator: {},
      errorHandler: {
        warning: function() {},
        error: function() {},
        fatalError: function() {}
      },
      // Disable entity expansion
      entityResolver: function() { return ''; }
    });
    const doc = parser.parseFromString(xmlInput, 'text/xml');
    
    // Convert DOM to JSON (simplified)
    const result = { root: doc.documentElement.nodeName };
    res.json(result);
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  app.post('/convert-xml', (req, res) => {
    const xmlData = req.body.data;
    
    // Sanitize XML by removing DOCTYPE declarations
    const sanitizedXml = xmlData.replace(/<!DOCTYPE[^>]*>/g, '');
    
    // ok: xml2json-xxe-ts-rule
    const parser = new XMLParser({
      ignoreDeclaration: true,
      isEnabledXmlEntities: false
    });
    const jsonObj = parser.parse(sanitizedXml);
    
    res.json(jsonObj);
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_6() {
  const app = express();
  
  app.post('/process', (req, res) => {
    let xmlData = '';
    
    req.on('data', (chunk) => {
      xmlData += chunk.toString();
    });
    
    req.on('end', () => {
      // Remove any DOCTYPE declarations
      const safeXml = xmlData.replace(/<!DOCTYPE[^>]*>/g, '');
      
      // ok: xml2json-xxe-ts-rule
      const parser = new Parser({
        explicitArray: false,
        normalizeTags: true,
        trim: true
      });
      const json = parser.parse(safeXml);
      
      res.json(json);
    });
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  app.post('/upload-xml', (req, res) => {
    const xmlContent = req.body.xmlString;
    let result;
    
    try {
      // ok: xml2json-xxe-ts-rule
      const xmlDoc = libxmljs.parseXml(xmlContent, {
        noent: false,  // Don't substitute entities
        dtdload: false, // Don't load external DTDs
        dtdvalid: false, // Don't validate with DTDs
        nonet: true,   // Prevent network access
        noblanks: true // Remove blank nodes
      });
      result = { rootName: xmlDoc.root().name() };
    } catch (error) {
      result = { error: 'Failed to parse XML' };
    }
    
    res.json(result);
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_8() {
  const app = express();
  
  app.post('/transform', (req, res) => {
    const userXml = req.body.xml;
    
    // Remove any DOCTYPE or ENTITY declarations
    const safeXml = userXml.replace(/<!DOCTYPE[^>]*>|<!ENTITY[^>]*>/gi, '');
    
    // ok: xml2json-xxe-ts-rule
    const parser = new Parser({ 
      reversible: true,
      coerce: true,
      trim: true,
      sanitize: true
    });
    const jsonOutput = parser.parse(safeXml);
    
    res.send(jsonOutput);
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  app.get('/fetch-and-parse', async (req, res) => {
    const url = req.query.url as string;
    
    try {
      const response = await fetch(url);
      const xmlData = await response.text();
      
      // Remove DOCTYPE declarations
      const sanitizedXml = xmlData.replace(/<!DOCTYPE[^>]*>/g, '');
      
      // ok: xml2json-xxe-ts-rule
      const parser = new XMLParser({
        isEnabledXmlEntities: false,
        allowBooleanAttributes: true,
        ignoreAttributes: false
      });
      const jsonData = parser.parse(sanitizedXml);
      
      res.json(jsonData);
    } catch (error) {
      res.status(500).send('Error processing XML');
    }
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  app.post('/validate-xml', (req, res) => {
    const xmlInput = req.body.xml;
    
    // Remove DOCTYPE declarations
    const sanitizedXml = xmlInput.replace(/<!DOCTYPE[^>]*>/g, '');
    
    try {
      // ok: xml2json-xxe-ts-rule
      const doc = new DOMParser({
        locator: {},
        errorHandler: { warning: () => {}, error: () => {}, fatalError: () => {} },
        entityResolver: () => '' // Prevent entity resolution
      }).parseFromString(sanitizedXml, 'application/xml');
      
      const isValid = doc.documentElement.nodeName !== 'parsererror';
      res.json({ valid: isValid });
    } catch (error) {
      res.status(400).json({ valid: false, error: error.message });
    }
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  app.post('/process-form', (req, res) => {
    const formData = req.body.formXml;
    
    // Remove any DOCTYPE or ENTITY declarations
    const safeXml = formData.replace(/<!DOCTYPE[^>]*>|<!ENTITY[^>]*>/gi, '');
    
    // ok: xml2json-xxe-ts-rule
    parseString(safeXml, { 
      explicitArray: false,
      normalizeTags: true,
      trim: true,
      explicitRoot: false,
      explicitCharkey: true,
      strict: true
    }, (err, result) => {
      if (err) {
        return res.status(400).send('Invalid XML format');
      }
      
      res.json(result);
    });
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  app.post('/api/import', (req, res) => {
    const importData = req.body.importXml;
    
    // Sanitize XML by removing DOCTYPE declarations
    const safeXml = importData.replace(/<!DOCTYPE[^>]*>/g, '');
    
    // ok: xml2json-xxe-ts-rule
    const parser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: "@_",
      isEnabledXmlEntities: false,
      allowBooleanAttributes: true
    });
    const result = parser.parse(safeXml);
    
    res.json({ success: true, data: result });
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  app.post('/parse-config', (req, res) => {
    const configXml = req.body.config;
    let config;
    
    try {
      // ok: xml2json-xxe-ts-rule
      const xmlDoc = libxmljs.parseXml(configXml, { 
        noent: false,  // Don't substitute entities
        dtdload: false, // Don't load external DTDs
        dtdvalid: false, // Don't validate with DTDs
        nonet: true,   // Prevent network access
        noblanks: true // Remove blank nodes
      });
      config = { name: xmlDoc.get('//name')?.text() };
    } catch (error) {
      return res.status(400).send('Invalid configuration');
    }
    
    res.json(config);
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  app.post('/convert-data', (req, res) => {
    const xmlContent = req.body.content;
    
    // Remove DOCTYPE declarations
    const safeXml = xmlContent.replace(/<!DOCTYPE[^>]*>/g, '');
    
    // ok: xml2json-xxe-ts-rule
    const parser = new Parser({ 
      trim: true, 
      coerce: true,
      sanitize: true,
      explicitArray: false
    });
    const jsonData = parser.parse(safeXml);
    
    res.json(jsonData);
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  app.post('/api/xml-rpc', (req, res) => {
    let data = '';
    
    req.on('data', chunk => {
      data += chunk;
    });
    
    req.on('end', () => {
      try {
        // Remove DOCTYPE declarations
        const safeXml = data.replace(/<!DOCTYPE[^>]*>/g, '');
        
        // ok: xml2json-xxe-ts-rule
        const parser = new DOMParser({
          locator: {},
          errorHandler: { warning: () => {}, error: () => {}, fatalError: () => {} },
          entityResolver: () => '' // Prevent entity resolution
        });
        const xmlDoc = parser.parseFromString(safeXml, 'text/xml');
        const methodName = xmlDoc.getElementsByTagName('methodName')[0].textContent;
        
        res.json({ method: methodName });
      } catch (error) {
        res.status(400).send('Invalid XML-RPC request');
      }
    });
  });
}
// {/fact}