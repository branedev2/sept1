// Test cases for javascript-xxe-injection vulnerability (CWE-611)
const express = require('express');
const app = express();
const libxmljs = require('libxmljs');
const DOMParser = require('xmldom').DOMParser;
const sax = require('sax');
const xml2js = require('xml2js');
const fs = require('fs');
const https = require('https');
const http = require('http');
const axios = require('axios');
const bodyParser = require('body-parser');
const { JSDOM } = require('jsdom');

app.use(bodyParser.text({ type: 'application/xml' }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// True Positive Examples (Vulnerable Code)

// Bad Case 1: Using libxmljs with user input without disabling external entities
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_1(req, res) {
    const xmlData = req.body;
    try {
        // ruleid: javascript-xxe-injection
        const xmlDoc = libxmljs.parseXml(xmlData, { noent: true });
        const result = xmlDoc.toString();
        res.send(`Parsed XML: ${result}`);
    } catch (error) {
        res.status(500).send('Error parsing XML');
    }
}
// {/fact}

// Bad Case 2: Using DOMParser from xmldom with user input
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_2(req, res) {
    const xmlData = req.query.xml;
    const parser = new DOMParser({
        locator: {},
        errorHandler: { warning: function (w) { }, error: function (e) { } }
    });
    
    try {
        // ruleid: javascript-xxe-injection
        const doc = parser.parseFromString(xmlData, "text/xml");
        const elements = doc.getElementsByTagName('item');
        let response = '';
        for (let i = 0; i < elements.length; i++) {
            response += elements[i].textContent + '<br>';
        }
        res.send(response);
    } catch (error) {
        res.status(500).send('Error parsing XML');
    }
}
// {/fact}

// Bad Case 3: Using xml2js with explicitEntities enabled
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_3(req, res) {
    const xmlData = req.headers['x-xml-data'];
    
    const parser = new xml2js.Parser({
        explicitEntities: true
    });
    
    // ruleid: javascript-xxe-injection
    parser.parseString(xmlData, (err, result) => {
        if (err) {
            res.status(500).send('Error parsing XML');
            return;
        }
        res.json(result);
    });
}
// {/fact}

// Bad Case 4: Using sax parser with opt.resolveEntities set to true
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_4(req, res) {
    const xmlData = req.body.xmlContent;
    
    const parser = sax.parser(true, {
        resolveEntities: true
    });
    
    let result = '';
    
    parser.ontext = function(text) {
        result += text;
    };
    
    parser.onend = function() {
        res.send(result);
    };
    
    // ruleid: javascript-xxe-injection
    parser.write(xmlData).close();
}
// {/fact}

// Bad Case 5: Using DOMParser with user input from cookies
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_5(req, res) {
    const xmlData = req.cookies.xmlData;
    const parser = new DOMParser();
    
    try {
        // ruleid: javascript-xxe-injection
        const doc = parser.parseFromString(xmlData, "text/xml");
        const rootElement = doc.documentElement;
        res.send(`Root element: ${rootElement.nodeName}`);
    } catch (error) {
        res.status(500).send('Error parsing XML');
    }
}
// {/fact}

// Bad Case 6: Using libxmljs with user input from POST form data
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_6(req, res) {
    const xmlData = req.body.xml;
    
    try {
        // ruleid: javascript-xxe-injection
        const xmlDoc = libxmljs.parseXmlString(xmlData);
        const nodes = xmlDoc.root().childNodes();
        let result = '';
        nodes.forEach(node => {
            if (node.type() === 'element') {
                result += `${node.name()}: ${node.text()}\n`;
            }
        });
        res.send(result);
    } catch (error) {
        res.status(500).send('Error parsing XML');
    }
}
// {/fact}

// Bad Case 7: Using JSDOM with user input
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_7(req, res) {
    const xmlData = req.query.data;
    
    try {
        // ruleid: javascript-xxe-injection
        const dom = new JSDOM(xmlData, {
            contentType: "text/xml"
        });
        
        const document = dom.window.document;
        const elements = document.getElementsByTagName("*");
        let response = `Found ${elements.length} elements`;
        
        res.send(response);
    } catch (error) {
        res.status(500).send('Error parsing XML');
    }
}
// {/fact}

// Bad Case 8: Using xml2js with user input from URL parameter
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_8(req, res) {
    const xmlData = req.params.xml;
    
    // ruleid: javascript-xxe-injection
    xml2js.parseString(xmlData, { explicitEntities: true }, (err, result) => {
        if (err) {
            return res.status(400).send('Invalid XML');
        }
        
        res.json({
            parsedData: result
        });
    });
}
// {/fact}

// Bad Case 9: Using DOMParser with user input in a more complex scenario
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_9(req, res) {
    const operation = req.query.operation;
    const xmlData = req.body;
    
    if (operation === 'parse') {
        const parser = new DOMParser();
        try {
            // ruleid: javascript-xxe-injection
            const doc = parser.parseFromString(xmlData, "application/xml");
            const users = doc.getElementsByTagName('user');
            const userList = [];
            
            for (let i = 0; i < users.length; i++) {
                userList.push({
                    id: users[i].getAttribute('id'),
                    name: users[i].getElementsByTagName('name')[0].textContent
                });
            }
            
            res.json(userList);
        } catch (error) {
            res.status(500).send('Error processing XML');
        }
    } else {
        res.status(400).send('Unknown operation');
    }
}
// {/fact}

// Bad Case 10: Using libxmljs with conditional user input
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_10(req, res) {
    let xmlData;
    
    if (req.query.source === 'body') {
        xmlData = req.body;
    } else if (req.query.source === 'file') {
        xmlData = req.query.content;
    } else {
        xmlData = req.query.xml;
    }
    
    if (xmlData) {
        try {
            // ruleid: javascript-xxe-injection
            const doc = libxmljs.parseXml(xmlData, { noent: true });
            res.send(`Parsed successfully. Root: ${doc.root().name()}`);
        } catch (error) {
            res.status(500).send('Failed to parse XML');
        }
    } else {
        res.status(400).send('No XML data provided');
    }
}
// {/fact}

// Bad Case 11: Using sax parser with user input from a request header
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_11(req, res) {
    const xmlData = req.headers['content-xml'];
    
    if (!xmlData) {
        return res.status(400).send('No XML data in header');
    }
    
    const parser = sax.parser(true);
    const results = [];
    
    parser.onopentag = function(node) {
        results.push(`<${node.name}>`);
    };
    
    parser.onclosetag = function(name) {
        results.push(`</${name}>`);
    };
    
    parser.onend = function() {
        res.send(results.join(''));
    };
    
    // ruleid: javascript-xxe-injection
    parser.write(xmlData).close();
}
// {/fact}

// Bad Case 12: Using xml2js with user input in an async/await pattern
// {fact rule=xml-external-entity@v1.0 defects=1}
async function bad_case_12(req, res) {
    const xmlData = req.body.xmlString;
    
    try {
        const parser = new xml2js.Parser({
            explicitEntities: true,
            xmlns: true
        });
        
        // ruleid: javascript-xxe-injection
        const result = await parser.parseStringPromise(xmlData);
        
        const processedData = {
            title: result.root?.title?.[0] || 'No title',
            items: result.root?.items?.[0]?.item?.map(i => i.name?.[0]) || []
        };
        
        res.json(processedData);
    } catch (error) {
        res.status(500).send(`Error processing XML: ${error.message}`);
    }
}
// {/fact}

// Bad Case 13: Using DOMParser with user input from a POST request with JSON
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_13(req, res) {
    const { xmlContent } = req.body;
    
    if (!xmlContent || typeof xmlContent !== 'string') {
        return res.status(400).send('Invalid or missing XML content');
    }
    
    try {
        const parser = new DOMParser();
        // ruleid: javascript-xxe-injection
        const xmlDoc = parser.parseFromString(xmlContent, 'text/xml');
        
        const elements = xmlDoc.getElementsByTagName('*');
        const elementCount = elements.length;
        
        let response = {
            status: 'success',
            elementCount,
            rootName: xmlDoc.documentElement.nodeName
        };
        
        res.json(response);
    } catch (error) {
        res.status(500).send('XML parsing failed');
    }
}
// {/fact}

// Bad Case 14: Using libxmljs with user input in a switch statement
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_14(req, res) {
    const action = req.query.action;
    const xmlInput = req.body;
    
    switch (action) {
        case 'validate':
            try {
                // ruleid: javascript-xxe-injection
                const doc = libxmljs.parseXml(xmlInput);
                res.send('XML is valid');
            } catch (error) {
                res.status(400).send('XML is invalid');
            }
            break;
            
        case 'count':
            try {
                // ruleid: javascript-xxe-injection
                const doc = libxmljs.parseXml(xmlInput);
                const count = doc.childNodes().length;
                res.send(`XML has ${count} child nodes`);
            } catch (error) {
                res.status(500).send('Error processing XML');
            }
            break;
            
        default:
            res.status(400).send('Unknown action');
    }
}
// {/fact}

// Bad Case 15: Using xml2js with user input from multiple possible sources
// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_15(req, res) {
    let xmlData = null;
    
    if (req.body && req.body.xml) {
        xmlData = req.body.xml;
    } else if (req.query.xml) {
        xmlData = req.query.xml;
    } else if (req.headers['x-xml-data']) {
        xmlData = req.headers['x-xml-data'];
    }
    
    if (!xmlData) {
        return res.status(400).send('No XML data provided');
    }
    
    // ruleid: javascript-xxe-injection
    xml2js.parseString(xmlData, { explicitEntities: true }, (err, result) => {
        if (err) {
            return res.status(400).send(`XML parsing error: ${err.message}`);
        }
        
        try {
            const processedResult = {
                version: result?.['?xml']?.['@']?.version || 'unknown',
                data: result
            };
            
            res.json(processedResult);
        } catch (error) {
            res.status(500).send('Error processing parsed XML');
        }
    });
}
// {/fact}

// True Negative Examples (Secure Code)

// Good Case 1: Using libxmljs with noent set to false
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_1(req, res) {
    const xmlData = req.body;
    try {
        // ok: javascript-xxe-injection
        const xmlDoc = libxmljs.parseXml(xmlData, { noent: false });
        const result = xmlDoc.toString();
        res.send(`Parsed XML: ${result}`);
    } catch (error) {
        res.status(500).send('Error parsing XML');
    }
}
// {/fact}

// Good Case 2: Using DOMParser from xmldom with secure configuration
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_2(req, res) {
    const xmlData = req.query.xml;
    
    // Secure configuration that disables entity expansion
    const parser = new DOMParser({
        locator: {},
        errorHandler: { warning: function (w) { }, error: function (e) { } },
        // ok: javascript-xxe-injection
        entityExpansion: false
    });
    
    try {
        const doc = parser.parseFromString(xmlData, "text/xml");
        const elements = doc.getElementsByTagName('item');
        let response = '';
        for (let i = 0; i < elements.length; i++) {
            response += elements[i].textContent + '<br>';
        }
        res.send(response);
    } catch (error) {
        res.status(500).send('Error parsing XML');
    }
}
// {/fact}

// Good Case 3: Using xml2js with explicitEntities disabled
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_3(req, res) {
    const xmlData = req.headers['x-xml-data'];
    
    // ok: javascript-xxe-injection
    const parser = new xml2js.Parser({
        explicitEntities: false
    });
    
    parser.parseString(xmlData, (err, result) => {
        if (err) {
            res.status(500).send('Error parsing XML');
            return;
        }
        res.json(result);
    });
}
// {/fact}

// Good Case 4: Using sax parser with resolveEntities set to false
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_4(req, res) {
    const xmlData = req.body.xmlContent;
    
    // ok: javascript-xxe-injection
    const parser = sax.parser(true, {
        resolveEntities: false
    });
    
    let result = '';
    
    parser.ontext = function(text) {
        result += text;
    };
    
    parser.onend = function() {
        res.send(result);
    };
    
    parser.write(xmlData).close();
}
// {/fact}

// Good Case 5: Validating XML input before parsing
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_5(req, res) {
    const xmlData = req.cookies.xmlData;
    
    // Simple validation to check for DOCTYPE declarations
    if (xmlData.includes('<!DOCTYPE') || xmlData.includes('<!ENTITY')) {
        return res.status(400).send('XML with DOCTYPE or ENTITY is not allowed');
    }
    
    // ok: javascript-xxe-injection
    const parser = new DOMParser({
        entityExpansion: false
    });
    
    try {
        const doc = parser.parseFromString(xmlData, "text/xml");
        const rootElement = doc.documentElement;
        res.send(`Root element: ${rootElement.nodeName}`);
    } catch (error) {
        res.status(500).send('Error parsing XML');
    }
}
// {/fact}

// Good Case 6: Using a custom function to sanitize XML before parsing
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_6(req, res) {
    const xmlData = req.body.xml;
    
    // Function to remove DOCTYPE and ENTITY declarations
    function sanitizeXml(xml) {
        return xml.replace(/<!DOCTYPE[^>]*>/g, '')
                 .replace(/<!ENTITY[^>]*>/g, '');
    }
    
    const sanitizedXml = sanitizeXml(xmlData);
    
    try {
        // ok: javascript-xxe-injection
        const xmlDoc = libxmljs.parseXml(sanitizedXml, { noent: false });
        const nodes = xmlDoc.root().childNodes();
        let result = '';
        nodes.forEach(node => {
            if (node.type() === 'element') {
                result += `${node.name()}: ${node.text()}\n`;
            }
        });
        res.send(result);
    } catch (error) {
        res.status(500).send('Error parsing XML');
    }
}
// {/fact}

// Good Case 7: Using JSDOM with secure configuration
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_7(req, res) {
    const xmlData = req.query.data;
    
    // Check for potentially dangerous XML content
    if (xmlData.includes('<!DOCTYPE') || xmlData.includes('<!ENTITY')) {
        return res.status(403).send('Potentially malicious XML rejected');
    }
    
    try {
        // ok: javascript-xxe-injection
        const dom = new JSDOM(xmlData, {
            contentType: "text/xml",
            runScripts: "outside-only"  // Prevents script execution
        });
        
        const document = dom.window.document;
        const elements = document.getElementsByTagName("*");
        let response = `Found ${elements.length} elements`;
        
        res.send(response);
    } catch (error) {
        res.status(500).send('Error parsing XML');
    }
}
// {/fact}

// Good Case 8: Using xml2js with secure configuration
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_8(req, res) {
    const xmlData = req.params.xml;
    
    // ok: javascript-xxe-injection
    xml2js.parseString(xmlData, { 
        explicitEntities: false,
        xmlns: true
    }, (err, result) => {
        if (err) {
            return res.status(400).send('Invalid XML');
        }
        
        res.json({
            parsedData: result
        });
    });
}
// {/fact}

// Good Case 9: Using a regex to check for XXE patterns before parsing
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_9(req, res) {
    const xmlData = req.body;
    
    // Check for XXE patterns
    const xxePattern = /<!ENTITY|\bSYSTEM\b|\bPUBLIC\b|<!DOCTYPE/i;
    if (xxePattern.test(xmlData)) {
        return res.status(403).send('Potentially dangerous XML rejected');
    }
    
    const parser = new DOMParser();
    try {
        // ok: javascript-xxe-injection
        const doc = parser.parseFromString(xmlData, "application/xml");
        const users = doc.getElementsByTagName('user');
        const userList = [];
        
        for (let i = 0; i < users.length; i++) {
            userList.push({
                id: users[i].getAttribute('id'),
                name: users[i].getElementsByTagName('name')[0].textContent
            });
        }
        
        res.json(userList);
    } catch (error) {
        res.status(500).send('Error processing XML');
    }
}
// {/fact}

// Good Case 10: Using a secure XML parsing library
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_10(req, res) {
    const xmlData = req.query.xml;
    
    // This is a hypothetical secure XML parsing function
    function parseXmlSecurely(xmlString) {
        // Remove any DOCTYPE declarations
        const sanitized = xmlString.replace(/<!DOCTYPE[^>]*>/g, '');
        
        // ok: javascript-xxe-injection
        return libxmljs.parseXml(sanitized, { 
            noent: false,
            nocdata: true,
            nonet: true
        });
    }
    
    try {
        const doc = parseXmlSecurely(xmlData);
        res.send(`Parsed successfully. Root: ${doc.root().name()}`);
    } catch (error) {
        res.status(500).send('Failed to parse XML');
    }
}
// {/fact}

// Good Case 11: Using a wrapper around sax parser with secure defaults
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_11(req, res) {
    const xmlData = req.headers['content-xml'];
    
    if (!xmlData) {
        return res.status(400).send('No XML data in header');
    }
    
    // Secure SAX parser wrapper
    function createSecureSaxParser() {
        // ok: javascript-xxe-injection
        return sax.parser(true, {
            lowercase: true,
            resolveEntities: false,
            position: false
        });
    }
    
    const parser = createSecureSaxParser();
    const results = [];
    
    parser.onopentag = function(node) {
        results.push(`<${node.name}>`);
    };
    
    parser.onclosetag = function(name) {
        results.push(`</${name}>`);
    };
    
    parser.onend = function() {
        res.send(results.join(''));
    };
    
    parser.write(xmlData).close();
}
// {/fact}

// Good Case 12: Using xml2js with secure configuration in async/await pattern
// {fact rule=xml-external-entity@v1.0 defects=0}
async function good_case_12(req, res) {
    const xmlData = req.body.xmlString;
    
    // Check for XXE patterns
    if (xmlData.includes('<!DOCTYPE') || xmlData.includes('<!ENTITY')) {
        return res.status(403).send('XML with DOCTYPE or ENTITY declarations is not allowed');
    }
    
    try {
        // ok: javascript-xxe-injection
        const parser = new xml2js.Parser({
            explicitEntities: false,
            xmlns: true
        });
        
        const result = await parser.parseStringPromise(xmlData);
        
        const processedData = {
            title: result.root?.title?.[0] || 'No title',
            items: result.root?.items?.[0]?.item?.map(i => i.name?.[0]) || []
        };
        
        res.json(processedData);
    } catch (error) {
        res.status(500).send(`Error processing XML: ${error.message}`);
    }
}
// {/fact}

// Good Case 13: Using a custom XML validator before parsing
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_13(req, res) {
    const { xmlContent } = req.body;
    
    if (!xmlContent || typeof xmlContent !== 'string') {
        return res.status(400).send('Invalid or missing XML content');
    }
    
    // XML validation function
    function isXmlSafe(xml) {
        const dangerousPatterns = [
            /<!DOCTYPE/i,
            /<!ENTITY/i,
            /\bSYSTEM\b/i,
            /\bPUBLIC\b/i
        ];
        
        return !dangerousPatterns.some(pattern => pattern.test(xml));
    }
    
    if (!isXmlSafe(xmlContent)) {
        return res.status(403).send('XML contains potentially dangerous constructs');
    }
    
    try {
        const parser = new DOMParser();
        // ok: javascript-xxe-injection
        const xmlDoc = parser.parseFromString(xmlContent, 'text/xml');
        
        const elements = xmlDoc.getElementsByTagName('*');
        const elementCount = elements.length;
        
        let response = {
            status: 'success',
            elementCount,
            rootName: xmlDoc.documentElement.nodeName
        };
        
        res.json(response);
    } catch (error) {
        res.status(500).send('XML parsing failed');
    }
}
// {/fact}

// Good Case 14: Using libxmljs with secure options in a switch statement
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_14(req, res) {
    const action = req.query.action;
    const xmlInput = req.body;
    
    // Secure parsing options
    const secureOptions = {
        noent: false,  // Don't expand entities
        nonet: true,   // Forbid network access
        nocdata: true  // Merge CDATA as text nodes
    };
    
    switch (action) {
        case 'validate':
            try {
                // ok: javascript-xxe-injection
                const doc = libxmljs.parseXml(xmlInput, secureOptions);
                res.send('XML is valid');
            } catch (error) {
                res.status(400).send('XML is invalid');
            }
            break;
            
        case 'count':
            try {
                // ok: javascript-xxe-injection
                const doc = libxmljs.parseXml(xmlInput, secureOptions);
                const count = doc.childNodes().length;
                res.send(`XML has ${count} child nodes`);
            } catch (error) {
                res.status(500).send('Error processing XML');
            }
            break;
            
        default:
            res.status(400).send('Unknown action');
    }
}
// {/fact}

// Good Case 15: Using xml2js with secure configuration and input validation
// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_15(req, res) {
    let xmlData = null;
    
    if (req.body && req.body.xml) {
        xmlData = req.body.xml;
    } else if (req.query.xml) {
        xmlData = req.query.xml;
    } else if (req.headers['x-xml-data']) {
        xmlData = req.headers['x-xml-data'];
    }
    
    if (!xmlData) {
        return res.status(400).send('No XML data provided');
    }
    
    // Validate XML for XXE patterns
    if (typeof xmlData === 'string' && 
        (xmlData.includes('<!DOCTYPE') || 
         xmlData.includes('<!ENTITY') || 
         xmlData.includes('SYSTEM') || 
         xmlData.includes('PUBLIC'))) {
        return res.status(403).send('XML contains potentially dangerous constructs');
    }
    
    // ok: javascript-xxe-injection
    xml2js.parseString(xmlData, { 
        explicitEntities: false,
        xmlns: true,
        normalizeTags: true
    }, (err, result) => {
        if (err) {
            return res.status(400).send(`XML parsing error: ${err.message}`);
        }
        
        try {
            const processedResult = {
                version: result?.['?xml']?.['@']?.version || 'unknown',
                data: result
            };
            
            res.json(processedResult);
        } catch (error) {
            res.status(500).send('Error processing parsed XML');
        }
    });
}
// {/fact}

module.exports = {
    bad_case_1, bad_case_2, bad_case_3, bad_case_4, bad_case_5,
    bad_case_6, bad_case_7, bad_case_8, bad_case_9, bad_case_10,
    bad_case_11, bad_case_12, bad_case_13, bad_case_14, bad_case_15,
    good_case_1, good_case_2, good_case_3, good_case_4, good_case_5,
    good_case_6, good_case_7, good_case_8, good_case_9, good_case_10,
    good_case_11, good_case_12, good_case_13, good_case_14, good_case_15
};