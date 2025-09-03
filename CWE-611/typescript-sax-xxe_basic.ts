// File: sax_xxe_examples.js

const sax = require('sax');
const http = require('http');
const https = require('https');
const fs = require('fs');
const express = require('express');
const app = express();
const bodyParser = require('body-parser');

app.use(bodyParser.text({ type: 'application/xml' }));

// True Positive Examples (Vulnerable Code)

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_1() {
  const server = http.createServer((req, res) => {
    if (req.method === 'POST') {
      let data = '';
      req.on('data', chunk => {
        data += chunk;
      });
      req.on('end', () => {
        const parser = sax.parser(true);
        
        // ruleid: typescript_sax_xxe
        parser.ondoctype = doctype => {
          console.log('DOCTYPE:', doctype);
        };
        
        parser.write(data);
        parser.end();
        res.end('XML parsed');
      });
    }
  });
  server.listen(3000);
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_2() {
  app.post('/parse-xml', (req, res) => {
    const xmlData = req.body;
    const parser = sax.parser(true);
    
    // ruleid: typescript_sax_xxe
    parser.ondoctype = function(doctype) {
      // Process the doctype
      return doctype;
    };
    
    parser.ontext = text => {
      console.log('Text:', text);
    };
    
    parser.write(xmlData).close();
    res.send('XML processed');
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_3() {
  const xmlProcessor = (xmlString) => {
    const strictParser = sax.parser(true);
    let result = '';
    
    // ruleid: typescript_sax_xxe
    strictParser.ondoctype = (dt) => {
      result += `DOCTYPE: ${dt}\n`;
    };
    
    strictParser.ontext = (t) => {
      result += t;
    };
    
    strictParser.write(xmlString).close();
    return result;
  };
  
  http.createServer((req, res) => {
    if (req.url === '/process' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk.toString(); });
      req.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(xmlProcessor(body));
      });
    }
  }).listen(8080);
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_4() {
  app.post('/upload-xml', (req, res) => {
    const xmlContent = req.body;
    const parser = sax.parser(false); // Non-strict mode
    
    // ruleid: typescript_sax_xxe
    parser.ondoctype = doctype => {
      // Custom DTD handling
      if (doctype.includes('SYSTEM')) {
        console.warn('External entity detected');
      }
    };
    
    parser.onopentag = tag => {
      console.log('Tag:', tag.name);
    };
    
    try {
      parser.write(xmlContent).close();
      res.status(200).send('XML processed successfully');
    } catch (error) {
      res.status(400).send('XML parsing failed');
    }
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_5() {
  function processXmlFromUrl(url) {
    https.get(url, (response) => {
      let data = '';
      response.on('data', (chunk) => {
        data += chunk;
      });
      
      response.on('end', () => {
        const parser = sax.parser(true);
        
        // ruleid: typescript_sax_xxe
        parser.ondoctype = function(doctype) {
          console.log('Processing DOCTYPE:', doctype);
        };
        
        parser.write(data).close();
      });
    });
  }
  
  app.get('/fetch-xml', (req, res) => {
    const xmlUrl = req.query.url;
    processXmlFromUrl(xmlUrl);
    res.send('Fetching XML');
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_6() {
  app.post('/validate-xml', (req, res) => {
    const xmlData = req.body;
    let isValid = true;
    const parser = sax.parser(true);
    
    // ruleid: typescript_sax_xxe
    parser.ondoctype = (doctype) => {
      if (doctype.indexOf('SYSTEM') >= 0) {
        isValid = false;
      }
    };
    
    parser.onerror = () => {
      isValid = false;
    };
    
    parser.write(xmlData).close();
    res.json({ valid: isValid });
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_7() {
  const createXmlParser = () => {
    const parser = sax.parser(true);
    
    // ruleid: typescript_sax_xxe
    parser.ondoctype = (dt) => {
      // Just logging the doctype
      console.log(dt);
    };
    
    return parser;
  };
  
  app.post('/xml-endpoint', (req, res) => {
    const parser = createXmlParser();
    parser.onend = () => {
      res.send('Parsing complete');
    };
    parser.write(req.body).close();
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_8() {
  http.createServer((req, res) => {
    if (req.headers['content-type'] === 'application/xml') {
      let xmlData = '';
      req.on('data', chunk => {
        xmlData += chunk;
      });
      
      req.on('end', () => {
        const saxStream = sax.createStream(true);
        
        // ruleid: typescript_sax_xxe
        saxStream.ondoctype = function(doctype) {
          // Custom DTD handling logic
          return;
        };
        
        saxStream.on('end', function() {
          res.end('XML processed');
        });
        
        saxStream.write(xmlData);
        saxStream.end();
      });
    }
  }).listen(3001);
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_9() {
  app.post('/xml-transform', (req, res) => {
    const xmlInput = req.body;
    let output = '';
    
    const parser = sax.parser(true);
    
    // ruleid: typescript_sax_xxe
    parser.ondoctype = doctype => {
      output += `<!DOCTYPE ${doctype}>\n`;
    };
    
    parser.onopentag = node => {
      output += `<${node.name}>`;
    };
    
    parser.ontext = text => {
      output += text;
    };
    
    parser.onclosetag = tag => {
      output += `</${tag}>`;
    };
    
    parser.write(xmlInput).close();
    res.type('application/xml').send(output);
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_10() {
  const processXmlFile = (filePath, callback) => {
    fs.readFile(filePath, 'utf8', (err, data) => {
      if (err) {
        return callback(err);
      }
      
      const parser = sax.parser(true);
      const result = { elements: [] };
      
      // ruleid: typescript_sax_xxe
      parser.ondoctype = doctype => {
        result.doctype = doctype;
      };
      
      parser.onopentag = node => {
        result.elements.push(node.name);
      };
      
      parser.write(data).close();
      callback(null, result);
    });
  };
  
  app.post('/process-xml-file', (req, res) => {
    const filePath = req.body.path;
    processXmlFile(filePath, (err, result) => {
      if (err) {
        return res.status(500).send(err.message);
      }
      res.json(result);
    });
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_11() {
  app.post('/xml-to-json', (req, res) => {
    const xmlContent = req.body;
    const result = {};
    let currentElement = '';
    
    const parser = sax.parser(true);
    
    // ruleid: typescript_sax_xxe
    parser.ondoctype = dt => {
      result.doctype = dt;
    };
    
    parser.onopentag = node => {
      currentElement = node.name;
      result[currentElement] = '';
    };
    
    parser.ontext = text => {
      if (currentElement) {
        result[currentElement] += text;
      }
    };
    
    parser.write(xmlContent).close();
    res.json(result);
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_12() {
  const xmlValidator = {
    validate: function(xmlString) {
      const parser = sax.parser(true);
      let valid = true;
      
      // ruleid: typescript_sax_xxe
      parser.ondoctype = function(doctype) {
        // Check if doctype is allowed
        if (!this.isAllowedDoctype(doctype)) {
          valid = false;
        }
      };
      
      parser.onerror = function() {
        valid = false;
      };
      
      parser.write(xmlString).close();
      return valid;
    },
    
    isAllowedDoctype: function(doctype) {
      return !doctype.includes('SYSTEM');
    }
  };
  
  app.post('/check-xml', (req, res) => {
    const isValid = xmlValidator.validate(req.body);
    res.json({ valid: isValid });
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_13() {
  const streamProcessor = (req, res) => {
    const saxStream = sax.createStream(true);
    
    // ruleid: typescript_sax_xxe
    saxStream.ondoctype = doctype => {
      console.log('DOCTYPE found:', doctype);
    };
    
    saxStream.on('opentag', node => {
      res.write(`<${node.name}>`);
    });
    
    saxStream.on('text', text => {
      res.write(text);
    });
    
    saxStream.on('closetag', name => {
      res.write(`</${name}>`);
    });
    
    saxStream.on('end', () => {
      res.end();
    });
    
    req.pipe(saxStream);
  };
  
  app.post('/stream-xml', streamProcessor);
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_14() {
  const xmlAnalyzer = (xmlContent) => {
    const stats = {
      elements: 0,
      attributes: 0,
      doctypes: []
    };
    
    const parser = sax.parser(true);
    
    // ruleid: typescript_sax_xxe
    parser.ondoctype = doctype => {
      stats.doctypes.push(doctype);
    };
    
    parser.onopentag = node => {
      stats.elements++;
      stats.attributes += Object.keys(node.attributes).length;
    };
    
    parser.write(xmlContent).close();
    return stats;
  };
  
  app.post('/analyze-xml', (req, res) => {
    const stats = xmlAnalyzer(req.body);
    res.json(stats);
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_15() {
  app.post('/xml-search', (req, res) => {
    const { xml, searchTerm } = req.body;
    const results = [];
    let currentPath = [];
    
    const parser = sax.parser(true);
    
    // ruleid: typescript_sax_xxe
    parser.ondoctype = doctype => {
      // Just logging
      console.log('DOCTYPE:', doctype);
    };
    
    parser.onopentag = node => {
      currentPath.push(node.name);
      
      if (node.name.includes(searchTerm)) {
        results.push({
          element: node.name,
          path: [...currentPath].join('/')
        });
      }
    };
    
    parser.onclosetag = () => {
      currentPath.pop();
    };
    
    parser.write(xml).close();
    res.json({ results });
  });
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_1() {
  const server = http.createServer((req, res) => {
    if (req.method === 'POST') {
      let data = '';
      req.on('data', chunk => {
        data += chunk;
      });
      req.on('end', () => {
        const parser = sax.parser(true);
        
        // ok: typescript_sax_xxe
        // Not using ondoctype handler, which avoids XXE vulnerabilities
        parser.ontext = text => {
          console.log('Text:', text);
        };
        
        parser.write(data);
        parser.end();
        res.end('XML parsed safely');
      });
    }
  });
  server.listen(3000);
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_2() {
  app.post('/parse-xml', (req, res) => {
    const xmlData = req.body;
    
    // ok: typescript_sax_xxe
    // Using sax without ondoctype handler
    const parser = sax.parser(true, {
      lowercase: true
    });
    
    let result = '';
    
    parser.ontext = text => {
      result += text;
    };
    
    parser.write(xmlData).close();
    res.send('XML processed safely: ' + result);
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_3() {
  const xmlProcessor = (xmlString) => {
    // ok: typescript_sax_xxe
    // Using sax without ondoctype handler
    const strictParser = sax.parser(true);
    let result = '';
    
    strictParser.ontext = (t) => {
      result += t;
    };
    
    strictParser.onopentag = (node) => {
      result += `<${node.name}>`;
    };
    
    strictParser.onclosetag = (tagName) => {
      result += `</${tagName}>`;
    };
    
    strictParser.write(xmlString).close();
    return result;
  };
  
  http.createServer((req, res) => {
    if (req.url === '/process' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk.toString(); });
      req.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(xmlProcessor(body));
      });
    }
  }).listen(8080);
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_4() {
  app.post('/upload-xml', (req, res) => {
    const xmlContent = req.body;
    
    // ok: typescript_sax_xxe
    // Using sax without ondoctype handler
    const parser = sax.parser(false); // Non-strict mode
    
    parser.onopentag = tag => {
      console.log('Tag:', tag.name);
    };
    
    try {
      parser.write(xmlContent).close();
      res.status(200).send('XML processed successfully');
    } catch (error) {
      res.status(400).send('XML parsing failed');
    }
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_5() {
  function processXmlFromUrl(url) {
    https.get(url, (response) => {
      let data = '';
      response.on('data', (chunk) => {
        data += chunk;
      });
      
      response.on('end', () => {
        // ok: typescript_sax_xxe
        // Using sax without ondoctype handler
        const parser = sax.parser(true);
        
        parser.onopentag = function(node) {
          console.log('Tag:', node.name);
        };
        
        parser.ontext = function(text) {
          console.log('Text:', text);
        };
        
        parser.write(data).close();
      });
    });
  }
  
  app.get('/fetch-xml', (req, res) => {
    const xmlUrl = req.query.url;
    processXmlFromUrl(xmlUrl);
    res.send('Fetching XML safely');
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_6() {
  app.post('/validate-xml', (req, res) => {
    const xmlData = req.body;
    let isValid = true;
    
    // ok: typescript_sax_xxe
    // Using sax without ondoctype handler
    const parser = sax.parser(true);
    
    parser.onerror = () => {
      isValid = false;
    };
    
    parser.onopentag = (node) => {
      // Validate tags if needed
      if (node.name === 'invalid') {
        isValid = false;
      }
    };
    
    parser.write(xmlData).close();
    res.json({ valid: isValid });
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_7() {
  const createXmlParser = () => {
    // ok: typescript_sax_xxe
    // Using sax without ondoctype handler
    const parser = sax.parser(true);
    
    parser.onopentag = (node) => {
      console.log('Opening tag:', node.name);
    };
    
    parser.onclosetag = (name) => {
      console.log('Closing tag:', name);
    };
    
    return parser;
  };
  
  app.post('/xml-endpoint', (req, res) => {
    const parser = createXmlParser();
    parser.onend = () => {
      res.send('Parsing complete');
    };
    parser.write(req.body).close();
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_8() {
  http.createServer((req, res) => {
    if (req.headers['content-type'] === 'application/xml') {
      let xmlData = '';
      req.on('data', chunk => {
        xmlData += chunk;
      });
      
      req.on('end', () => {
        // ok: typescript_sax_xxe
        // Using sax stream without ondoctype handler
        const saxStream = sax.createStream(true);
        
        saxStream.on('opentag', function(node) {
          console.log('Tag:', node.name);
        });
        
        saxStream.on('end', function() {
          res.end('XML processed safely');
        });
        
        saxStream.write(xmlData);
        saxStream.end();
      });
    }
  }).listen(3001);
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_9() {
  app.post('/xml-transform', (req, res) => {
    const xmlInput = req.body;
    let output = '';
    
    // ok: typescript_sax_xxe
    // Using sax without ondoctype handler
    const parser = sax.parser(true);
    
    parser.onopentag = node => {
      output += `<${node.name}>`;
    };
    
    parser.ontext = text => {
      output += text;
    };
    
    parser.onclosetag = tag => {
      output += `</${tag}>`;
    };
    
    parser.write(xmlInput).close();
    res.type('application/xml').send(output);
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_10() {
  const processXmlFile = (filePath, callback) => {
    fs.readFile(filePath, 'utf8', (err, data) => {
      if (err) {
        return callback(err);
      }
      
      // ok: typescript_sax_xxe
      // Using sax without ondoctype handler
      const parser = sax.parser(true);
      const result = { elements: [] };
      
      parser.onopentag = node => {
        result.elements.push(node.name);
      };
      
      parser.write(data).close();
      callback(null, result);
    });
  };
  
  app.post('/process-xml-file', (req, res) => {
    const filePath = req.body.path;
    processXmlFile(filePath, (err, result) => {
      if (err) {
        return res.status(500).send(err.message);
      }
      res.json(result);
    });
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_11() {
  app.post('/xml-to-json', (req, res) => {
    const xmlContent = req.body;
    const result = {};
    let currentElement = '';
    
    // ok: typescript_sax_xxe
    // Using sax without ondoctype handler
    const parser = sax.parser(true);
    
    parser.onopentag = node => {
      currentElement = node.name;
      result[currentElement] = '';
    };
    
    parser.ontext = text => {
      if (currentElement) {
        result[currentElement] += text;
      }
    };
    
    parser.write(xmlContent).close();
    res.json(result);
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_12() {
  const xmlValidator = {
    validate: function(xmlString) {
      // ok: typescript_sax_xxe
      // Using sax without ondoctype handler
      const parser = sax.parser(true);
      let valid = true;
      
      parser.onerror = function() {
        valid = false;
      };
      
      // Validate structure without using ondoctype
      parser.onopentag = function(node) {
        if (!this.isAllowedTag(node.name)) {
          valid = false;
        }
      };
      
      parser.write(xmlString).close();
      return valid;
    },
    
    isAllowedTag: function(tagName) {
      const allowedTags = ['root', 'item', 'name', 'description'];
      return allowedTags.includes(tagName);
    }
  };
  
  app.post('/check-xml', (req, res) => {
    const isValid = xmlValidator.validate(req.body);
    res.json({ valid: isValid });
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_13() {
  const streamProcessor = (req, res) => {
    // ok: typescript_sax_xxe
    // Using sax stream without ondoctype handler
    const saxStream = sax.createStream(true);
    
    saxStream.on('opentag', node => {
      res.write(`<${node.name}>`);
    });
    
    saxStream.on('text', text => {
      res.write(text);
    });
    
    saxStream.on('closetag', name => {
      res.write(`</${name}>`);
    });
    
    saxStream.on('end', () => {
      res.end();
    });
    
    req.pipe(saxStream);
  };
  
  app.post('/stream-xml', streamProcessor);
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_14() {
  const xmlAnalyzer = (xmlContent) => {
    const stats = {
      elements: 0,
      attributes: 0,
      textNodes: 0
    };
    
    // ok: typescript_sax_xxe
    // Using sax without ondoctype handler
    const parser = sax.parser(true);
    
    parser.onopentag = node => {
      stats.elements++;
      stats.attributes += Object.keys(node.attributes).length;
    };
    
    parser.ontext = text => {
      if (text.trim()) {
        stats.textNodes++;
      }
    };
    
    parser.write(xmlContent).close();
    return stats;
  };
  
  app.post('/analyze-xml', (req, res) => {
    const stats = xmlAnalyzer(req.body);
    res.json(stats);
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_15() {
  app.post('/xml-search', (req, res) => {
    const { xml, searchTerm } = req.body;
    const results = [];
    let currentPath = [];
    
    // ok: typescript_sax_xxe
    // Using sax without ondoctype handler
    const parser = sax.parser(true);
    
    parser.onopentag = node => {
      currentPath.push(node.name);
      
      if (node.name.includes(searchTerm)) {
        results.push({
          element: node.name,
          path: [...currentPath].join('/')
        });
      }
    };
    
    parser.onclosetag = () => {
      currentPath.pop();
    };
    
    parser.write(xml).close();
    res.json({ results });
  });
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = {
  bad_case_1, bad_case_2, bad_case_3, bad_case_4, bad_case_5,
  bad_case_6, bad_case_7, bad_case_8, bad_case_9, bad_case_10,
  bad_case_11, bad_case_12, bad_case_13, bad_case_14, bad_case_15,
  good_case_1, good_case_2, good_case_3, good_case_4, good_case_5,
  good_case_6, good_case_7, good_case_8, good_case_9, good_case_10,
  good_case_11, good_case_12, good_case_13, good_case_14, good_case_15
};