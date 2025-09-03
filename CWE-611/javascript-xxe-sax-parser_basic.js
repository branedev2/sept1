// Import the required libraries
const sax = require('sax');
const fs = require('fs');
const http = require('http');
const https = require('https');
const express = require('express');
const app = express();
const bodyParser = require('body-parser');

// True Positive Examples (Vulnerable Code)

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_1() {
  // Creating a SAX parser with ondoctype event handler
  const parser = sax.parser(true);
  
  // ruleid: javascript-xxe-sax-parser
  parser.ondoctype = function(doctype) {
    console.log("DOCTYPE:", doctype);
  };
  
  // Parse XML from a file
  const xmlData = fs.readFileSync('user_data.xml', 'utf8');
  parser.write(xmlData).close();
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_2() {
  // Creating a SAX parser and setting up ondoctype handler from user input
  const parser = sax.parser(true);
  
  http.createServer((req, res) => {
    // ruleid: javascript-xxe-sax-parser
    parser.ondoctype = function(doctype) {
      res.write("Processing DOCTYPE: " + doctype);
    };
    
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    
    req.on('end', () => {
      parser.write(body).close();
      res.end('XML processed');
    });
  }).listen(3000);
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_3() {
  // Creating a SAX stream with doctype event
  const saxStream = sax.createStream(true);
  
  // ruleid: javascript-xxe-sax-parser
  saxStream.on("doctype", function(doctype) {
    console.log("DOCTYPE found:", doctype);
  });
  
  // Process XML from an HTTP request
  app.post('/process-xml', (req, res) => {
    req.pipe(saxStream);
    res.send('XML processing started');
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_4() {
  // Creating a SAX parser in a function that processes user-uploaded files
  function processXmlFile(filePath) {
    const parser = sax.parser(true);
    
    // ruleid: javascript-xxe-sax-parser
    parser.ondoctype = (doctype) => {
      return doctype;
    };
    
    const xmlData = fs.readFileSync(filePath, 'utf8');
    return parser.write(xmlData).close();
  }
  
  app.post('/upload', (req, res) => {
    const result = processXmlFile(req.body.filePath);
    res.json({ result });
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_5() {
  // Creating a SAX stream with doctype event in an async function
  async function processXmlStream(url) {
    const saxStream = sax.createStream(true);
    
    // ruleid: javascript-xxe-sax-parser
    saxStream.on("doctype", doctype => {
      console.log(`DOCTYPE declaration: ${doctype}`);
    });
    
    return new Promise((resolve, reject) => {
      https.get(url, (response) => {
        response.pipe(saxStream);
        saxStream.on('end', resolve);
        saxStream.on('error', reject);
      });
    });
  }
  
  app.get('/fetch-xml', async (req, res) => {
    try {
      await processXmlStream(req.query.url);
      res.send('XML processed successfully');
    } catch (error) {
      res.status(500).send('Error processing XML');
    }
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_6() {
  // Using SAX parser with ondoctype in a class method
  class XmlProcessor {
    constructor() {
      this.parser = sax.parser(true);
      
      // ruleid: javascript-xxe-sax-parser
      this.parser.ondoctype = function(doctype) {
        this.lastDoctype = doctype;
      };
    }
    
    process(xmlString) {
      this.parser.write(xmlString).close();
      return this.lastDoctype;
    }
  }
  
  app.post('/xml-service', bodyParser.text(), (req, res) => {
    const processor = new XmlProcessor();
    const result = processor.process(req.body);
    res.send(result);
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_7() {
  // Using SAX stream with doctype event in a conditional block
  app.post('/conditional-xml', (req, res) => {
    const shouldProcessDoctype = req.query.processDoctype === 'true';
    const saxStream = sax.createStream(true);
    
    if (shouldProcessDoctype) {
      // ruleid: javascript-xxe-sax-parser
      saxStream.on("doctype", function(doctype) {
        console.log("Processing DOCTYPE conditionally:", doctype);
      });
    }
    
    req.pipe(saxStream);
    res.send('Processing XML');
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_8() {
  // Using SAX parser with ondoctype in a higher-order function
  function createXmlProcessor(options) {
    return function(xmlData) {
      const parser = sax.parser(options.strict);
      
      // ruleid: javascript-xxe-sax-parser
      parser.ondoctype = options.doctypeHandler || function(doctype) {
        console.log("Default DOCTYPE handler:", doctype);
      };
      
      return parser.write(xmlData).close();
    };
  }
  
  const processor = createXmlProcessor({ strict: true });
  
  app.post('/process', bodyParser.text(), (req, res) => {
    processor(req.body);
    res.send('Processed');
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_9() {
  // Using SAX parser with ondoctype in an event-driven architecture
  const EventEmitter = require('events');
  class XmlEventProcessor extends EventEmitter {
    processXml(xmlData) {
      const parser = sax.parser(true);
      
      // ruleid: javascript-xxe-sax-parser
      parser.ondoctype = (doctype) => {
        this.emit('doctype', doctype);
      };
      
      parser.write(xmlData).close();
    }
  }
  
  const processor = new XmlEventProcessor();
  processor.on('doctype', (doctype) => {
    console.log('Received DOCTYPE:', doctype);
  });
  
  app.post('/event-xml', bodyParser.text(), (req, res) => {
    processor.processXml(req.body);
    res.send('Processing with events');
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_10() {
  // Using SAX stream with doctype in a promise-based API
  function parseXmlWithPromise(xmlString) {
    return new Promise((resolve, reject) => {
      const saxStream = sax.createStream(true);
      
      // ruleid: javascript-xxe-sax-parser
      saxStream.on("doctype", function(doctype) {
        console.log("Promise-based DOCTYPE handling:", doctype);
      });
      
      saxStream.on("end", resolve);
      saxStream.on("error", reject);
      
      const Readable = require('stream').Readable;
      const s = new Readable();
      s.push(xmlString);
      s.push(null);
      s.pipe(saxStream);
    });
  }
  
  app.post('/promise-xml', bodyParser.text(), async (req, res) => {
    await parseXmlWithPromise(req.body);
    res.send('Processed with promises');
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_11() {
  // Using SAX parser with ondoctype in a middleware function
  function xmlMiddleware(req, res, next) {
    if (!req.is('text/xml') && !req.is('application/xml')) {
      return next();
    }
    
    let xmlData = '';
    req.on('data', chunk => {
      xmlData += chunk.toString();
    });
    
    req.on('end', () => {
      const parser = sax.parser(true);
      
      // ruleid: javascript-xxe-sax-parser
      parser.ondoctype = function(doctype) {
        req.doctype = doctype;
      };
      
      parser.write(xmlData).close();
      next();
    });
  }
  
  app.use(xmlMiddleware);
  app.post('/middleware-test', (req, res) => {
    res.json({ doctype: req.doctype });
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_12() {
  // Using SAX stream with doctype in a factory pattern
  const xmlProcessorFactory = {
    createBasicProcessor() {
      const saxStream = sax.createStream(true);
      
      // ruleid: javascript-xxe-sax-parser
      saxStream.on("doctype", function(doctype) {
        console.log("Factory-created processor DOCTYPE:", doctype);
      });
      
      return saxStream;
    }
  };
  
  app.post('/factory-xml', (req, res) => {
    const processor = xmlProcessorFactory.createBasicProcessor();
    req.pipe(processor);
    res.send('Processing with factory-created processor');
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_13() {
  // Using SAX parser with ondoctype in a callback pattern
  function processXmlWithCallback(xmlData, callback) {
    const parser = sax.parser(true);
    
    // ruleid: javascript-xxe-sax-parser
    parser.ondoctype = function(doctype) {
      callback(null, doctype);
    };
    
    parser.onerror = function(error) {
      callback(error);
    };
    
    parser.write(xmlData).close();
  }
  
  app.post('/callback-xml', bodyParser.text(), (req, res) => {
    processXmlWithCallback(req.body, (error, doctype) => {
      if (error) {
        return res.status(500).send('Error processing XML');
      }
      res.json({ doctype });
    });
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_14() {
  // Using SAX parser with ondoctype in a try-catch block
  app.post('/safe-xml', bodyParser.text(), (req, res) => {
    try {
      const parser = sax.parser(true);
      
      // ruleid: javascript-xxe-sax-parser
      parser.ondoctype = function(doctype) {
        console.log("Try-catch DOCTYPE handling:", doctype);
      };
      
      parser.write(req.body).close();
      res.send('XML processed safely');
    } catch (error) {
      res.status(500).send('Error: ' + error.message);
    }
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=1}
function bad_case_15() {
  // Using SAX stream with doctype in a module pattern
  const xmlModule = (function() {
    const saxStream = sax.createStream(true);
    
    // ruleid: javascript-xxe-sax-parser
    saxStream.on("doctype", function(doctype) {
      console.log("Module pattern DOCTYPE handling:", doctype);
    });
    
    return {
      process: function(readableStream) {
        readableStream.pipe(saxStream);
      }
    };
  })();
  
  app.post('/module-xml', (req, res) => {
    xmlModule.process(req);
    res.send('Processing with module pattern');
  });
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_1() {
  // Creating a SAX parser without ondoctype event handler
  const parser = sax.parser(true);
  
  // ok: javascript-xxe-sax-parser
  parser.onopentag = function(node) {
    console.log("Node opened:", node.name);
  };
  
  // Parse XML from a file
  const xmlData = fs.readFileSync('user_data.xml', 'utf8');
  parser.write(xmlData).close();
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_2() {
  // Creating a SAX parser with secure configuration
  const parser = sax.parser(true, {
    // ok: javascript-xxe-sax-parser
    lowercase: true,
    position: true
  });
  
  parser.ontext = function(text) {
    console.log("Text node:", text);
  };
  
  http.createServer((req, res) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    
    req.on('end', () => {
      parser.write(body).close();
      res.end('XML processed securely');
    });
  }).listen(3000);
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_3() {
  // Creating a SAX stream without doctype event
  const saxStream = sax.createStream(true);
  
  // ok: javascript-xxe-sax-parser
  saxStream.on("text", function(text) {
    console.log("Text content:", text);
  });
  
  // Process XML from an HTTP request
  app.post('/process-xml-safely', (req, res) => {
    req.pipe(saxStream);
    res.send('XML processing started safely');
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_4() {
  // Creating a SAX parser in a function that processes user-uploaded files
  function processXmlFileSafely(filePath) {
    const parser = sax.parser(true);
    
    // ok: javascript-xxe-sax-parser
    parser.onopentag = (node) => {
      console.log("Processing tag:", node.name);
    };
    
    const xmlData = fs.readFileSync(filePath, 'utf8');
    return parser.write(xmlData).close();
  }
  
  app.post('/upload-safe', (req, res) => {
    const result = processXmlFileSafely(req.body.filePath);
    res.json({ result });
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_5() {
  // Creating a SAX stream without doctype event in an async function
  async function processXmlStreamSafely(url) {
    const saxStream = sax.createStream(true);
    
    // ok: javascript-xxe-sax-parser
    saxStream.on("opentag", node => {
      console.log(`Tag opened: ${node.name}`);
    });
    
    return new Promise((resolve, reject) => {
      https.get(url, (response) => {
        response.pipe(saxStream);
        saxStream.on('end', resolve);
        saxStream.on('error', reject);
      });
    });
  }
  
  app.get('/fetch-xml-safely', async (req, res) => {
    try {
      await processXmlStreamSafely(req.query.url);
      res.send('XML processed successfully and safely');
    } catch (error) {
      res.status(500).send('Error processing XML');
    }
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_6() {
  // Using SAX parser without ondoctype in a class method
  class SafeXmlProcessor {
    constructor() {
      this.parser = sax.parser(true);
      
      // ok: javascript-xxe-sax-parser
      this.parser.onopentag = function(node) {
        console.log("Processing tag:", node.name);
      };
    }
    
    process(xmlString) {
      this.parser.write(xmlString).close();
      return 'Processed safely';
    }
  }
  
  app.post('/xml-service-safe', bodyParser.text(), (req, res) => {
    const processor = new SafeXmlProcessor();
    const result = processor.process(req.body);
    res.send(result);
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_7() {
  // Using a different XML parser library that doesn't have XXE vulnerabilities
  const { XMLParser } = require('fast-xml-parser');
  
  // ok: javascript-xxe-sax-parser
  const parser = new XMLParser({
    ignoreDeclaration: true,
    ignorePiTags: true
  });
  
  app.post('/alternative-parser', bodyParser.text(), (req, res) => {
    const result = parser.parse(req.body);
    res.json(result);
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_8() {
  // Using SAX parser with secure event handlers in a higher-order function
  function createSafeXmlProcessor(options) {
    return function(xmlData) {
      const parser = sax.parser(options.strict);
      
      // ok: javascript-xxe-sax-parser
      parser.onopentag = options.openTagHandler || function(node) {
        console.log("Default open tag handler:", node.name);
      };
      
      return parser.write(xmlData).close();
    };
  }
  
  const processor = createSafeXmlProcessor({ strict: true });
  
  app.post('/process-safe', bodyParser.text(), (req, res) => {
    processor(req.body);
    res.send('Processed safely');
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_9() {
  // Using SAX parser with secure events in an event-driven architecture
  const EventEmitter = require('events');
  class SafeXmlEventProcessor extends EventEmitter {
    processXml(xmlData) {
      const parser = sax.parser(true);
      
      // ok: javascript-xxe-sax-parser
      parser.ontext = (text) => {
        this.emit('text', text);
      };
      
      parser.onopentag = (node) => {
        this.emit('tag', node);
      };
      
      parser.write(xmlData).close();
    }
  }
  
  const processor = new SafeXmlEventProcessor();
  processor.on('text', (text) => {
    console.log('Received text:', text);
  });
  
  app.post('/event-xml-safe', bodyParser.text(), (req, res) => {
    processor.processXml(req.body);
    res.send('Processing with events safely');
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_10() {
  // Using SAX stream with safe events in a promise-based API
  function parseXmlSafelyWithPromise(xmlString) {
    return new Promise((resolve, reject) => {
      const saxStream = sax.createStream(true);
      
      // ok: javascript-xxe-sax-parser
      saxStream.on("opentag", function(node) {
        console.log("Promise-based tag handling:", node.name);
      });
      
      saxStream.on("end", resolve);
      saxStream.on("error", reject);
      
      const Readable = require('stream').Readable;
      const s = new Readable();
      s.push(xmlString);
      s.push(null);
      s.pipe(saxStream);
    });
  }
  
  app.post('/promise-xml-safe', bodyParser.text(), async (req, res) => {
    await parseXmlSafelyWithPromise(req.body);
    res.send('Processed with promises safely');
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_11() {
  // Using SAX parser with safe events in a middleware function
  function safeXmlMiddleware(req, res, next) {
    if (!req.is('text/xml') && !req.is('application/xml')) {
      return next();
    }
    
    let xmlData = '';
    req.on('data', chunk => {
      xmlData += chunk.toString();
    });
    
    req.on('end', () => {
      const parser = sax.parser(true);
      
      // ok: javascript-xxe-sax-parser
      parser.onopentag = function(node) {
        if (!req.xmlTags) req.xmlTags = [];
        req.xmlTags.push(node.name);
      };
      
      parser.write(xmlData).close();
      next();
    });
  }
  
  app.use(safeXmlMiddleware);
  app.post('/middleware-test-safe', (req, res) => {
    res.json({ tags: req.xmlTags });
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_12() {
  // Using SAX stream with safe events in a factory pattern
  const safeXmlProcessorFactory = {
    createBasicProcessor() {
      const saxStream = sax.createStream(true);
      
      // ok: javascript-xxe-sax-parser
      saxStream.on("text", function(text) {
        console.log("Factory-created processor text:", text);
      });
      
      return saxStream;
    }
  };
  
  app.post('/factory-xml-safe', (req, res) => {
    const processor = safeXmlProcessorFactory.createBasicProcessor();
    req.pipe(processor);
    res.send('Processing with factory-created safe processor');
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_13() {
  // Using SAX parser with safe events in a callback pattern
  function processXmlSafelyWithCallback(xmlData, callback) {
    const parser = sax.parser(true);
    
    // ok: javascript-xxe-sax-parser
    parser.onopentag = function(node) {
      callback(null, node);
    };
    
    parser.onerror = function(error) {
      callback(error);
    };
    
    parser.write(xmlData).close();
  }
  
  app.post('/callback-xml-safe', bodyParser.text(), (req, res) => {
    processXmlSafelyWithCallback(req.body, (error, node) => {
      if (error) {
        return res.status(500).send('Error processing XML');
      }
      res.json({ node: node.name });
    });
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_14() {
  // Using a custom XML processor that validates and sanitizes input
  function createSecureXmlProcessor() {
    // ok: javascript-xxe-sax-parser
    const parser = sax.parser(true);
    
    // Only set up safe event handlers
    parser.onopentag = function(node) {
      console.log("Processing tag:", node.name);
    };
    
    parser.ontext = function(text) {
      console.log("Processing text:", text);
    };
    
    return parser;
  }
  
  app.post('/secure-processor', bodyParser.text(), (req, res) => {
    const parser = createSecureXmlProcessor();
    parser.write(req.body).close();
    res.send('Processed securely');
  });
}
// {/fact}

// {fact rule=xml-external-entity@v1.0 defects=0}
function good_case_15() {
  // Using SAX stream with safe events in a module pattern
  const safeXmlModule = (function() {
    const saxStream = sax.createStream(true);
    
    // ok: javascript-xxe-sax-parser
    saxStream.on("opentag", function(node) {
      console.log("Module pattern tag handling:", node.name);
    });
    
    saxStream.on("text", function(text) {
      console.log("Module pattern text handling:", text);
    });
    
    return {
      process: function(readableStream) {
        readableStream.pipe(saxStream);
      }
    };
  })();
  
  app.post('/module-xml-safe', (req, res) => {
    safeXmlModule.process(req);
    res.send('Processing with safe module pattern');
  });
}
// {/fact}

// Start the server
app.listen(3000, () => {
  console.log('Server running on port 3000');
});