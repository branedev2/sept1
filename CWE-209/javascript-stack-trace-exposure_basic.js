const express = require('express');
const app = express();
app.use(express.json());

// True Positive Examples (Vulnerable Code)

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  app.get('/api/data', (req, res) => {
    try {
      const id = req.query.id;
      if (!id) {
        throw new Error('ID is required');
      }
      // Process data...
    } catch (error) {
      // ruleid: javascript-stack-trace-exposure
      res.status(500).send(`Error: ${error.stack}`);
    }
  });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  app.post('/process', (req, res) => {
    try {
      const data = JSON.parse(req.body.data);
      // Process data...
      if (!data.valid) {
        throw new Error('Invalid data format');
      }
    } catch (error) {
      // ruleid: javascript-stack-trace-exposure
      res.status(500).json({ error: error.toString(), stack: error.stack });
    }
  });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_3() {
  const http = require('http');
  
  http.createServer((req, res) => {
    try {
      if (req.url === '/error') {
        throw new Error('Simulated error');
      }
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('Success');
    } catch (error) {
      // ruleid: javascript-stack-trace-exposure
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end(`Server Error: ${error.stack}`);
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  app.use((err, req, res, next) => {
    console.error(err);
    // ruleid: javascript-stack-trace-exposure
    res.status(500).send(`<html><body><h1>Error</h1><pre>${err.stack}</pre></body></html>`);
  });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  app.get('/user/:id', (req, res) => {
    try {
      const userId = req.params.id;
      if (isNaN(parseInt(userId))) {
        throw new Error('Invalid user ID');
      }
      // Process user...
    } catch (error) {
      const errorResponse = {
        message: 'Failed to get user',
        details: error.message,
        // ruleid: javascript-stack-trace-exposure
        trace: error.stack.split('\n')
      };
      res.status(500).json(errorResponse);
    }
  });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_6() {
  const fastify = require('fastify')();
  
  fastify.get('/products', async (request, reply) => {
    try {
      const category = request.query.category;
      if (!category) {
        throw new Error('Category parameter is required');
      }
      // Get products...
    } catch (err) {
      // ruleid: javascript-stack-trace-exposure
      reply.code(500).send(`Failed to get products: ${err.stack}`);
    }
  });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  app.get('/search', (req, res) => {
    try {
      const query = req.query.q;
      if (!query || query.length < 3) {
        throw new Error('Search query must be at least 3 characters');
      }
      // Perform search...
    } catch (error) {
      const debugMode = true; // This would typically be an environment variable
      if (debugMode) {
        // ruleid: javascript-stack-trace-exposure
        res.status(400).send(`Error in search: ${error.stack}`);
      } else {
        res.status(400).send('Invalid search query');
      }
    }
  });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_8() {
  const Koa = require('koa');
  const app = new Koa();
  
  app.use(async (ctx, next) => {
    try {
      await next();
    } catch (err) {
      ctx.status = 500;
      // ruleid: javascript-stack-trace-exposure
      ctx.body = `Server Error: ${err.stack}`;
    }
  });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  app.post('/upload', (req, res) => {
    try {
      if (!req.files || Object.keys(req.files).length === 0) {
        throw new Error('No files were uploaded');
      }
      // Process file upload...
    } catch (error) {
      const errorLog = {
        timestamp: new Date(),
        message: error.message,
        // ruleid: javascript-stack-trace-exposure
        stackTrace: error.stack
      };
      console.error(errorLog);
      res.status(500).json(errorLog);
    }
  });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  app.get('/api/report', (req, res) => {
    try {
      const reportId = req.query.id;
      if (!reportId) {
        throw new Error('Report ID is required');
      }
      // Generate report...
    } catch (error) {
      // ruleid: javascript-stack-trace-exposure
      res.status(500).send(`
        <div class="error-container">
          <h2>Error Generating Report</h2>
          <div class="error-details">
            <pre>${error.stack}</pre>
          </div>
        </div>
      `);
    }
  });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_11() {
  const WebSocket = require('ws');
  const wss = new WebSocket.Server({ port: 8080 });
  
  wss.on('connection', (ws) => {
    ws.on('message', (message) => {
      try {
        const data = JSON.parse(message);
        // Process message...
        if (!data.action) {
          throw new Error('Action is required');
        }
      } catch (error) {
        // ruleid: javascript-stack-trace-exposure
        ws.send(JSON.stringify({
          type: 'error',
          message: error.message,
          stack: error.stack
        }));
      }
    });
  });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  app.get('/api/health', (req, res) => {
    try {
      // Check system health...
      const dbStatus = checkDatabaseConnection();
      if (!dbStatus.connected) {
        throw new Error('Database connection failed');
      }
      res.json({ status: 'ok' });
    } catch (error) {
      // Log the error for internal use
      console.error('Health check failed:', error);
      
      // ruleid: javascript-stack-trace-exposure
      res.status(500).json({
        status: 'error',
        error: {
          message: error.message,
          time: new Date().toISOString(),
          trace: error.stack
        }
      });
    }
  });
  
  function checkDatabaseConnection() {
    // Mock implementation
    return { connected: false };
  }
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  app.get('/debug', (req, res) => {
    try {
      const section = req.query.section;
      if (!section) {
        throw new Error('Section parameter is required');
      }
      // Get debug info...
    } catch (error) {
      const adminToken = req.headers['admin-token'];
      // Even with token validation, exposing stack traces is risky
      if (adminToken === 'secret-admin-token') {
        // ruleid: javascript-stack-trace-exposure
        res.status(500).json({
          error: error.message,
          stack: error.stack,
          timestamp: Date.now()
        });
      } else {
        res.status(500).send('An error occurred');
      }
    }
  });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  app.use((req, res, next) => {
    res.renderError = (error) => {
      // ruleid: javascript-stack-trace-exposure
      res.status(500).render('error', {
        message: error.message,
        stack: process.env.NODE_ENV === 'development' ? error.stack : null
      });
    };
    next();
  });
  
  app.get('/profile', (req, res) => {
    try {
      const userId = req.query.id;
      if (!userId) {
        throw new Error('User ID is required');
      }
      // Get user profile...
    } catch (error) {
      res.renderError(error);
    }
  });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  app.get('/api/config', (req, res) => {
    try {
      const configName = req.query.name;
      if (!configName) {
        throw new Error('Config name is required');
      }
      // Get configuration...
    } catch (error) {
      // Creating a custom error object but still exposing stack trace
      const errorResponse = {
        status: 'error',
        code: 500,
        message: 'Failed to retrieve configuration',
        // ruleid: javascript-stack-trace-exposure
        details: error.stack.split('\n').map(line => line.trim())
      };
      res.status(500).json(errorResponse);
    }
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  app.get('/api/data', (req, res) => {
    try {
      const id = req.query.id;
      if (!id) {
        throw new Error('ID is required');
      }
      // Process data...
    } catch (error) {
      console.error('Error processing request:', error);
      // ok: javascript-stack-trace-exposure
      res.status(500).send('An internal server error occurred');
    }
  });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  app.post('/process', (req, res) => {
    try {
      const data = JSON.parse(req.body.data);
      // Process data...
      if (!data.valid) {
        throw new Error('Invalid data format');
      }
    } catch (error) {
      console.error('Processing error:', error);
      // ok: javascript-stack-trace-exposure
      res.status(500).json({ error: 'Failed to process data' });
    }
  });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_3() {
  const http = require('http');
  
  http.createServer((req, res) => {
    try {
      if (req.url === '/error') {
        throw new Error('Simulated error');
      }
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('Success');
    } catch (error) {
      console.error('Server error:', error);
      // ok: javascript-stack-trace-exposure
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('Internal Server Error');
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  app.use((err, req, res, next) => {
    console.error('Application error:', err);
    // ok: javascript-stack-trace-exposure
    res.status(500).send(`<html><body><h1>Error</h1><p>An unexpected error occurred</p></body></html>`);
  });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  app.get('/user/:id', (req, res) => {
    try {
      const userId = req.params.id;
      if (isNaN(parseInt(userId))) {
        throw new Error('Invalid user ID');
      }
      // Process user...
    } catch (error) {
      console.error('User retrieval error:', error);
      // ok: javascript-stack-trace-exposure
      const errorResponse = {
        message: 'Failed to get user',
        errorCode: 'INVALID_USER_ID'
      };
      res.status(400).json(errorResponse);
    }
  });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_6() {
  const fastify = require('fastify')();
  
  fastify.get('/products', async (request, reply) => {
    try {
      const category = request.query.category;
      if (!category) {
        throw new Error('Category parameter is required');
      }
      // Get products...
    } catch (err) {
      console.error('Products error:', err);
      // ok: javascript-stack-trace-exposure
      reply.code(400).send('Failed to get products: Missing or invalid category');
    }
  });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  app.get('/search', (req, res) => {
    try {
      const query = req.query.q;
      if (!query || query.length < 3) {
        throw new Error('Search query must be at least 3 characters');
      }
      // Perform search...
    } catch (error) {
      console.error('Search error:', error);
      const debugMode = true; // This would typically be an environment variable
      
      // ok: javascript-stack-trace-exposure
      if (debugMode) {
        res.status(400).send('Error in search: Invalid query format or length');
      } else {
        res.status(400).send('Invalid search query');
      }
    }
  });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_8() {
  const Koa = require('koa');
  const app = new Koa();
  
  app.use(async (ctx, next) => {
    try {
      await next();
    } catch (err) {
      console.error('Koa server error:', err);
      ctx.status = 500;
      // ok: javascript-stack-trace-exposure
      ctx.body = 'Internal Server Error';
    }
  });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  app.post('/upload', (req, res) => {
    try {
      if (!req.files || Object.keys(req.files).length === 0) {
        throw new Error('No files were uploaded');
      }
      // Process file upload...
    } catch (error) {
      console.error('File upload error:', error);
      const errorLog = {
        timestamp: new Date(),
        message: 'File upload failed',
        errorCode: 'UPLOAD_ERROR'
      };
      
      // ok: javascript-stack-trace-exposure
      res.status(400).json({
        error: 'File upload failed',
        details: 'Please ensure you have selected a file'
      });
    }
  });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  app.get('/api/report', (req, res) => {
    try {
      const reportId = req.query.id;
      if (!reportId) {
        throw new Error('Report ID is required');
      }
      // Generate report...
    } catch (error) {
      console.error('Report generation error:', error);
      // ok: javascript-stack-trace-exposure
      res.status(400).send(`
        <div class="error-container">
          <h2>Error Generating Report</h2>
          <div class="error-details">
            <p>Unable to generate report. Please check the report ID and try again.</p>
          </div>
        </div>
      `);
    }
  });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_11() {
  const WebSocket = require('ws');
  const wss = new WebSocket.Server({ port: 8080 });
  
  wss.on('connection', (ws) => {
    ws.on('message', (message) => {
      try {
        const data = JSON.parse(message);
        // Process message...
        if (!data.action) {
          throw new Error('Action is required');
        }
      } catch (error) {
        console.error('WebSocket message error:', error);
        // ok: javascript-stack-trace-exposure
        ws.send(JSON.stringify({
          type: 'error',
          message: 'Invalid message format or missing required fields'
        }));
      }
    });
  });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  app.get('/api/health', (req, res) => {
    try {
      // Check system health...
      const dbStatus = checkDatabaseConnection();
      if (!dbStatus.connected) {
        throw new Error('Database connection failed');
      }
      res.json({ status: 'ok' });
    } catch (error) {
      // Log the error for internal use
      console.error('Health check failed:', error);
      
      // ok: javascript-stack-trace-exposure
      res.status(500).json({
        status: 'error',
        message: 'System health check failed',
        component: 'database',
        time: new Date().toISOString()
      });
    }
  });
  
  function checkDatabaseConnection() {
    // Mock implementation
    return { connected: false };
  }
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  app.get('/debug', (req, res) => {
    try {
      const section = req.query.section;
      if (!section) {
        throw new Error('Section parameter is required');
      }
      // Get debug info...
    } catch (error) {
      console.error('Debug info error:', error);
      const adminToken = req.headers['admin-token'];
      
      // ok: javascript-stack-trace-exposure
      if (adminToken === 'secret-admin-token') {
        res.status(400).json({
          error: 'Invalid section parameter',
          validSections: ['system', 'network', 'database'],
          timestamp: Date.now()
        });
      } else {
        res.status(500).send('An error occurred');
      }
    }
  });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  app.use((req, res, next) => {
    res.renderError = (error) => {
      console.error('Render error:', error);
      // ok: javascript-stack-trace-exposure
      res.status(500).render('error', {
        message: 'An error occurred while processing your request',
        supportId: generateSupportId()
      });
    };
    next();
  });
  
  app.get('/profile', (req, res) => {
    try {
      const userId = req.query.id;
      if (!userId) {
        throw new Error('User ID is required');
      }
      // Get user profile...
    } catch (error) {
      res.renderError(error);
    }
  });
  
  function generateSupportId() {
    return `ERR-${Date.now().toString(36)}-${Math.random().toString(36).substr(2, 5)}`;
  }
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  app.get('/api/config', (req, res) => {
    try {
      const configName = req.query.name;
      if (!configName) {
        throw new Error('Config name is required');
      }
      // Get configuration...
    } catch (error) {
      console.error('Configuration error:', error);
      // Creating a custom error object without exposing stack trace
      // ok: javascript-stack-trace-exposure
      const errorResponse = {
        status: 'error',
        code: 400,
        message: 'Failed to retrieve configuration',
        details: 'Configuration name is required'
      };
      res.status(400).json(errorResponse);
    }
  });
}
// {/fact}