// Express bodyParser deprecation examples
const express = require('express');
const bodyParser = require('body-parser');
const app = express();

// True Positive Examples (Vulnerable/Deprecated Code)

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  // ruleid: javascript-express-bodyparser
  app.use(bodyParser.json());
  
  app.post('/api/users', (req, res) => {
    const user = req.body;
    res.json({ success: true, user });
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  // ruleid: javascript-express-bodyparser
  app.use(bodyParser.urlencoded({ extended: false }));
  
  app.post('/login', (req, res) => {
    const { username, password } = req.body;
    res.send(`Login attempt for ${username}`);
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  // ruleid: javascript-express-bodyparser
  app.use(bodyParser.raw({ type: 'application/octet-stream' }));
  
  app.post('/upload', (req, res) => {
    const data = req.body;
    res.send(`Received ${data.length} bytes`);
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  // ruleid: javascript-express-bodyparser
  app.use(bodyParser.text({ type: 'text/plain' }));
  
  app.post('/message', (req, res) => {
    const message = req.body;
    res.send(`Message received: ${message}`);
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  // ruleid: javascript-express-bodyparser
  const jsonParser = bodyParser.json();
  
  app.post('/api/data', jsonParser, (req, res) => {
    const data = req.body;
    res.json({ received: data });
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  // ruleid: javascript-express-bodyparser
  const urlencodedParser = bodyParser.urlencoded({ extended: true });
  
  app.post('/submit-form', urlencodedParser, (req, res) => {
    const formData = req.body;
    res.send(`Form submitted with ${Object.keys(formData).length} fields`);
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  const router = express.Router();
  
  // ruleid: javascript-express-bodyparser
  router.use(bodyParser.json());
  
  router.post('/items', (req, res) => {
    const item = req.body;
    res.json({ id: 123, ...item });
  });
  
  app.use('/api', router);
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  // ruleid: javascript-express-bodyparser
  app.use('/api', bodyParser.json());
  
  app.post('/api/products', (req, res) => {
    const product = req.body;
    res.json({ success: true, product });
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_9() {
  function setupAPI() {
    const app = express();
    // ruleid: javascript-express-bodyparser
    app.use(bodyParser.json({ limit: '10mb' }));
    
    app.post('/api/upload', (req, res) => {
      const data = req.body;
      res.json({ success: true, size: JSON.stringify(data).length });
    });
    
    return app;
  }
  
  const api = setupAPI();
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  if (process.env.ENABLE_JSON_PARSER === 'true') {
    // ruleid: javascript-express-bodyparser
    app.use(bodyParser.json());
  }
  
  app.post('/api/comments', (req, res) => {
    const comment = req.body;
    res.json({ success: true, comment });
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  const jsonOptions = { 
    limit: '1mb',
    strict: false
  };
  
  // ruleid: javascript-express-bodyparser
  app.use(bodyParser.json(jsonOptions));
  
  app.post('/api/feedback', (req, res) => {
    const feedback = req.body;
    res.json({ received: true, feedback });
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_12() {
  class ApiServer {
    constructor() {
      this.app = express();
      // ruleid: javascript-express-bodyparser
      this.app.use(bodyParser.json());
      this.app.use(bodyParser.urlencoded({ extended: true }));
    }
    
    start() {
      this.app.listen(3000);
    }
  }
  
  const server = new ApiServer();
  server.start();
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  const middleware = [
    // ruleid: javascript-express-bodyparser
    bodyParser.json(),
    bodyParser.urlencoded({ extended: true }),
    (req, res, next) => {
      console.log('Request received');
      next();
    }
  ];
  
  app.use(middleware);
  
  app.post('/api/users', (req, res) => {
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  function configureMiddleware(app) {
    // ruleid: javascript-express-bodyparser
    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({ extended: true }));
  }
  
  configureMiddleware(app);
  
  app.post('/api/orders', (req, res) => {
    const order = req.body;
    res.json({ orderId: 'ORD-123', ...order });
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  const parsers = {
    json: bodyParser.json(),
    urlencoded: bodyParser.urlencoded({ extended: true }),
    raw: bodyParser.raw()
  };
  
  // ruleid: javascript-express-bodyparser
  app.use(parsers.json);
  app.use(parsers.urlencoded);
  
  app.post('/api/data', (req, res) => {
    res.json({ success: true, data: req.body });
  });
}
// {/fact}

// True Negative Examples (Secure/Recommended Code)

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_1() {
  const app = express();
  // ok: javascript-express-bodyparser
  app.use(express.json());
  
  app.post('/api/users', (req, res) => {
    const user = req.body;
    res.json({ success: true, user });
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_2() {
  const app = express();
  // ok: javascript-express-bodyparser
  app.use(express.urlencoded({ extended: false }));
  
  app.post('/login', (req, res) => {
    const { username, password } = req.body;
    res.send(`Login attempt for ${username}`);
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_3() {
  const app = express();
  // ok: javascript-express-bodyparser
  app.use(express.json({ limit: '10mb' }));
  
  app.post('/api/upload', (req, res) => {
    const data = req.body;
    res.json({ success: true, size: JSON.stringify(data).length });
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_4() {
  const app = express();
  // ok: javascript-express-bodyparser
  app.use(express.urlencoded({ extended: true, limit: '2mb' }));
  
  app.post('/submit-form', (req, res) => {
    const formData = req.body;
    res.send(`Form submitted with ${Object.keys(formData).length} fields`);
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_5() {
  const app = express();
  // ok: javascript-express-bodyparser
  const jsonParser = express.json();
  
  app.post('/api/data', jsonParser, (req, res) => {
    const data = req.body;
    res.json({ received: data });
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_6() {
  const app = express();
  // ok: javascript-express-bodyparser
  const urlencodedParser = express.urlencoded({ extended: true });
  
  app.post('/submit-form', urlencodedParser, (req, res) => {
    const formData = req.body;
    res.send(`Form submitted with ${Object.keys(formData).length} fields`);
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_7() {
  const app = express();
  const router = express.Router();
  
  // ok: javascript-express-bodyparser
  router.use(express.json());
  
  router.post('/items', (req, res) => {
    const item = req.body;
    res.json({ id: 123, ...item });
  });
  
  app.use('/api', router);
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_8() {
  const app = express();
  // ok: javascript-express-bodyparser
  app.use('/api', express.json());
  
  app.post('/api/products', (req, res) => {
    const product = req.body;
    res.json({ success: true, product });
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_9() {
  function setupAPI() {
    const app = express();
    // ok: javascript-express-bodyparser
    app.use(express.json({ limit: '10mb' }));
    
    app.post('/api/upload', (req, res) => {
      const data = req.body;
      res.json({ success: true, size: JSON.stringify(data).length });
    });
    
    return app;
  }
  
  const api = setupAPI();
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  if (process.env.ENABLE_JSON_PARSER === 'true') {
    // ok: javascript-express-bodyparser
    app.use(express.json());
  }
  
  app.post('/api/comments', (req, res) => {
    const comment = req.body;
    res.json({ success: true, comment });
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_11() {
  const app = express();
  const jsonOptions = { 
    limit: '1mb',
    strict: false
  };
  
  // ok: javascript-express-bodyparser
  app.use(express.json(jsonOptions));
  
  app.post('/api/feedback', (req, res) => {
    const feedback = req.body;
    res.json({ received: true, feedback });
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_12() {
  class ApiServer {
    constructor() {
      this.app = express();
      // ok: javascript-express-bodyparser
      this.app.use(express.json());
      this.app.use(express.urlencoded({ extended: true }));
    }
    
    start() {
      this.app.listen(3000);
    }
  }
  
  const server = new ApiServer();
  server.start();
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  const middleware = [
    // ok: javascript-express-bodyparser
    express.json(),
    express.urlencoded({ extended: true }),
    (req, res, next) => {
      console.log('Request received');
      next();
    }
  ];
  
  app.use(middleware);
  
  app.post('/api/users', (req, res) => {
    res.json({ success: true });
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  function configureMiddleware(app) {
    // ok: javascript-express-bodyparser
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
  }
  
  configureMiddleware(app);
  
  app.post('/api/orders', (req, res) => {
    const order = req.body;
    res.json({ orderId: 'ORD-123', ...order });
  });
}
// {/fact}

// {fact rule=deprecated-method@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  const parsers = {
    json: express.json(),
    urlencoded: express.urlencoded({ extended: true })
  };
  
  // ok: javascript-express-bodyparser
  app.use(parsers.json);
  app.use(parsers.urlencoded);
  
  app.post('/api/data', (req, res) => {
    res.json({ success: true, data: req.body });
  });
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});