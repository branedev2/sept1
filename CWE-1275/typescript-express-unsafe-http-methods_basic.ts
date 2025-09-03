// Filename: express_unsafe_http_methods.ts
import express, { Request, Response, Router, NextFunction } from 'express';
import bodyParser from 'body-parser';

// TRUE POSITIVES - Vulnerable code examples that should be detected

// Example 1: Using app.all() for user authentication
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  // ruleid: typescript-express-unsafe-http-methods
  app.all('/login', (req: Request, res: Response) => {
    const { username, password } = req.body;
    // Authentication logic
    if (username === 'admin' && password === 'password') {
      res.send('Logged in successfully');
    } else {
      res.status(401).send('Authentication failed');
    }
  });
  
  app.listen(3000);
}
// {/fact}

// Example 2: Using Router.all() for API endpoint
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  const router = express.Router();
  
  // ruleid: typescript-express-unsafe-http-methods
  router.all('/api/data', (req: Request, res: Response) => {
    if (req.method === 'GET') {
      res.json({ data: 'Here is your data' });
    } else if (req.method === 'POST') {
      // Process the data
      res.json({ status: 'Data saved' });
    } else if (req.method === 'DELETE') {
      // Delete the data
      res.json({ status: 'Data deleted' });
    }
  });
  
  app.use(router);
  app.listen(3000);
}
// {/fact}

// Example 3: Using app.route().all() for user profile
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  // ruleid: typescript-express-unsafe-http-methods
  app.route('/profile')
    .all((req: Request, res: Response, next: NextFunction) => {
      console.log('Accessing profile');
      next();
    })
    .get((req: Request, res: Response) => {
      res.send('Get profile');
    })
    .post((req: Request, res: Response) => {
      res.send('Update profile');
    });
  
  app.listen(3000);
}
// {/fact}

// Example 4: Using Router.route().all() for product management
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  const router = express.Router();
  
  // ruleid: typescript-express-unsafe-http-methods
  router.route('/products')
    .all((req: Request, res: Response, next: NextFunction) => {
      console.log('Product API accessed');
      next();
    })
    .get((req: Request, res: Response) => {
      res.json({ products: ['Product1', 'Product2'] });
    })
    .post((req: Request, res: Response) => {
      res.json({ status: 'Product added' });
    });
  
  app.use('/api', router);
  app.listen(3000);
}
// {/fact}

// Example 5: Using app.all() for CSRF-vulnerable endpoint
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  // ruleid: typescript-express-unsafe-http-methods
  app.all('/transfer', (req: Request, res: Response) => {
    const { to, amount } = req.query;
    // This is vulnerable to CSRF since GET can also trigger the transfer
    res.send(`Transferred ${amount} to ${to}`);
  });
  
  app.listen(3000);
}
// {/fact}

// Example 6: Using Router.all() with middleware for admin operations
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  const adminRouter = express.Router();
  
  const authMiddleware = (req: Request, res: Response, next: NextFunction) => {
    // Authentication logic
    next();
  };
  
  // ruleid: typescript-express-unsafe-http-methods
  adminRouter.all('/settings', authMiddleware, (req: Request, res: Response) => {
    if (req.method === 'GET') {
      res.json({ settings: { theme: 'dark' } });
    } else if (req.method === 'PUT') {
      // Update settings
      res.json({ status: 'Settings updated' });
    }
  });
  
  app.use('/admin', adminRouter);
  app.listen(3000);
}
// {/fact}

// Example 7: Using app.all() for file operations
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  // ruleid: typescript-express-unsafe-http-methods
  app.all('/files/:filename', (req: Request, res: Response) => {
    const { filename } = req.params;
    
    if (req.method === 'GET') {
      res.send(`Serving file: ${filename}`);
    } else if (req.method === 'DELETE') {
      res.send(`Deleted file: ${filename}`);
    } else if (req.method === 'PUT') {
      res.send(`Updated file: ${filename}`);
    }
  });
  
  app.listen(3000);
}
// {/fact}

// Example 8: Using Router.route().all() for user management
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  const userRouter = express.Router();
  
  // ruleid: typescript-express-unsafe-http-methods
  userRouter.route('/users/:id')
    .all((req: Request, res: Response, next: NextFunction) => {
      console.log(`Accessing user ${req.params.id}`);
      next();
    })
    .get((req: Request, res: Response) => {
      res.send(`User ${req.params.id} details`);
    })
    .put((req: Request, res: Response) => {
      res.send(`Updated user ${req.params.id}`);
    })
    .delete((req: Request, res: Response) => {
      res.send(`Deleted user ${req.params.id}`);
    });
  
  app.use('/api', userRouter);
  app.listen(3000);
}
// {/fact}

// Example 9: Using app.all() for payment processing
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  app.use(bodyParser.json());
  
  // ruleid: typescript-express-unsafe-http-methods
  app.all('/payment', (req: Request, res: Response) => {
    const { amount, cardNumber } = req.body;
    
    if (req.method === 'POST') {
      res.json({ status: 'Payment processed', amount });
    } else if (req.method === 'GET') {
      // This could leak payment information
      res.json({ lastPayment: { amount, cardNumber: '****' + cardNumber.slice(-4) } });
    }
  });
  
  app.listen(3000);
}
// {/fact}

// Example 10: Using Router.all() for comment management
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  const router = express.Router();
  
  // ruleid: typescript-express-unsafe-http-methods
  router.all('/posts/:postId/comments', (req: Request, res: Response) => {
    const { postId } = req.params;
    
    if (req.method === 'GET') {
      res.json({ comments: [`Comment 1 for post ${postId}`, `Comment 2 for post ${postId}`] });
    } else if (req.method === 'POST') {
      const { text } = req.body;
      res.json({ status: 'Comment added', postId, text });
    } else if (req.method === 'DELETE') {
      res.json({ status: 'All comments deleted', postId });
    }
  });
  
  app.use(router);
  app.listen(3000);
}
// {/fact}

// Example 11: Using app.route().all() for subscription management
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  // ruleid: typescript-express-unsafe-http-methods
  app.route('/subscriptions/:id')
    .all((req: Request, res: Response, next: NextFunction) => {
      console.log(`Subscription ${req.params.id} accessed`);
      next();
    })
    .get((req: Request, res: Response) => {
      res.json({ subscription: { id: req.params.id, status: 'active' } });
    })
    .put((req: Request, res: Response) => {
      res.json({ status: 'Subscription updated', id: req.params.id });
    })
    .delete((req: Request, res: Response) => {
      res.json({ status: 'Subscription cancelled', id: req.params.id });
    });
  
  app.listen(3000);
}
// {/fact}

// Example 12: Using Router.route().all() for order processing
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  const orderRouter = express.Router();
  
  // ruleid: typescript-express-unsafe-http-methods
  orderRouter.route('/orders/:orderId')
    .all((req: Request, res: Response, next: NextFunction) => {
      console.log(`Order ${req.params.orderId} accessed via ${req.method}`);
      next();
    })
    .get((req: Request, res: Response) => {
      res.json({ order: { id: req.params.orderId, items: ['item1', 'item2'] } });
    })
    .put((req: Request, res: Response) => {
      res.json({ status: 'Order updated', id: req.params.orderId });
    })
    .delete((req: Request, res: Response) => {
      res.json({ status: 'Order cancelled', id: req.params.orderId });
    });
  
  app.use('/api', orderRouter);
  app.listen(3000);
}
// {/fact}

// Example 13: Using app.all() for webhook handling
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  app.use(bodyParser.json());
  
  // ruleid: typescript-express-unsafe-http-methods
  app.all('/webhook', (req: Request, res: Response) => {
    const payload = req.body;
    
    console.log('Webhook received:', payload);
    res.status(200).send('Webhook received');
  });
  
  app.listen(3000);
}
// {/fact}

// Example 14: Using Router.all() for search functionality
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  const searchRouter = express.Router();
  
  // ruleid: typescript-express-unsafe-http-methods
  searchRouter.all('/search', (req: Request, res: Response) => {
    const query = req.query.q as string || '';
    
    if (req.method === 'GET') {
      res.json({ results: [`Result 1 for ${query}`, `Result 2 for ${query}`] });
    } else if (req.method === 'POST') {
      // Advanced search with filters in body
      const filters = req.body.filters;
      res.json({ results: [`Filtered result for ${query}`, `Another result for ${query}`], filters });
    }
  });
  
  app.use(searchRouter);
  app.listen(3000);
}
// {/fact}

// Example 15: Using app.all() for authentication middleware
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  // ruleid: typescript-express-unsafe-http-methods
  app.all('*', (req: Request, res: Response, next: NextFunction) => {
    const token = req.headers.authorization;
    
    if (!token) {
      return res.status(401).send('Authentication required');
    }
    
    // Validate token
    if (token === 'valid-token') {
      next();
    } else {
      res.status(403).send('Invalid token');
    }
  });
  
  app.get('/protected', (req: Request, res: Response) => {
    res.send('Protected resource');
  });
  
  app.listen(3000);
}
// {/fact}

// TRUE NEGATIVES - Secure code examples that should not be detected

// Example 1: Using specific HTTP methods for login
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_1() {
  const app = express();
  app.use(bodyParser.json());
  
  // ok: typescript-express-unsafe-http-methods
  app.get('/login', (req: Request, res: Response) => {
    res.send('Login form');
  });
  
  // ok: typescript-express-unsafe-http-methods
  app.post('/login', (req: Request, res: Response) => {
    const { username, password } = req.body;
    // Authentication logic
    if (username === 'admin' && password === 'password') {
      res.send('Logged in successfully');
    } else {
      res.status(401).send('Authentication failed');
    }
  });
  
  app.listen(3000);
}
// {/fact}

// Example 2: Using specific HTTP methods with Router
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_2() {
  const app = express();
  const router = express.Router();
  
  // ok: typescript-express-unsafe-http-methods
  router.get('/api/data', (req: Request, res: Response) => {
    res.json({ data: 'Here is your data' });
  });
  
  // ok: typescript-express-unsafe-http-methods
  router.post('/api/data', (req: Request, res: Response) => {
    // Process the data
    res.json({ status: 'Data saved' });
  });
  
  // ok: typescript-express-unsafe-http-methods
  router.delete('/api/data', (req: Request, res: Response) => {
    // Delete the data
    res.json({ status: 'Data deleted' });
  });
  
  app.use(router);
  app.listen(3000);
}
// {/fact}

// Example 3: Using app.route() with specific methods
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  // ok: typescript-express-unsafe-http-methods
  app.route('/profile')
    .get((req: Request, res: Response) => {
      res.send('Get profile');
    })
    .post((req: Request, res: Response) => {
      res.send('Update profile');
    });
  
  app.listen(3000);
}
// {/fact}

// Example 4: Using Router.route() with specific methods
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_4() {
  const app = express();
  const router = express.Router();
  
  // ok: typescript-express-unsafe-http-methods
  router.route('/products')
    .get((req: Request, res: Response) => {
      res.json({ products: ['Product1', 'Product2'] });
    })
    .post((req: Request, res: Response) => {
      res.json({ status: 'Product added' });
    });
  
  app.use('/api', router);
  app.listen(3000);
}
// {/fact}

// Example 5: Using specific HTTP methods for money transfer
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  // ok: typescript-express-unsafe-http-methods
  app.get('/transfer', (req: Request, res: Response) => {
    res.send('Transfer form');
  });
  
  // ok: typescript-express-unsafe-http-methods
  app.post('/transfer', (req: Request, res: Response) => {
    const { to, amount } = req.body;
    // Process transfer
    res.send(`Transferred ${amount} to ${to}`);
  });
  
  app.listen(3000);
}
// {/fact}

// Example 6: Using specific HTTP methods with middleware for admin operations
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_6() {
  const app = express();
  const adminRouter = express.Router();
  
  const authMiddleware = (req: Request, res: Response, next: NextFunction) => {
    // Authentication logic
    next();
  };
  
  // ok: typescript-express-unsafe-http-methods
  adminRouter.get('/settings', authMiddleware, (req: Request, res: Response) => {
    res.json({ settings: { theme: 'dark' } });
  });
  
  // ok: typescript-express-unsafe-http-methods
  adminRouter.put('/settings', authMiddleware, (req: Request, res: Response) => {
    // Update settings
    res.json({ status: 'Settings updated' });
  });
  
  app.use('/admin', adminRouter);
  app.listen(3000);
}
// {/fact}

// Example 7: Using specific HTTP methods for file operations
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  // ok: typescript-express-unsafe-http-methods
  app.get('/files/:filename', (req: Request, res: Response) => {
    const { filename } = req.params;
    res.send(`Serving file: ${filename}`);
  });
  
  // ok: typescript-express-unsafe-http-methods
  app.delete('/files/:filename', (req: Request, res: Response) => {
    const { filename } = req.params;
    res.send(`Deleted file: ${filename}`);
  });
  
  // ok: typescript-express-unsafe-http-methods
  app.put('/files/:filename', (req: Request, res: Response) => {
    const { filename } = req.params;
    res.send(`Updated file: ${filename}`);
  });
  
  app.listen(3000);
}
// {/fact}

// Example 8: Using Router.route() with specific methods for user management
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_8() {
  const app = express();
  const userRouter = express.Router();
  
  // ok: typescript-express-unsafe-http-methods
  userRouter.route('/users/:id')
    .get((req: Request, res: Response) => {
      res.send(`User ${req.params.id} details`);
    })
    .put((req: Request, res: Response) => {
      res.send(`Updated user ${req.params.id}`);
    })
    .delete((req: Request, res: Response) => {
      res.send(`Deleted user ${req.params.id}`);
    });
  
  app.use('/api', userRouter);
  app.listen(3000);
}
// {/fact}

// Example 9: Using specific HTTP methods for payment processing
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_9() {
  const app = express();
  app.use(bodyParser.json());
  
  // ok: typescript-express-unsafe-http-methods
  app.post('/payment', (req: Request, res: Response) => {
    const { amount, cardNumber } = req.body;
    res.json({ status: 'Payment processed', amount });
  });
  
  // ok: typescript-express-unsafe-http-methods
  app.get('/payment/history', (req: Request, res: Response) => {
    // Get payment history
    res.json({ payments: [{ amount: 100, date: '2023-01-01' }] });
  });
  
  app.listen(3000);
}
// {/fact}

// Example 10: Using specific HTTP methods for comment management
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_10() {
  const app = express();
  const router = express.Router();
  app.use(bodyParser.json());
  
  // ok: typescript-express-unsafe-http-methods
  router.get('/posts/:postId/comments', (req: Request, res: Response) => {
    const { postId } = req.params;
    res.json({ comments: [`Comment 1 for post ${postId}`, `Comment 2 for post ${postId}`] });
  });
  
  // ok: typescript-express-unsafe-http-methods
  router.post('/posts/:postId/comments', (req: Request, res: Response) => {
    const { postId } = req.params;
    const { text } = req.body;
    res.json({ status: 'Comment added', postId, text });
  });
  
  // ok: typescript-express-unsafe-http-methods
  router.delete('/posts/:postId/comments', (req: Request, res: Response) => {
    const { postId } = req.params;
    res.json({ status: 'All comments deleted', postId });
  });
  
  app.use(router);
  app.listen(3000);
}
// {/fact}

// Example 11: Using app.route() with specific methods for subscription management
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  // ok: typescript-express-unsafe-http-methods
  app.route('/subscriptions/:id')
    .get((req: Request, res: Response) => {
      res.json({ subscription: { id: req.params.id, status: 'active' } });
    })
    .put((req: Request, res: Response) => {
      res.json({ status: 'Subscription updated', id: req.params.id });
    })
    .delete((req: Request, res: Response) => {
      res.json({ status: 'Subscription cancelled', id: req.params.id });
    });
  
  app.listen(3000);
}
// {/fact}

// Example 12: Using Router.route() with specific methods for order processing
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_12() {
  const app = express();
  const orderRouter = express.Router();
  
  // ok: typescript-express-unsafe-http-methods
  orderRouter.route('/orders/:orderId')
    .get((req: Request, res: Response) => {
      res.json({ order: { id: req.params.orderId, items: ['item1', 'item2'] } });
    })
    .put((req: Request, res: Response) => {
      res.json({ status: 'Order updated', id: req.params.orderId });
    })
    .delete((req: Request, res: Response) => {
      res.json({ status: 'Order cancelled', id: req.params.orderId });
    });
  
  app.use('/api', orderRouter);
  app.listen(3000);
}
// {/fact}

// Example 13: Using specific HTTP methods for webhook handling
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_13() {
  const app = express();
  app.use(bodyParser.json());
  
  // ok: typescript-express-unsafe-http-methods
  app.post('/webhook', (req: Request, res: Response) => {
    const payload = req.body;
    
    console.log('Webhook received:', payload);
    res.status(200).send('Webhook received');
  });
  
  app.listen(3000);
}
// {/fact}

// Example 14: Using specific HTTP methods for search functionality
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_14() {
  const app = express();
  const searchRouter = express.Router();
  app.use(bodyParser.json());
  
  // ok: typescript-express-unsafe-http-methods
  searchRouter.get('/search', (req: Request, res: Response) => {
    const query = req.query.q as string || '';
    res.json({ results: [`Result 1 for ${query}`, `Result 2 for ${query}`] });
  });
  
  // ok: typescript-express-unsafe-http-methods
  searchRouter.post('/search', (req: Request, res: Response) => {
    const query = req.query.q as string || '';
    const filters = req.body.filters;
    res.json({ results: [`Filtered result for ${query}`, `Another result for ${query}`], filters });
  });
  
  app.use(searchRouter);
  app.listen(3000);
}
// {/fact}

// Example 15: Using middleware with specific HTTP methods
// {fact rule=sensitive-cookie-with-improper-same-site-attribute@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  const authMiddleware = (req: Request, res: Response, next: NextFunction) => {
    const token = req.headers.authorization;
    
    if (!token) {
      return res.status(401).send('Authentication required');
    }
    
    // Validate token
    if (token === 'valid-token') {
      next();
    } else {
      res.status(403).send('Invalid token');
    }
  };
  
  // ok: typescript-express-unsafe-http-methods
  app.get('/protected', authMiddleware, (req: Request, res: Response) => {
    res.send('Protected resource');
  });
  
  // ok: typescript-express-unsafe-http-methods
  app.post('/protected', authMiddleware, (req: Request, res: Response) => {
    res.send('Resource updated');
  });
  
  app.listen(3000);
}
// {/fact}

export {
  bad_case_1, bad_case_2, bad_case_3, bad_case_4, bad_case_5,
  bad_case_6, bad_case_7, bad_case_8, bad_case_9, bad_case_10,
  bad_case_11, bad_case_12, bad_case_13, bad_case_14, bad_case_15,
  good_case_1, good_case_2, good_case_3, good_case_4, good_case_5,
  good_case_6, good_case_7, good_case_8, good_case_9, good_case_10,
  good_case_11, good_case_12, good_case_13, good_case_14, good_case_15
};