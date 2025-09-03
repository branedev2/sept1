// csrf-protection-examples.ts
import express from 'express';
import axios from 'axios';
import fetch from 'node-fetch';
import request from 'request';
import superagent from 'superagent';
import got from 'got';
import csrf from 'csurf';
import cookieParser from 'cookie-parser';
import bodyParser from 'body-parser';

// True Positive Examples (Vulnerable Code)

// Example 1: Basic Express POST request without CSRF protection
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  app.use(bodyParser.json());
  
  // ruleid: csrf-protection-missing-ts-rule
  app.post('/api/user', (req, res) => {
    const { username, email } = req.body;
    // Process user data and update database
    res.json({ success: true });
  });
}
// {/fact}

// Example 2: Express PUT request without CSRF protection
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  app.use(bodyParser.urlencoded({ extended: true }));
  
  // ruleid: csrf-protection-missing-ts-rule
  app.put('/api/profile/:id', (req, res) => {
    const userId = req.params.id;
    const { name, bio } = req.body;
    // Update user profile
    res.json({ updated: true });
  });
}
// {/fact}

// Example 3: Express DELETE request without CSRF protection
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  // ruleid: csrf-protection-missing-ts-rule
  app.delete('/api/posts/:id', (req, res) => {
    const postId = req.params.id;
    // Delete post from database
    res.json({ deleted: true });
  });
}
// {/fact}

// Example 4: Using Axios for POST request without CSRF token
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_4() {
  const updateUserData = async (userData: any) => {
    // ruleid: csrf-protection-missing-ts-rule
    const response = await axios.post('https://api.example.com/users', userData);
    return response.data;
  };
}
// {/fact}

// Example 5: Using Fetch API for PUT request without CSRF token
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_5() {
  const updateArticle = async (articleId: string, content: string) => {
    // ruleid: csrf-protection-missing-ts-rule
    const response = await fetch(`https://api.example.com/articles/${articleId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ content })
    });
    return response.json();
  };
}
// {/fact}

// Example 6: Using Request library for DELETE without CSRF token
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_6() {
  const deleteComment = (commentId: string) => {
    // ruleid: csrf-protection-missing-ts-rule
    request.delete(`https://api.example.com/comments/${commentId}`, (error, response, body) => {
      if (error) console.error(error);
      console.log(body);
    });
  };
}
// {/fact}

// Example 7: Using Superagent for POST without CSRF token
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_7() {
  const createOrder = async (orderData: any) => {
    // ruleid: csrf-protection-missing-ts-rule
    const response = await superagent
      .post('https://api.example.com/orders')
      .send(orderData);
    return response.body;
  };
}
// {/fact}

// Example 8: Using Got for PUT without CSRF token
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_8() {
  const updateSettings = async (settings: any) => {
    // ruleid: csrf-protection-missing-ts-rule
    const response = await got.put('https://api.example.com/settings', {
      json: settings,
      responseType: 'json'
    });
    return response.body;
  };
}
// {/fact}

// Example 9: Express router with POST endpoint without CSRF protection
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_9() {
  const router = express.Router();
  
  // ruleid: csrf-protection-missing-ts-rule
  router.post('/checkout', (req, res) => {
    const { items, paymentInfo } = req.body;
    // Process checkout
    res.json({ orderId: '12345' });
  });
}
// {/fact}

// Example 10: Express app with multiple unprotected routes
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  app.use(bodyParser.json());
  
  // ruleid: csrf-protection-missing-ts-rule
  app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    // Authenticate user
    res.json({ token: 'jwt-token' });
  });
  
  // ruleid: csrf-protection-missing-ts-rule
  app.put('/api/password', (req, res) => {
    const { oldPassword, newPassword } = req.body;
    // Update password
    res.json({ updated: true });
  });
}
// {/fact}

// Example 11: Using XMLHttpRequest for POST without CSRF token
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_11() {
  const submitForm = (formData: any) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', 'https://api.example.com/submit', true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    
    // ruleid: csrf-protection-missing-ts-rule
    xhr.send(JSON.stringify(formData));
  };
}
// {/fact}

// Example 12: Express subapp without CSRF protection
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_12() {
  const mainApp = express();
  const apiApp = express();
  
  // ruleid: csrf-protection-missing-ts-rule
  apiApp.post('/users', (req, res) => {
    // Create user
    res.json({ userId: '12345' });
  });
  
  mainApp.use('/api', apiApp);
}
// {/fact}

// Example 13: Class-based API client without CSRF protection
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_13() {
  class ApiClient {
    baseUrl: string;
    
    constructor(baseUrl: string) {
      this.baseUrl = baseUrl;
    }
    
    async createResource(data: any) {
      // ruleid: csrf-protection-missing-ts-rule
      const response = await fetch(`${this.baseUrl}/resources`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
      });
      return response.json();
    }
    
    async updateResource(id: string, data: any) {
      // ruleid: csrf-protection-missing-ts-rule
      const response = await fetch(`${this.baseUrl}/resources/${id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
      });
      return response.json();
    }
  }
}
// {/fact}

// Example 14: Using async/await with axios without CSRF token
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_14() {
  const processPayment = async (paymentDetails: any) => {
    try {
      // ruleid: csrf-protection-missing-ts-rule
      const result = await axios.post('https://payment.example.com/process', paymentDetails);
      return { success: true, transactionId: result.data.id };
    } catch (error) {
      return { success: false, error: error.message };
    }
  };
}
// {/fact}

// Example 15: Express middleware chain without CSRF protection
// {fact rule=coral-csrf-rule@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  const validateInput = (req: any, res: any, next: any) => {
    if (!req.body.name) {
      return res.status(400).json({ error: 'Name is required' });
    }
    next();
  };
  
  const logRequest = (req: any, res: any, next: any) => {
    console.log(`Request to ${req.path} at ${new Date()}`);
    next();
  };
  
  // ruleid: csrf-protection-missing-ts-rule
  app.post('/api/register', logRequest, validateInput, (req, res) => {
    // Register user
    res.json({ userId: '12345' });
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// Example 1: Express POST with CSRF protection
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_1() {
  const app = express();
  app.use(cookieParser());
  app.use(bodyParser.urlencoded({ extended: true }));
  
  // ok: csrf-protection-missing-ts-rule
  app.use(csrf({ cookie: true }));
  
  app.post('/api/user', (req, res) => {
    const { username, email } = req.body;
    // Process user data and update database
    res.json({ success: true });
  });
}
// {/fact}

// Example 2: Express PUT with CSRF protection
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_2() {
  const app = express();
  app.use(bodyParser.json());
  app.use(cookieParser());
  
  // ok: csrf-protection-missing-ts-rule
  const csrfProtection = csrf({ cookie: true });
  
  app.put('/api/profile/:id', csrfProtection, (req, res) => {
    const userId = req.params.id;
    const { name, bio } = req.body;
    // Update user profile
    res.json({ updated: true });
  });
}
// {/fact}

// Example 3: Express DELETE with CSRF protection
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_3() {
  const app = express();
  app.use(cookieParser());
  
  // ok: csrf-protection-missing-ts-rule
  app.use(csrf({ cookie: { sameSite: 'strict' } }));
  
  app.delete('/api/posts/:id', (req, res) => {
    const postId = req.params.id;
    // Delete post from database
    res.json({ deleted: true });
  });
}
// {/fact}

// Example 4: Using Axios for POST with CSRF token
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_4() {
  const updateUserData = async (userData: any, csrfToken: string) => {
    // ok: csrf-protection-missing-ts-rule
    const response = await axios.post('https://api.example.com/users', userData, {
      headers: {
        'X-CSRF-Token': csrfToken
      }
    });
    return response.data;
  };
}
// {/fact}

// Example 5: Using Fetch API for PUT with CSRF token
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_5() {
  const updateArticle = async (articleId: string, content: string, csrfToken: string) => {
    // ok: csrf-protection-missing-ts-rule
    const response = await fetch(`https://api.example.com/articles/${articleId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken
      },
      body: JSON.stringify({ content })
    });
    return response.json();
  };
}
// {/fact}

// Example 6: Using Request library for DELETE with CSRF token
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_6() {
  const deleteComment = (commentId: string, csrfToken: string) => {
    // ok: csrf-protection-missing-ts-rule
    request.delete({
      url: `https://api.example.com/comments/${commentId}`,
      headers: {
        'X-CSRF-Token': csrfToken
      }
    }, (error, response, body) => {
      if (error) console.error(error);
      console.log(body);
    });
  };
}
// {/fact}

// Example 7: Using Superagent for POST with CSRF token
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_7() {
  const createOrder = async (orderData: any, csrfToken: string) => {
    // ok: csrf-protection-missing-ts-rule
    const response = await superagent
      .post('https://api.example.com/orders')
      .set('X-CSRF-Token', csrfToken)
      .send(orderData);
    return response.body;
  };
}
// {/fact}

// Example 8: Using Got for PUT with CSRF token
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_8() {
  const updateSettings = async (settings: any, csrfToken: string) => {
    // ok: csrf-protection-missing-ts-rule
    const response = await got.put('https://api.example.com/settings', {
      json: settings,
      headers: {
        'X-CSRF-Token': csrfToken
      },
      responseType: 'json'
    });
    return response.body;
  };
}
// {/fact}

// Example 9: Express router with POST endpoint with CSRF protection
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_9() {
  const router = express.Router();
  const csrfProtection = csrf({ cookie: true });
  
  // ok: csrf-protection-missing-ts-rule
  router.post('/checkout', csrfProtection, (req, res) => {
    const { items, paymentInfo } = req.body;
    // Process checkout
    res.json({ orderId: '12345' });
  });
}
// {/fact}

// Example 10: Express app with multiple protected routes
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_10() {
  const app = express();
  app.use(bodyParser.json());
  app.use(cookieParser());
  
  // ok: csrf-protection-missing-ts-rule
  const csrfProtection = csrf({ cookie: true });
  
  app.post('/api/login', csrfProtection, (req, res) => {
    const { username, password } = req.body;
    // Authenticate user
    res.json({ token: 'jwt-token' });
  });
  
  app.put('/api/password', csrfProtection, (req, res) => {
    const { oldPassword, newPassword } = req.body;
    // Update password
    res.json({ updated: true });
  });
}
// {/fact}

// Example 11: Using XMLHttpRequest for POST with CSRF token
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_11() {
  const submitForm = (formData: any, csrfToken: string) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', 'https://api.example.com/submit', true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    // ok: csrf-protection-missing-ts-rule
    xhr.setRequestHeader('X-CSRF-Token', csrfToken);
    xhr.send(JSON.stringify(formData));
  };
}
// {/fact}

// Example 12: Express subapp with CSRF protection
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_12() {
  const mainApp = express();
  const apiApp = express();
  
  apiApp.use(cookieParser());
  // ok: csrf-protection-missing-ts-rule
  apiApp.use(csrf({ cookie: true }));
  
  apiApp.post('/users', (req, res) => {
    // Create user
    res.json({ userId: '12345' });
  });
  
  mainApp.use('/api', apiApp);
}
// {/fact}

// Example 13: Class-based API client with CSRF protection
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_13() {
  class ApiClient {
    baseUrl: string;
    csrfToken: string;
    
    constructor(baseUrl: string, csrfToken: string) {
      this.baseUrl = baseUrl;
      this.csrfToken = csrfToken;
    }
    
    async createResource(data: any) {
      // ok: csrf-protection-missing-ts-rule
      const response = await fetch(`${this.baseUrl}/resources`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': this.csrfToken
        },
        body: JSON.stringify(data)
      });
      return response.json();
    }
    
    async updateResource(id: string, data: any) {
      // ok: csrf-protection-missing-ts-rule
      const response = await fetch(`${this.baseUrl}/resources/${id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': this.csrfToken
        },
        body: JSON.stringify(data)
      });
      return response.json();
    }
  }
}
// {/fact}

// Example 14: Using async/await with axios with CSRF token
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_14() {
  const processPayment = async (paymentDetails: any, csrfToken: string) => {
    try {
      // ok: csrf-protection-missing-ts-rule
      const result = await axios.post('https://payment.example.com/process', paymentDetails, {
        headers: {
          'X-CSRF-Token': csrfToken
        }
      });
      return { success: true, transactionId: result.data.id };
    } catch (error) {
      return { success: false, error: error.message };
    }
  };
}
// {/fact}

// Example 15: Express middleware chain with CSRF protection
// {fact rule=coral-csrf-rule@v1.0 defects=0}
function good_case_15() {
  const app = express();
  app.use(cookieParser());
  app.use(bodyParser.json());
  
  const validateInput = (req: any, res: any, next: any) => {
    if (!req.body.name) {
      return res.status(400).json({ error: 'Name is required' });
    }
    next();
  };
  
  const logRequest = (req: any, res: any, next: any) => {
    console.log(`Request to ${req.path} at ${new Date()}`);
    next();
  };
  
  // ok: csrf-protection-missing-ts-rule
  const csrfProtection = csrf({ cookie: true });
  
  app.post('/api/register', logRequest, csrfProtection, validateInput, (req, res) => {
    // Register user
    res.json({ userId: '12345' });
  });
}
// {/fact}