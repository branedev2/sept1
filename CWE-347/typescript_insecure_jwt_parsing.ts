import * as jwt from 'jsonwebtoken';
import * as express from 'express';
import { Request, Response } from 'express';

// True Positives (Vulnerable Code)

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_1() {
  const token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.";
  try {
    // ruleid: typescript_insecure_jwt_parsing
    const decoded = jwt.verify(token, "", { algorithms: ['none'] });
    console.log("Decoded:", decoded);
    return decoded;
  } catch (err) {
    console.error("Invalid token");
    return null;
  }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  
  app.get('/verify-token', (req: Request, res: Response) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    try {
      // ruleid: typescript_insecure_jwt_parsing
      const decoded = jwt.verify(token, null, { algorithms: ['none'] });
      return res.json({ user: decoded });
    } catch (err) {
      return res.status(401).json({ message: 'Invalid token' });
    }
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_3() {
  const token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.";
  
  // ruleid: typescript_insecure_jwt_parsing
  jwt.verify(token, undefined, { algorithms: ['none'] });
  
  return "Verification completed";
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  app.post('/auth', (req: Request, res: Response) => {
    const { token } = req.body;
    
    try {
      // ruleid: typescript_insecure_jwt_parsing
      const decoded = jwt.verify(token, false, { algorithms: ['none'] });
      return res.json({ success: true, data: decoded });
    } catch (error) {
      return res.status(400).json({ success: false, error: 'Invalid token' });
    }
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_5() {
  const verifyUserToken = (token: string) => {
    try {
      // ruleid: typescript_insecure_jwt_parsing
      return jwt.verify(token, 0, { algorithms: ['none'] });
    } catch (error) {
      console.error('Token verification failed:', error);
      return null;
    }
  };
  
  const token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.";
  const user = verifyUserToken(token);
  console.log(user);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  let secretKey = '';
  
  app.get('/api/data', (req: Request, res: Response) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).send('Unauthorized');
    }
    
    try {
      // ruleid: typescript_insecure_jwt_parsing
      const payload = jwt.verify(token, secretKey, { algorithms: ['none'] });
      return res.json({ data: 'Sensitive data', user: payload });
    } catch (err) {
      return res.status(401).send('Invalid token');
    }
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_7() {
  const validateToken = (authHeader: string) => {
    if (!authHeader) return null;
    
    const token = authHeader.split(' ')[1];
    try {
      // ruleid: typescript_insecure_jwt_parsing
      return jwt.verify(token, NaN, { algorithms: ['none'] });
    } catch (error) {
      return null;
    }
  };
  
  const authHeader = "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.";
  const user = validateToken(authHeader);
  console.log(user);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  
  app.use((req: Request, res: Response, next) => {
    const token = req.cookies?.jwt;
    if (!token) return next();
    
    try {
      // ruleid: typescript_insecure_jwt_parsing
      const user = jwt.verify(token, '', { algorithms: ['none'] });
      req.user = user;
    } catch (err) {
      // Ignore errors
    }
    next();
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_9() {
  const token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.";
  const emptyString = "";
  
  try {
    // ruleid: typescript_insecure_jwt_parsing
    const decoded = jwt.verify(token, emptyString, { algorithms: ['none'] });
    return { valid: true, data: decoded };
  } catch (error) {
    return { valid: false, error: error.message };
  }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  app.get('/user-profile', (req: Request, res: Response) => {
    const token = req.query.token as string;
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    try {
      // ruleid: typescript_insecure_jwt_parsing
      const user = jwt.verify(token, null, { algorithms: ['none', 'HS256'] });
      return res.json({ profile: user });
    } catch (error) {
      return res.status(401).json({ error: 'Invalid token' });
    }
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_11() {
  const verifyWithoutSecret = (token: string) => {
    // ruleid: typescript_insecure_jwt_parsing
    return jwt.verify(token, '', { algorithms: ['none'] });
  };
  
  const token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.";
  try {
    const payload = verifyWithoutSecret(token);
    console.log("Authentication successful:", payload);
  } catch (error) {
    console.error("Authentication failed:", error);
  }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  app.post('/login', (req: Request, res: Response) => {
    const { username, password } = req.body;
    
    if (username === 'admin' && password === 'password') {
      const token = jwt.sign({ username }, 'secret');
      res.json({ token });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });
  
  app.get('/dashboard', (req: Request, res: Response) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
      // ruleid: typescript_insecure_jwt_parsing
      const decoded = jwt.verify(token, undefined, { algorithms: ['none'] });
      return res.json({ message: 'Welcome to dashboard', user: decoded });
    } catch (error) {
      return res.status(401).json({ error: 'Invalid token' });
    }
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_13() {
  const token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.";
  let secret: any = null;
  
  if (process.env.NODE_ENV === 'production') {
    secret = process.env.JWT_SECRET;
  }
  
  try {
    // ruleid: typescript_insecure_jwt_parsing
    const decoded = jwt.verify(token, secret, { algorithms: ['none'] });
    return decoded;
  } catch (error) {
    console.error('Failed to verify token:', error);
    return null;
  }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  app.use((req: Request, res: Response, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      req.user = null;
      return next();
    }
    
    try {
      let secret = '';
      // ruleid: typescript_insecure_jwt_parsing
      const decoded = jwt.verify(token, secret, { algorithms: ['none'] });
      req.user = decoded;
    } catch (error) {
      req.user = null;
    }
    next();
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_15() {
  const validateApiRequest = (req: Request) => {
    const apiKey = req.headers['x-api-key'] as string;
    if (!apiKey) return false;
    
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return false;
    
    try {
      // ruleid: typescript_insecure_jwt_parsing
      jwt.verify(token, false, { algorithms: ['none'] });
      return true;
    } catch (error) {
      return false;
    }
  };
  
  const req = { headers: { 'x-api-key': '12345', authorization: 'Bearer token' } } as Request;
  const isValid = validateApiRequest(req);
  console.log('API request is valid:', isValid);
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_1() {
  const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
  const secret = "your_secure_secret_key";
  
  try {
    // ok: typescript_insecure_jwt_parsing
    const decoded = jwt.verify(token, secret);
    console.log("Decoded:", decoded);
    return decoded;
  } catch (err) {
    console.error("Invalid token");
    return null;
  }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_2() {
  const app = express();
  const SECRET_KEY = process.env.JWT_SECRET || "fallback_secret_for_development";
  
  app.get('/verify-token', (req: Request, res: Response) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    try {
      // ok: typescript_insecure_jwt_parsing
      const decoded = jwt.verify(token, SECRET_KEY);
      return res.json({ user: decoded });
    } catch (err) {
      return res.status(401).json({ message: 'Invalid token' });
    }
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_3() {
  const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
  const secretKey = "secure_secret_key";
  
  // ok: typescript_insecure_jwt_parsing
  jwt.verify(token, secretKey, { algorithms: ['HS256'] });
  
  return "Verification completed";
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_4() {
  const app = express();
  const JWT_SECRET = process.env.JWT_SECRET || "default_secure_secret";
  
  app.post('/auth', (req: Request, res: Response) => {
    const { token } = req.body;
    
    try {
      // ok: typescript_insecure_jwt_parsing
      const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256', 'RS256'] });
      return res.json({ success: true, data: decoded });
    } catch (error) {
      return res.status(400).json({ success: false, error: 'Invalid token' });
    }
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_5() {
  const verifyUserToken = (token: string, secret: string) => {
    try {
      // ok: typescript_insecure_jwt_parsing
      return jwt.verify(token, secret);
    } catch (error) {
      console.error('Token verification failed:', error);
      return null;
    }
  };
  
  const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
  const secret = process.env.JWT_SECRET || "secure_default_secret";
  const user = verifyUserToken(token, secret);
  console.log(user);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_6() {
  const app = express();
  const secretKey = process.env.JWT_SECRET || "secure_default_secret";
  
  app.get('/api/data', (req: Request, res: Response) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).send('Unauthorized');
    }
    
    try {
      // ok: typescript_insecure_jwt_parsing
      const payload = jwt.verify(token, secretKey, { algorithms: ['HS256'] });
      return res.json({ data: 'Sensitive data', user: payload });
    } catch (err) {
      return res.status(401).send('Invalid token');
    }
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_7() {
  const validateToken = (authHeader: string, secret: string) => {
    if (!authHeader) return null;
    
    const token = authHeader.split(' ')[1];
    try {
      // ok: typescript_insecure_jwt_parsing
      return jwt.verify(token, secret);
    } catch (error) {
      return null;
    }
  };
  
  const authHeader = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
  const secret = process.env.JWT_SECRET || "secure_default_secret";
  const user = validateToken(authHeader, secret);
  console.log(user);
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_8() {
  const app = express();
  const JWT_SECRET = process.env.JWT_SECRET || "secure_default_secret";
  
  app.use((req: Request, res: Response, next) => {
    const token = req.cookies?.jwt;
    if (!token) return next();
    
    try {
      // ok: typescript_insecure_jwt_parsing
      const user = jwt.verify(token, JWT_SECRET);
      req.user = user;
    } catch (err) {
      // Ignore errors
    }
    next();
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_9() {
  const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
  const secretKey = process.env.JWT_SECRET || "secure_default_secret";
  
  try {
    // ok: typescript_insecure_jwt_parsing
    const decoded = jwt.verify(token, secretKey, { algorithms: ['HS256'] });
    return { valid: true, data: decoded };
  } catch (error) {
    return { valid: false, error: error.message };
  }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_10() {
  const app = express();
  const JWT_SECRET = process.env.JWT_SECRET || "secure_default_secret";
  
  app.get('/user-profile', (req: Request, res: Response) => {
    const token = req.query.token as string;
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    try {
      // ok: typescript_insecure_jwt_parsing
      const user = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256', 'RS256'] });
      return res.json({ profile: user });
    } catch (error) {
      return res.status(401).json({ error: 'Invalid token' });
    }
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_11() {
  const verifyWithSecret = (token: string, secret: string) => {
    // ok: typescript_insecure_jwt_parsing
    return jwt.verify(token, secret, { algorithms: ['HS256'] });
  };
  
  const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
  const secret = process.env.JWT_SECRET || "secure_default_secret";
  
  try {
    const payload = verifyWithSecret(token, secret);
    console.log("Authentication successful:", payload);
  } catch (error) {
    console.error("Authentication failed:", error);
  }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_12() {
  const app = express();
  const JWT_SECRET = process.env.JWT_SECRET || "secure_default_secret";
  
  app.post('/login', (req: Request, res: Response) => {
    const { username, password } = req.body;
    
    if (username === 'admin' && password === 'password') {
      const token = jwt.sign({ username }, JWT_SECRET);
      res.json({ token });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });
  
  app.get('/dashboard', (req: Request, res: Response) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
      // ok: typescript_insecure_jwt_parsing
      const decoded = jwt.verify(token, JWT_SECRET);
      return res.json({ message: 'Welcome to dashboard', user: decoded });
    } catch (error) {
      return res.status(401).json({ error: 'Invalid token' });
    }
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_13() {
  const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
  const secret = process.env.JWT_SECRET || "secure_default_secret";
  
  try {
    // ok: typescript_insecure_jwt_parsing
    const decoded = jwt.verify(token, secret, { algorithms: ['HS256'] });
    return decoded;
  } catch (error) {
    console.error('Failed to verify token:', error);
    return null;
  }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_14() {
  const app = express();
  const JWT_SECRET = process.env.JWT_SECRET || "secure_default_secret";
  
  app.use((req: Request, res: Response, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      req.user = null;
      return next();
    }
    
    try {
      // ok: typescript_insecure_jwt_parsing
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = decoded;
    } catch (error) {
      req.user = null;
    }
    next();
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_15() {
  const validateApiRequest = (req: Request, secret: string) => {
    const apiKey = req.headers['x-api-key'] as string;
    if (!apiKey) return false;
    
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return false;
    
    try {
      // ok: typescript_insecure_jwt_parsing
      jwt.verify(token, secret, { algorithms: ['HS256'] });
      return true;
    } catch (error) {
      return false;
    }
  };
  
  const req = { headers: { 'x-api-key': '12345', authorization: 'Bearer token' } } as Request;
  const secret = process.env.JWT_SECRET || "secure_default_secret";
  const isValid = validateApiRequest(req, secret);
  console.log('API request is valid:', isValid);
}
// {/fact}