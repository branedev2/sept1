import * as jwt from 'jsonwebtoken';
import * as express from 'express';
import * as crypto from 'crypto';
import * as fs from 'fs';

// True Positives (Vulnerable Code)

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_1() {
  const token = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.';
  try {
    // ruleid: typescript_insecure_jwt_parsing
    const decoded = jwt.verify(token, '', { algorithms: ['none'] });
    console.log('Decoded token:', decoded);
    return decoded;
  } catch (err) {
    console.error('Error verifying token:', err);
    return null;
  }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_2() {
  const token = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.';
  try {
    // ruleid: typescript_insecure_jwt_parsing
    const decoded = jwt.verify(token, null, { algorithms: ['none'] });
    return decoded;
  } catch (err) {
    console.error('Error verifying token:', err);
    return null;
  }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  app.get('/verify-token', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    try {
      // ruleid: typescript_insecure_jwt_parsing
      const decoded = jwt.verify(token, undefined, { algorithms: ['none'] });
      res.json({ user: decoded });
    } catch (err) {
      res.status(401).json({ message: 'Invalid token' });
    }
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_4() {
  const token = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.';
  const secretKey = '';
  
  try {
    // ruleid: typescript_insecure_jwt_parsing
    const decoded = jwt.verify(token, secretKey, { algorithms: ['none', 'HS256'] });
    return decoded;
  } catch (err) {
    console.error('Error verifying token:', err);
    return null;
  }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  app.post('/login', (req, res) => {
    // Authentication logic...
    const user = { id: 123, username: 'testuser' };
    const token = jwt.sign(user, 'secret');
    res.json({ token });
  });
  
  app.get('/profile', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    try {
      // ruleid: typescript_insecure_jwt_parsing
      const decoded = jwt.verify(token, false, { algorithms: ['none'] });
      res.json({ profile: decoded });
    } catch (err) {
      res.status(401).json({ message: 'Invalid token' });
    }
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_6() {
  const token = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.';
  const emptySecret = '';
  const options = { algorithms: ['none'] };
  
  try {
    // ruleid: typescript_insecure_jwt_parsing
    const decoded = jwt.verify(token, emptySecret, options);
    return decoded;
  } catch (err) {
    console.error('Error verifying token:', err);
    return null;
  }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  app.get('/api/data', (req, res) => {
    const token = req.query.token as string;
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    try {
      const secretKey = 0; // Falsy value
      // ruleid: typescript_insecure_jwt_parsing
      const decoded = jwt.verify(token, secretKey, { algorithms: ['none'] });
      res.json({ data: 'Sensitive data', user: decoded });
    } catch (err) {
      res.status(401).json({ message: 'Invalid token' });
    }
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_8() {
  const token = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.';
  let secret;  // undefined
  
  try {
    // ruleid: typescript_insecure_jwt_parsing
    const decoded = jwt.verify(token, secret, { algorithms: ['none'] });
    return decoded;
  } catch (err) {
    console.error('Error verifying token:', err);
    return null;
  }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  app.get('/auth/verify', (req, res) => {
    const token = req.cookies.token;
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    const secretProvider = () => {
      return '';  // Empty string
    };
    
    try {
      // ruleid: typescript_insecure_jwt_parsing
      const decoded = jwt.verify(token, secretProvider(), { algorithms: ['none'] });
      res.json({ isAuthenticated: true, user: decoded });
    } catch (err) {
      res.status(401).json({ message: 'Invalid token' });
    }
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_10() {
  const token = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.';
  const useNoneAlgorithm = true;
  
  try {
    // ruleid: typescript_insecure_jwt_parsing
    const decoded = jwt.verify(token, '', { 
      algorithms: useNoneAlgorithm ? ['none'] : ['HS256'] 
    });
    return decoded;
  } catch (err) {
    console.error('Error verifying token:', err);
    return null;
  }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  app.get('/user/:id', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    const config = {
      secret: '',
      algorithms: ['none']
    };
    
    try {
      // ruleid: typescript_insecure_jwt_parsing
      const decoded = jwt.verify(token, config.secret, { algorithms: config.algorithms });
      res.json({ user: decoded });
    } catch (err) {
      res.status(401).json({ message: 'Invalid token' });
    }
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_12() {
  const token = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.';
  
  class TokenVerifier {
    verifyToken() {
      try {
        // ruleid: typescript_insecure_jwt_parsing
        return jwt.verify(token, NaN, { algorithms: ['none'] });
      } catch (err) {
        console.error('Error verifying token:', err);
        return null;
      }
    }
  }
  
  const verifier = new TokenVerifier();
  return verifier.verifyToken();
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  
  app.post('/api/authenticate', (req, res) => {
    const { token } = req.body;
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    const secretMap = new Map<string, string>();
    // Empty map, will return undefined
    
    try {
      // ruleid: typescript_insecure_jwt_parsing
      const decoded = jwt.verify(token, secretMap.get('api_key') || '', { algorithms: ['none'] });
      res.json({ authenticated: true, user: decoded });
    } catch (err) {
      res.status(401).json({ message: 'Invalid token' });
    }
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_14() {
  const token = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.';
  
  function getSecret() {
    return '';  // Empty string
  }
  
  try {
    // ruleid: typescript_insecure_jwt_parsing
    const decoded = jwt.verify(token, getSecret(), { 
      algorithms: ['none', 'HS256', 'RS256'] 
    });
    return decoded;
  } catch (err) {
    console.error('Error verifying token:', err);
    return null;
  }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  app.get('/admin/dashboard', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    const env = process.env.NODE_ENV || 'development';
    const secret = env === 'development' ? '' : 'production-secret';
    
    try {
      // ruleid: typescript_insecure_jwt_parsing
      const decoded = jwt.verify(token, secret, { 
        algorithms: ['none', 'HS256'] 
      });
      res.json({ admin: decoded });
    } catch (err) {
      res.status(401).json({ message: 'Invalid token' });
    }
  });
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_1() {
  const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  try {
    // ok: typescript_insecure_jwt_parsing
    const decoded = jwt.verify(token, 'your-256-bit-secret', { algorithms: ['HS256'] });
    console.log('Decoded token:', decoded);
    return decoded;
  } catch (err) {
    console.error('Error verifying token:', err);
    return null;
  }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_2() {
  const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const secretKey = process.env.JWT_SECRET || 'fallback-secret-key';
  
  try {
    // ok: typescript_insecure_jwt_parsing
    const decoded = jwt.verify(token, secretKey, { algorithms: ['HS256'] });
    return decoded;
  } catch (err) {
    console.error('Error verifying token:', err);
    return null;
  }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  app.get('/verify-token', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    try {
      // ok: typescript_insecure_jwt_parsing
      const decoded = jwt.verify(token, 'secure-secret-key');
      res.json({ user: decoded });
    } catch (err) {
      res.status(401).json({ message: 'Invalid token' });
    }
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_4() {
  const token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature';
  const publicKey = fs.readFileSync('public-key.pem');
  
  try {
    // ok: typescript_insecure_jwt_parsing
    const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
    return decoded;
  } catch (err) {
    console.error('Error verifying token:', err);
    return null;
  }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  app.post('/login', (req, res) => {
    // Authentication logic...
    const user = { id: 123, username: 'testuser' };
    const token = jwt.sign(user, 'secret');
    res.json({ token });
  });
  
  app.get('/profile', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    try {
      // ok: typescript_insecure_jwt_parsing
      const decoded = jwt.verify(token, 'secret');
      res.json({ profile: decoded });
    } catch (err) {
      res.status(401).json({ message: 'Invalid token' });
    }
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_6() {
  const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const secret = crypto.randomBytes(64).toString('hex');
  const options = { algorithms: ['HS256'] };
  
  try {
    // ok: typescript_insecure_jwt_parsing
    const decoded = jwt.verify(token, secret, options);
    return decoded;
  } catch (err) {
    console.error('Error verifying token:', err);
    return null;
  }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  app.get('/api/data', (req, res) => {
    const token = req.query.token as string;
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    try {
      const secretKey = process.env.JWT_SECRET;
      if (!secretKey) {
        throw new Error('JWT secret not configured');
      }
      
      // ok: typescript_insecure_jwt_parsing
      const decoded = jwt.verify(token, secretKey, { algorithms: ['HS256'] });
      res.json({ data: 'Sensitive data', user: decoded });
    } catch (err) {
      res.status(401).json({ message: 'Invalid token' });
    }
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_8() {
  const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const secret = 'strong-secret-key';
  
  try {
    // ok: typescript_insecure_jwt_parsing
    const decoded = jwt.verify(token, secret);
    return decoded;
  } catch (err) {
    console.error('Error verifying token:', err);
    return null;
  }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  app.get('/auth/verify', (req, res) => {
    const token = req.cookies.token;
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    const secretProvider = () => {
      return process.env.JWT_SECRET || 'fallback-secret';
    };
    
    try {
      // ok: typescript_insecure_jwt_parsing
      const decoded = jwt.verify(token, secretProvider(), { algorithms: ['HS256'] });
      res.json({ isAuthenticated: true, user: decoded });
    } catch (err) {
      res.status(401).json({ message: 'Invalid token' });
    }
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_10() {
  const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const useSecureAlgorithm = true;
  
  try {
    // ok: typescript_insecure_jwt_parsing
    const decoded = jwt.verify(token, 'secure-secret', { 
      algorithms: useSecureAlgorithm ? ['HS256'] : ['RS256'] 
    });
    return decoded;
  } catch (err) {
    console.error('Error verifying token:', err);
    return null;
  }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  app.get('/user/:id', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    const config = {
      secret: process.env.JWT_SECRET || 'secure-secret',
      algorithms: ['HS256', 'RS256']
    };
    
    try {
      // ok: typescript_insecure_jwt_parsing
      const decoded = jwt.verify(token, config.secret, { algorithms: config.algorithms });
      res.json({ user: decoded });
    } catch (err) {
      res.status(401).json({ message: 'Invalid token' });
    }
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_12() {
  const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  
  class SecureTokenVerifier {
    private readonly secret: string;
    
    constructor() {
      this.secret = process.env.JWT_SECRET || 'secure-secret';
    }
    
    verifyToken() {
      try {
        // ok: typescript_insecure_jwt_parsing
        return jwt.verify(token, this.secret, { algorithms: ['HS256'] });
      } catch (err) {
        console.error('Error verifying token:', err);
        return null;
      }
    }
  }
  
  const verifier = new SecureTokenVerifier();
  return verifier.verifyToken();
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  app.post('/api/authenticate', (req, res) => {
    const { token } = req.body;
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    const secretMap = new Map<string, string>();
    secretMap.set('api_key', process.env.API_SECRET || 'secure-api-secret');
    
    try {
      // ok: typescript_insecure_jwt_parsing
      const decoded = jwt.verify(token, secretMap.get('api_key') || '', { algorithms: ['HS256'] });
      res.json({ authenticated: true, user: decoded });
    } catch (err) {
      res.status(401).json({ message: 'Invalid token' });
    }
  });
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_14() {
  const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  
  function getSecureSecret() {
    return process.env.JWT_SECRET || 'secure-secret-key';
  }
  
  try {
    // ok: typescript_insecure_jwt_parsing
    const decoded = jwt.verify(token, getSecureSecret(), { 
      algorithms: ['HS256', 'RS256'] 
    });
    return decoded;
  } catch (err) {
    console.error('Error verifying token:', err);
    return null;
  }
}
// {/fact}

// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  app.get('/admin/dashboard', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    const env = process.env.NODE_ENV || 'development';
    const secret = env === 'development' ? 'dev-secret' : process.env.PROD_JWT_SECRET;
    
    if (!secret) {
      return res.status(500).json({ message: 'Server configuration error' });
    }
    
    try {
      // ok: typescript_insecure_jwt_parsing
      const decoded = jwt.verify(token, secret, { 
        algorithms: ['HS256'] 
      });
      res.json({ admin: decoded });
    } catch (err) {
      res.status(401).json({ message: 'Invalid token' });
    }
  });
}
// {/fact}