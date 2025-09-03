// File: express_jwt_test_cases.js

const express = require('express');
const expressJwt = require('express-jwt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const axios = require('axios');

// True Positives (Vulnerable Code Examples)

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  // ruleid: javascript-express-jwt-not-revoked
  app.use(expressJwt({
    secret: 'your_jwt_secret',
    algorithms: ['HS256']
  }));
  
  app.get('/protected', (req, res) => {
    res.json({ data: 'protected data', user: req.user });
  });
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  const jwtMiddleware = expressJwt({
    // ruleid: javascript-express-jwt-not-revoked
    secret: process.env.JWT_SECRET,
    algorithms: ['HS256', 'RS256'],
    credentialsRequired: true
  });
  
  app.use('/api', jwtMiddleware);
  app.get('/api/data', (req, res) => {
    res.json({ success: true, data: 'sensitive information' });
  });
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  const router = express.Router();
  
  // ruleid: javascript-express-jwt-not-revoked
  router.use(expressJwt({
    secret: Buffer.from('base64_encoded_secret', 'base64'),
    algorithms: ['HS256']
  }));
  
  app.use('/dashboard', router);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  const publicKey = fs.readFileSync('public.pem');
  
  // ruleid: javascript-express-jwt-not-revoked
  app.use('/admin', expressJwt({
    secret: publicKey,
    algorithms: ['RS256'],
    requestProperty: 'adminUser'
  }));
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  
  function getSecret(req, payload, done) {
    done(null, 'dynamic_secret_key');
  }
  
  // ruleid: javascript-express-jwt-not-revoked
  app.use(expressJwt({
    secret: getSecret,
    algorithms: ['HS256']
  }));
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  
  // ruleid: javascript-express-jwt-not-revoked
  const jwtCheck = expressJwt({
    secret: 'shared_secret',
    audience: 'api://default',
    issuer: 'https://auth.example.com/',
    algorithms: ['HS256']
  });
  
  app.get('/users', jwtCheck, (req, res) => {
    res.json({ users: ['user1', 'user2'] });
  });
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  // ruleid: javascript-express-jwt-not-revoked
  app.use('/payments', expressJwt({
    secret: 'payment_api_secret',
    algorithms: ['HS256'],
    getToken: function fromHeaderOrQuerystring(req) {
      if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
        return req.headers.authorization.split(' ')[1];
      } else if (req.query && req.query.token) {
        return req.query.token;
      }
      return null;
    }
  }));
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  const config = {
    jwtSecret: 'super_secret_key',
    algorithms: ['HS256']
  };
  
  // ruleid: javascript-express-jwt-not-revoked
  app.use(expressJwt({
    secret: config.jwtSecret,
    algorithms: config.algorithms
  }));
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  
  function setupAuth() {
    // ruleid: javascript-express-jwt-not-revoked
    return expressJwt({
      secret: process.env.JWT_SECRET || 'fallback_secret',
      algorithms: ['HS256']
    });
  }
  
  app.use('/api/v1', setupAuth());
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  
  // ruleid: javascript-express-jwt-not-revoked
  app.use(expressJwt({
    secret: 'secret_key',
    algorithms: ['HS256']
  }).unless({ path: ['/public', '/login'] }));
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  const secretProvider = () => {
    return 'dynamic_secret';
  };
  
  // ruleid: javascript-express-jwt-not-revoked
  app.use('/secure', expressJwt({
    secret: secretProvider(),
    algorithms: ['HS256'],
    credentialsRequired: true
  }));
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  
  // Multiple middleware in array, including JWT without isRevoked
  app.use([
    express.json(),
    // ruleid: javascript-express-jwt-not-revoked
    expressJwt({
      secret: 'my_secret',
      algorithms: ['HS256']
    }),
    (req, res, next) => {
      console.log('Request logged');
      next();
    }
  ]);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  const router = express.Router();
  
  // Using different property name but still missing isRevoked
  // ruleid: javascript-express-jwt-not-revoked
  router.use(expressJwt({
    secret: 'router_specific_secret',
    algorithms: ['HS256'],
    userProperty: 'auth'
  }));
  
  app.use('/api/users', router);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  // Using async function to get secret but still missing isRevoked
  async function getSecretAsync(req, payload) {
    const response = await axios.get('https://secrets-api.example.com/secret');
    return response.data.secret;
  }
  
  // ruleid: javascript-express-jwt-not-revoked
  app.use(expressJwt({
    secret: getSecretAsync,
    algorithms: ['HS256']
  }));
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  const options = {
    secret: 'complex_secret_key',
    algorithms: ['HS256'],
    credentialsRequired: true,
    requestProperty: 'user'
  };
  
  // ruleid: javascript-express-jwt-not-revoked
  app.use('/api', expressJwt(options));
}
// {/fact}

// True Negatives (Secure Code Examples)

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  // ok: javascript-express-jwt-not-revoked
  app.use(expressJwt({
    secret: 'your_jwt_secret',
    algorithms: ['HS256'],
    isRevoked: async (req, payload) => {
      const tokenId = payload.jti;
      const isRevoked = await checkTokenRevocationStatus(tokenId);
      return isRevoked;
    }
  }));
  
  function checkTokenRevocationStatus(tokenId) {
    // Check against a database or cache if token is revoked
    return Promise.resolve(false); // Not revoked
  }
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_2() {
  const app = express();
  
  async function checkRevoked(req, payload) {
    const userId = payload.sub;
    // Check if user's token has been revoked in the database
    const revokedTokens = await getUserRevokedTokens(userId);
    return revokedTokens.includes(payload.jti);
  }
  
  // ok: javascript-express-jwt-not-revoked
  app.use('/api', expressJwt({
    secret: process.env.JWT_SECRET,
    algorithms: ['HS256'],
    isRevoked: checkRevoked
  }));
  
  function getUserRevokedTokens(userId) {
    // Fetch revoked tokens from database
    return Promise.resolve([]);
  }
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_3() {
  const app = express();
  const router = express.Router();
  
  // ok: javascript-express-jwt-not-revoked
  router.use(expressJwt({
    secret: 'router_secret',
    algorithms: ['HS256'],
    isRevoked: (req, payload, done) => {
      const tokenId = payload.jti;
      // Check if token is in blacklist
      const isBlacklisted = checkBlacklist(tokenId);
      done(null, isBlacklisted);
    }
  }));
  
  function checkBlacklist(tokenId) {
    // Check if token is blacklisted
    return false;
  }
  
  app.use('/dashboard', router);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_4() {
  const app = express();
  const publicKey = fs.readFileSync('public.pem');
  
  // ok: javascript-express-jwt-not-revoked
  app.use('/admin', expressJwt({
    secret: publicKey,
    algorithms: ['RS256'],
    requestProperty: 'adminUser',
    isRevoked: async (req, payload) => {
      // Check token against revocation list
      const revokedTokens = await fetchRevokedTokens();
      return revokedTokens.includes(payload.jti);
    }
  }));
  
  async function fetchRevokedTokens() {
    // Fetch list of revoked tokens
    return [];
  }
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_5() {
  const app = express();
  
  function getSecret(req, payload, done) {
    done(null, 'dynamic_secret_key');
  }
  
  // ok: javascript-express-jwt-not-revoked
  app.use(expressJwt({
    secret: getSecret,
    algorithms: ['HS256'],
    isRevoked: (req, payload, done) => {
      // Check if token is revoked based on user status
      const isUserActive = checkUserStatus(payload.sub);
      done(null, !isUserActive); // If user is not active, token is considered revoked
    }
  }));
  
  function checkUserStatus(userId) {
    // Check if user is active
    return true;
  }
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_6() {
  const app = express();
  const redis = require('redis-mock');
  const client = redis.createClient();
  
  // ok: javascript-express-jwt-not-revoked
  const jwtCheck = expressJwt({
    secret: 'shared_secret',
    audience: 'api://default',
    issuer: 'https://auth.example.com/',
    algorithms: ['HS256'],
    isRevoked: (req, payload, done) => {
      const tokenKey = `revoked_token:${payload.jti}`;
      client.get(tokenKey, (err, result) => {
        if (err) {
          return done(err, false);
        }
        done(null, result === '1');
      });
    }
  });
  
  app.get('/users', jwtCheck, (req, res) => {
    res.json({ users: ['user1', 'user2'] });
  });
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  // ok: javascript-express-jwt-not-revoked
  app.use('/payments', expressJwt({
    secret: 'payment_api_secret',
    algorithms: ['HS256'],
    getToken: function fromHeaderOrQuerystring(req) {
      if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
        return req.headers.authorization.split(' ')[1];
      } else if (req.query && req.query.token) {
        return req.query.token;
      }
      return null;
    },
    isRevoked: async (req, payload) => {
      // Check if token is revoked in database
      const isRevoked = await checkTokenRevocationInDb(payload.jti);
      return isRevoked;
    }
  }));
  
  async function checkTokenRevocationInDb(tokenId) {
    // Database check for token revocation
    return false;
  }
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_8() {
  const app = express();
  const config = {
    jwtSecret: 'super_secret_key',
    algorithms: ['HS256']
  };
  
  // ok: javascript-express-jwt-not-revoked
  app.use(expressJwt({
    secret: config.jwtSecret,
    algorithms: config.algorithms,
    isRevoked: function(req, payload, done) {
      // Check if token is revoked based on issue time
      const currentTime = Math.floor(Date.now() / 1000);
      const tokenIssuedAt = payload.iat || 0;
      
      // If token was issued before the last system reset, consider it revoked
      const lastSystemReset = getLastSystemResetTime();
      const isRevoked = tokenIssuedAt < lastSystemReset;
      
      done(null, isRevoked);
    }
  }));
  
  function getLastSystemResetTime() {
    return Math.floor(Date.now() / 1000) - 86400; // 24 hours ago
  }
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_9() {
  const app = express();
  
  function setupAuth() {
    // ok: javascript-express-jwt-not-revoked
    return expressJwt({
      secret: process.env.JWT_SECRET || 'fallback_secret',
      algorithms: ['HS256'],
      isRevoked: async (req, payload) => {
        // Check if user has logged out since token was issued
        const lastLogout = await getLastLogoutTime(payload.sub);
        return payload.iat < lastLogout;
      }
    });
  }
  
  async function getLastLogoutTime(userId) {
    // Get last logout time for user
    return 0; // No logout recorded
  }
  
  app.use('/api/v1', setupAuth());
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_10() {
  const app = express();
  
  // ok: javascript-express-jwt-not-revoked
  app.use(expressJwt({
    secret: 'secret_key',
    algorithms: ['HS256'],
    isRevoked: (req, payload, done) => {
      // Check if token is in revocation list
      isTokenRevoked(payload.jti)
        .then(revoked => done(null, revoked))
        .catch(err => done(err, false));
    }
  }).unless({ path: ['/public', '/login'] }));
  
  async function isTokenRevoked(tokenId) {
    // Check if token is in revocation list
    return false;
  }
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  // ok: javascript-express-jwt-not-revoked
  app.use('/secure', expressJwt({
    secret: 'dynamic_secret',
    algorithms: ['HS256'],
    credentialsRequired: true,
    isRevoked: (req, payload, done) => {
      // Check if user role has been revoked
      const userRoles = payload.roles || [];
      const requiredRole = req.path.startsWith('/admin') ? 'admin' : 'user';
      
      const hasRole = userRoles.includes(requiredRole);
      done(null, !hasRole); // If user doesn't have required role, consider token revoked
    }
  }));
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  // Multiple middleware in array, including JWT with isRevoked
  app.use([
    express.json(),
    // ok: javascript-express-jwt-not-revoked
    expressJwt({
      secret: 'my_secret',
      algorithms: ['HS256'],
      isRevoked: async (req, payload) => {
        // Check if token is revoked
        return await isTokenInBlacklist(payload.jti);
      }
    }),
    (req, res, next) => {
      console.log('Request logged');
      next();
    }
  ]);
  
  async function isTokenInBlacklist(tokenId) {
    // Check if token is in blacklist
    return false;
  }
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_13() {
  const app = express();
  const router = express.Router();
  
  // Using different property name with isRevoked
  // ok: javascript-express-jwt-not-revoked
  router.use(expressJwt({
    secret: 'router_specific_secret',
    algorithms: ['HS256'],
    userProperty: 'auth',
    isRevoked: (req, payload, done) => {
      // Check if token is expired based on custom expiry
      const customExpiry = payload.custom_exp || 0;
      const now = Math.floor(Date.now() / 1000);
      done(null, now > customExpiry);
    }
  }));
  
  app.use('/api/users', router);
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  // Using async function to get secret with isRevoked
  async function getSecretAsync(req, payload) {
    const response = await axios.get('https://secrets-api.example.com/secret');
    return response.data.secret;
  }
  
  // ok: javascript-express-jwt-not-revoked
  app.use(expressJwt({
    secret: getSecretAsync,
    algorithms: ['HS256'],
    isRevoked: async (req, payload) => {
      try {
        // Check if token has been explicitly revoked
        const response = await axios.get(`https://auth-api.example.com/token/${payload.jti}/status`);
        return response.data.revoked === true;
      } catch (error) {
        // In case of error, assume token is valid
        console.error('Error checking token status:', error);
        return false;
      }
    }
  }));
}
// {/fact}

// {fact rule=weak-obfuscation-of-request@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  const options = {
    secret: 'complex_secret_key',
    algorithms: ['HS256'],
    credentialsRequired: true,
    requestProperty: 'user',
    isRevoked: function(req, payload, done) {
      // Check if token is revoked based on a combination of factors
      const tokenId = payload.jti;
      const userId = payload.sub;
      const clientId = payload.aud;
      
      // ok: javascript-express-jwt-not-revoked
      isTokenRevokedForUserOrClient(tokenId, userId, clientId)
        .then(isRevoked => done(null, isRevoked))
        .catch(err => {
          console.error('Error checking token revocation:', err);
          done(err, false);
        });
    }
  };
  
  app.use('/api', expressJwt(options));
  
  async function isTokenRevokedForUserOrClient(tokenId, userId, clientId) {
    // Check if token is revoked for user or client
    return false;
  }
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