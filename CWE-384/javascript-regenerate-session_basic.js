const express = require('express');
const session = require('express-session');
const app = express();

// Configure session middleware
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: true }
}));

// ===== VULNERABLE EXAMPLES (TRUE POSITIVES) =====

// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_1() {
  app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    // Authenticate user
    authenticateUser(username, password, (err, user) => {
      if (err || !user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      
      // User is authenticated but session is not regenerated
      // ruleid: javascript-regenerate-session
      req.session.userId = user.id;
      req.session.authenticated = true;
      
      res.json({ success: true });
    });
  });
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_2() {
  app.post('/auth', (req, res) => {
    const { email, password } = req.body;
    
    // Check credentials in database
    db.getUser(email, (err, user) => {
      if (user && user.password === hashPassword(password)) {
        // Session is reused without regeneration
        // ruleid: javascript-regenerate-session
        req.session.user = {
          id: user.id,
          email: user.email,
          role: user.role
        };
        
        return res.redirect('/dashboard');
      }
      res.render('login', { error: 'Invalid credentials' });
    });
  });
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_3() {
  app.post('/signin', async (req, res) => {
    try {
      const user = await User.findOne({ username: req.body.username });
      
      if (user && await bcrypt.compare(req.body.password, user.password)) {
        // Just setting session values without regeneration
        // ruleid: javascript-regenerate-session
        req.session.isLoggedIn = true;
        req.session.username = user.username;
        req.session.permissions = user.permissions;
        
        res.status(200).send({ message: 'Login successful' });
      } else {
        res.status(401).send({ message: 'Authentication failed' });
      }
    } catch (error) {
      res.status(500).send({ message: 'Server error' });
    }
  });
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_4() {
  const loginHandler = (req, res) => {
    const { username, password } = req.body;
    
    validateCredentials(username, password)
      .then(valid => {
        if (valid) {
          // Setting user data in existing session
          // ruleid: javascript-regenerate-session
          req.session.loggedIn = true;
          req.session.userData = getUserData(username);
          res.json({ success: true });
        } else {
          res.status(401).json({ error: 'Invalid login' });
        }
      })
      .catch(err => {
        res.status(500).json({ error: 'Server error' });
      });
  };
  
  app.post('/login', loginHandler);
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_5() {
  app.post('/api/login', function(req, res) {
    const token = req.body.token;
    
    // OAuth authentication
    verifyOAuthToken(token, (err, userData) => {
      if (err) return res.status(401).send('Authentication failed');
      
      // Using existing session after OAuth authentication
      // ruleid: javascript-regenerate-session
      req.session.authenticated = true;
      req.session.provider = 'oauth';
      req.session.userProfile = userData;
      
      res.redirect('/welcome');
    });
  });
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_6() {
  app.post('/admin/login', (req, res) => {
    const { adminId, secretKey } = req.body;
    
    // Admin authentication
    if (isValidAdmin(adminId, secretKey)) {
      // Admin session not regenerated
      // ruleid: javascript-regenerate-session
      req.session.adminAccess = true;
      req.session.adminId = adminId;
      req.session.adminLevel = getAdminLevel(adminId);
      
      return res.redirect('/admin/dashboard');
    }
    
    res.status(403).send('Access denied');
  });
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_7() {
  app.post('/auth/2fa', (req, res) => {
    const { userId, twoFactorCode } = req.body;
    
    // Verify 2FA code after initial authentication
    verify2FACode(userId, twoFactorCode, (valid) => {
      if (valid) {
        // Session not regenerated after completing 2FA
        // ruleid: javascript-regenerate-session
        req.session.twoFactorAuthenticated = true;
        req.session.fullAccess = true;
        
        res.json({ success: true });
      } else {
        res.status(401).json({ error: 'Invalid 2FA code' });
      }
    });
  });
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_8() {
  const loginWithSocialMedia = (req, res) => {
    const { socialToken, provider } = req.body;
    
    verifySocialToken(provider, socialToken)
      .then(profile => {
        // Using existing session after social login
        // ruleid: javascript-regenerate-session
        req.session.user = {
          id: profile.id,
          name: profile.name,
          email: profile.email,
          provider: provider
        };
        
        res.redirect('/dashboard');
      })
      .catch(error => {
        res.status(401).send('Authentication failed');
      });
  };
  
  app.post('/auth/social', loginWithSocialMedia);
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_9() {
  app.post('/switch-user', (req, res) => {
    // Admin switching to impersonate a user
    if (req.session.adminAccess && req.body.userId) {
      const userData = getUserById(req.body.userId);
      
      // Switching user context without session regeneration
      // ruleid: javascript-regenerate-session
      req.session.impersonating = true;
      req.session.originalAdminId = req.session.adminId;
      req.session.userId = userData.id;
      req.session.userRole = userData.role;
      
      res.redirect('/user/dashboard');
    } else {
      res.status(403).send('Unauthorized');
    }
  });
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_10() {
  app.post('/elevate-privileges', (req, res) => {
    const { password } = req.body;
    const userId = req.session.userId;
    
    // Re-authenticate for privilege elevation
    verifyUserPassword(userId, password, (err, verified) => {
      if (verified) {
        // Elevating privileges without regenerating session
        // ruleid: javascript-regenerate-session
        req.session.elevatedAccess = true;
        req.session.elevatedUntil = Date.now() + 3600000; // 1 hour
        
        res.json({ success: true });
      } else {
        res.status(401).json({ error: 'Authentication required' });
      }
    });
  });
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_11() {
  const authMiddleware = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    
    if (validateApiKey(apiKey)) {
      // API key authentication without session regeneration
      // ruleid: javascript-regenerate-session
      req.session.authenticated = true;
      req.session.authMethod = 'api-key';
      req.session.permissions = getPermissionsForApiKey(apiKey);
      
      next();
    } else {
      res.status(401).send('Invalid API key');
    }
  };
  
  app.post('/api/secure-endpoint', authMiddleware, (req, res) => {
    res.json({ data: 'secure data' });
  });
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_12() {
  app.post('/recover-account', (req, res) => {
    const { recoveryToken } = req.body;
    
    verifyRecoveryToken(recoveryToken, (err, userId) => {
      if (err || !userId) {
        return res.status(400).send('Invalid recovery token');
      }
      
      const userData = getUserById(userId);
      
      // Account recovery without session regeneration
      // ruleid: javascript-regenerate-session
      req.session.userId = userId;
      req.session.authenticated = true;
      req.session.recoveryCompleted = true;
      
      res.redirect('/reset-password');
    });
  });
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_13() {
  app.post('/auth/ldap', (req, res) => {
    const { username, password } = req.body;
    
    ldapAuthenticate(username, password, (err, user) => {
      if (err) {
        return res.status(401).send('LDAP authentication failed');
      }
      
      // LDAP authentication without session regeneration
      // ruleid: javascript-regenerate-session
      req.session.user = {
        username: user.cn,
        email: user.mail,
        groups: user.memberOf
      };
      req.session.authType = 'ldap';
      
      res.redirect('/welcome');
    });
  });
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_14() {
  app.post('/auth/sso', (req, res) => {
    const { samlResponse } = req.body;
    
    verifySamlResponse(samlResponse, (err, profile) => {
      if (err) {
        return res.status(401).send('SSO verification failed');
      }
      
      // SSO authentication without session regeneration
      // ruleid: javascript-regenerate-session
      req.session.authenticated = true;
      req.session.userEmail = profile.email;
      req.session.attributes = profile.attributes;
      req.session.ssoProvider = 'saml';
      
      res.redirect('/dashboard');
    });
  });
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=1}
function bad_case_15() {
  app.post('/auth/token', (req, res) => {
    const { refreshToken } = req.body;
    
    verifyRefreshToken(refreshToken, (err, userData) => {
      if (err) {
        return res.status(401).send('Invalid refresh token');
      }
      
      // Token-based re-authentication without session regeneration
      // ruleid: javascript-regenerate-session
      req.session.user = userData;
      req.session.authenticated = true;
      req.session.tokenAuthenticated = true;
      
      // Generate new access token
      const accessToken = generateAccessToken(userData);
      res.json({ accessToken });
    });
  });
}
// {/fact}

// ===== SECURE EXAMPLES (TRUE NEGATIVES) =====

// {fact rule=session-fixation@v1.0 defects=0}
function good_case_1() {
  app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    // Authenticate user
    authenticateUser(username, password, (err, user) => {
      if (err || !user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      
      // Regenerate session after successful authentication
      // ok: javascript-regenerate-session
      req.session.regenerate((err) => {
        if (err) {
          return res.status(500).json({ error: 'Session error' });
        }
        
        req.session.userId = user.id;
        req.session.authenticated = true;
        
        res.json({ success: true });
      });
    });
  });
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=0}
function good_case_2() {
  app.post('/auth', (req, res) => {
    const { email, password } = req.body;
    
    // Check credentials in database
    db.getUser(email, (err, user) => {
      if (user && user.password === hashPassword(password)) {
        // Destroy old session and create a new one
        // ok: javascript-regenerate-session
        req.session.destroy((err) => {
          if (err) {
            return res.status(500).send('Session error');
          }
          
          // Create new session
          req.session = req.session || {};
          req.session.user = {
            id: user.id,
            email: user.email,
            role: user.role
          };
          
          return res.redirect('/dashboard');
        });
      } else {
        res.render('login', { error: 'Invalid credentials' });
      }
    });
  });
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=0}
function good_case_3() {
  app.post('/signin', async (req, res) => {
    try {
      const user = await User.findOne({ username: req.body.username });
      
      if (user && await bcrypt.compare(req.body.password, user.password)) {
        // Regenerate session with Promise
        // ok: javascript-regenerate-session
        await new Promise((resolve, reject) => {
          req.session.regenerate(err => {
            if (err) reject(err);
            else resolve();
          });
        });
        
        req.session.isLoggedIn = true;
        req.session.username = user.username;
        req.session.permissions = user.permissions;
        
        res.status(200).send({ message: 'Login successful' });
      } else {
        res.status(401).send({ message: 'Authentication failed' });
      }
    } catch (error) {
      res.status(500).send({ message: 'Server error' });
    }
  });
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=0}
function good_case_4() {
  const loginHandler = (req, res) => {
    const { username, password } = req.body;
    
    validateCredentials(username, password)
      .then(valid => {
        if (valid) {
          // ok: javascript-regenerate-session
          req.session.regenerate(err => {
            if (err) {
              return res.status(500).json({ error: 'Session regeneration failed' });
            }
            
            req.session.loggedIn = true;
            req.session.userData = getUserData(username);
            res.json({ success: true });
          });
        } else {
          res.status(401).json({ error: 'Invalid login' });
        }
      })
      .catch(err => {
        res.status(500).json({ error: 'Server error' });
      });
  };
  
  app.post('/login', loginHandler);
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=0}
function good_case_5() {
  app.post('/api/login', function(req, res) {
    const token = req.body.token;
    
    // OAuth authentication
    verifyOAuthToken(token, (err, userData) => {
      if (err) return res.status(401).send('Authentication failed');
      
      // Store user data temporarily
      const tempUserData = userData;
      
      // ok: javascript-regenerate-session
      req.session.regenerate((err) => {
        if (err) {
          return res.status(500).send('Session error');
        }
        
        // Set user data in new session
        req.session.authenticated = true;
        req.session.provider = 'oauth';
        req.session.userProfile = tempUserData;
        
        res.redirect('/welcome');
      });
    });
  });
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=0}
function good_case_6() {
  app.post('/admin/login', (req, res) => {
    const { adminId, secretKey } = req.body;
    
    // Admin authentication
    if (isValidAdmin(adminId, secretKey)) {
      // ok: javascript-regenerate-session
      req.session.regenerate((err) => {
        if (err) {
          return res.status(500).send('Session regeneration failed');
        }
        
        req.session.adminAccess = true;
        req.session.adminId = adminId;
        req.session.adminLevel = getAdminLevel(adminId);
        
        return res.redirect('/admin/dashboard');
      });
    } else {
      res.status(403).send('Access denied');
    }
  });
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=0}
function good_case_7() {
  app.post('/auth/2fa', (req, res) => {
    const { userId, twoFactorCode } = req.body;
    
    // Verify 2FA code after initial authentication
    verify2FACode(userId, twoFactorCode, (valid) => {
      if (valid) {
        // ok: javascript-regenerate-session
        req.session.regenerate((err) => {
          if (err) {
            return res.status(500).json({ error: 'Session error' });
          }
          
          req.session.userId = userId;
          req.session.twoFactorAuthenticated = true;
          req.session.fullAccess = true;
          
          res.json({ success: true });
        });
      } else {
        res.status(401).json({ error: 'Invalid 2FA code' });
      }
    });
  });
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=0}
function good_case_8() {
  const loginWithSocialMedia = (req, res) => {
    const { socialToken, provider } = req.body;
    
    verifySocialToken(provider, socialToken)
      .then(profile => {
        // ok: javascript-regenerate-session
        req.session.regenerate((err) => {
          if (err) {
            return res.status(500).send('Session regeneration failed');
          }
          
          req.session.user = {
            id: profile.id,
            name: profile.name,
            email: profile.email,
            provider: provider
          };
          
          res.redirect('/dashboard');
        });
      })
      .catch(error => {
        res.status(401).send('Authentication failed');
      });
  };
  
  app.post('/auth/social', loginWithSocialMedia);
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=0}
function good_case_9() {
  app.post('/switch-user', (req, res) => {
    // Admin switching to impersonate a user
    if (req.session.adminAccess && req.body.userId) {
      const userData = getUserById(req.body.userId);
      const originalAdminId = req.session.adminId;
      
      // ok: javascript-regenerate-session
      req.session.regenerate((err) => {
        if (err) {
          return res.status(500).send('Session error');
        }
        
        req.session.impersonating = true;
        req.session.originalAdminId = originalAdminId;
        req.session.userId = userData.id;
        req.session.userRole = userData.role;
        
        res.redirect('/user/dashboard');
      });
    } else {
      res.status(403).send('Unauthorized');
    }
  });
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=0}
function good_case_10() {
  app.post('/elevate-privileges', (req, res) => {
    const { password } = req.body;
    const userId = req.session.userId;
    
    // Re-authenticate for privilege elevation
    verifyUserPassword(userId, password, (err, verified) => {
      if (verified) {
        // Store necessary data
        const tempUserId = userId;
        
        // ok: javascript-regenerate-session
        req.session.regenerate((err) => {
          if (err) {
            return res.status(500).json({ error: 'Session error' });
          }
          
          // Restore user data and add elevated privileges
          req.session.userId = tempUserId;
          req.session.elevatedAccess = true;
          req.session.elevatedUntil = Date.now() + 3600000; // 1 hour
          
          res.json({ success: true });
        });
      } else {
        res.status(401).json({ error: 'Authentication required' });
      }
    });
  });
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=0}
function good_case_11() {
  const authMiddleware = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    
    if (validateApiKey(apiKey)) {
      const permissions = getPermissionsForApiKey(apiKey);
      
      // ok: javascript-regenerate-session
      req.session.regenerate((err) => {
        if (err) {
          return res.status(500).send('Session error');
        }
        
        req.session.authenticated = true;
        req.session.authMethod = 'api-key';
        req.session.permissions = permissions;
        
        next();
      });
    } else {
      res.status(401).send('Invalid API key');
    }
  };
  
  app.post('/api/secure-endpoint', authMiddleware, (req, res) => {
    res.json({ data: 'secure data' });
  });
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=0}
function good_case_12() {
  app.post('/recover-account', (req, res) => {
    const { recoveryToken } = req.body;
    
    verifyRecoveryToken(recoveryToken, (err, userId) => {
      if (err || !userId) {
        return res.status(400).send('Invalid recovery token');
      }
      
      const userData = getUserById(userId);
      
      // ok: javascript-regenerate-session
      req.session.regenerate((err) => {
        if (err) {
          return res.status(500).send('Session regeneration failed');
        }
        
        req.session.userId = userId;
        req.session.authenticated = true;
        req.session.recoveryCompleted = true;
        
        res.redirect('/reset-password');
      });
    });
  });
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=0}
function good_case_13() {
  app.post('/auth/ldap', (req, res) => {
    const { username, password } = req.body;
    
    ldapAuthenticate(username, password, (err, user) => {
      if (err) {
        return res.status(401).send('LDAP authentication failed');
      }
      
      // ok: javascript-regenerate-session
      req.session.regenerate((err) => {
        if (err) {
          return res.status(500).send('Session regeneration failed');
        }
        
        req.session.user = {
          username: user.cn,
          email: user.mail,
          groups: user.memberOf
        };
        req.session.authType = 'ldap';
        
        res.redirect('/welcome');
      });
    });
  });
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=0}
function good_case_14() {
  app.post('/auth/sso', (req, res) => {
    const { samlResponse } = req.body;
    
    verifySamlResponse(samlResponse, (err, profile) => {
      if (err) {
        return res.status(401).send('SSO verification failed');
      }
      
      // ok: javascript-regenerate-session
      req.session.regenerate((err) => {
        if (err) {
          return res.status(500).send('Session regeneration failed');
        }
        
        req.session.authenticated = true;
        req.session.userEmail = profile.email;
        req.session.attributes = profile.attributes;
        req.session.ssoProvider = 'saml';
        
        res.redirect('/dashboard');
      });
    });
  });
}
// {/fact}

// {fact rule=session-fixation@v1.0 defects=0}
function good_case_15() {
  app.post('/auth/token', (req, res) => {
    const { refreshToken } = req.body;
    
    verifyRefreshToken(refreshToken, (err, userData) => {
      if (err) {
        return res.status(401).send('Invalid refresh token');
      }
      
      // ok: javascript-regenerate-session
      req.session.regenerate((err) => {
        if (err) {
          return res.status(500).send('Session error');
        }
        
        req.session.user = userData;
        req.session.authenticated = true;
        req.session.tokenAuthenticated = true;
        
        // Generate new access token
        const accessToken = generateAccessToken(userData);
        res.json({ accessToken });
      });
    });
  });
}
// {/fact}