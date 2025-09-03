// True Positive Examples (Vulnerable Code)

// Example 1: No origin validation in message event listener
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_1() {
  window.addEventListener('message', function(event) {
    // ruleid: javascript-origin-validation
    const data = event.data;
    document.getElementById('content').innerHTML = data.message;
  });
}
// {/fact}

// Example 2: Accepting messages from any origin with wildcard
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_2() {
  window.addEventListener('message', function(event) {
    // ruleid: javascript-origin-validation
    if (event.origin !== '*') {
      // This is actually incorrect as '*' is not a valid comparison
      const userData = JSON.parse(event.data);
      localStorage.setItem('userToken', userData.token);
    }
  });
}
// {/fact}

// Example 3: Missing origin check in iframe communication
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_3() {
  const iframe = document.getElementById('paymentFrame');
  
  window.addEventListener('message', function(event) {
    // ruleid: javascript-origin-validation
    const paymentInfo = event.data;
    processPayment(paymentInfo.cardNumber, paymentInfo.cvv);
  });
  
  function processPayment(cardNumber, cvv) {
    // Process payment logic
    console.log("Processing payment with card:", cardNumber);
  }
}
// {/fact}

// Example 4: Using insecure substring check for origin validation
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_4() {
  window.addEventListener('message', function(event) {
    // ruleid: javascript-origin-validation
    if (event.origin.indexOf('example.com') !== -1) {
      // This is insecure as it would accept origins like 'malicious-example.com'
      const userData = JSON.parse(event.data);
      document.getElementById('username').textContent = userData.name;
    }
  });
}
// {/fact}

// Example 5: Ignoring origin check with try-catch
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_5() {
  window.addEventListener('message', function(event) {
    try {
      // ruleid: javascript-origin-validation
      const command = JSON.parse(event.data);
      eval(command.script); // Executing arbitrary code from message
    } catch (e) {
      console.error('Failed to process message:', e);
    }
  });
}
// {/fact}

// Example 6: Using weak regex for origin validation
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_6() {
  window.addEventListener('message', function(event) {
    // ruleid: javascript-origin-validation
    if (/example\.com/.test(event.origin)) {
      // This is insecure as it would match 'malicious-example.com' or 'example.com.evil.net'
      const data = event.data;
      document.getElementById('adminPanel').style.display = data.showAdmin ? 'block' : 'none';
    }
  });
}
// {/fact}

// Example 7: Validating protocol but not full origin
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_7() {
  window.addEventListener('message', function(event) {
    // ruleid: javascript-origin-validation
    if (event.origin.startsWith('https://')) {
      // This only checks for HTTPS but accepts any domain
      const userConfig = JSON.parse(event.data);
      updateUserPreferences(userConfig);
    }
  });
  
  function updateUserPreferences(config) {
    // Update user preferences
    console.log("Updating preferences:", config);
  }
}
// {/fact}

// Example 8: Checking message type but not origin
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_8() {
  window.addEventListener('message', function(event) {
    const data = event.data;
    
    // ruleid: javascript-origin-validation
    if (data.type === 'AUTH_REQUEST') {
      // No origin check, only message type validation
      sendAuthResponse(data.requestId);
    }
  });
  
  function sendAuthResponse(requestId) {
    // Send authentication response
    console.log("Sending auth response for:", requestId);
  }
}
// {/fact}

// Example 9: Using event.source without origin validation
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_9() {
  window.addEventListener('message', function(event) {
    // ruleid: javascript-origin-validation
    const message = event.data;
    
    // Responding to the sender without validating origin
    if (event.source) {
      event.source.postMessage({
        type: 'RESPONSE',
        data: sensitiveUserData
      }, '*');
    }
  });
  
  const sensitiveUserData = {
    name: 'John Doe',
    ssn: '123-45-6789'
  };
}
// {/fact}

// Example 10: Validating origin with loose equality (==)
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_10() {
  const TRUSTED_ORIGIN = 'https://trusted.example.com';
  
  window.addEventListener('message', function(event) {
    // ruleid: javascript-origin-validation
    if (event.origin == TRUSTED_ORIGIN) {
      // Using == instead of === can lead to type coercion issues
      const command = event.data;
      executeCommand(command);
    }
  });
  
  function executeCommand(cmd) {
    console.log("Executing command:", cmd);
  }
}
// {/fact}

// Example 11: Using a variable origin without validation
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_11() {
  let partnerOrigin = null;
  
  // First message sets the partner origin
  window.addEventListener('message', function(event) {
    if (!partnerOrigin) {
      partnerOrigin = event.origin;
      console.log('Partner origin set to:', partnerOrigin);
    }
    
    // ruleid: javascript-origin-validation
    // Subsequent messages use that origin without validation
    if (event.origin === partnerOrigin) {
      processPartnerData(event.data);
    }
  });
  
  function processPartnerData(data) {
    console.log("Processing partner data:", data);
  }
}
// {/fact}

// Example 12: Using multiple origins without proper validation
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_12() {
  const possibleOrigins = [
    'https://partner1.com',
    'https://partner2.com',
    'https://partner3.com'
  ];
  
  window.addEventListener('message', function(event) {
    // ruleid: javascript-origin-validation
    if (possibleOrigins.includes(event.origin)) {
      // This is vulnerable if the list includes untrusted origins
      const userData = JSON.parse(event.data);
      document.cookie = `userSession=${userData.sessionId}; path=/`;
    }
  });
}
// {/fact}

// Example 13: Checking origin in a separate function but not using the result
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_13() {
  window.addEventListener('message', function(event) {
    checkOrigin(event.origin);
    
    // ruleid: javascript-origin-validation
    // Origin check result is not used to guard the sensitive operation
    const data = JSON.parse(event.data);
    document.getElementById('userProfile').innerHTML = data.profileHtml;
  });
  
  function checkOrigin(origin) {
    if (origin !== 'https://trusted.example.com') {
      console.warn('Received message from untrusted origin:', origin);
      return false;
    }
    return true;
  }
}
// {/fact}

// Example 14: Using an overly permissive list of origins
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_14() {
  const allowedOrigins = [
    'https://example.com',
    'http://example.com',
    'https://dev.example.com',
    'http://localhost:8080',
    'null' // Allows messages from sandboxed iframes
  ];
  
  window.addEventListener('message', function(event) {
    // ruleid: javascript-origin-validation
    if (allowedOrigins.includes(event.origin) || event.origin === 'null') {
      // Too permissive, especially with 'null' origin
      const command = event.data;
      executeAdminCommand(command);
    }
  });
  
  function executeAdminCommand(cmd) {
    console.log("Executing admin command:", cmd);
  }
}
// {/fact}

// Example 15: Accepting messages from subdomains without proper validation
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_15() {
  window.addEventListener('message', function(event) {
    // ruleid: javascript-origin-validation
    if (event.origin.endsWith('.example.com')) {
      // This would accept messages from any subdomain, including malicious ones
      const data = event.data;
      if (data.type === 'UPDATE_ACCOUNT') {
        updateUserAccount(data.userId, data.newEmail);
      }
    }
  });
  
  function updateUserAccount(userId, newEmail) {
    console.log(`Updating user ${userId} email to ${newEmail}`);
  }
}
// {/fact}

// True Negative Examples (Secure Code)

// Example 1: Proper origin validation with exact match
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_1() {
  const TRUSTED_ORIGIN = 'https://trusted.example.com';
  
  window.addEventListener('message', function(event) {
    // ok: javascript-origin-validation
    if (event.origin === TRUSTED_ORIGIN) {
      const data = event.data;
      document.getElementById('content').innerHTML = data.message;
    } else {
      console.error('Received message from untrusted origin:', event.origin);
    }
  });
}
// {/fact}

// Example 2: Multiple trusted origins with strict validation
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_2() {
  const TRUSTED_ORIGINS = [
    'https://main.example.com',
    'https://api.example.com',
    'https://auth.example.com'
  ];
  
  window.addEventListener('message', function(event) {
    // ok: javascript-origin-validation
    if (TRUSTED_ORIGINS.includes(event.origin)) {
      const userData = JSON.parse(event.data);
      localStorage.setItem('userToken', userData.token);
    } else {
      console.error('Rejected message from untrusted origin:', event.origin);
    }
  });
}
// {/fact}

// Example 3: Origin validation with iframe communication
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_3() {
  const PAYMENT_ORIGIN = 'https://payments.example.com';
  const iframe = document.getElementById('paymentFrame');
  
  window.addEventListener('message', function(event) {
    // ok: javascript-origin-validation
    if (event.origin === PAYMENT_ORIGIN && event.source === iframe.contentWindow) {
      const paymentInfo = event.data;
      processPayment(paymentInfo.cardNumber, paymentInfo.cvv);
    } else {
      console.error('Rejected payment message from untrusted source:', event.origin);
    }
  });
  
  function processPayment(cardNumber, cvv) {
    // Process payment logic
    console.log("Processing payment with card:", cardNumber);
  }
}
// {/fact}

// Example 4: Using URL object for strict origin validation
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_4() {
  const TRUSTED_ORIGIN = new URL('https://trusted.example.com').origin;
  
  window.addEventListener('message', function(event) {
    // ok: javascript-origin-validation
    if (event.origin === TRUSTED_ORIGIN) {
      const userData = JSON.parse(event.data);
      document.getElementById('username').textContent = userData.name;
    } else {
      console.warn('Ignored message from untrusted origin:', event.origin);
    }
  });
}
// {/fact}

// Example 5: Origin validation with additional message type check
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_5() {
  const ADMIN_ORIGIN = 'https://admin.example.com';
  
  window.addEventListener('message', function(event) {
    // ok: javascript-origin-validation
    if (event.origin === ADMIN_ORIGIN) {
      try {
        const command = JSON.parse(event.data);
        
        if (command.type === 'ADMIN_COMMAND' && command.hasOwnProperty('script')) {
          // Additional validation of message structure
          executeAdminScript(command.script);
        }
      } catch (e) {
        console.error('Failed to process admin message:', e);
      }
    }
  });
  
  function executeAdminScript(script) {
    // Safer execution method instead of eval
    const scriptElement = document.createElement('script');
    scriptElement.textContent = script;
    document.head.appendChild(scriptElement);
  }
}
// {/fact}

// Example 6: Using environment configuration for trusted origins
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_6() {
  // In a real app, this would come from environment config
  const TRUSTED_ORIGINS = [
    'https://app.example.com',
    'https://staging.example.com'
  ];
  
  window.addEventListener('message', function(event) {
    // ok: javascript-origin-validation
    const originIsTrusted = TRUSTED_ORIGINS.includes(event.origin);
    
    if (originIsTrusted) {
      const data = event.data;
      document.getElementById('adminPanel').style.display = data.showAdmin ? 'block' : 'none';
    } else {
      console.error('Rejected UI control message from untrusted origin:', event.origin);
    }
  });
}
// {/fact}

// Example 7: Origin validation with protocol and domain check
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_7() {
  function isValidOrigin(origin) {
    try {
      const url = new URL(origin);
      return url.protocol === 'https:' && 
             (url.hostname === 'api.example.com' || url.hostname === 'app.example.com');
    } catch (e) {
      return false;
    }
  }
  
  window.addEventListener('message', function(event) {
    // ok: javascript-origin-validation
    if (isValidOrigin(event.origin)) {
      const userConfig = JSON.parse(event.data);
      updateUserPreferences(userConfig);
    } else {
      console.error('Rejected config message from invalid origin:', event.origin);
    }
  });
  
  function updateUserPreferences(config) {
    // Update user preferences
    console.log("Updating preferences:", config);
  }
}
// {/fact}

// Example 8: Validating both origin and message structure
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_8() {
  const AUTH_ORIGIN = 'https://auth.example.com';
  
  window.addEventListener('message', function(event) {
    // ok: javascript-origin-validation
    if (event.origin === AUTH_ORIGIN) {
      const data = event.data;
      
      if (data && data.type === 'AUTH_REQUEST' && data.requestId) {
        sendAuthResponse(data.requestId);
      } else {
        console.warn('Received malformed auth message from trusted origin');
      }
    } else {
      console.error('Rejected auth message from untrusted origin:', event.origin);
    }
  });
  
  function sendAuthResponse(requestId) {
    // Send authentication response
    console.log("Sending auth response for:", requestId);
  }
}
// {/fact}

// Example 9: Secure response using validated origin
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_9() {
  const TRUSTED_ORIGIN = 'https://partner.example.com';
  
  window.addEventListener('message', function(event) {
    // ok: javascript-origin-validation
    if (event.origin === TRUSTED_ORIGIN && event.source) {
      const message = event.data;
      
      // Responding to the sender using their validated origin
      event.source.postMessage({
        type: 'RESPONSE',
        data: sensitiveUserData
      }, event.origin); // Using validated origin instead of '*'
    } else {
      console.error('Rejected message from untrusted source:', event.origin);
    }
  });
  
  const sensitiveUserData = {
    name: 'John Doe',
    ssn: '123-45-6789'
  };
}
// {/fact}

// Example 10: Using strict equality and constant-time comparison
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_10() {
  const TRUSTED_ORIGIN = 'https://trusted.example.com';
  
  // Simple constant-time string comparison to prevent timing attacks
  function secureCompare(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') {
      return false;
    }
    
    if (a.length !== b.length) {
      return false;
    }
    
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    
    return result === 0;
  }
  
  window.addEventListener('message', function(event) {
    // ok: javascript-origin-validation
    if (secureCompare(event.origin, TRUSTED_ORIGIN)) {
      const command = event.data;
      executeCommand(command);
    } else {
      console.error('Rejected command from untrusted origin:', event.origin);
    }
  });
  
  function executeCommand(cmd) {
    console.log("Executing command:", cmd);
  }
}
// {/fact}

// Example 11: Using a whitelist with domain validation
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_11() {
  const trustedDomains = [
    'example.com',
    'example-api.com'
  ];
  
  function isFromTrustedDomain(origin) {
    try {
      const url = new URL(origin);
      const hostname = url.hostname;
      
      return trustedDomains.some(domain => {
        // Check if hostname is exactly the domain or a subdomain
        return hostname === domain || 
               hostname.endsWith('.' + domain);
      });
    } catch (e) {
      return false;
    }
  }
  
  window.addEventListener('message', function(event) {
    // ok: javascript-origin-validation
    if (event.origin.startsWith('https://') && isFromTrustedDomain(event.origin)) {
      processPartnerData(event.data);
    } else {
      console.error('Rejected message from untrusted domain:', event.origin);
    }
  });
  
  function processPartnerData(data) {
    console.log("Processing partner data:", data);
  }
}
// {/fact}

// Example 12: Using environment variables for origin validation
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_12() {
  // In a real app, these would be injected during build or from environment
  const ENV = {
    TRUSTED_ORIGINS: JSON.stringify([
      'https://partner1.com',
      'https://partner2.com'
    ])
  };
  
  const trustedOrigins = JSON.parse(ENV.TRUSTED_ORIGINS);
  
  window.addEventListener('message', function(event) {
    // ok: javascript-origin-validation
    if (trustedOrigins.includes(event.origin)) {
      const userData = JSON.parse(event.data);
      
      // Using HttpOnly cookies set by the server instead
      console.log('Processing user data from trusted partner:', userData);
    } else {
      console.error('Rejected message from untrusted origin:', event.origin);
    }
  });
}
// {/fact}

// Example 13: Using a validation function and acting on the result
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_13() {
  const TRUSTED_ORIGIN = 'https://trusted.example.com';
  
  function validateOrigin(origin) {
    return origin === TRUSTED_ORIGIN;
  }
  
  window.addEventListener('message', function(event) {
    // ok: javascript-origin-validation
    const isValidOrigin = validateOrigin(event.origin);
    
    if (isValidOrigin) {
      const data = JSON.parse(event.data);
      
      // Using DOMPurify to sanitize HTML content even from trusted origins
      const sanitizedHtml = DOMPurify.sanitize(data.profileHtml);
      document.getElementById('userProfile').innerHTML = sanitizedHtml;
    } else {
      console.error('Rejected profile update from untrusted origin:', event.origin);
    }
  });
  
  // Mock DOMPurify for the example
  const DOMPurify = {
    sanitize: function(html) {
      // In a real app, this would be the actual DOMPurify library
      return html.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
    }
  };
}
// {/fact}

// Example 14: Strict production vs. development origins
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_14() {
  // In a real app, this would be set based on the environment
  const IS_PRODUCTION = true;
  
  const ORIGINS = {
    production: [
      'https://app.example.com',
      'https://api.example.com'
    ],
    development: [
      'https://dev.example.com',
      'http://localhost:8080'
    ]
  };
  
  const allowedOrigins = IS_PRODUCTION ? ORIGINS.production : ORIGINS.development;
  
  window.addEventListener('message', function(event) {
    // ok: javascript-origin-validation
    if (allowedOrigins.includes(event.origin)) {
      const command = event.data;
      
      // Additional validation of command structure
      if (typeof command === 'object' && command.action && command.params) {
        executeAdminCommand(command);
      } else {
        console.warn('Received malformed command from trusted origin');
      }
    } else {
      console.error('Rejected command from untrusted origin:', event.origin);
    }
  });
  
  function executeAdminCommand(cmd) {
    console.log("Executing admin command:", cmd);
  }
}
// {/fact}

// Example 15: Using subdomain validation with proper regex
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_15() {
  const BASE_DOMAIN = 'example.com';
  
  function isValidSubdomain(origin) {
    try {
      const url = new URL(origin);
      
      // Ensure HTTPS protocol
      if (url.protocol !== 'https:') {
        return false;
      }
      
      // Check if hostname is exactly the base domain or a direct subdomain
      const hostname = url.hostname;
      const regex = new RegExp(`^([a-zA-Z0-9-]+\\.)?${BASE_DOMAIN.replace('.', '\\.')}$`);
      
      return regex.test(hostname);
    } catch (e) {
      return false;
    }
  }
  
  window.addEventListener('message', function(event) {
    // ok: javascript-origin-validation
    if (isValidSubdomain(event.origin)) {
      const data = event.data;
      
      if (data.type === 'UPDATE_ACCOUNT' && data.userId && data.newEmail) {
        // Additional validation of email format
        if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.newEmail)) {
          updateUserAccount(data.userId, data.newEmail);
        } else {
          console.error('Invalid email format in account update request');
        }
      }
    } else {
      console.error('Rejected account update from untrusted origin:', event.origin);
    }
  });
  
  function updateUserAccount(userId, newEmail) {
    console.log(`Updating user ${userId} email to ${newEmail}`);
  }
}
// {/fact}