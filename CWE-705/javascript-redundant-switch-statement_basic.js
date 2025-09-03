// Test cases for javascript-redundant-switch-statement rule
// This rule detects switch statements with fewer than three case clauses

// True Positives (vulnerable code that should be detected)

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_1() {
  const userRole = 'admin';
  
  // ruleid: javascript-redundant-switch-statement
  switch (userRole) {
    case 'admin':
      console.log('Admin access granted');
      break;
    default:
      console.log('Access denied');
      break;
  }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_2() {
  const statusCode = 404;
  
  // ruleid: javascript-redundant-switch-statement
  switch (statusCode) {
    case 200:
      return 'OK';
    case 404:
      return 'Not Found';
  }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_3() {
  const authMethod = 'oauth';
  let authStrategy;
  
  // ruleid: javascript-redundant-switch-statement
  switch (authMethod) {
    case 'basic':
      authStrategy = 'BasicAuth';
      break;
    case 'oauth':
      authStrategy = 'OAuthStrategy';
      break;
  }
  
  return authStrategy;
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_4() {
  const securityLevel = 1;
  
  // ruleid: javascript-redundant-switch-statement
  switch (securityLevel) {
    case 1:
      enableBasicSecurity();
      break;
    default:
      enableAdvancedSecurity();
      break;
  }
  
  function enableBasicSecurity() {
    console.log('Basic security enabled');
  }
  
  function enableAdvancedSecurity() {
    console.log('Advanced security enabled');
  }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_5() {
  const errorType = 'validation';
  let errorMessage = '';
  
  // ruleid: javascript-redundant-switch-statement
  switch (errorType) {
    case 'validation':
      errorMessage = 'Validation failed';
      break;
    case 'authentication':
      errorMessage = 'Authentication failed';
      break;
  }
  
  return errorMessage;
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_6() {
  const httpMethod = 'GET';
  
  // ruleid: javascript-redundant-switch-statement
  switch (httpMethod) {
    case 'GET':
      handleGetRequest();
      break;
    default:
      handleOtherRequest();
      break;
  }
  
  function handleGetRequest() {
    console.log('Handling GET request');
  }
  
  function handleOtherRequest() {
    console.log('Handling other request');
  }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_7() {
  const encryptionType = 'AES';
  let keySize;
  
  // ruleid: javascript-redundant-switch-statement
  switch (encryptionType) {
    case 'AES':
      keySize = 256;
      break;
    case 'DES':
      keySize = 56;
      break;
  }
  
  return keySize;
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_8() {
  const logLevel = 'error';
  
  // ruleid: javascript-redundant-switch-statement
  switch (logLevel) {
    case 'error':
      console.error('This is an error');
      break;
    default:
      console.log('This is a regular log');
      break;
  }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_9() {
  const accessControl = 'restricted';
  let accessRights;
  
  // ruleid: javascript-redundant-switch-statement
  switch (accessControl) {
    case 'public':
      accessRights = ['read'];
      break;
    case 'restricted':
      accessRights = ['read', 'write'];
      break;
  }
  
  return accessRights;
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_10() {
  const dataFormat = 'json';
  
  // ruleid: javascript-redundant-switch-statement
  switch (dataFormat) {
    case 'json':
      return parseJSON();
    default:
      return parseXML();
  }
  
  function parseJSON() {
    return { parsed: true, format: 'json' };
  }
  
  function parseXML() {
    return { parsed: true, format: 'xml' };
  }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_11() {
  const connectionState = 'connected';
  
  // ruleid: javascript-redundant-switch-statement
  switch (connectionState) {
    case 'connected':
      console.log('Connection established');
      break;
    case 'disconnected':
      console.log('Connection lost');
      break;
  }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_12() {
  const validationResult = false;
  
  // ruleid: javascript-redundant-switch-statement
  switch (validationResult) {
    case true:
      processValidData();
      break;
    case false:
      handleInvalidData();
      break;
  }
  
  function processValidData() {
    console.log('Processing valid data');
  }
  
  function handleInvalidData() {
    console.log('Handling invalid data');
  }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_13() {
  const cacheStrategy = 'memory';
  let cacheImplementation;
  
  // ruleid: javascript-redundant-switch-statement
  switch (cacheStrategy) {
    case 'memory':
      cacheImplementation = new MemoryCache();
      break;
    default:
      cacheImplementation = new DiskCache();
      break;
  }
  
  function MemoryCache() {
    this.store = () => console.log('Storing in memory');
  }
  
  function DiskCache() {
    this.store = () => console.log('Storing on disk');
  }
  
  return cacheImplementation;
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_14() {
  const compressionLevel = 'high';
  let algorithm;
  
  // ruleid: javascript-redundant-switch-statement
  switch (compressionLevel) {
    case 'high':
      algorithm = 'gzip';
      break;
    case 'low':
      algorithm = 'deflate';
      break;
  }
  
  return algorithm;
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_15() {
  const transportProtocol = 'https';
  
  // ruleid: javascript-redundant-switch-statement
  switch (transportProtocol) {
    case 'http':
      return 80;
    case 'https':
      return 443;
  }
}
// {/fact}

// True Negatives (safe code that should not be detected)

// {fact rule=code-injection@v1.0 defects=0}
function good_case_1() {
  const userRole = 'admin';
  
  // ok: javascript-redundant-switch-statement
  switch (userRole) {
    case 'admin':
      console.log('Admin access granted');
      break;
    case 'manager':
      console.log('Manager access granted');
      break;
    case 'user':
      console.log('User access granted');
      break;
    default:
      console.log('Access denied');
      break;
  }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_2() {
  const statusCode = 404;
  
  // ok: javascript-redundant-switch-statement
  switch (statusCode) {
    case 200:
      return 'OK';
    case 404:
      return 'Not Found';
    case 500:
      return 'Server Error';
    case 403:
      return 'Forbidden';
  }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_3() {
  const authMethod = 'oauth';
  let authStrategy;
  
  // ok: javascript-redundant-switch-statement
  switch (authMethod) {
    case 'basic':
      authStrategy = 'BasicAuth';
      break;
    case 'oauth':
      authStrategy = 'OAuthStrategy';
      break;
    case 'jwt':
      authStrategy = 'JWTStrategy';
      break;
    case 'saml':
      authStrategy = 'SAMLStrategy';
      break;
  }
  
  return authStrategy;
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_4() {
  const securityLevel = 1;
  
  // Using if-else instead of a switch with fewer than 3 cases
  // ok: javascript-redundant-switch-statement
  if (securityLevel === 1) {
    enableBasicSecurity();
  } else {
    enableAdvancedSecurity();
  }
  
  function enableBasicSecurity() {
    console.log('Basic security enabled');
  }
  
  function enableAdvancedSecurity() {
    console.log('Advanced security enabled');
  }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_5() {
  const errorType = 'validation';
  
  // Using object literal instead of switch with fewer than 3 cases
  // ok: javascript-redundant-switch-statement
  const errorMessages = {
    'validation': 'Validation failed',
    'authentication': 'Authentication failed'
  };
  
  return errorMessages[errorType] || 'Unknown error';
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_6() {
  const httpMethod = 'GET';
  
  // ok: javascript-redundant-switch-statement
  switch (httpMethod) {
    case 'GET':
      handleGetRequest();
      break;
    case 'POST':
      handlePostRequest();
      break;
    case 'PUT':
      handlePutRequest();
      break;
    case 'DELETE':
      handleDeleteRequest();
      break;
    default:
      handleOtherRequest();
      break;
  }
  
  function handleGetRequest() { console.log('Handling GET'); }
  function handlePostRequest() { console.log('Handling POST'); }
  function handlePutRequest() { console.log('Handling PUT'); }
  function handleDeleteRequest() { console.log('Handling DELETE'); }
  function handleOtherRequest() { console.log('Handling other'); }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_7() {
  const encryptionType = 'AES';
  
  // Using a Map instead of a switch with fewer than 3 cases
  // ok: javascript-redundant-switch-statement
  const keySizes = new Map([
    ['AES', 256],
    ['DES', 56]
  ]);
  
  return keySizes.get(encryptionType);
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_8() {
  const logLevel = 'error';
  
  // Using ternary operator instead of switch with fewer than 3 cases
  // ok: javascript-redundant-switch-statement
  logLevel === 'error' ? console.error('This is an error') : console.log('This is a regular log');
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_9() {
  const accessControl = 'restricted';
  
  // ok: javascript-redundant-switch-statement
  switch (accessControl) {
    case 'public':
      return ['read'];
    case 'restricted':
      return ['read', 'write'];
    case 'private':
      return ['read', 'write', 'delete'];
    case 'admin':
      return ['read', 'write', 'delete', 'manage'];
  }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_10() {
  const dataFormat = 'json';
  
  // Using if-else instead of switch with fewer than 3 cases
  // ok: javascript-redundant-switch-statement
  if (dataFormat === 'json') {
    return parseJSON();
  } else {
    return parseXML();
  }
  
  function parseJSON() {
    return { parsed: true, format: 'json' };
  }
  
  function parseXML() {
    return { parsed: true, format: 'xml' };
  }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_11() {
  const connectionState = 'connected';
  
  // ok: javascript-redundant-switch-statement
  switch (connectionState) {
    case 'connecting':
      console.log('Establishing connection');
      break;
    case 'connected':
      console.log('Connection established');
      break;
    case 'disconnected':
      console.log('Connection lost');
      break;
    case 'reconnecting':
      console.log('Attempting to reconnect');
      break;
  }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_12() {
  const validationResult = false;
  
  // Using direct boolean check instead of switch
  // ok: javascript-redundant-switch-statement
  if (validationResult) {
    processValidData();
  } else {
    handleInvalidData();
  }
  
  function processValidData() {
    console.log('Processing valid data');
  }
  
  function handleInvalidData() {
    console.log('Handling invalid data');
  }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_13() {
  const cacheStrategy = 'memory';
  
  // ok: javascript-redundant-switch-statement
  switch (cacheStrategy) {
    case 'memory':
      return new MemoryCache();
    case 'disk':
      return new DiskCache();
    case 'redis':
      return new RedisCache();
    case 'memcached':
      return new MemcachedCache();
  }
  
  function MemoryCache() {
    this.store = () => console.log('Storing in memory');
  }
  
  function DiskCache() {
    this.store = () => console.log('Storing on disk');
  }
  
  function RedisCache() {
    this.store = () => console.log('Storing in Redis');
  }
  
  function MemcachedCache() {
    this.store = () => console.log('Storing in Memcached');
  }
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_14() {
  const compressionLevel = 'high';
  
  // Using object literal instead of switch
  // ok: javascript-redundant-switch-statement
  const algorithms = {
    'high': 'gzip',
    'low': 'deflate'
  };
  
  return algorithms[compressionLevel] || 'none';
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_15() {
  const transportProtocol = 'https';
  
  // ok: javascript-redundant-switch-statement
  switch (transportProtocol) {
    case 'http':
      return 80;
    case 'https':
      return 443;
    case 'ftp':
      return 21;
    case 'ssh':
      return 22;
    case 'smtp':
      return 25;
  }
}
// {/fact}