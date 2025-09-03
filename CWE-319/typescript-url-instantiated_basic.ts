// typescript-url-instantiated test cases

// True Positives (vulnerable code that should be detected)

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1() {
  // Creating a URL with HTTP protocol
  // ruleid: typescript-url-instantiated
  const url = new URL('http://example.com/api/data');
  fetch(url.toString())
    .then(response => response.json())
    .then(data => console.log(data));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2() {
  // String literal with HTTP protocol passed to URL constructor
  // ruleid: typescript-url-instantiated
  const apiEndpoint = new URL('http://api.myservice.com/v1/users');
  const response = await fetch(apiEndpoint);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3() {
  // Variable containing HTTP URL
  const baseUrl = 'http://data.example.org';
  // ruleid: typescript-url-instantiated
  const completeUrl = new URL('/api/products', baseUrl);
  return completeUrl.href;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4() {
  // Template literal with HTTP
  const domain = 'example.com';
  const path = 'users/profile';
  // ruleid: typescript-url-instantiated
  const url = new URL(`http://${domain}/${path}`);
  console.log(url.toString());
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5() {
  // HTTP URL in a configuration object
  const config = {
    // ruleid: typescript-url-instantiated
    endpoint: new URL('http://analytics.example.com/track'),
    method: 'POST'
  };
  sendData(config);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6() {
  // HTTP URL with port specification
  // ruleid: typescript-url-instantiated
  const dbUrl = new URL('http://database.internal:8080');
  connectToDatabase(dbUrl.toString());
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7() {
  // HTTP URL with query parameters
  const userId = '12345';
  // ruleid: typescript-url-instantiated
  const profileUrl = new URL(`http://users.example.com/profile?id=${userId}`);
  loadUserProfile(profileUrl);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8() {
  // HTTP URL in an array of endpoints
  const endpoints = [
    // ruleid: typescript-url-instantiated
    new URL('http://api1.example.com'),
    new URL('https://api2.example.com'),
    new URL('https://api3.example.com')
  ];
  return endpoints;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9() {
  // HTTP URL in a class property
  class ApiClient {
    constructor() {
      // ruleid: typescript-url-instantiated
      this.baseUrl = new URL('http://api.example.com');
    }
    
    fetchData() {
      return fetch(this.baseUrl.toString());
    }
  }
  
  const client = new ApiClient();
  return client.fetchData();
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10() {
  // HTTP URL with authentication information
  // ruleid: typescript-url-instantiated
  const url = new URL('http://user:password@legacy-system.example.com');
  return url.toString();
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11() {
  // HTTP URL constructed from parts
  const protocol = 'http:';
  const hostname = 'example.org';
  // ruleid: typescript-url-instantiated
  const url = new URL(`${protocol}//${hostname}/api/data`);
  return url;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12() {
  // HTTP URL in a conditional statement
  const useSecure = false;
  // ruleid: typescript-url-instantiated
  const url = new URL(useSecure ? 'https://example.com' : 'http://example.com');
  return url.href;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13() {
  // HTTP URL in a function that processes URLs
  function processUrl(path: string) {
    // ruleid: typescript-url-instantiated
    const url = new URL(`http://processor.example.com${path}`);
    return fetch(url);
  }
  
  return processUrl('/analyze');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14() {
  // HTTP URL with hash fragment
  // ruleid: typescript-url-instantiated
  const url = new URL('http://docs.example.com/guide#section-3');
  navigateTo(url);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15() {
  // HTTP URL in a map of service endpoints
  const serviceMap = new Map<string, URL>();
  // ruleid: typescript-url-instantiated
  serviceMap.set('auth', new URL('http://auth.internal/'));
  serviceMap.set('data', new URL('https://data.example.com/'));
  
  return serviceMap.get('auth');
}
// {/fact}

// True Negatives (secure code that should not be detected)

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1() {
  // Using HTTPS protocol
  // ok: typescript-url-instantiated
  const url = new URL('https://example.com/api/data');
  fetch(url.toString())
    .then(response => response.json())
    .then(data => console.log(data));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2() {
  // HTTPS URL with query parameters
  const userId = '12345';
  // ok: typescript-url-instantiated
  const profileUrl = new URL(`https://users.example.com/profile?id=${userId}`);
  loadUserProfile(profileUrl);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3() {
  // HTTPS base URL with path
  const baseUrl = 'https://data.example.org';
  // ok: typescript-url-instantiated
  const completeUrl = new URL('/api/products', baseUrl);
  return completeUrl.href;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4() {
  // Relative URL (no protocol specified)
  const baseUrl = document.baseURI; // This will inherit the protocol from the current page
  // ok: typescript-url-instantiated
  const relativeUrl = new URL('/api/data', baseUrl);
  return fetch(relativeUrl);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5() {
  // HTTPS URL in a configuration object
  const config = {
    // ok: typescript-url-instantiated
    endpoint: new URL('https://analytics.example.com/track'),
    method: 'POST'
  };
  sendData(config);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6() {
  // HTTPS URL with port specification
  // ok: typescript-url-instantiated
  const dbUrl = new URL('https://database.internal:8443');
  connectToDatabase(dbUrl.toString());
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7() {
  // Using environment variable for base URL (assuming it's HTTPS)
  const apiBaseUrl = process.env.API_BASE_URL || 'https://api.example.com';
  // ok: typescript-url-instantiated
  const url = new URL('/users', apiBaseUrl);
  return fetch(url);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8() {
  // Array of HTTPS endpoints
  const endpoints = [
    // ok: typescript-url-instantiated
    new URL('https://api1.example.com'),
    new URL('https://api2.example.com'),
    new URL('https://api3.example.com')
  ];
  return endpoints;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9() {
  // HTTPS URL in a class property
  class SecureApiClient {
    constructor() {
      // ok: typescript-url-instantiated
      this.baseUrl = new URL('https://api.example.com');
    }
    
    fetchData() {
      return fetch(this.baseUrl.toString());
    }
  }
  
  const client = new SecureApiClient();
  return client.fetchData();
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10() {
  // File URL (not HTTP)
  // ok: typescript-url-instantiated
  const fileUrl = new URL('file:///path/to/local/file.txt');
  readLocalFile(fileUrl);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11() {
  // Data URL (not HTTP)
  // ok: typescript-url-instantiated
  const dataUrl = new URL('data:text/plain;base64,SGVsbG8gV29ybGQh');
  processDataUrl(dataUrl);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12() {
  // HTTPS URL with authentication information
  // ok: typescript-url-instantiated
  const url = new URL('https://user:password@secure-system.example.com');
  return url.toString();
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13() {
  // HTTPS URL constructed from parts
  const protocol = 'https:';
  const hostname = 'example.org';
  // ok: typescript-url-instantiated
  const url = new URL(`${protocol}//${hostname}/api/data`);
  return url;
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14() {
  // WebSocket secure URL (wss)
  // ok: typescript-url-instantiated
  const wsUrl = new URL('wss://websocket.example.com/socket');
  const socket = new WebSocket(wsUrl);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15() {
  // Localhost URL (exception for development)
  // ok: typescript-url-instantiated
  const localUrl = new URL('http://localhost:3000/api');
  return fetch(localUrl);
}
// {/fact}

// Helper functions to make the examples work
function sendData(config: any) {}
function connectToDatabase(url: string) {}
function loadUserProfile(url: URL) {}
function navigateTo(url: URL) {}
function readLocalFile(url: URL) {}
function processDataUrl(url: URL) {}