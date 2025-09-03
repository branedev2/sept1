// Test cases for javascript-origins-verified-cross-origin-communication
// CWE-346: Origin Validation Error

// True Positives (Vulnerable Code)

// Bad case 1: Using wildcard (*) as target origin in postMessage
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_1() {
  const iframe = document.getElementById('myIframe');
  const message = { secret: 'sensitive data' };
  
  // ruleid: javascript-origins-verified-cross-origin-communication
  iframe.contentWindow.postMessage(message, '*');
}
// {/fact}

// Bad case 2: Not checking origin in message event listener
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_2() {
  window.addEventListener('message', function(event) {
    // ruleid: javascript-origins-verified-cross-origin-communication
    const data = event.data;
    document.getElementById('result').textContent = data.text;
  });
}
// {/fact}

// Bad case 3: Using wildcard with structured data
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_3() {
  const popup = window.open('https://example.com');
  const userData = {
    id: 12345,
    username: 'user',
    token: 'abc123xyz'
  };
  
  // ruleid: javascript-origins-verified-cross-origin-communication
  popup.postMessage(userData, '*');
}
// {/fact}

// Bad case 4: Ignoring origin check in complex message handler
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_4() {
  window.addEventListener('message', function(event) {
    // ruleid: javascript-origins-verified-cross-origin-communication
    try {
      const command = JSON.parse(event.data);
      if (command.action === 'update') {
        updateUserProfile(command.data);
      } else if (command.action === 'delete') {
        deleteUserAccount(command.userId);
      }
    } catch (e) {
      console.error('Invalid message format', e);
    }
  });
}
// {/fact}

// Bad case 5: Using wildcard in iframe communication
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_5() {
  const iframe = document.createElement('iframe');
  iframe.src = 'https://third-party-site.com';
  document.body.appendChild(iframe);
  
  const sensitiveData = { apiKey: 'secret-api-key-12345' };
  setTimeout(() => {
    // ruleid: javascript-origins-verified-cross-origin-communication
    iframe.contentWindow.postMessage(sensitiveData, '*');
  }, 1000);
}
// {/fact}

// Bad case 6: Event listener with conditional logic but no origin check
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_6() {
  window.addEventListener('message', function(event) {
    // ruleid: javascript-origins-verified-cross-origin-communication
    if (event.data && event.data.type === 'AUTH_REQUEST') {
      const token = generateAuthToken();
      event.source.postMessage({ type: 'AUTH_RESPONSE', token: token }, '*');
    }
  });
}
// {/fact}

// Bad case 7: Using wildcard in a React component
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_7() {
  class CrossOriginComponent extends React.Component {
    componentDidMount() {
      // ruleid: javascript-origins-verified-cross-origin-communication
      window.parent.postMessage({ loaded: true, componentId: this.props.id }, '*');
    }
    
    render() {
      return <div>Cross-origin component</div>;
    }
  }
  
  return <CrossOriginComponent id="widget123" />;
}
// {/fact}

// Bad case 8: Message handler in arrow function without origin check
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_8() {
  // ruleid: javascript-origins-verified-cross-origin-communication
  window.addEventListener('message', (event) => {
    const { method, params } = event.data;
    
    switch (method) {
      case 'getData':
        const data = fetchData(params);
        event.source.postMessage({ result: data }, '*');
        break;
      case 'setConfig':
        setConfiguration(params);
        break;
    }
  });
}
// {/fact}

// Bad case 9: Using wildcard in multiple postMessage calls
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_9() {
  const frames = document.querySelectorAll('iframe');
  const notification = { type: 'refresh', timestamp: Date.now() };
  
  frames.forEach(frame => {
    // ruleid: javascript-origins-verified-cross-origin-communication
    frame.contentWindow.postMessage(notification, '*');
  });
}
// {/fact}

// Bad case 10: Message event handler with destructuring but no origin check
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_10() {
  window.addEventListener('message', function(event) {
    // ruleid: javascript-origins-verified-cross-origin-communication
    const { type, payload } = event.data;
    
    if (type === 'SUBMIT_FORM') {
      processFormData(payload);
      event.source.postMessage({ type: 'FORM_PROCESSED', success: true }, '*');
    }
  });
}
// {/fact}

// Bad case 11: Using wildcard in a promise-based communication
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_11() {
  function requestDataFromIframe(iframe, requestData) {
    return new Promise((resolve) => {
      const messageHandler = (event) => {
        // ruleid: javascript-origins-verified-cross-origin-communication
        if (event.data.requestId === requestData.id) {
          window.removeEventListener('message', messageHandler);
          resolve(event.data.response);
        }
      };
      
      window.addEventListener('message', messageHandler);
      // ruleid: javascript-origins-verified-cross-origin-communication
      iframe.contentWindow.postMessage(requestData, '*');
    });
  }
  
  const iframe = document.getElementById('dataFrame');
  requestDataFromIframe(iframe, { id: 'request-123', action: 'getUsers' })
    .then(response => console.log(response));
}
// {/fact}

// Bad case 12: Using wildcard in broadcast channel alternative
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_12() {
  const windows = [
    window.open('https://example.com/page1'),
    window.open('https://example.com/page2'),
    window.open('https://example.com/page3')
  ];
  
  function broadcast(message) {
    windows.forEach(win => {
      if (win && !win.closed) {
        // ruleid: javascript-origins-verified-cross-origin-communication
        win.postMessage(message, '*');
      }
    });
  }
  
  broadcast({ type: 'CONFIG_CHANGE', settings: { theme: 'dark' } });
}
// {/fact}

// Bad case 13: Event listener with async function but no origin check
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_13() {
  window.addEventListener('message', async function(event) {
    // ruleid: javascript-origins-verified-cross-origin-communication
    if (event.data.type === 'FETCH_DATA') {
      try {
        const response = await fetch(`/api/data/${event.data.id}`);
        const data = await response.json();
        event.source.postMessage({ type: 'DATA_RESULT', data }, '*');
      } catch (error) {
        event.source.postMessage({ type: 'ERROR', message: error.message }, '*');
      }
    }
  });
}
// {/fact}

// Bad case 14: Using wildcard in a library wrapper function
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_14() {
  class CrossWindowMessenger {
    constructor(targetWindow) {
      this.targetWindow = targetWindow;
    }
    
    send(message) {
      // ruleid: javascript-origins-verified-cross-origin-communication
      this.targetWindow.postMessage(message, '*');
    }
    
    listen(callback) {
      window.addEventListener('message', event => {
        // ruleid: javascript-origins-verified-cross-origin-communication
        callback(event.data);
      });
    }
  }
  
  const messenger = new CrossWindowMessenger(window.parent);
  messenger.send({ type: 'READY' });
  messenger.listen(data => console.log('Received:', data));
}
// {/fact}

// Bad case 15: Using wildcard with conditional target origin
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_15() {
  function sendToParent(message, targetOrigin = null) {
    // ruleid: javascript-origins-verified-cross-origin-communication
    window.parent.postMessage(message, targetOrigin || '*');
  }
  
  sendToParent({ type: 'PAGE_VIEW', url: window.location.href });
}
// {/fact}

// True Negatives (Secure Code)

// Good case 1: Specifying exact target origin in postMessage
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_1() {
  const iframe = document.getElementById('myIframe');
  const message = { secret: 'sensitive data' };
  
  // ok: javascript-origins-verified-cross-origin-communication
  iframe.contentWindow.postMessage(message, 'https://trusted-site.com');
}
// {/fact}

// Good case 2: Checking origin in message event listener
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_2() {
  window.addEventListener('message', function(event) {
    // ok: javascript-origins-verified-cross-origin-communication
    if (event.origin === 'https://trusted-site.com') {
      const data = event.data;
      document.getElementById('result').textContent = data.text;
    }
  });
}
// {/fact}

// Good case 3: Verifying origin with multiple allowed domains
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_3() {
  const allowedOrigins = [
    'https://trusted-site.com',
    'https://another-trusted-site.org',
    'https://third-trusted-site.net'
  ];
  
  window.addEventListener('message', function(event) {
    // ok: javascript-origins-verified-cross-origin-communication
    if (allowedOrigins.includes(event.origin)) {
      processMessage(event.data);
    } else {
      console.warn('Received message from untrusted origin:', event.origin);
    }
  });
}
// {/fact}

// Good case 4: Using specific origin with structured data
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_4() {
  const popup = window.open('https://example.com');
  const userData = {
    id: 12345,
    username: 'user',
    token: 'abc123xyz'
  };
  
  // ok: javascript-origins-verified-cross-origin-communication
  popup.postMessage(userData, 'https://example.com');
}
// {/fact}

// Good case 5: Comprehensive origin and source verification
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_5() {
  const expectedWindow = document.getElementById('trustedIframe').contentWindow;
  
  window.addEventListener('message', function(event) {
    // ok: javascript-origins-verified-cross-origin-communication
    if (event.origin === 'https://trusted-site.com' && event.source === expectedWindow) {
      try {
        const data = JSON.parse(event.data);
        processVerifiedData(data);
      } catch (e) {
        console.error('Invalid message format');
      }
    }
  });
}
// {/fact}

// Good case 6: Using specific origin with iframe creation
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_6() {
  const iframe = document.createElement('iframe');
  iframe.src = 'https://third-party-site.com';
  document.body.appendChild(iframe);
  
  const sensitiveData = { apiKey: 'secret-api-key-12345' };
  setTimeout(() => {
    // ok: javascript-origins-verified-cross-origin-communication
    iframe.contentWindow.postMessage(sensitiveData, 'https://third-party-site.com');
  }, 1000);
}
// {/fact}

// Good case 7: Origin check with conditional logic
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_7() {
  window.addEventListener('message', function(event) {
    // ok: javascript-origins-verified-cross-origin-communication
    if (event.origin === 'https://trusted-site.com') {
      if (event.data && event.data.type === 'AUTH_REQUEST') {
        const token = generateAuthToken();
        event.source.postMessage({ type: 'AUTH_RESPONSE', token: token }, event.origin);
      }
    }
  });
}
// {/fact}

// Good case 8: Origin verification in a React component
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_8() {
  class SecureCrossOriginComponent extends React.Component {
    componentDidMount() {
      // ok: javascript-origins-verified-cross-origin-communication
      window.parent.postMessage(
        { loaded: true, componentId: this.props.id },
        this.props.parentOrigin // Specific origin passed as prop
      );
      
      window.addEventListener('message', this.handleMessage);
    }
    
    handleMessage = (event) => {
      // ok: javascript-origins-verified-cross-origin-communication
      if (event.origin === this.props.parentOrigin) {
        // Process the message
        this.setState({ data: event.data });
      }
    }
    
    componentWillUnmount() {
      window.removeEventListener('message', this.handleMessage);
    }
    
    render() {
      return <div>Secure cross-origin component</div>;
    }
  }
  
  return <SecureCrossOriginComponent id="widget123" parentOrigin="https://parent-app.com" />;
}
// {/fact}

// Good case 9: Origin check with arrow function
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_9() {
  window.addEventListener('message', (event) => {
    // ok: javascript-origins-verified-cross-origin-communication
    if (event.origin === 'https://trusted-site.com') {
      const { method, params } = event.data;
      
      switch (method) {
        case 'getData':
          const data = fetchData(params);
          event.source.postMessage({ result: data }, event.origin);
          break;
        case 'setConfig':
          setConfiguration(params);
          break;
      }
    }
  });
}
// {/fact}

// Good case 10: Using specific origins for multiple frames
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_10() {
  const frames = [
    { element: document.getElementById('frame1'), origin: 'https://site1.com' },
    { element: document.getElementById('frame2'), origin: 'https://site2.com' },
    { element: document.getElementById('frame3'), origin: 'https://site3.com' }
  ];
  
  const notification = { type: 'refresh', timestamp: Date.now() };
  
  frames.forEach(frame => {
    if (frame.element && frame.element.contentWindow) {
      // ok: javascript-origins-verified-cross-origin-communication
      frame.element.contentWindow.postMessage(notification, frame.origin);
    }
  });
}
// {/fact}

// Good case 11: Origin check with destructuring
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_11() {
  window.addEventListener('message', function(event) {
    // ok: javascript-origins-verified-cross-origin-communication
    if (event.origin === 'https://trusted-site.com') {
      const { type, payload } = event.data;
      
      if (type === 'SUBMIT_FORM') {
        processFormData(payload);
        event.source.postMessage({ type: 'FORM_PROCESSED', success: true }, event.origin);
      }
    }
  });
}
// {/fact}

// Good case 12: Promise-based communication with origin verification
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_12() {
  function secureRequestDataFromIframe(iframe, requestData, targetOrigin) {
    return new Promise((resolve, reject) => {
      const messageHandler = (event) => {
        // ok: javascript-origins-verified-cross-origin-communication
        if (event.origin === targetOrigin && event.data.requestId === requestData.id) {
          window.removeEventListener('message', messageHandler);
          resolve(event.data.response);
        }
      };
      
      window.addEventListener('message', messageHandler);
      // ok: javascript-origins-verified-cross-origin-communication
      iframe.contentWindow.postMessage(requestData, targetOrigin);
      
      // Add timeout for security
      setTimeout(() => {
        window.removeEventListener('message', messageHandler);
        reject(new Error('Request timed out'));
      }, 5000);
    });
  }
  
  const iframe = document.getElementById('dataFrame');
  const targetOrigin = 'https://data-provider.com';
  
  secureRequestDataFromIframe(iframe, { id: 'request-123', action: 'getUsers' }, targetOrigin)
    .then(response => console.log(response))
    .catch(error => console.error(error));
}
// {/fact}

// Good case 13: Secure broadcast with specific origins
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_13() {
  const windowsWithOrigins = [
    { window: window.open('https://example.com/page1'), origin: 'https://example.com' },
    { window: window.open('https://example.org/page2'), origin: 'https://example.org' },
    { window: window.open('https://example.net/page3'), origin: 'https://example.net' }
  ];
  
  function secureBroadcast(message) {
    windowsWithOrigins.forEach(item => {
      if (item.window && !item.window.closed) {
        // ok: javascript-origins-verified-cross-origin-communication
        item.window.postMessage(message, item.origin);
      }
    });
  }
  
  secureBroadcast({ type: 'CONFIG_CHANGE', settings: { theme: 'dark' } });
}
// {/fact}

// Good case 14: Async function with origin verification
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_14() {
  window.addEventListener('message', async function(event) {
    // ok: javascript-origins-verified-cross-origin-communication
    if (event.origin === 'https://trusted-api.com') {
      if (event.data.type === 'FETCH_DATA') {
        try {
          const response = await fetch(`/api/data/${event.data.id}`);
          const data = await response.json();
          event.source.postMessage({ type: 'DATA_RESULT', data }, event.origin);
        } catch (error) {
          event.source.postMessage({ type: 'ERROR', message: error.message }, event.origin);
        }
      }
    }
  });
}
// {/fact}

// Good case 15: Secure library wrapper with origin verification
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_15() {
  class SecureCrossWindowMessenger {
    constructor(targetWindow, targetOrigin) {
      this.targetWindow = targetWindow;
      this.targetOrigin = targetOrigin;
      this.allowedOrigins = [targetOrigin];
    }
    
    addAllowedOrigin(origin) {
      this.allowedOrigins.push(origin);
    }
    
    send(message) {
      // ok: javascript-origins-verified-cross-origin-communication
      this.targetWindow.postMessage(message, this.targetOrigin);
    }
    
    listen(callback) {
      window.addEventListener('message', event => {
        // ok: javascript-origins-verified-cross-origin-communication
        if (this.allowedOrigins.includes(event.origin)) {
          callback(event.data, event.origin, event.source);
        } else {
          console.warn('Ignored message from untrusted origin:', event.origin);
        }
      });
    }
  }
  
  const messenger = new SecureCrossWindowMessenger(window.parent, 'https://parent-app.com');
  messenger.send({ type: 'READY' });
  messenger.listen((data, origin) => console.log(`Received from ${origin}:`, data));
}
// {/fact}