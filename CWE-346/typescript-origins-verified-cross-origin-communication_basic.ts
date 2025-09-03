// typescript-origins-verified-cross-origin-communication.ts

// True Positives (Vulnerable Code)

// Bad case 1: Using postMessage with wildcard origin
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_1() {
  const iframe = document.getElementById('myIframe') as HTMLIFrameElement;
  const message = { action: 'getData', id: 123 };
  
  // ruleid: typescript-origins-verified-cross-origin-communication
  iframe.contentWindow?.postMessage(message, '*');
}
// {/fact}

// Bad case 2: Receiving message without origin check
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_2() {
  // ruleid: typescript-origins-verified-cross-origin-communication
  window.addEventListener('message', (event) => {
    const data = event.data;
    document.getElementById('output')!.textContent = data.message;
  });
}
// {/fact}

// Bad case 3: Using postMessage with wildcard in a complex scenario
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_3() {
  const popup = window.open('https://external-site.com/page');
  const userInfo = {
    username: 'user123',
    token: 'abcd1234',
    permissions: ['read', 'write']
  };
  
  if (popup) {
    setTimeout(() => {
      // ruleid: typescript-origins-verified-cross-origin-communication
      popup.postMessage(userInfo, '*');
    }, 1000);
  }
}
// {/fact}

// Bad case 4: Message listener without origin verification in a React component
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_4() {
  class MessageComponent {
    componentDidMount() {
      // ruleid: typescript-origins-verified-cross-origin-communication
      window.addEventListener('message', this.handleMessage);
    }
    
    handleMessage = (event: MessageEvent) => {
      this.setState({ data: event.data });
    }
    
    componentWillUnmount() {
      window.removeEventListener('message', this.handleMessage);
    }
  }
}
// {/fact}

// Bad case 5: Using postMessage with dynamic but unverified target origin
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_5() {
  const iframe = document.getElementById('dynamicIframe') as HTMLIFrameElement;
  const targetOrigin = document.getElementById('originInput')?.getAttribute('data-origin') || '*';
  const message = { type: 'update', content: 'New data available' };
  
  // ruleid: typescript-origins-verified-cross-origin-communication
  iframe.contentWindow?.postMessage(message, targetOrigin);
}
// {/fact}

// Bad case 6: Message handler with partial but insufficient origin check
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_6() {
  // ruleid: typescript-origins-verified-cross-origin-communication
  window.addEventListener('message', (event: MessageEvent) => {
    // This check is insufficient as it only checks if origin exists, not what it is
    if (event.origin) {
      const data = event.data;
      processUserData(data);
    }
  });
  
  function processUserData(data: any) {
    console.log('Processing:', data);
  }
}
// {/fact}

// Bad case 7: Using postMessage in a service worker without origin check
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_7() {
  // Inside a service worker
  self.addEventListener('fetch', (event) => {
    const clients = self.clients.matchAll();
    clients.then(clientList => {
      clientList.forEach(client => {
        // ruleid: typescript-origins-verified-cross-origin-communication
        client.postMessage({
          type: 'cache-update',
          url: event.request.url
        });
      });
    });
  });
}
// {/fact}

// Bad case 8: Message handling with conditional logic but missing origin check
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_8() {
  // ruleid: typescript-origins-verified-cross-origin-communication
  window.addEventListener('message', (event: MessageEvent) => {
    const data = event.data;
    
    if (data && typeof data === 'object') {
      if (data.type === 'auth') {
        handleAuth(data.token);
      } else if (data.type === 'data') {
        updateUI(data.content);
      }
    }
  });
  
  function handleAuth(token: string) { console.log(token); }
  function updateUI(content: any) { console.log(content); }
}
// {/fact}

// Bad case 9: Using postMessage with template literal but still wildcard origin
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_9() {
  const iframe = document.getElementById('configIframe') as HTMLIFrameElement;
  const config = { theme: 'dark', language: 'en' };
  const wildcard = '*';
  
  // ruleid: typescript-origins-verified-cross-origin-communication
  iframe.contentWindow?.postMessage(config, `${wildcard}`);
}
// {/fact}

// Bad case 10: Message event listener with async processing but no origin check
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_10() {
  // ruleid: typescript-origins-verified-cross-origin-communication
  window.addEventListener('message', async (event: MessageEvent) => {
    const response = await processMessageData(event.data);
    updateApplicationState(response);
  });
  
  async function processMessageData(data: any): Promise<any> {
    return new Promise(resolve => {
      setTimeout(() => resolve({ processed: data }), 100);
    });
  }
  
  function updateApplicationState(state: any) {
    console.log('State updated:', state);
  }
}
// {/fact}

// Bad case 11: Using postMessage with origin from untrusted input
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_11() {
  const iframe = document.getElementById('communicationFrame') as HTMLIFrameElement;
  const urlParams = new URLSearchParams(window.location.search);
  const targetOrigin = urlParams.get('targetOrigin') || '*';
  
  // ruleid: typescript-origins-verified-cross-origin-communication
  iframe.contentWindow?.postMessage({ action: 'sync', timestamp: Date.now() }, targetOrigin);
}
// {/fact}

// Bad case 12: Message handler with try/catch but missing origin verification
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_12() {
  // ruleid: typescript-origins-verified-cross-origin-communication
  window.addEventListener('message', (event: MessageEvent) => {
    try {
      const parsedData = JSON.parse(event.data);
      document.getElementById('status')!.textContent = parsedData.status;
    } catch (error) {
      console.error('Failed to parse message data:', error);
    }
  });
}
// {/fact}

// Bad case 13: Using postMessage with concatenated wildcard string
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_13() {
  const popup = window.open('https://partner-site.com/widget');
  const wildcardPart1 = '*';
  const wildcardPart2 = '';
  
  if (popup) {
    // ruleid: typescript-origins-verified-cross-origin-communication
    popup.postMessage({ command: 'initialize', parameters: { id: 'client123' } }, wildcardPart1 + wildcardPart2);
  }
}
// {/fact}

// Bad case 14: Message event handling with destructuring but no origin check
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_14() {
  // ruleid: typescript-origins-verified-cross-origin-communication
  window.addEventListener('message', (event: MessageEvent) => {
    const { type, payload } = event.data;
    
    switch (type) {
      case 'UPDATE_PROFILE':
        updateUserProfile(payload);
        break;
      case 'LOGOUT':
        performLogout();
        break;
      default:
        console.log('Unknown message type:', type);
    }
  });
  
  function updateUserProfile(data: any) { console.log('Profile updated:', data); }
  function performLogout() { console.log('User logged out'); }
}
// {/fact}

// Bad case 15: Using postMessage with variable that resolves to wildcard
// {fact rule=origin-validation-error@v1.0 defects=1}
function bad_case_15() {
  const iframe = document.getElementById('partnerIframe') as HTMLIFrameElement;
  const config = { allowAnyOrigin: true };
  const targetOrigin = config.allowAnyOrigin ? '*' : 'https://trusted-partner.com';
  
  // ruleid: typescript-origins-verified-cross-origin-communication
  iframe.contentWindow?.postMessage({ action: 'refresh', timestamp: Date.now() }, targetOrigin);
}
// {/fact}

// True Negatives (Secure Code)

// Good case 1: Using postMessage with specific origin
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_1() {
  const iframe = document.getElementById('myIframe') as HTMLIFrameElement;
  const message = { action: 'getData', id: 123 };
  
  // ok: typescript-origins-verified-cross-origin-communication
  iframe.contentWindow?.postMessage(message, 'https://trusted-domain.com');
}
// {/fact}

// Good case 2: Receiving message with proper origin check
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_2() {
  // ok: typescript-origins-verified-cross-origin-communication
  window.addEventListener('message', (event) => {
    if (event.origin === 'https://trusted-domain.com') {
      const data = event.data;
      document.getElementById('output')!.textContent = data.message;
    }
  });
}
// {/fact}

// Good case 3: Using postMessage with specific origin in a complex scenario
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_3() {
  const popup = window.open('https://external-site.com/page');
  const userInfo = {
    username: 'user123',
    token: 'abcd1234',
    permissions: ['read', 'write']
  };
  
  if (popup) {
    setTimeout(() => {
      // ok: typescript-origins-verified-cross-origin-communication
      popup.postMessage(userInfo, 'https://external-site.com');
    }, 1000);
  }
}
// {/fact}

// Good case 4: Message listener with origin verification in a React component
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_4() {
  class MessageComponent {
    private trustedOrigins = ['https://trusted-site.com', 'https://partner-site.org'];
    
    componentDidMount() {
      window.addEventListener('message', this.handleMessage);
    }
    
    handleMessage = (event: MessageEvent) => {
      // ok: typescript-origins-verified-cross-origin-communication
      if (this.trustedOrigins.includes(event.origin)) {
        this.setState({ data: event.data });
      }
    }
    
    componentWillUnmount() {
      window.removeEventListener('message', this.handleMessage);
    }
  }
}
// {/fact}

// Good case 5: Using postMessage with dynamically determined but verified target origin
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_5() {
  const iframe = document.getElementById('dynamicIframe') as HTMLIFrameElement;
  const allowedOrigins = ['https://partner1.com', 'https://partner2.com'];
  const targetOrigin = document.getElementById('originInput')?.getAttribute('data-origin') || '';
  const message = { type: 'update', content: 'New data available' };
  
  if (allowedOrigins.includes(targetOrigin)) {
    // ok: typescript-origins-verified-cross-origin-communication
    iframe.contentWindow?.postMessage(message, targetOrigin);
  } else {
    console.error('Invalid target origin');
  }
}
// {/fact}

// Good case 6: Message handler with comprehensive origin check
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_6() {
  const TRUSTED_ORIGINS = new Set(['https://trusted-app.com', 'https://admin.trusted-app.com']);
  
  // ok: typescript-origins-verified-cross-origin-communication
  window.addEventListener('message', (event: MessageEvent) => {
    if (TRUSTED_ORIGINS.has(event.origin)) {
      const data = event.data;
      processUserData(data);
    } else {
      console.warn('Received message from untrusted origin:', event.origin);
    }
  });
  
  function processUserData(data: any) {
    console.log('Processing:', data);
  }
}
// {/fact}

// Good case 7: Using postMessage in a service worker with origin check
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_7() {
  // Inside a service worker
  const ALLOWED_ORIGINS = ['https://example.com', 'https://sub.example.com'];
  
  self.addEventListener('fetch', (event) => {
    const clients = self.clients.matchAll();
    clients.then(clientList => {
      clientList.forEach(client => {
        const clientUrl = new URL(client.url);
        if (ALLOWED_ORIGINS.includes(clientUrl.origin)) {
          // ok: typescript-origins-verified-cross-origin-communication
          client.postMessage({
            type: 'cache-update',
            url: event.request.url
          });
        }
      });
    });
  });
}
// {/fact}

// Good case 8: Message handling with conditional logic and proper origin check
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_8() {
  const TRUSTED_ORIGIN = 'https://auth-provider.com';
  
  // ok: typescript-origins-verified-cross-origin-communication
  window.addEventListener('message', (event: MessageEvent) => {
    if (event.origin !== TRUSTED_ORIGIN) {
      console.error('Message from untrusted origin rejected');
      return;
    }
    
    const data = event.data;
    if (data && typeof data === 'object') {
      if (data.type === 'auth') {
        handleAuth(data.token);
      } else if (data.type === 'data') {
        updateUI(data.content);
      }
    }
  });
  
  function handleAuth(token: string) { console.log(token); }
  function updateUI(content: any) { console.log(content); }
}
// {/fact}

// Good case 9: Using postMessage with template literal for specific origin
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_9() {
  const iframe = document.getElementById('configIframe') as HTMLIFrameElement;
  const config = { theme: 'dark', language: 'en' };
  const subdomain = 'config';
  const baseDomain = 'trusted-partner.com';
  
  // ok: typescript-origins-verified-cross-origin-communication
  iframe.contentWindow?.postMessage(config, `https://${subdomain}.${baseDomain}`);
}
// {/fact}

// Good case 10: Message event listener with async processing and origin check
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_10() {
  const ALLOWED_ORIGINS = ['https://api.partner.com', 'https://cdn.partner.com'];
  
  // ok: typescript-origins-verified-cross-origin-communication
  window.addEventListener('message', async (event: MessageEvent) => {
    if (!ALLOWED_ORIGINS.includes(event.origin)) {
      console.warn('Rejected message from unauthorized origin:', event.origin);
      return;
    }
    
    const response = await processMessageData(event.data);
    updateApplicationState(response);
  });
  
  async function processMessageData(data: any): Promise<any> {
    return new Promise(resolve => {
      setTimeout(() => resolve({ processed: data }), 100);
    });
  }
  
  function updateApplicationState(state: any) {
    console.log('State updated:', state);
  }
}
// {/fact}

// Good case 11: Using postMessage with origin validation from input
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_11() {
  const iframe = document.getElementById('communicationFrame') as HTMLIFrameElement;
  const urlParams = new URLSearchParams(window.location.search);
  const requestedOrigin = urlParams.get('targetOrigin');
  const VALID_ORIGINS = ['https://app1.example.com', 'https://app2.example.com'];
  
  if (requestedOrigin && VALID_ORIGINS.includes(requestedOrigin)) {
    // ok: typescript-origins-verified-cross-origin-communication
    iframe.contentWindow?.postMessage({ action: 'sync', timestamp: Date.now() }, requestedOrigin);
  } else {
    console.error('Invalid or missing target origin');
  }
}
// {/fact}

// Good case 12: Message handler with try/catch and proper origin verification
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_12() {
  const TRUSTED_ORIGIN = 'https://data-provider.example.com';
  
  // ok: typescript-origins-verified-cross-origin-communication
  window.addEventListener('message', (event: MessageEvent) => {
    if (event.origin !== TRUSTED_ORIGIN) {
      console.warn('Ignoring message from untrusted origin:', event.origin);
      return;
    }
    
    try {
      const parsedData = JSON.parse(event.data);
      document.getElementById('status')!.textContent = parsedData.status;
    } catch (error) {
      console.error('Failed to parse message data:', error);
    }
  });
}
// {/fact}

// Good case 13: Using postMessage with origin validation function
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_13() {
  const popup = window.open('https://partner-site.com/widget');
  
  function isValidOrigin(origin: string): boolean {
    const validOrigins = ['https://partner-site.com', 'https://api.partner-site.com'];
    return validOrigins.includes(origin);
  }
  
  if (popup) {
    const targetOrigin = 'https://partner-site.com';
    
    if (isValidOrigin(targetOrigin)) {
      // ok: typescript-origins-verified-cross-origin-communication
      popup.postMessage({ command: 'initialize', parameters: { id: 'client123' } }, targetOrigin);
    }
  }
}
// {/fact}

// Good case 14: Message event handling with destructuring and origin check
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_14() {
  const TRUSTED_ORIGIN = 'https://admin-panel.example.com';
  
  // ok: typescript-origins-verified-cross-origin-communication
  window.addEventListener('message', (event: MessageEvent) => {
    if (event.origin !== TRUSTED_ORIGIN) {
      console.error('Message rejected from untrusted origin:', event.origin);
      return;
    }
    
    const { type, payload } = event.data;
    
    switch (type) {
      case 'UPDATE_PROFILE':
        updateUserProfile(payload);
        break;
      case 'LOGOUT':
        performLogout();
        break;
      default:
        console.log('Unknown message type:', type);
    }
  });
  
  function updateUserProfile(data: any) { console.log('Profile updated:', data); }
  function performLogout() { console.log('User logged out'); }
}
// {/fact}

// Good case 15: Using postMessage with origin validation based on configuration
// {fact rule=origin-validation-error@v1.0 defects=0}
function good_case_15() {
  const iframe = document.getElementById('partnerIframe') as HTMLIFrameElement;
  const config = { 
    allowedOrigins: ['https://trusted-partner.com', 'https://sandbox.trusted-partner.com'],
    defaultOrigin: 'https://trusted-partner.com'
  };
  
  // ok: typescript-origins-verified-cross-origin-communication
  iframe.contentWindow?.postMessage(
    { action: 'refresh', timestamp: Date.now() }, 
    config.defaultOrigin
  );
}
// {/fact}