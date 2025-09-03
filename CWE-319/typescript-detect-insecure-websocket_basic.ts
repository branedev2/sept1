// File: insecure_websocket_test_cases.ts

// Import necessary libraries
import * as WebSocket from 'ws';

// TRUE POSITIVES (Insecure/Vulnerable Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1() {
  // Direct instantiation with insecure protocol
  // ruleid: typescript-detect-insecure-websocket
  const socket = new WebSocket('ws://example.com/socket');
  
  socket.onmessage = (event) => {
    console.log('Received data:', event.data);
  };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2() {
  // Using a variable with insecure protocol
  const url = 'ws://api.example.com/v1/socket';
  
  // ruleid: typescript-detect-insecure-websocket
  const socket = new WebSocket(url);
  
  socket.onopen = () => {
    socket.send('Hello server!');
  };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3() {
  // Using template literals with insecure protocol
  const domain = 'realtime.example.com';
  const path = '/chat';
  
  // ruleid: typescript-detect-insecure-websocket
  const socket = new WebSocket(`ws://${domain}${path}`);
  
  socket.addEventListener('message', (event) => {
    const data = JSON.parse(event.data);
    console.log('Message from server:', data);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4() {
  // Using insecure protocol with port specification
  // ruleid: typescript-detect-insecure-websocket
  const socket = new WebSocket('ws://example.com:8080/socket');
  
  socket.onclose = (event) => {
    console.log('Connection closed with code:', event.code);
  };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5() {
  // Using insecure protocol in a function that creates WebSocket
  function createConnection(id: string) {
    // ruleid: typescript-detect-insecure-websocket
    return new WebSocket(`ws://api.example.com/connect/${id}`);
  }
  
  const socket = createConnection('user123');
  socket.onmessage = (event) => {
    console.log(event.data);
  };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6() {
  // Using insecure protocol with query parameters
  const userId = 'user456';
  const token = 'abc123';
  
  // ruleid: typescript-detect-insecure-websocket
  const socket = new WebSocket(`ws://chat.example.com/socket?userId=${userId}&token=${token}`);
  
  socket.onopen = () => {
    console.log('Connection established');
  };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7() {
  // Using insecure protocol with conditional URL
  const isProd = false;
  const baseUrl = isProd ? 'example.com' : 'localhost:8080';
  
  // ruleid: typescript-detect-insecure-websocket
  const socket = new WebSocket(`ws://${baseUrl}/ws`);
  
  socket.addEventListener('error', (error) => {
    console.error('WebSocket error:', error);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8() {
  // Using insecure protocol in a class
  class ChatClient {
    private socket: WebSocket;
    
    constructor(roomId: string) {
      // ruleid: typescript-detect-insecure-websocket
      this.socket = new WebSocket(`ws://chat.example.com/room/${roomId}`);
    }
    
    sendMessage(message: string) {
      this.socket.send(JSON.stringify({ type: 'message', content: message }));
    }
  }
  
  const client = new ChatClient('general');
  client.sendMessage('Hello everyone!');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9() {
  // Using insecure protocol with authentication token in URL
  const authToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
  
  // ruleid: typescript-detect-insecure-websocket
  const socket = new WebSocket(`ws://api.example.com/socket?auth=${authToken}`);
  
  socket.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.type === 'auth_success') {
      console.log('Authentication successful');
    }
  };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10() {
  // Using insecure protocol with a connection manager
  class ConnectionManager {
    connect(endpoint: string) {
      // ruleid: typescript-detect-insecure-websocket
      const socket = new WebSocket(`ws://${endpoint}`);
      return socket;
    }
  }
  
  const manager = new ConnectionManager();
  const socket = manager.connect('realtime.example.com/feed');
  
  socket.onopen = () => {
    socket.send(JSON.stringify({ action: 'subscribe', channel: 'updates' }));
  };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11() {
  // Using insecure protocol with a retry mechanism
  function connectWithRetry(url: string, maxRetries: number) {
    let retries = 0;
    
    function attempt() {
      // ruleid: typescript-detect-insecure-websocket
      const socket = new WebSocket(`ws://${url}`);
      
      socket.onclose = () => {
        if (retries < maxRetries) {
          retries++;
          setTimeout(attempt, 1000 * retries);
        }
      };
      
      return socket;
    }
    
    return attempt();
  }
  
  const socket = connectWithRetry('api.example.com/live', 3);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12() {
  // Using insecure protocol with environment-based URL
  const env = process.env.NODE_ENV || 'development';
  const urls = {
    development: 'localhost:3000',
    staging: 'staging-api.example.com',
    production: 'api.example.com'
  };
  
  // ruleid: typescript-detect-insecure-websocket
  const socket = new WebSocket(`ws://${urls[env as keyof typeof urls]}/socket`);
  
  socket.onmessage = (event) => {
    console.log(`[${env}] Received:`, event.data);
  };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13() {
  // Using insecure protocol with a connection pool
  class WebSocketPool {
    private connections: Map<string, WebSocket> = new Map();
    
    getConnection(endpoint: string): WebSocket {
      if (!this.connections.has(endpoint)) {
        // ruleid: typescript-detect-insecure-websocket
        const socket = new WebSocket(`ws://${endpoint}`);
        this.connections.set(endpoint, socket);
      }
      
      return this.connections.get(endpoint)!;
    }
  }
  
  const pool = new WebSocketPool();
  const socket = pool.getConnection('api.example.com/notifications');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14() {
  // Using insecure protocol with a factory function
  interface WebSocketOptions {
    autoReconnect?: boolean;
    timeout?: number;
  }
  
  function createWebSocket(url: string, options?: WebSocketOptions): WebSocket {
    // ruleid: typescript-detect-insecure-websocket
    const socket = new WebSocket(`ws://${url}`);
    
    if (options?.autoReconnect) {
      socket.onclose = () => {
        setTimeout(() => createWebSocket(url, options), options.timeout || 1000);
      };
    }
    
    return socket;
  }
  
  const socket = createWebSocket('example.com/socket', { autoReconnect: true });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15() {
  // Using insecure protocol with a dynamic subdomain
  function connectToRegion(region: string) {
    // ruleid: typescript-detect-insecure-websocket
    const socket = new WebSocket(`ws://${region}.api.example.com/v2/stream`);
    
    socket.onopen = () => {
      console.log(`Connected to ${region} region`);
    };
    
    return socket;
  }
  
  const euSocket = connectToRegion('eu');
  const usSocket = connectToRegion('us');
}
// {/fact}

// TRUE NEGATIVES (Secure/Safe Code)

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1() {
  // Using secure WebSocket protocol
  // ok: typescript-detect-insecure-websocket
  const socket = new WebSocket('wss://example.com/socket');
  
  socket.onmessage = (event) => {
    console.log('Received data:', event.data);
  };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2() {
  // Using a variable with secure protocol
  const url = 'wss://api.example.com/v1/socket';
  
  // ok: typescript-detect-insecure-websocket
  const socket = new WebSocket(url);
  
  socket.onopen = () => {
    socket.send('Hello server!');
  };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3() {
  // Using template literals with secure protocol
  const domain = 'realtime.example.com';
  const path = '/chat';
  
  // ok: typescript-detect-insecure-websocket
  const socket = new WebSocket(`wss://${domain}${path}`);
  
  socket.addEventListener('message', (event) => {
    const data = JSON.parse(event.data);
    console.log('Message from server:', data);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4() {
  // Using secure protocol with port specification
  // ok: typescript-detect-insecure-websocket
  const socket = new WebSocket('wss://example.com:8443/socket');
  
  socket.onclose = (event) => {
    console.log('Connection closed with code:', event.code);
  };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5() {
  // Using secure protocol in a function that creates WebSocket
  function createConnection(id: string) {
    // ok: typescript-detect-insecure-websocket
    return new WebSocket(`wss://api.example.com/connect/${id}`);
  }
  
  const socket = createConnection('user123');
  socket.onmessage = (event) => {
    console.log(event.data);
  };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6() {
  // Using secure protocol with query parameters
  const userId = 'user456';
  const token = 'abc123';
  
  // ok: typescript-detect-insecure-websocket
  const socket = new WebSocket(`wss://chat.example.com/socket?userId=${userId}&token=${token}`);
  
  socket.onopen = () => {
    console.log('Connection established');
  };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7() {
  // Using secure protocol with conditional URL
  const isProd = false;
  const baseUrl = isProd ? 'example.com' : 'localhost:8080';
  
  // ok: typescript-detect-insecure-websocket
  const socket = new WebSocket(`wss://${baseUrl}/ws`);
  
  socket.addEventListener('error', (error) => {
    console.error('WebSocket error:', error);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8() {
  // Using secure protocol in a class
  class ChatClient {
    private socket: WebSocket;
    
    constructor(roomId: string) {
      // ok: typescript-detect-insecure-websocket
      this.socket = new WebSocket(`wss://chat.example.com/room/${roomId}`);
    }
    
    sendMessage(message: string) {
      this.socket.send(JSON.stringify({ type: 'message', content: message }));
    }
  }
  
  const client = new ChatClient('general');
  client.sendMessage('Hello everyone!');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9() {
  // Using secure protocol with authentication token in URL
  const authToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
  
  // ok: typescript-detect-insecure-websocket
  const socket = new WebSocket(`wss://api.example.com/socket?auth=${authToken}`);
  
  socket.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.type === 'auth_success') {
      console.log('Authentication successful');
    }
  };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10() {
  // Using secure protocol with a connection manager
  class ConnectionManager {
    connect(endpoint: string) {
      // ok: typescript-detect-insecure-websocket
      const socket = new WebSocket(`wss://${endpoint}`);
      return socket;
    }
  }
  
  const manager = new ConnectionManager();
  const socket = manager.connect('realtime.example.com/feed');
  
  socket.onopen = () => {
    socket.send(JSON.stringify({ action: 'subscribe', channel: 'updates' }));
  };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11() {
  // Using secure protocol with a retry mechanism
  function connectWithRetry(url: string, maxRetries: number) {
    let retries = 0;
    
    function attempt() {
      // ok: typescript-detect-insecure-websocket
      const socket = new WebSocket(`wss://${url}`);
      
      socket.onclose = () => {
        if (retries < maxRetries) {
          retries++;
          setTimeout(attempt, 1000 * retries);
        }
      };
      
      return socket;
    }
    
    return attempt();
  }
  
  const socket = connectWithRetry('api.example.com/live', 3);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12() {
  // Using secure protocol with environment-based URL
  const env = process.env.NODE_ENV || 'development';
  const urls = {
    development: 'localhost:3000',
    staging: 'staging-api.example.com',
    production: 'api.example.com'
  };
  
  // ok: typescript-detect-insecure-websocket
  const socket = new WebSocket(`wss://${urls[env as keyof typeof urls]}/socket`);
  
  socket.onmessage = (event) => {
    console.log(`[${env}] Received:`, event.data);
  };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13() {
  // Using secure protocol with a connection pool
  class WebSocketPool {
    private connections: Map<string, WebSocket> = new Map();
    
    getConnection(endpoint: string): WebSocket {
      if (!this.connections.has(endpoint)) {
        // ok: typescript-detect-insecure-websocket
        const socket = new WebSocket(`wss://${endpoint}`);
        this.connections.set(endpoint, socket);
      }
      
      return this.connections.get(endpoint)!;
    }
  }
  
  const pool = new WebSocketPool();
  const socket = pool.getConnection('api.example.com/notifications');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14() {
  // Using secure protocol with a factory function
  interface WebSocketOptions {
    autoReconnect?: boolean;
    timeout?: number;
  }
  
  function createWebSocket(url: string, options?: WebSocketOptions): WebSocket {
    // ok: typescript-detect-insecure-websocket
    const socket = new WebSocket(`wss://${url}`);
    
    if (options?.autoReconnect) {
      socket.onclose = () => {
        setTimeout(() => createWebSocket(url, options), options.timeout || 1000);
      };
    }
    
    return socket;
  }
  
  const socket = createWebSocket('example.com/socket', { autoReconnect: true });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15() {
  // Using secure protocol with a dynamic subdomain
  function connectToRegion(region: string) {
    // ok: typescript-detect-insecure-websocket
    const socket = new WebSocket(`wss://${region}.api.example.com/v2/stream`);
    
    socket.onopen = () => {
      console.log(`Connected to ${region} region`);
    };
    
    return socket;
  }
  
  const euSocket = connectToRegion('eu');
  const usSocket = connectToRegion('us');
}
// {/fact}