// This file contains test cases for detecting insecure WebSocket connections
// Rule ID: javascript-detect-insecure-websocket

// True Positives (Vulnerable Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1() {
    // Direct use of insecure WebSocket protocol
    // ruleid: javascript-detect-insecure-websocket
    const socket = new WebSocket('ws://example.com/socket');
    
    socket.onopen = function(e) {
        console.log('Connection established');
        socket.send('Hello Server!');
    };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2() {
    // Using insecure WebSocket with port specification
    // ruleid: javascript-detect-insecure-websocket
    const socket = new WebSocket('ws://api.example.com:8080/chat');
    
    socket.onmessage = function(event) {
        console.log('Message from server:', event.data);
    };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3() {
    // Using insecure WebSocket with a variable (but still hardcoded insecure URL)
    const wsUrl = 'ws://data.example.org/feed';
    
    // ruleid: javascript-detect-insecure-websocket
    const socket = new WebSocket(wsUrl);
    
    socket.onerror = function(error) {
        console.error('WebSocket Error:', error);
    };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4() {
    // Using insecure WebSocket in a conditional block
    const isProduction = false;
    let socketUrl;
    
    if (isProduction) {
        socketUrl = 'wss://secure.example.com/socket';
    } else {
        socketUrl = 'ws://dev.example.com/socket';
    }
    
    // ruleid: javascript-detect-insecure-websocket
    const socket = new WebSocket(socketUrl);
    
    socket.onclose = function(event) {
        console.log('Connection closed with code:', event.code);
    };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5() {
    // Using insecure WebSocket with template literals
    const server = 'example.com';
    const endpoint = 'realtime';
    
    // ruleid: javascript-detect-insecure-websocket
    const socket = new WebSocket(`ws://${server}/${endpoint}`);
    
    socket.addEventListener('message', function(event) {
        const data = JSON.parse(event.data);
        console.log('Received data:', data);
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6() {
    // Using insecure WebSocket with user input (still insecure)
    const userId = document.getElementById('userId').value;
    
    // ruleid: javascript-detect-insecure-websocket
    const socket = new WebSocket(`ws://chat.example.com/room?user=${userId}`);
    
    socket.onopen = () => {
        document.getElementById('status').textContent = 'Connected';
    };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7() {
    // Using insecure WebSocket in a class
    class ChatClient {
        constructor(roomId) {
            this.roomId = roomId;
            // ruleid: javascript-detect-insecure-websocket
            this.socket = new WebSocket(`ws://chat.example.com/room/${roomId}`);
            this.setupListeners();
        }
        
        setupListeners() {
            this.socket.onmessage = this.handleMessage.bind(this);
        }
        
        handleMessage(event) {
            console.log(`Message in room ${this.roomId}:`, event.data);
        }
    }
    
    const client = new ChatClient('general');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8() {
    // Using insecure WebSocket with a function that returns the URL
    function getWebSocketUrl(endpoint) {
        return `ws://api.example.com/${endpoint}`;
    }
    
    // ruleid: javascript-detect-insecure-websocket
    const socket = new WebSocket(getWebSocketUrl('notifications'));
    
    socket.addEventListener('open', () => {
        socket.send(JSON.stringify({ subscribe: 'all' }));
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9() {
    // Using insecure WebSocket in a promise chain
    fetch('/api/get-chat-server')
        .then(response => response.json())
        .then(data => {
            const serverUrl = `ws://${data.server}/chat`;
            // ruleid: javascript-detect-insecure-websocket
            const socket = new WebSocket(serverUrl);
            
            socket.onopen = () => console.log('Connected to chat server');
        })
        .catch(error => console.error('Error:', error));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10() {
    // Using insecure WebSocket with async/await
    async function connectToServer() {
        try {
            const response = await fetch('/api/server-info');
            const data = await response.json();
            
            // ruleid: javascript-detect-insecure-websocket
            const socket = new WebSocket(`ws://${data.host}:${data.port}`);
            
            socket.onmessage = event => {
                console.log('Received:', event.data);
            };
        } catch (error) {
            console.error('Connection error:', error);
        }
    }
    
    connectToServer();
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11() {
    // Using insecure WebSocket with a configuration object
    const config = {
        protocol: 'ws',
        host: 'realtime.example.com',
        path: '/stocks'
    };
    
    // ruleid: javascript-detect-insecure-websocket
    const socket = new WebSocket(`${config.protocol}://${config.host}${config.path}`);
    
    socket.addEventListener('message', event => {
        updateStockPrices(JSON.parse(event.data));
    });
    
    function updateStockPrices(data) {
        // Update UI with stock prices
        console.log('Updated stock prices:', data);
    }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12() {
    // Using insecure WebSocket in a React-like component
    class LiveDataComponent {
        constructor(props) {
            this.state = { data: null, connected: false };
            this.connect();
        }
        
        connect() {
            const endpoint = this.props?.endpoint || 'default';
            // ruleid: javascript-detect-insecure-websocket
            this.socket = new WebSocket(`ws://data.example.com/${endpoint}`);
            
            this.socket.onopen = () => {
                this.setState({ connected: true });
            };
            
            this.socket.onmessage = (event) => {
                this.setState({ data: JSON.parse(event.data) });
            };
        }
        
        setState(newState) {
            this.state = { ...this.state, ...newState };
            console.log('State updated:', this.state);
        }
    }
    
    const component = new LiveDataComponent({ endpoint: 'metrics' });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13() {
    // Using insecure WebSocket with environment-specific URL
    const env = {
        development: 'ws://localhost:8080',
        staging: 'ws://staging.example.com',
        production: 'wss://api.example.com'
    };
    
    const currentEnv = 'development';
    
    // ruleid: javascript-detect-insecure-websocket
    const socket = new WebSocket(env[currentEnv]);
    
    socket.onopen = () => {
        socket.send('Connected to ' + currentEnv);
    };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14() {
    // Using insecure WebSocket with a URL from localStorage
    // This simulates retrieving a previously stored URL
    localStorage.setItem('websocket_url', 'ws://saved.example.com/socket');
    
    const savedUrl = localStorage.getItem('websocket_url');
    
    // ruleid: javascript-detect-insecure-websocket
    const socket = new WebSocket(savedUrl);
    
    socket.addEventListener('open', () => {
        console.log('Using saved connection:', savedUrl);
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15() {
    // Using insecure WebSocket with URL constructed from multiple parts
    const protocol = 'ws';
    const domain = 'api.example.com';
    const endpoint = '/v2/events';
    const query = '?type=all&format=json';
    
    // ruleid: javascript-detect-insecure-websocket
    const socket = new WebSocket(`${protocol}://${domain}${endpoint}${query}`);
    
    socket.onmessage = function(event) {
        const events = JSON.parse(event.data);
        events.forEach(event => {
            console.log(`Event ${event.id}: ${event.description}`);
        });
    };
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1() {
    // Using secure WebSocket protocol
    // ok: javascript-detect-insecure-websocket
    const socket = new WebSocket('wss://example.com/socket');
    
    socket.onopen = function(e) {
        console.log('Secure connection established');
        socket.send('Hello Server!');
    };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2() {
    // Using secure WebSocket with port specification
    // ok: javascript-detect-insecure-websocket
    const socket = new WebSocket('wss://api.example.com:8443/chat');
    
    socket.onmessage = function(event) {
        console.log('Message from secure server:', event.data);
    };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3() {
    // Using secure WebSocket with a variable
    const wsUrl = 'wss://data.example.org/feed';
    
    // ok: javascript-detect-insecure-websocket
    const socket = new WebSocket(wsUrl);
    
    socket.onerror = function(error) {
        console.error('Secure WebSocket Error:', error);
    };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4() {
    // Using secure WebSocket in a conditional block
    const isProduction = true;
    let socketUrl;
    
    if (isProduction) {
        socketUrl = 'wss://secure.example.com/socket';
    } else {
        socketUrl = 'wss://dev.example.com/socket';
    }
    
    // ok: javascript-detect-insecure-websocket
    const socket = new WebSocket(socketUrl);
    
    socket.onclose = function(event) {
        console.log('Secure connection closed with code:', event.code);
    };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5() {
    // Using secure WebSocket with template literals
    const server = 'example.com';
    const endpoint = 'realtime';
    
    // ok: javascript-detect-insecure-websocket
    const socket = new WebSocket(`wss://${server}/${endpoint}`);
    
    socket.addEventListener('message', function(event) {
        const data = JSON.parse(event.data);
        console.log('Received secure data:', data);
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6() {
    // Using secure WebSocket with user input
    const userId = document.getElementById('userId').value;
    
    // ok: javascript-detect-insecure-websocket
    const socket = new WebSocket(`wss://chat.example.com/room?user=${userId}`);
    
    socket.onopen = () => {
        document.getElementById('status').textContent = 'Securely Connected';
    };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7() {
    // Using secure WebSocket in a class
    class SecureChatClient {
        constructor(roomId) {
            this.roomId = roomId;
            // ok: javascript-detect-insecure-websocket
            this.socket = new WebSocket(`wss://chat.example.com/room/${roomId}`);
            this.setupListeners();
        }
        
        setupListeners() {
            this.socket.onmessage = this.handleMessage.bind(this);
        }
        
        handleMessage(event) {
            console.log(`Secure message in room ${this.roomId}:`, event.data);
        }
    }
    
    const client = new SecureChatClient('general');
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8() {
    // Using secure WebSocket with a function that returns the URL
    function getSecureWebSocketUrl(endpoint) {
        return `wss://api.example.com/${endpoint}`;
    }
    
    // ok: javascript-detect-insecure-websocket
    const socket = new WebSocket(getSecureWebSocketUrl('notifications'));
    
    socket.addEventListener('open', () => {
        socket.send(JSON.stringify({ subscribe: 'all' }));
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9() {
    // Using secure WebSocket in a promise chain
    fetch('/api/get-chat-server')
        .then(response => response.json())
        .then(data => {
            const serverUrl = `wss://${data.server}/chat`;
            // ok: javascript-detect-insecure-websocket
            const socket = new WebSocket(serverUrl);
            
            socket.onopen = () => console.log('Securely connected to chat server');
        })
        .catch(error => console.error('Error:', error));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10() {
    // Using secure WebSocket with async/await
    async function connectToSecureServer() {
        try {
            const response = await fetch('/api/server-info');
            const data = await response.json();
            
            // ok: javascript-detect-insecure-websocket
            const socket = new WebSocket(`wss://${data.host}:${data.port}`);
            
            socket.onmessage = event => {
                console.log('Received from secure connection:', event.data);
            };
        } catch (error) {
            console.error('Secure connection error:', error);
        }
    }
    
    connectToSecureServer();
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11() {
    // Using secure WebSocket with a configuration object
    const config = {
        protocol: 'wss',
        host: 'realtime.example.com',
        path: '/stocks'
    };
    
    // ok: javascript-detect-insecure-websocket
    const socket = new WebSocket(`${config.protocol}://${config.host}${config.path}`);
    
    socket.addEventListener('message', event => {
        updateStockPrices(JSON.parse(event.data));
    });
    
    function updateStockPrices(data) {
        // Update UI with stock prices from secure connection
        console.log('Updated stock prices from secure source:', data);
    }
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12() {
    // Using secure WebSocket in a React-like component
    class SecureLiveDataComponent {
        constructor(props) {
            this.state = { data: null, connected: false };
            this.connect();
        }
        
        connect() {
            const endpoint = this.props?.endpoint || 'default';
            // ok: javascript-detect-insecure-websocket
            this.socket = new WebSocket(`wss://data.example.com/${endpoint}`);
            
            this.socket.onopen = () => {
                this.setState({ connected: true });
            };
            
            this.socket.onmessage = (event) => {
                this.setState({ data: JSON.parse(event.data) });
            };
        }
        
        setState(newState) {
            this.state = { ...this.state, ...newState };
            console.log('State updated from secure connection:', this.state);
        }
    }
    
    const component = new SecureLiveDataComponent({ endpoint: 'metrics' });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13() {
    // Using secure WebSocket with environment-specific URL
    const env = {
        development: 'wss://localhost:8443',
        staging: 'wss://staging.example.com',
        production: 'wss://api.example.com'
    };
    
    const currentEnv = 'development';
    
    // ok: javascript-detect-insecure-websocket
    const socket = new WebSocket(env[currentEnv]);
    
    socket.onopen = () => {
        socket.send('Securely connected to ' + currentEnv);
    };
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14() {
    // Using secure WebSocket with a URL from localStorage
    // This simulates retrieving a previously stored URL
    localStorage.setItem('secure_websocket_url', 'wss://saved.example.com/socket');
    
    const savedUrl = localStorage.getItem('secure_websocket_url');
    
    // ok: javascript-detect-insecure-websocket
    const socket = new WebSocket(savedUrl);
    
    socket.addEventListener('open', () => {
        console.log('Using saved secure connection:', savedUrl);
    });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15() {
    // Using secure WebSocket with URL constructed from multiple parts
    const protocol = 'wss';
    const domain = 'api.example.com';
    const endpoint = '/v2/events';
    const query = '?type=all&format=json';
    
    // ok: javascript-detect-insecure-websocket
    const socket = new WebSocket(`${protocol}://${domain}${endpoint}${query}`);
    
    socket.onmessage = function(event) {
        const events = JSON.parse(event.data);
        events.forEach(event => {
            console.log(`Secure event ${event.id}: ${event.description}`);
        });
    };
}
// {/fact}