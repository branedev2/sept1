// Test cases for javascript-unsafe-dynamic-method-access
// This rule detects when API methods are stored in global scope and accessed via window object

// True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
  // Storing API methods in global scope
  function fetchUserData(userId) {
    return fetch(`/api/users/${userId}`).then(response => response.json());
  }
  
  function updateUserData(userId, data) {
    return fetch(`/api/users/${userId}`, {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  }
  
  // User input determining which method to call
  const methodName = new URLSearchParams(window.location.search).get('method');
  
  // ruleid: javascript-unsafe-dynamic-method-access
  window[methodName](123, { name: 'John' });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
  // API methods in global scope
  function sendMessage(recipient, message) {
    console.log(`Sending "${message}" to ${recipient}`);
  }
  
  function deleteAccount(userId) {
    console.log(`Deleting account ${userId}`);
  }
  
  // Getting method from URL hash
  const action = window.location.hash.substring(1);
  
  // ruleid: javascript-unsafe-dynamic-method-access
  window[action]("user123", "Hello world");
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
  // Define API functions globally
  function transferFunds(from, to, amount) {
    console.log(`Transferring $${amount} from ${from} to ${to}`);
  }
  
  function checkBalance(accountId) {
    return 1000; // Dummy value
  }
  
  // Get function name from cookie
  const getCookie = name => {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
  };
  
  const functionToCall = getCookie('action');
  
  // ruleid: javascript-unsafe-dynamic-method-access
  const result = window[functionToCall]('account123', 'account456', 500);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
  // Global API functions
  function createUser(userData) {
    console.log('Creating user:', userData);
  }
  
  function deleteUser(userId) {
    console.log('Deleting user:', userId);
  }
  
  // Get action from POST data
  async function processForm() {
    const formData = await new FormData(document.querySelector('form'));
    const action = formData.get('action');
    
    // ruleid: javascript-unsafe-dynamic-method-access
    window[action]({ name: formData.get('name'), email: formData.get('email') });
  }
  
  processForm();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
  // Global API methods
  function approveTransaction(id) {
    console.log(`Transaction ${id} approved`);
  }
  
  function rejectTransaction(id) {
    console.log(`Transaction ${id} rejected`);
  }
  
  // Get data from JSON in request body
  async function handleRequest() {
    const response = await fetch('/api/transaction-action');
    const data = await response.json();
    
    // ruleid: javascript-unsafe-dynamic-method-access
    window[data.action](data.transactionId);
  }
  
  handleRequest();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
  // Global API functions
  function addToCart(productId, quantity) {
    console.log(`Adding ${quantity} of product ${productId} to cart`);
  }
  
  function removeFromCart(productId) {
    console.log(`Removing product ${productId} from cart`);
  }
  
  // Get action from message event
  window.addEventListener('message', (event) => {
    if (event.origin !== 'https://trusted-source.com') return;
    
    const { action, productId, quantity } = event.data;
    
    // ruleid: javascript-unsafe-dynamic-method-access
    window[action](productId, quantity);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
  // Global API methods
  function executeQuery(sql) {
    console.log(`Executing SQL: ${sql}`);
    // Pretend to execute SQL
  }
  
  function backupDatabase() {
    console.log('Backing up database');
  }
  
  // WebSocket handling
  const socket = new WebSocket('wss://api.example.com');
  
  socket.onmessage = (event) => {
    const data = JSON.parse(event.data);
    
    // ruleid: javascript-unsafe-dynamic-method-access
    window[data.operation](data.params);
  };
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
  // Global API methods
  function sendEmail(recipient, subject, body) {
    console.log(`Sending email to ${recipient}: ${subject}`);
  }
  
  function scheduleEmail(recipient, subject, body, date) {
    console.log(`Scheduling email to ${recipient} for ${date}`);
  }
  
  // Function to process form submission
  document.getElementById('emailForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const actionType = formData.get('actionType');
    
    // ruleid: javascript-unsafe-dynamic-method-access
    window[actionType](
      formData.get('recipient'),
      formData.get('subject'),
      formData.get('body'),
      formData.get('date')
    );
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
  // Global API methods
  function generateReport(type, startDate, endDate) {
    console.log(`Generating ${type} report from ${startDate} to ${endDate}`);
  }
  
  function exportData(format) {
    console.log(`Exporting data as ${format}`);
  }
  
  // Function that uses URL parameters to determine action
  function processAction() {
    const urlParams = new URLSearchParams(window.location.search);
    const action = urlParams.get('action') || 'generateReport';
    const params = JSON.parse(urlParams.get('params') || '{}');
    
    // ruleid: javascript-unsafe-dynamic-method-access
    window[action](...Object.values(params));
  }
  
  processAction();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
  // Global API methods
  function updateSettings(settings) {
    console.log('Updating settings:', settings);
  }
  
  function resetSettings() {
    console.log('Resetting settings to default');
  }
  
  // Function that processes a custom event
  document.addEventListener('customAction', (event) => {
    const { action, data } = event.detail;
    
    // ruleid: javascript-unsafe-dynamic-method-access
    window[action](data);
  });
  
  // Simulate dispatching the event
  const event = new CustomEvent('customAction', {
    detail: { action: 'updateSettings', data: { theme: 'dark' } }
  });
  document.dispatchEvent(event);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
  // Global API methods
  function processPayment(amount, cardDetails) {
    console.log(`Processing payment of $${amount}`);
  }
  
  function refundPayment(transactionId) {
    console.log(`Refunding transaction ${transactionId}`);
  }
  
  // Function that reads from localStorage
  function handleStoredAction() {
    const storedAction = localStorage.getItem('pendingAction');
    if (storedAction) {
      const { action, params } = JSON.parse(storedAction);
      
      // ruleid: javascript-unsafe-dynamic-method-access
      window[action](...params);
      
      localStorage.removeItem('pendingAction');
    }
  }
  
  handleStoredAction();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
  // Global API methods
  function uploadFile(file, destination) {
    console.log(`Uploading ${file} to ${destination}`);
  }
  
  function deleteFile(path) {
    console.log(`Deleting file at ${path}`);
  }
  
  // Function that processes a server-sent event
  const eventSource = new EventSource('/api/events');
  
  eventSource.onmessage = (event) => {
    const { command, args } = JSON.parse(event.data);
    
    // ruleid: javascript-unsafe-dynamic-method-access
    window[command](...args);
  };
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
  // Global API methods
  function login(username, password) {
    console.log(`Logging in as ${username}`);
  }
  
  function logout() {
    console.log('Logging out');
  }
  
  // Function that uses data from sessionStorage
  function resumeSession() {
    const sessionData = JSON.parse(sessionStorage.getItem('sessionData') || '{}');
    if (sessionData.pendingAction) {
      // ruleid: javascript-unsafe-dynamic-method-access
      window[sessionData.pendingAction](...(sessionData.params || []));
    }
  }
  
  resumeSession();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
  // Global API methods
  function setPermissions(userId, permissions) {
    console.log(`Setting permissions for ${userId}:`, permissions);
  }
  
  function revokePermissions(userId) {
    console.log(`Revoking all permissions for ${userId}`);
  }
  
  // Function that processes data from IndexedDB
  async function processStoredCommands() {
    const db = await indexedDB.open('commandsDB', 1);
    
    db.onsuccess = function(event) {
      const transaction = db.result.transaction(['commands'], 'readonly');
      const objectStore = transaction.objectStore('commands');
      const request = objectStore.getAll();
      
      request.onsuccess = function() {
        request.result.forEach(item => {
          // ruleid: javascript-unsafe-dynamic-method-access
          window[item.command](...item.args);
        });
      };
    };
  }
  
  processStoredCommands();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
  // Global API methods
  function createInvoice(customer, amount) {
    console.log(`Creating invoice for ${customer} for $${amount}`);
  }
  
  function cancelInvoice(invoiceId) {
    console.log(`Cancelling invoice ${invoiceId}`);
  }
  
  // Function that processes a broadcast channel message
  const channel = new BroadcastChannel('invoices');
  
  channel.onmessage = (event) => {
    const { action, params } = event.data;
    
    // ruleid: javascript-unsafe-dynamic-method-access
    window[action](...params);
  };
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
  // API methods contained in an object
  const api = {
    fetchUserData: function(userId) {
      return fetch(`/api/users/${userId}`).then(response => response.json());
    },
    updateUserData: function(userId, data) {
      return fetch(`/api/users/${userId}`, {
        method: 'PUT',
        body: JSON.stringify(data)
      });
    }
  };
  
  // User input determining which method to call
  const methodName = new URLSearchParams(window.location.search).get('method');
  
  // ok: javascript-unsafe-dynamic-method-access
  if (methodName in api) {
    api[methodName](123, { name: 'John' });
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
  // API methods in a Map with explicit allowed methods
  const apiMethods = new Map([
    ['sendMessage', (recipient, message) => {
      console.log(`Sending "${message}" to ${recipient}`);
    }],
    ['checkStatus', (userId) => {
      console.log(`Checking status for ${userId}`);
    }]
  ]);
  
  // Getting method from URL hash
  const action = window.location.hash.substring(1);
  
  // ok: javascript-unsafe-dynamic-method-access
  if (apiMethods.has(action)) {
    apiMethods.get(action)("user123", "Hello world");
  } else {
    console.error('Invalid action requested');
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
  // Define API functions in a dedicated object
  const bankingAPI = {
    transferFunds: function(from, to, amount) {
      console.log(`Transferring $${amount} from ${from} to ${to}`);
    },
    checkBalance: function(accountId) {
      return 1000; // Dummy value
    }
  };
  
  // Get function name from cookie
  const getCookie = name => {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
  };
  
  const functionToCall = getCookie('action');
  
  // ok: javascript-unsafe-dynamic-method-access
  const allowedFunctions = ['transferFunds', 'checkBalance'];
  if (allowedFunctions.includes(functionToCall) && functionToCall in bankingAPI) {
    const result = bankingAPI[functionToCall]('account123', 'account456', 500);
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
  // API functions in a dedicated object
  const userAPI = {
    createUser: function(userData) {
      console.log('Creating user:', userData);
    },
    deleteUser: function(userId) {
      console.log('Deleting user:', userId);
    }
  };
  
  // Get action from POST data
  async function processForm() {
    const formData = await new FormData(document.querySelector('form'));
    const action = formData.get('action');
    
    // ok: javascript-unsafe-dynamic-method-access
    const allowedActions = {
      'createUser': () => userAPI.createUser({ 
        name: formData.get('name'), 
        email: formData.get('email') 
      }),
      'deleteUser': () => userAPI.deleteUser(formData.get('userId'))
    };
    
    if (action in allowedActions) {
      allowedActions[action]();
    }
  }
  
  processForm();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
  // API methods in a dedicated object
  const transactionAPI = {
    approveTransaction: function(id) {
      console.log(`Transaction ${id} approved`);
    },
    rejectTransaction: function(id) {
      console.log(`Transaction ${id} rejected`);
    }
  };
  
  // Get data from JSON in request body
  async function handleRequest() {
    const response = await fetch('/api/transaction-action');
    const data = await response.json();
    
    // ok: javascript-unsafe-dynamic-method-access
    switch (data.action) {
      case 'approveTransaction':
        transactionAPI.approveTransaction(data.transactionId);
        break;
      case 'rejectTransaction':
        transactionAPI.rejectTransaction(data.transactionId);
        break;
      default:
        console.error('Unknown action:', data.action);
    }
  }
  
  handleRequest();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
  // API functions in a dedicated object
  const cartAPI = {
    addToCart: function(productId, quantity) {
      console.log(`Adding ${quantity} of product ${productId} to cart`);
    },
    removeFromCart: function(productId) {
      console.log(`Removing product ${productId} from cart`);
    }
  };
  
  // Get action from message event
  window.addEventListener('message', (event) => {
    if (event.origin !== 'https://trusted-source.com') return;
    
    const { action, productId, quantity } = event.data;
    
    // ok: javascript-unsafe-dynamic-method-access
    const actionHandlers = {
      'addToCart': () => cartAPI.addToCart(productId, quantity),
      'removeFromCart': () => cartAPI.removeFromCart(productId)
    };
    
    if (action in actionHandlers) {
      actionHandlers[action]();
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
  // API methods in a dedicated object
  const dbAPI = {
    executeQuery: function(sql) {
      console.log(`Executing SQL: ${sql}`);
      // Pretend to execute SQL
    },
    backupDatabase: function() {
      console.log('Backing up database');
    }
  };
  
  // WebSocket handling
  const socket = new WebSocket('wss://api.example.com');
  
  socket.onmessage = (event) => {
    const data = JSON.parse(event.data);
    
    // ok: javascript-unsafe-dynamic-method-access
    const allowedOperations = new Map([
      ['executeQuery', (params) => dbAPI.executeQuery(params)],
      ['backupDatabase', () => dbAPI.backupDatabase()]
    ]);
    
    if (allowedOperations.has(data.operation)) {
      allowedOperations.get(data.operation)(data.params);
    }
  };
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
  // API methods in a dedicated object
  const emailAPI = {
    sendEmail: function(recipient, subject, body) {
      console.log(`Sending email to ${recipient}: ${subject}`);
    },
    scheduleEmail: function(recipient, subject, body, date) {
      console.log(`Scheduling email to ${recipient} for ${date}`);
    }
  };
  
  // Function to process form submission
  document.getElementById('emailForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const actionType = formData.get('actionType');
    
    // ok: javascript-unsafe-dynamic-method-access
    const validActions = {
      'sendEmail': () => emailAPI.sendEmail(
        formData.get('recipient'),
        formData.get('subject'),
        formData.get('body')
      ),
      'scheduleEmail': () => emailAPI.scheduleEmail(
        formData.get('recipient'),
        formData.get('subject'),
        formData.get('body'),
        formData.get('date')
      )
    };
    
    if (actionType in validActions) {
      validActions[actionType]();
    }
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
  // API methods in a dedicated object
  const reportAPI = {
    generateReport: function(type, startDate, endDate) {
      console.log(`Generating ${type} report from ${startDate} to ${endDate}`);
    },
    exportData: function(format) {
      console.log(`Exporting data as ${format}`);
    }
  };
  
  // Function that uses URL parameters to determine action
  function processAction() {
    const urlParams = new URLSearchParams(window.location.search);
    const action = urlParams.get('action') || 'generateReport';
    const params = JSON.parse(urlParams.get('params') || '{}');
    
    // ok: javascript-unsafe-dynamic-method-access
    const actionMap = {
      'generateReport': () => reportAPI.generateReport(
        params.type, params.startDate, params.endDate
      ),
      'exportData': () => reportAPI.exportData(params.format)
    };
    
    if (action in actionMap) {
      actionMap[action]();
    }
  }
  
  processAction();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
  // API methods in a dedicated object
  const settingsAPI = {
    updateSettings: function(settings) {
      console.log('Updating settings:', settings);
    },
    resetSettings: function() {
      console.log('Resetting settings to default');
    }
  };
  
  // Function that processes a custom event
  document.addEventListener('customAction', (event) => {
    const { action, data } = event.detail;
    
    // ok: javascript-unsafe-dynamic-method-access
    if (action === 'updateSettings') {
      settingsAPI.updateSettings(data);
    } else if (action === 'resetSettings') {
      settingsAPI.resetSettings();
    }
  });
  
  // Simulate dispatching the event
  const event = new CustomEvent('customAction', {
    detail: { action: 'updateSettings', data: { theme: 'dark' } }
  });
  document.dispatchEvent(event);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
  // API methods in a dedicated object
  const paymentAPI = {
    processPayment: function(amount, cardDetails) {
      console.log(`Processing payment of $${amount}`);
    },
    refundPayment: function(transactionId) {
      console.log(`Refunding transaction ${transactionId}`);
    }
  };
  
  // Function that reads from localStorage
  function handleStoredAction() {
    const storedAction = localStorage.getItem('pendingAction');
    if (storedAction) {
      const { action, params } = JSON.parse(storedAction);
      
      // ok: javascript-unsafe-dynamic-method-access
      const actionHandlers = {
        'processPayment': () => paymentAPI.processPayment(...params),
        'refundPayment': () => paymentAPI.refundPayment(...params)
      };
      
      if (action in actionHandlers) {
        actionHandlers[action]();
      }
      
      localStorage.removeItem('pendingAction');
    }
  }
  
  handleStoredAction();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
  // API methods in a dedicated object
  const fileAPI = {
    uploadFile: function(file, destination) {
      console.log(`Uploading ${file} to ${destination}`);
    },
    deleteFile: function(path) {
      console.log(`Deleting file at ${path}`);
    }
  };
  
  // Function that processes a server-sent event
  const eventSource = new EventSource('/api/events');
  
  eventSource.onmessage = (event) => {
    const { command, args } = JSON.parse(event.data);
    
    // ok: javascript-unsafe-dynamic-method-access
    const commandHandlers = new Map([
      ['uploadFile', (args) => fileAPI.uploadFile(...args)],
      ['deleteFile', (args) => fileAPI.deleteFile(...args)]
    ]);
    
    if (commandHandlers.has(command)) {
      commandHandlers.get(command)(args);
    }
  };
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
  // API methods in a dedicated object
  const authAPI = {
    login: function(username, password) {
      console.log(`Logging in as ${username}`);
    },
    logout: function() {
      console.log('Logging out');
    }
  };
  
  // Function that uses data from sessionStorage
  function resumeSession() {
    const sessionData = JSON.parse(sessionStorage.getItem('sessionData') || '{}');
    if (sessionData.pendingAction) {
      // ok: javascript-unsafe-dynamic-method-access
      const validActions = {
        'login': () => authAPI.login(...(sessionData.params || [])),
        'logout': () => authAPI.logout()
      };
      
      if (sessionData.pendingAction in validActions) {
        validActions[sessionData.pendingAction]();
      }
    }
  }
  
  resumeSession();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
  // API methods in a dedicated object
  const permissionsAPI = {
    setPermissions: function(userId, permissions) {
      console.log(`Setting permissions for ${userId}:`, permissions);
    },
    revokePermissions: function(userId) {
      console.log(`Revoking all permissions for ${userId}`);
    }
  };
  
  // Function that processes data from IndexedDB
  async function processStoredCommands() {
    const db = await indexedDB.open('commandsDB', 1);
    
    db.onsuccess = function(event) {
      const transaction = db.result.transaction(['commands'], 'readonly');
      const objectStore = transaction.objectStore('commands');
      const request = objectStore.getAll();
      
      request.onsuccess = function() {
        request.result.forEach(item => {
          // ok: javascript-unsafe-dynamic-method-access
          const commandMap = {
            'setPermissions': (args) => permissionsAPI.setPermissions(...args),
            'revokePermissions': (args) => permissionsAPI.revokePermissions(...args)
          };
          
          if (item.command in commandMap) {
            commandMap[item.command](item.args);
          }
        });
      };
    };
  }
  
  processStoredCommands();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
  // API methods in a dedicated object
  const invoiceAPI = {
    createInvoice: function(customer, amount) {
      console.log(`Creating invoice for ${customer} for $${amount}`);
    },
    cancelInvoice: function(invoiceId) {
      console.log(`Cancelling invoice ${invoiceId}`);
    }
  };
  
  // Function that processes a broadcast channel message
  const channel = new BroadcastChannel('invoices');
  
  channel.onmessage = (event) => {
    const { action, params } = event.data;
    
    // ok: javascript-unsafe-dynamic-method-access
    const allowedActions = {
      'createInvoice': () => invoiceAPI.createInvoice(...params),
      'cancelInvoice': () => invoiceAPI.cancelInvoice(...params)
    };
    
    if (action in allowedActions) {
      allowedActions[action]();
    } else {
      console.error('Invalid action requested');
    }
  };
}
// {/fact}