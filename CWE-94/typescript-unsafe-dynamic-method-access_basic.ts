// File: unsafe_dynamic_method_access_tests.ts

// True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
  // Storing API methods in global scope
  window.fetchData = (url: string) => {
    return fetch(url).then(response => response.json());
  };
  
  window.processData = (data: any) => {
    return JSON.stringify(data);
  };
  
  // User input determines which method to call
  function executeUserAction(methodName: string, param: string) {
    // ruleid: typescript-unsafe-dynamic-method-access
    return window[methodName](param);
  }
  
  const userInput = new URLSearchParams(window.location.search).get('method') || 'fetchData';
  executeUserAction(userInput, 'https://api.example.com/data');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
  // API methods defined globally
  function getData() { return 'sensitive data'; }
  function setData(value: string) { console.log(`Setting data: ${value}`); }
  function deleteData() { console.log('Deleting data'); }
  
  // Taking method name from URL hash
  function executeMethod() {
    const methodName = window.location.hash.substring(1);
    // ruleid: typescript-unsafe-dynamic-method-access
    if (window[methodName] && typeof window[methodName] === 'function') {
      return window[methodName]();
    }
    return null;
  }
  
  executeMethod();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
  // Define API methods globally
  window.userAPI = {
    getUser: (id: number) => ({ id, name: 'User' + id }),
    updateUser: (id: number, data: object) => console.log(`Updating user ${id}`, data),
    deleteUser: (id: number) => console.log(`Deleting user ${id}`)
  };
  
  function processRequest(action: string, id: number, data?: object) {
    const methodName = `${action}User`;
    // ruleid: typescript-unsafe-dynamic-method-access
    if (typeof window.userAPI[methodName] === 'function') {
      if (data) {
        return window.userAPI[methodName](id, data);
      } else {
        return window.userAPI[methodName](id);
      }
    }
  }
  
  const action = new URLSearchParams(window.location.search).get('action') || 'get';
  const userId = parseInt(new URLSearchParams(window.location.search).get('id') || '1');
  processRequest(action, userId);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
  // Global API methods
  window.apiMethods = {};
  window.apiMethods.get = (resource: string) => fetch(`/api/${resource}`);
  window.apiMethods.post = (resource: string, data: any) => fetch(`/api/${resource}`, {
    method: 'POST',
    body: JSON.stringify(data)
  });
  
  async function handleRequest() {
    const method = document.getElementById('method')?.getAttribute('data-method') || 'get';
    const resource = document.getElementById('resource')?.getAttribute('data-resource') || 'users';
    
    // ruleid: typescript-unsafe-dynamic-method-access
    const response = await window.apiMethods[method](resource);
    return response.json();
  }
  
  handleRequest();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
  // Global event handlers
  window.handlers = {
    click: () => console.log('Clicked'),
    hover: () => console.log('Hovered'),
    submit: (data: any) => console.log('Submitted', data)
  };
  
  function setupEventListener(element: HTMLElement, eventType: string) {
    element.addEventListener(eventType, (e) => {
      // ruleid: typescript-unsafe-dynamic-method-access
      window.handlers[eventType](e);
    });
  }
  
  const button = document.getElementById('action-button');
  if (button) {
    const eventType = button.getAttribute('data-event-type') || 'click';
    setupEventListener(button, eventType);
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
  // Global calculator functions
  window.add = (a: number, b: number) => a + b;
  window.subtract = (a: number, b: number) => a - b;
  window.multiply = (a: number, b: number) => a * b;
  window.divide = (a: number, b: number) => a / b;
  
  function calculate() {
    const operation = new URLSearchParams(window.location.search).get('op') || 'add';
    const a = parseFloat(new URLSearchParams(window.location.search).get('a') || '0');
    const b = parseFloat(new URLSearchParams(window.location.search).get('b') || '0');
    
    // ruleid: typescript-unsafe-dynamic-method-access
    return window[operation](a, b);
  }
  
  console.log(calculate());
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
  // Global data processors
  window.dataProcessors = {
    format: (data: string) => data.toUpperCase(),
    clean: (data: string) => data.trim(),
    validate: (data: string) => data.length > 0
  };
  
  function processUserInput() {
    const input = document.getElementById('user-input') as HTMLInputElement;
    const processorName = input?.getAttribute('data-processor') || 'format';
    
    if (input) {
      // ruleid: typescript-unsafe-dynamic-method-access
      return window.dataProcessors[processorName](input.value);
    }
    return null;
  }
  
  processUserInput();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
  // Global rendering functions
  window.renderers = {};
  window.renderers.text = (content: string) => `<p>${content}</p>`;
  window.renderers.heading = (content: string) => `<h1>${content}</h1>`;
  window.renderers.list = (items: string[]) => `<ul>${items.map(item => `<li>${item}</li>`).join('')}</ul>`;
  
  function renderContent(type: string, content: any) {
    // ruleid: typescript-unsafe-dynamic-method-access
    const rendered = window.renderers[type](content);
    document.getElementById('output')!.innerHTML = rendered;
  }
  
  const contentType = new URLSearchParams(window.location.search).get('type') || 'text';
  renderContent(contentType, 'Hello World');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
  // Global API endpoints
  window.endpoints = {
    users: '/api/users',
    products: '/api/products',
    orders: '/api/orders'
  };
  
  // Global API methods
  window.api = {
    get: (endpoint: string) => fetch(endpoint),
    post: (endpoint: string, data: any) => fetch(endpoint, {
      method: 'POST',
      body: JSON.stringify(data)
    })
  };
  
  async function fetchData() {
    const resource = new URLSearchParams(window.location.search).get('resource') || 'users';
    const method = new URLSearchParams(window.location.search).get('method') || 'get';
    
    // ruleid: typescript-unsafe-dynamic-method-access
    const endpoint = window.endpoints[resource];
    // ruleid: typescript-unsafe-dynamic-method-access
    const response = await window.api[method](endpoint);
    return response.json();
  }
  
  fetchData();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
  // Global utility functions
  window.utils = {};
  window.utils.formatDate = (date: Date) => date.toLocaleDateString();
  window.utils.formatCurrency = (amount: number) => `$${amount.toFixed(2)}`;
  window.utils.formatPercentage = (value: number) => `${(value * 100).toFixed(1)}%`;
  
  function formatValue(value: any, type: string) {
    // ruleid: typescript-unsafe-dynamic-method-access
    if (typeof window.utils[type] === 'function') {
      return window.utils[type](value);
    }
    return String(value);
  }
  
  const dataType = document.querySelector('input[name="format-type"]:checked')?.value || 'formatDate';
  const formattedValue = formatValue(new Date(), dataType);
  console.log(formattedValue);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
  // Global validation functions
  window.validators = {
    email: (value: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value),
    phone: (value: string) => /^\d{10}$/.test(value),
    zipcode: (value: string) => /^\d{5}(-\d{4})?$/.test(value)
  };
  
  function validateField(field: HTMLInputElement) {
    const validatorType = field.getAttribute('data-validator');
    if (validatorType) {
      // ruleid: typescript-unsafe-dynamic-method-access
      const isValid = window.validators[validatorType](field.value);
      field.classList.toggle('invalid', !isValid);
      return isValid;
    }
    return true;
  }
  
  const emailField = document.getElementById('email') as HTMLInputElement;
  if (emailField) {
    validateField(emailField);
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
  // Global chart renderers
  window.chartRenderers = {
    bar: (data: number[]) => console.log('Rendering bar chart with', data),
    line: (data: number[]) => console.log('Rendering line chart with', data),
    pie: (data: number[]) => console.log('Rendering pie chart with', data)
  };
  
  function renderChart() {
    const chartType = new URLSearchParams(window.location.search).get('chart') || 'bar';
    const data = [10, 20, 30, 40, 50];
    
    // ruleid: typescript-unsafe-dynamic-method-access
    window.chartRenderers[chartType](data);
  }
  
  renderChart();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
  // Global export functions
  window.exporters = {
    csv: (data: any[]) => data.map(row => Object.values(row).join(',')).join('\n'),
    json: (data: any[]) => JSON.stringify(data),
    xml: (data: any[]) => `<root>${data.map(item => `<item>${JSON.stringify(item)}</item>`).join('')}</root>`
  };
  
  function exportData() {
    const data = [{ id: 1, name: 'Item 1' }, { id: 2, name: 'Item 2' }];
    const format = document.querySelector('select#export-format')?.value || 'json';
    
    // ruleid: typescript-unsafe-dynamic-method-access
    const result = window.exporters[format](data);
    
    const blob = new Blob([result], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `export.${format}`;
    a.click();
  }
  
  document.getElementById('export-button')?.addEventListener('click', exportData);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
  // Global form handlers
  window.formHandlers = {
    login: (formData: FormData) => console.log('Handling login', Object.fromEntries(formData)),
    register: (formData: FormData) => console.log('Handling registration', Object.fromEntries(formData)),
    contact: (formData: FormData) => console.log('Handling contact form', Object.fromEntries(formData))
  };
  
  function handleFormSubmit(event: Event) {
    event.preventDefault();
    const form = event.target as HTMLFormElement;
    const formType = form.getAttribute('data-form-type') || 'contact';
    const formData = new FormData(form);
    
    // ruleid: typescript-unsafe-dynamic-method-access
    window.formHandlers[formType](formData);
  }
  
  document.querySelectorAll('form').forEach(form => {
    form.addEventListener('submit', handleFormSubmit);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
  // Global state management
  window.stateManager = {
    setState: (key: string, value: any) => {
      localStorage.setItem(key, JSON.stringify(value));
    },
    getState: (key: string) => {
      const value = localStorage.getItem(key);
      return value ? JSON.parse(value) : null;
    },
    clearState: (key: string) => {
      localStorage.removeItem(key);
    }
  };
  
  function manageAppState(action: string, key: string, value?: any) {
    // ruleid: typescript-unsafe-dynamic-method-access
    if (action === 'setState' && value !== undefined) {
      return window.stateManager[action](key, value);
    } else {
      return window.stateManager[action](key);
    }
  }
  
  const action = new URLSearchParams(window.location.search).get('action') || 'getState';
  const key = new URLSearchParams(window.location.search).get('key') || 'user';
  manageAppState(action, key);
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
  // API methods contained in a specific object, not global scope
  const api = {
    fetchData: (url: string) => {
      return fetch(url).then(response => response.json());
    },
    processData: (data: any) => {
      return JSON.stringify(data);
    }
  };
  
  function executeUserAction(methodName: string, param: string) {
    // ok: typescript-unsafe-dynamic-method-access
    if (methodName === 'fetchData' || methodName === 'processData') {
      return api[methodName as keyof typeof api](param);
    }
    throw new Error('Invalid method name');
  }
  
  const userInput = new URLSearchParams(window.location.search).get('method') || 'fetchData';
  executeUserAction(userInput, 'https://api.example.com/data');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
  // Using a Map to store allowed methods
  const allowedMethods = new Map<string, Function>();
  allowedMethods.set('getData', () => 'sensitive data');
  allowedMethods.set('setData', (value: string) => console.log(`Setting data: ${value}`));
  allowedMethods.set('deleteData', () => console.log('Deleting data'));
  
  function executeMethod() {
    const methodName = window.location.hash.substring(1);
    // ok: typescript-unsafe-dynamic-method-access
    if (allowedMethods.has(methodName)) {
      return allowedMethods.get(methodName)!();
    }
    return null;
  }
  
  executeMethod();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
  // API methods in a dedicated object with validation
  const userAPI = {
    getUser: (id: number) => ({ id, name: 'User' + id }),
    updateUser: (id: number, data: object) => console.log(`Updating user ${id}`, data),
    deleteUser: (id: number) => console.log(`Deleting user ${id}`)
  };
  
  type UserAPIMethod = keyof typeof userAPI;
  
  function processRequest(action: string, id: number, data?: object) {
    const methodName = `${action}User` as UserAPIMethod;
    // ok: typescript-unsafe-dynamic-method-access
    if (methodName in userAPI) {
      if (data && methodName === 'updateUser') {
        return userAPI[methodName](id, data);
      } else {
        return userAPI[methodName](id);
      }
    }
    throw new Error('Invalid method');
  }
  
  const action = new URLSearchParams(window.location.search).get('action') || 'get';
  const userId = parseInt(new URLSearchParams(window.location.search).get('id') || '1');
  processRequest(action, userId);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
  // API methods in a dedicated object with explicit method calls
  const apiMethods = {
    get: (resource: string) => fetch(`/api/${resource}`),
    post: (resource: string, data: any) => fetch(`/api/${resource}`, {
      method: 'POST',
      body: JSON.stringify(data)
    })
  };
  
  async function handleRequest() {
    const method = document.getElementById('method')?.getAttribute('data-method') || 'get';
    const resource = document.getElementById('resource')?.getAttribute('data-resource') || 'users';
    
    // ok: typescript-unsafe-dynamic-method-access
    let response;
    if (method === 'get') {
      response = await apiMethods.get(resource);
    } else if (method === 'post') {
      response = await apiMethods.post(resource, {});
    } else {
      throw new Error('Invalid method');
    }
    
    return response.json();
  }
  
  handleRequest();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
  // Event handlers in a dedicated object with validation
  const handlers = {
    click: () => console.log('Clicked'),
    hover: () => console.log('Hovered'),
    submit: (data: any) => console.log('Submitted', data)
  };
  
  type HandlerType = keyof typeof handlers;
  
  function setupEventListener(element: HTMLElement, eventType: string) {
    // ok: typescript-unsafe-dynamic-method-access
    if (eventType in handlers) {
      element.addEventListener(eventType, (e) => {
        handlers[eventType as HandlerType](e);
      });
    }
  }
  
  const button = document.getElementById('action-button');
  if (button) {
    const eventType = button.getAttribute('data-event-type') || 'click';
    setupEventListener(button, eventType);
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
  // Calculator functions in a dedicated object with validation
  const calculatorFunctions = {
    add: (a: number, b: number) => a + b,
    subtract: (a: number, b: number) => a - b,
    multiply: (a: number, b: number) => a * b,
    divide: (a: number, b: number) => a / b
  };
  
  type Operation = keyof typeof calculatorFunctions;
  
  function calculate() {
    const operation = new URLSearchParams(window.location.search).get('op') || 'add';
    const a = parseFloat(new URLSearchParams(window.location.search).get('a') || '0');
    const b = parseFloat(new URLSearchParams(window.location.search).get('b') || '0');
    
    // ok: typescript-unsafe-dynamic-method-access
    if (operation in calculatorFunctions) {
      return calculatorFunctions[operation as Operation](a, b);
    }
    throw new Error('Invalid operation');
  }
  
  console.log(calculate());
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
  // Data processors in a dedicated object with validation
  const dataProcessors = {
    format: (data: string) => data.toUpperCase(),
    clean: (data: string) => data.trim(),
    validate: (data: string) => data.length > 0
  };
  
  type ProcessorName = keyof typeof dataProcessors;
  
  function processUserInput() {
    const input = document.getElementById('user-input') as HTMLInputElement;
    const processorName = input?.getAttribute('data-processor') || 'format';
    
    if (input) {
      // ok: typescript-unsafe-dynamic-method-access
      if (processorName in dataProcessors) {
        return dataProcessors[processorName as ProcessorName](input.value);
      }
      return input.value;
    }
    return null;
  }
  
  processUserInput();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
  // Rendering functions in a dedicated object with validation
  const renderers = {
    text: (content: string) => `<p>${content}</p>`,
    heading: (content: string) => `<h1>${content}</h1>`,
    list: (items: string[]) => `<ul>${items.map(item => `<li>${item}</li>`).join('')}</ul>`
  };
  
  type RendererType = keyof typeof renderers;
  const validRenderers: RendererType[] = ['text', 'heading', 'list'];
  
  function renderContent(type: string, content: any) {
    // ok: typescript-unsafe-dynamic-method-access
    if (validRenderers.includes(type as RendererType)) {
      const rendered = renderers[type as RendererType](content);
      document.getElementById('output')!.innerHTML = rendered;
    } else {
      document.getElementById('output')!.textContent = String(content);
    }
  }
  
  const contentType = new URLSearchParams(window.location.search).get('type') || 'text';
  renderContent(contentType, 'Hello World');
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
  // API endpoints and methods in dedicated objects with validation
  const endpoints = {
    users: '/api/users',
    products: '/api/products',
    orders: '/api/orders'
  };
  
  const api = {
    get: (endpoint: string) => fetch(endpoint),
    post: (endpoint: string, data: any) => fetch(endpoint, {
      method: 'POST',
      body: JSON.stringify(data)
    })
  };
  
  type ResourceType = keyof typeof endpoints;
  type ApiMethod = keyof typeof api;
  
  async function fetchData() {
    const resource = new URLSearchParams(window.location.search).get('resource') || 'users';
    const method = new URLSearchParams(window.location.search).get('method') || 'get';
    
    // ok: typescript-unsafe-dynamic-method-access
    if (resource in endpoints && method in api) {
      const endpoint = endpoints[resource as ResourceType];
      return await api[method as ApiMethod](endpoint);
    }
    throw new Error('Invalid resource or method');
  }
  
  fetchData();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
  // Utility functions in a dedicated object with validation
  const utils = {
    formatDate: (date: Date) => date.toLocaleDateString(),
    formatCurrency: (amount: number) => `$${amount.toFixed(2)}`,
    formatPercentage: (value: number) => `${(value * 100).toFixed(1)}%`
  };
  
  type FormatType = keyof typeof utils;
  
  function formatValue(value: any, type: string) {
    // ok: typescript-unsafe-dynamic-method-access
    if (type in utils) {
      return utils[type as FormatType](value);
    }
    return String(value);
  }
  
  const dataType = document.querySelector('input[name="format-type"]:checked')?.value || 'formatDate';
  const formattedValue = formatValue(new Date(), dataType);
  console.log(formattedValue);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
  // Validation functions in a dedicated object with validation
  const validators = {
    email: (value: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value),
    phone: (value: string) => /^\d{10}$/.test(value),
    zipcode: (value: string) => /^\d{5}(-\d{4})?$/.test(value)
  };
  
  type ValidatorType = keyof typeof validators;
  
  function validateField(field: HTMLInputElement) {
    const validatorType = field.getAttribute('data-validator');
    // ok: typescript-unsafe-dynamic-method-access
    if (validatorType && validatorType in validators) {
      const isValid = validators[validatorType as ValidatorType](field.value);
      field.classList.toggle('invalid', !isValid);
      return isValid;
    }
    return true;
  }
  
  const emailField = document.getElementById('email') as HTMLInputElement;
  if (emailField) {
    validateField(emailField);
  }
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
  // Chart renderers in a dedicated object with validation
  const chartRenderers = {
    bar: (data: number[]) => console.log('Rendering bar chart with', data),
    line: (data: number[]) => console.log('Rendering line chart with', data),
    pie: (data: number[]) => console.log('Rendering pie chart with', data)
  };
  
  type ChartType = keyof typeof chartRenderers;
  const validChartTypes: ChartType[] = ['bar', 'line', 'pie'];
  
  function renderChart() {
    const chartType = new URLSearchParams(window.location.search).get('chart') || 'bar';
    const data = [10, 20, 30, 40, 50];
    
    // ok: typescript-unsafe-dynamic-method-access
    if (validChartTypes.includes(chartType as ChartType)) {
      chartRenderers[chartType as ChartType](data);
    } else {
      console.error('Invalid chart type');
    }
  }
  
  renderChart();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
  // Export functions in a dedicated object with validation
  const exporters = {
    csv: (data: any[]) => data.map(row => Object.values(row).join(',')).join('\n'),
    json: (data: any[]) => JSON.stringify(data),
    xml: (data: any[]) => `<root>${data.map(item => `<item>${JSON.stringify(item)}</item>`).join('')}</root>`
  };
  
  type ExportFormat = keyof typeof exporters;
  const validFormats: ExportFormat[] = ['csv', 'json', 'xml'];
  
  function exportData() {
    const data = [{ id: 1, name: 'Item 1' }, { id: 2, name: 'Item 2' }];
    const format = document.querySelector('select#export-format')?.value || 'json';
    
    // ok: typescript-unsafe-dynamic-method-access
    if (validFormats.includes(format as ExportFormat)) {
      const result = exporters[format as ExportFormat](data);
      
      const blob = new Blob([result], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      
      const a = document.createElement('a');
      a.href = url;
      a.download = `export.${format}`;
      a.click();
    } else {
      console.error('Invalid export format');
    }
  }
  
  document.getElementById('export-button')?.addEventListener('click', exportData);
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
  // Form handlers in a dedicated object with validation
  const formHandlers = {
    login: (formData: FormData) => console.log('Handling login', Object.fromEntries(formData)),
    register: (formData: FormData) => console.log('Handling registration', Object.fromEntries(formData)),
    contact: (formData: FormData) => console.log('Handling contact form', Object.fromEntries(formData))
  };
  
  type FormType = keyof typeof formHandlers;
  
  function handleFormSubmit(event: Event) {
    event.preventDefault();
    const form = event.target as HTMLFormElement;
    const formType = form.getAttribute('data-form-type') || 'contact';
    const formData = new FormData(form);
    
    // ok: typescript-unsafe-dynamic-method-access
    if (formType in formHandlers) {
      formHandlers[formType as FormType](formData);
    } else {
      console.error('Unknown form type');
    }
  }
  
  document.querySelectorAll('form').forEach(form => {
    form.addEventListener('submit', handleFormSubmit);
  });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
  // State management in a dedicated object with validation using a switch statement
  const stateManager = {
    setState: (key: string, value: any) => {
      localStorage.setItem(key, JSON.stringify(value));
    },
    getState: (key: string) => {
      const value = localStorage.getItem(key);
      return value ? JSON.parse(value) : null;
    },
    clearState: (key: string) => {
      localStorage.removeItem(key);
    }
  };
  
  function manageAppState(action: string, key: string, value?: any) {
    // ok: typescript-unsafe-dynamic-method-access
    switch (action) {
      case 'setState':
        if (value !== undefined) {
          stateManager.setState(key, value);
        }
        break;
      case 'getState':
        return stateManager.getState(key);
      case 'clearState':
        stateManager.clearState(key);
        break;
      default:
        throw new Error('Invalid action');
    }
  }
  
  const action = new URLSearchParams(window.location.search).get('action') || 'getState';
  const key = new URLSearchParams(window.location.search).get('key') || 'user';
  manageAppState(action, key);
}
// {/fact}