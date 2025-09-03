// Prototype Pollution Examples in TypeScript
// Rule ID: typescript-prototype-pollution-function

// ==================== TRUE POSITIVES (VULNERABLE CODE) ====================

// Bad case 1: Unsafe recursive merge function
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_1() {
  function unsafeMerge(target: any, source: any): any {
    for (const key in source) {
      if (typeof source[key] === 'object' && source[key] !== null) {
        if (!target[key]) target[key] = {};
        // ruleid: typescript-prototype-pollution-function
        unsafeMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
    return target;
  }
  
  const userInput = JSON.parse('{"__proto__": {"isAdmin": true}}');
  const config = {};
  unsafeMerge(config, userInput);
  
  return config;
}
// {/fact}

// Bad case 2: Unsafe extend function with direct property assignment
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_2() {
  function unsafeExtend(target: any, source: any): any {
    for (const key in source) {
      // ruleid: typescript-prototype-pollution-function
      target[key] = source[key];
    }
    return target;
  }
  
  const userInput = JSON.parse('{"__proto__": {"polluted": true}}');
  const defaultSettings = { theme: 'light' };
  unsafeExtend(defaultSettings, userInput);
  
  return defaultSettings;
}
// {/fact}

// Bad case 3: Deep property assignment with user-controlled path
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_3() {
  function setNestedProperty(obj: any, path: string[], value: any): void {
    let current = obj;
    
    for (let i = 0; i < path.length - 1; i++) {
      const key = path[i];
      if (!current[key]) {
        current[key] = {};
      }
      current = current[key];
    }
    
    // ruleid: typescript-prototype-pollution-function
    current[path[path.length - 1]] = value;
  }
  
  const userObj = {};
  const userPath = ['__proto__', 'toString'];
  const userValue = () => 'Polluted';
  
  setNestedProperty(userObj, userPath, userValue);
  return userObj;
}
// {/fact}

// Bad case 4: Recursive object cloning with prototype pollution
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_4() {
  function deepClone(obj: any): any {
    if (obj === null || typeof obj !== 'object') {
      return obj;
    }
    
    const copy: any = Array.isArray(obj) ? [] : {};
    
    for (const key in obj) {
      // ruleid: typescript-prototype-pollution-function
      copy[key] = deepClone(obj[key]);
    }
    
    return copy;
  }
  
  const maliciousInput = JSON.parse('{"__proto__": {"malicious": true}}');
  const clonedObject = deepClone(maliciousInput);
  
  return clonedObject;
}
// {/fact}

// Bad case 5: Custom object assign implementation
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_5() {
  function customAssign(target: any, ...sources: any[]): any {
    sources.forEach(source => {
      for (const key in source) {
        // ruleid: typescript-prototype-pollution-function
        target[key] = source[key];
      }
    });
    return target;
  }
  
  const userInput = { '__proto__': { polluted: true } };
  const config = { debug: false };
  customAssign(config, userInput);
  
  return config;
}
// {/fact}

// Bad case 6: Recursive deep extend function
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_6() {
  function deepExtend(target: any, source: any): any {
    for (const prop in source) {
      if (source.hasOwnProperty(prop)) {
        if (target[prop] && typeof source[prop] === 'object') {
          // ruleid: typescript-prototype-pollution-function
          deepExtend(target[prop], source[prop]);
        } else {
          target[prop] = source[prop];
        }
      }
    }
    return target;
  }
  
  const userInput = JSON.parse('{"x": {"__proto__": {"polluted": true}}}');
  const config = { x: {} };
  deepExtend(config, userInput);
  
  return config;
}
// {/fact}

// Bad case 7: Dynamic property setter
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_7() {
  function setProperty(obj: any, path: string, value: any): void {
    const parts = path.split('.');
    let current = obj;
    
    for (let i = 0; i < parts.length - 1; i++) {
      const part = parts[i];
      if (!current[part]) {
        current[part] = {};
      }
      current = current[part];
    }
    
    const lastPart = parts[parts.length - 1];
    // ruleid: typescript-prototype-pollution-function
    current[lastPart] = value;
  }
  
  const obj = {};
  setProperty(obj, '__proto__.polluted', true);
  
  return obj;
}
// {/fact}

// Bad case 8: Config merger with nested objects
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_8() {
  function mergeConfigs(defaultConfig: any, userConfig: any): any {
    const result = { ...defaultConfig };
    
    for (const key in userConfig) {
      if (typeof userConfig[key] === 'object' && userConfig[key] !== null && 
          typeof result[key] === 'object' && result[key] !== null) {
        // ruleid: typescript-prototype-pollution-function
        result[key] = mergeConfigs(result[key], userConfig[key]);
      } else {
        result[key] = userConfig[key];
      }
    }
    
    return result;
  }
  
  const defaultConfig = { features: { darkMode: false } };
  const userConfig = JSON.parse('{"__proto__": {"isAdmin": true}}');
  
  return mergeConfigs(defaultConfig, userConfig);
}
// {/fact}

// Bad case 9: Object builder with dynamic keys
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_9() {
  function buildObjectFromPairs(pairs: [string, any][]): any {
    const result: any = {};
    
    for (const [key, value] of pairs) {
      if (typeof value === 'object' && value !== null) {
        // ruleid: typescript-prototype-pollution-function
        result[key] = { ...value };
      } else {
        result[key] = value;
      }
    }
    
    return result;
  }
  
  const userInput = [['__proto__', { polluted: true }]];
  return buildObjectFromPairs(userInput);
}
// {/fact}

// Bad case 10: Template-based object creator
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_10() {
  function createFromTemplate(template: any, values: any): any {
    const result: any = JSON.parse(JSON.stringify(template));
    
    function applyValues(obj: any, vals: any, prefix: string = ''): void {
      for (const key in vals) {
        const path = prefix ? `${prefix}.${key}` : key;
        
        if (typeof vals[key] === 'object' && vals[key] !== null) {
          applyValues(obj, vals[key], path);
        } else {
          const pathParts = path.split('.');
          let current = obj;
          
          for (let i = 0; i < pathParts.length - 1; i++) {
            if (!current[pathParts[i]]) {
              current[pathParts[i]] = {};
            }
            current = current[pathParts[i]];
          }
          
          // ruleid: typescript-prototype-pollution-function
          current[pathParts[pathParts.length - 1]] = vals[key];
        }
      }
    }
    
    applyValues(result, values);
    return result;
  }
  
  const template = { user: { name: '' } };
  const values = { '__proto__': { polluted: true } };
  
  return createFromTemplate(template, values);
}
// {/fact}

// Bad case 11: Recursive JSON schema validator with property assignment
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_11() {
  function validateAndAssign(target: any, schema: any, input: any): any {
    for (const key in schema) {
      if (input.hasOwnProperty(key)) {
        if (typeof schema[key] === 'object' && schema[key] !== null &&
            typeof input[key] === 'object' && input[key] !== null) {
          if (!target[key]) target[key] = {};
          // ruleid: typescript-prototype-pollution-function
          validateAndAssign(target[key], schema[key], input[key]);
        } else {
          target[key] = input[key];
        }
      }
    }
    return target;
  }
  
  const schema = { user: { name: 'string', role: 'string' } };
  const input = JSON.parse('{"__proto__": {"isAdmin": true}}');
  const result = {};
  
  return validateAndAssign(result, schema, input);
}
// {/fact}

// Bad case 12: Object path resolver with assignment
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_12() {
  function resolveAndSet(obj: any, path: string, value: any): void {
    const segments = path.split('.');
    let current = obj;
    
    for (let i = 0; i < segments.length - 1; i++) {
      const segment = segments[i];
      if (current[segment] === undefined) {
        current[segment] = {};
      }
      current = current[segment];
    }
    
    const lastSegment = segments[segments.length - 1];
    // ruleid: typescript-prototype-pollution-function
    current[lastSegment] = value;
  }
  
  const config = {};
  resolveAndSet(config, '__proto__.polluted', 'yes');
  
  return config;
}
// {/fact}

// Bad case 13: Custom object property copier
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_13() {
  function copyProperties(source: any, target: any, properties: string[]): void {
    for (const prop of properties) {
      if (source.hasOwnProperty(prop)) {
        // ruleid: typescript-prototype-pollution-function
        target[prop] = source[prop];
      }
    }
  }
  
  const source = JSON.parse('{"__proto__": {"malicious": true}}');
  const target = {};
  copyProperties(source, target, ['__proto__']);
  
  return target;
}
// {/fact}

// Bad case 14: Nested object creator with dynamic paths
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_14() {
  function createNestedObject(paths: string[][]): any {
    const result: any = {};
    
    for (const path of paths) {
      let current = result;
      
      for (let i = 0; i < path.length - 1; i++) {
        const segment = path[i];
        if (!current[segment]) {
          current[segment] = {};
        }
        current = current[segment];
      }
      
      // ruleid: typescript-prototype-pollution-function
      current[path[path.length - 1]] = true;
    }
    
    return result;
  }
  
  return createNestedObject([['__proto__', 'polluted']]);
}
// {/fact}

// Bad case 15: Object property mapper
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_15() {
  function mapProperties(obj: any, mapper: (key: string, value: any) => [string, any]): any {
    const result: any = {};
    
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        const [newKey, newValue] = mapper(key, obj[key]);
        // ruleid: typescript-prototype-pollution-function
        result[newKey] = newValue;
      }
    }
    
    return result;
  }
  
  const input = { key: 'value' };
  const result = mapProperties(input, (k, v) => ['__proto__', { polluted: true }]);
  
  return result;
}
// {/fact}

// ==================== TRUE NEGATIVES (SAFE CODE) ====================

// Good case 1: Safe merge function with prototype check
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_1() {
  function safeMerge(target: any, source: any): any {
    for (const key in source) {
      // ok: typescript-prototype-pollution-function
      if (key !== '__proto__' && key !== 'constructor' && source.hasOwnProperty(key)) {
        if (typeof source[key] === 'object' && source[key] !== null) {
          if (!target[key]) target[key] = {};
          safeMerge(target[key], source[key]);
        } else {
          target[key] = source[key];
        }
      }
    }
    return target;
  }
  
  const userInput = JSON.parse('{"__proto__": {"isAdmin": true}, "name": "test"}');
  const config = {};
  safeMerge(config, userInput);
  
  return config;
}
// {/fact}

// Good case 2: Safe extend function with hasOwnProperty check
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_2() {
  function safeExtend(target: any, source: any): any {
    for (const key in source) {
      // ok: typescript-prototype-pollution-function
      if (source.hasOwnProperty(key) && key !== '__proto__' && key !== 'constructor') {
        target[key] = source[key];
      }
    }
    return target;
  }
  
  const userInput = JSON.parse('{"__proto__": {"polluted": true}, "theme": "dark"}');
  const defaultSettings = { theme: 'light' };
  safeExtend(defaultSettings, userInput);
  
  return defaultSettings;
}
// {/fact}

// Good case 3: Safe deep property assignment with path validation
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_3() {
  function setNestedPropertySafely(obj: any, path: string[], value: any): void {
    // ok: typescript-prototype-pollution-function
    if (path.includes('__proto__') || path.includes('constructor')) {
      console.error('Attempt to modify prototype detected');
      return;
    }
    
    let current = obj;
    
    for (let i = 0; i < path.length - 1; i++) {
      const key = path[i];
      if (!current[key]) {
        current[key] = {};
      }
      current = current[key];
    }
    
    current[path[path.length - 1]] = value;
  }
  
  const userObj = {};
  const userPath = ['settings', 'theme'];
  const userValue = 'dark';
  
  setNestedPropertySafely(userObj, userPath, userValue);
  return userObj;
}
// {/fact}

// Good case 4: Safe object cloning with Object.assign and spread
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_4() {
  function safeClone(obj: any): any {
    if (obj === null || typeof obj !== 'object') {
      return obj;
    }
    
    // ok: typescript-prototype-pollution-function
    return Array.isArray(obj) ? [...obj] : { ...obj };
  }
  
  const userInput = { name: 'test', settings: { theme: 'dark' } };
  const clonedObject = safeClone(userInput);
  
  return clonedObject;
}
// {/fact}

// Good case 5: Using Object.create(null) to avoid prototype pollution
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_5() {
  function safeObjectMerge(target: any, source: any): any {
    // ok: typescript-prototype-pollution-function
    const result = Object.create(null);
    
    // Copy properties from target
    for (const key in target) {
      if (target.hasOwnProperty(key)) {
        result[key] = target[key];
      }
    }
    
    // Copy properties from source
    for (const key in source) {
      if (source.hasOwnProperty(key)) {
        result[key] = source[key];
      }
    }
    
    return result;
  }
  
  const userInput = JSON.parse('{"__proto__": {"polluted": true}, "name": "test"}');
  const config = { debug: false };
  const mergedConfig = safeObjectMerge(config, userInput);
  
  return mergedConfig;
}
// {/fact}

// Good case 6: Using Object.defineProperty for safe property assignment
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_6() {
  function safePropertyAssign(obj: any, key: string, value: any): void {
    // ok: typescript-prototype-pollution-function
    if (key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
      Object.defineProperty(obj, key, {
        value: value,
        writable: true,
        enumerable: true,
        configurable: true
      });
    }
  }
  
  const config = {};
  safePropertyAssign(config, 'theme', 'dark');
  safePropertyAssign(config, '__proto__', { polluted: true }); // This will be ignored
  
  return config;
}
// {/fact}

// Good case 7: Using Map instead of plain objects
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_7() {
  function safeConfigStore(): any {
    // ok: typescript-prototype-pollution-function
    const configMap = new Map<string, any>();
    
    return {
      set: (key: string, value: any) => {
        configMap.set(key, value);
      },
      get: (key: string) => configMap.get(key),
      has: (key: string) => configMap.has(key),
      delete: (key: string) => configMap.delete(key),
      toObject: () => {
        const result: any = {};
        configMap.forEach((value, key) => {
          result[key] = value;
        });
        return result;
      }
    };
  }
  
  const config = safeConfigStore();
  config.set('theme', 'dark');
  config.set('__proto__', { polluted: true }); // This won't affect Object.prototype
  
  return config.toObject();
}
// {/fact}

// Good case 8: Safe recursive merge with explicit property checks
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_8() {
  function safeDeepMerge(target: any, source: any): any {
    const output = Object.assign({}, target);
    
    if (isObject(source) && isObject(target)) {
      Object.keys(source).forEach(key => {
        // ok: typescript-prototype-pollution-function
        if (key === '__proto__' || key === 'constructor') {
          return; // Skip prototype properties
        }
        
        if (isObject(source[key]) && key in target) {
          output[key] = safeDeepMerge(target[key], source[key]);
        } else {
          output[key] = source[key];
        }
      });
    }
    
    return output;
  }
  
  function isObject(item: any): boolean {
    return (item && typeof item === 'object' && !Array.isArray(item));
  }
  
  const defaultConfig = { features: { darkMode: false } };
  const userConfig = JSON.parse('{"features": {"darkMode": true}, "__proto__": {"isAdmin": true}}');
  
  return safeDeepMerge(defaultConfig, userConfig);
}
// {/fact}

// Good case 9: Using Object.entries for safe property copying
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_9() {
  function safeObjectBuilder(data: Record<string, any>): any {
    const result: Record<string, any> = {};
    
    // ok: typescript-prototype-pollution-function
    Object.entries(data).forEach(([key, value]) => {
      if (key !== '__proto__' && key !== 'constructor') {
        result[key] = value;
      }
    });
    
    return result;
  }
  
  const userInput = { name: 'test', '__proto__': { polluted: true } };
  return safeObjectBuilder(userInput);
}
// {/fact}

// Good case 10: Using a whitelist of allowed properties
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_10() {
  function safeConfigBuilder(userInput: any): any {
    const allowedKeys = ['theme', 'language', 'notifications', 'fontSize'];
    const config: Record<string, any> = {};
    
    // ok: typescript-prototype-pollution-function
    for (const key of allowedKeys) {
      if (userInput.hasOwnProperty(key)) {
        config[key] = userInput[key];
      }
    }
    
    return config;
  }
  
  const userInput = {
    theme: 'dark',
    language: 'en',
    '__proto__': { polluted: true }
  };
  
  return safeConfigBuilder(userInput);
}
// {/fact}

// Good case 11: Using JSON.parse and JSON.stringify for deep cloning
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_11() {
  function safeDeepClone(obj: any): any {
    // ok: typescript-prototype-pollution-function
    return JSON.parse(JSON.stringify(obj));
  }
  
  const userConfig = {
    theme: 'dark',
    settings: {
      notifications: true
    },
    '__proto__': { polluted: true }
  };
  
  // This will strip the __proto__ property
  const clonedConfig = safeDeepClone(userConfig);
  return clonedConfig;
}
// {/fact}

// Good case 12: Using Object.getOwnPropertyNames for safe property iteration
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_12() {
  function safeObjectMerge(target: any, source: any): any {
    // ok: typescript-prototype-pollution-function
    Object.getOwnPropertyNames(source).forEach(key => {
      if (key !== '__proto__' && key !== 'constructor') {
        if (typeof source[key] === 'object' && source[key] !== null && 
            typeof target[key] === 'object' && target[key] !== null) {
          safeObjectMerge(target[key], source[key]);
        } else {
          target[key] = source[key];
        }
      }
    });
    
    return target;
  }
  
  const baseConfig = { debug: false };
  const userConfig = Object.create(null);
  userConfig.theme = 'dark';
  userConfig.__proto__ = { polluted: true }; // This won't be merged
  
  return safeObjectMerge(baseConfig, userConfig);
}
// {/fact}

// Good case 13: Using a sanitizer function to clean object keys
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_13() {
  function sanitizeKey(key: string): string | null {
    // Return null for potentially dangerous keys
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      return null;
    }
    return key;
  }
  
  function safeObjectBuilder(data: Record<string, any>): any {
    const result: Record<string, any> = {};
    
    for (const key in data) {
      if (data.hasOwnProperty(key)) {
        // ok: typescript-prototype-pollution-function
        const safeKey = sanitizeKey(key);
        if (safeKey !== null) {
          result[safeKey] = data[key];
        }
      }
    }
    
    return result;
  }
  
  const userInput = { name: 'test', '__proto__': { polluted: true } };
  return safeObjectBuilder(userInput);
}
// {/fact}

// Good case 14: Using Object.freeze to prevent modifications
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_14() {
  function createImmutableConfig(config: any): any {
    const safeConfig: any = {};
    
    // Copy only own properties
    for (const key in config) {
      if (config.hasOwnProperty(key) && key !== '__proto__' && key !== 'constructor') {
        safeConfig[key] = config[key];
      }
    }
    
    // ok: typescript-prototype-pollution-function
    return Object.freeze(safeConfig);
  }
  
  const userConfig = {
    theme: 'dark',
    '__proto__': { polluted: true }
  };
  
  return createImmutableConfig(userConfig);
}
// {/fact}

// Good case 15: Using a custom property descriptor to prevent prototype pollution
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_15() {
  function safeObjectAssign(target: any, source: any): any {
    for (const key in source) {
      if (source.hasOwnProperty(key)) {
        // ok: typescript-prototype-pollution-function
        if (key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
          if (typeof source[key] === 'object' && source[key] !== null) {
            target[key] = target[key] || {};
            safeObjectAssign(target[key], source[key]);
          } else {
            Object.defineProperty(target, key, {
              value: source[key],
              writable: true,
              enumerable: true,
              configurable: true
            });
          }
        }
      }
    }
    return target;
  }
  
  const baseConfig = { logging: { enabled: false } };
  const userConfig = JSON.parse('{"logging": {"level": "debug"}, "__proto__": {"polluted": true}}');
  
  return safeObjectAssign(baseConfig, userConfig);
}
// {/fact}