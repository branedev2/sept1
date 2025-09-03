import express from 'express';
import http from 'http';
import axios from 'axios';

// True Positive Examples (Vulnerable Code)

// Example 1: Direct assignment using user input as property name
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_1() {
    const app = express();
    
    app.get('/api/setProperty', (req, res) => {
        const obj = {};
        const key = req.query.key as string;
        const value = req.query.value;
        
        // ruleid: typescript-prototype-pollution-assignment
        obj[key] = value;
        
        res.json({ success: true, object: obj });
    });
}
// {/fact}

// Example 2: Using user input in nested object assignment
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_2() {
    const app = express();
    
    app.post('/api/updateUser', (req, res) => {
        const userData = {};
        const propertyPath = req.body.path;
        const value = req.body.value;
        
        let current = userData;
        const parts = propertyPath.split('.');
        
        for (let i = 0; i < parts.length - 1; i++) {
            if (!current[parts[i]]) {
                current[parts[i]] = {};
            }
            current = current[parts[i]];
        }
        
        // ruleid: typescript-prototype-pollution-assignment
        current[parts[parts.length - 1]] = value;
        
        res.json({ success: true, data: userData });
    });
}
// {/fact}

// Example 3: Using user input in object spread assignment
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_3() {
    const app = express();
    
    app.post('/api/mergeConfig', (req, res) => {
        const config = { theme: 'light' };
        const userConfig = req.body.config;
        
        for (const key in userConfig) {
            // ruleid: typescript-prototype-pollution-assignment
            config[key] = userConfig[key];
        }
        
        res.json({ success: true, config });
    });
}
// {/fact}

// Example 4: Using bracket notation with user input in a loop
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_4() {
    const app = express();
    
    app.post('/api/batchUpdate', (req, res) => {
        const data = {};
        const updates = req.body.updates;
        
        updates.forEach((update: {key: string, value: any}) => {
            // ruleid: typescript-prototype-pollution-assignment
            data[update.key] = update.value;
        });
        
        res.json({ success: true, data });
    });
}
// {/fact}

// Example 5: Using user input to update object via destructuring
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_5() {
    const app = express();
    
    app.post('/api/updateSettings', (req, res) => {
        const settings = {};
        const { key, value } = req.body;
        
        // ruleid: typescript-prototype-pollution-assignment
        settings[key] = value;
        
        res.json({ success: true, settings });
    });
}
// {/fact}

// Example 6: Using user input in recursive object assignment
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_6() {
    const app = express();
    
    app.post('/api/deepMerge', (req, res) => {
        const target = {};
        const source = req.body.data;
        
        function merge(target: any, source: any) {
            for (const key in source) {
                if (typeof source[key] === 'object' && source[key] !== null) {
                    if (!target[key]) target[key] = {};
                    merge(target[key], source[key]);
                } else {
                    // ruleid: typescript-prototype-pollution-assignment
                    target[key] = source[key];
                }
            }
        }
        
        merge(target, source);
        res.json({ success: true, result: target });
    });
}
// {/fact}

// Example 7: Using user input to set properties via Object.defineProperty
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_7() {
    const app = express();
    
    app.post('/api/defineProperty', (req, res) => {
        const obj = {};
        const key = req.body.key;
        const value = req.body.value;
        
        // ruleid: typescript-prototype-pollution-assignment
        Object.defineProperty(obj, key, {
            value: value,
            writable: true,
            enumerable: true
        });
        
        res.json({ success: true, object: obj });
    });
}
// {/fact}

// Example 8: Using user input to set object properties from URL parameters
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_8() {
    const app = express();
    
    app.get('/api/setFromUrl', (req, res) => {
        const obj = {};
        
        for (const param in req.query) {
            // ruleid: typescript-prototype-pollution-assignment
            obj[param] = req.query[param];
        }
        
        res.json({ success: true, object: obj });
    });
}
// {/fact}

// Example 9: Using user input to update global configuration object
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_9() {
    const app = express();
    const globalConfig: Record<string, any> = {};
    
    app.post('/api/updateConfig', (req, res) => {
        const { section, key, value } = req.body;
        
        if (!globalConfig[section]) {
            globalConfig[section] = {};
        }
        
        // ruleid: typescript-prototype-pollution-assignment
        globalConfig[section][key] = value;
        
        res.json({ success: true, config: globalConfig });
    });
}
// {/fact}

// Example 10: Using user input to create dynamic object paths
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_10() {
    const app = express();
    
    app.post('/api/setNestedValue', (req, res) => {
        const data = {};
        const path = req.body.path as string;
        const value = req.body.value;
        
        function setValueAtPath(obj: any, path: string, value: any) {
            const keys = path.split('.');
            let current = obj;
            
            for (let i = 0; i < keys.length - 1; i++) {
                if (!current[keys[i]]) {
                    current[keys[i]] = {};
                }
                current = current[keys[i]];
            }
            
            // ruleid: typescript-prototype-pollution-assignment
            current[keys[keys.length - 1]] = value;
        }
        
        setValueAtPath(data, path, value);
        res.json({ success: true, data });
    });
}
// {/fact}

// Example 11: Using user input to update object with computed property names
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_11() {
    const app = express();
    
    app.post('/api/updateWithComputed', (req, res) => {
        const obj = {};
        const prefix = req.body.prefix;
        const key = req.body.key;
        const value = req.body.value;
        
        // ruleid: typescript-prototype-pollution-assignment
        obj[`${prefix}_${key}`] = value;
        
        res.json({ success: true, object: obj });
    });
}
// {/fact}

// Example 12: Using user input to set properties via Reflect.set
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_12() {
    const app = express();
    
    app.post('/api/reflectSet', (req, res) => {
        const obj = {};
        const key = req.body.key;
        const value = req.body.value;
        
        // ruleid: typescript-prototype-pollution-assignment
        Reflect.set(obj, key, value);
        
        res.json({ success: true, object: obj });
    });
}
// {/fact}

// Example 13: Using user input in object assignment with HTTP headers
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_13() {
    const app = express();
    
    app.get('/api/headerConfig', (req, res) => {
        const config = {};
        const headerKey = req.headers['x-config-key'] as string;
        const headerValue = req.headers['x-config-value'];
        
        if (headerKey && headerValue) {
            // ruleid: typescript-prototype-pollution-assignment
            config[headerKey] = headerValue;
        }
        
        res.json({ success: true, config });
    });
}
// {/fact}

// Example 14: Using user input to create objects with dynamic keys from external API
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_14() {
    const app = express();
    
    app.post('/api/externalData', async (req, res) => {
        try {
            const externalApiUrl = req.body.apiUrl;
            const response = await axios.get(externalApiUrl);
            const data = {};
            
            const mappingKey = req.body.mappingKey;
            
            response.data.items.forEach((item: any) => {
                // ruleid: typescript-prototype-pollution-assignment
                data[item[mappingKey]] = item;
            });
            
            res.json({ success: true, data });
        } catch (error) {
            res.status(500).json({ error: 'Failed to fetch data' });
        }
    });
}
// {/fact}

// Example 15: Using user input to set properties in a custom object builder
// {fact rule=prototype-pollution@v1.0 defects=1}
function bad_case_15() {
    const app = express();
    
    app.post('/api/buildObject', (req, res) => {
        const properties = req.body.properties as Array<{key: string, value: any}>;
        const result = {};
        
        function buildObject(obj: any, props: Array<{key: string, value: any}>) {
            props.forEach(prop => {
                // ruleid: typescript-prototype-pollution-assignment
                obj[prop.key] = prop.value;
            });
            return obj;
        }
        
        const builtObject = buildObject(result, properties);
        res.json({ success: true, object: builtObject });
    });
}
// {/fact}

// True Negative Examples (Safe Code)

// Example 1: Validating user input before using as property name
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_1() {
    const app = express();
    
    app.get('/api/setProperty', (req, res) => {
        const obj = {};
        const key = req.query.key as string;
        const value = req.query.value;
        
        // Validate key to prevent prototype pollution
        // ok: typescript-prototype-pollution-assignment
        if (key && typeof key === 'string' && key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
            obj[key] = value;
        }
        
        res.json({ success: true, object: obj });
    });
}
// {/fact}

// Example 2: Using a whitelist of allowed property names
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_2() {
    const app = express();
    
    app.post('/api/updateUser', (req, res) => {
        const userData = {};
        const propertyName = req.body.property;
        const value = req.body.value;
        
        const allowedProperties = ['name', 'email', 'age', 'address'];
        
        // ok: typescript-prototype-pollution-assignment
        if (allowedProperties.includes(propertyName)) {
            userData[propertyName] = value;
        }
        
        res.json({ success: true, data: userData });
    });
}
// {/fact}

// Example 3: Using Object.create(null) to create objects without prototype
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_3() {
    const app = express();
    
    app.post('/api/mergeConfig', (req, res) => {
        // Create object with no prototype
        const config = Object.create(null);
        config.theme = 'light';
        
        const userConfig = req.body.config;
        
        for (const key in userConfig) {
            // ok: typescript-prototype-pollution-assignment
            config[key] = userConfig[key]; // Safe because config has no prototype
        }
        
        res.json({ success: true, config });
    });
}
// {/fact}

// Example 4: Using Map instead of plain objects
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_4() {
    const app = express();
    
    app.post('/api/batchUpdate', (req, res) => {
        const data = new Map();
        const updates = req.body.updates;
        
        updates.forEach((update: {key: string, value: any}) => {
            // ok: typescript-prototype-pollution-assignment
            data.set(update.key, update.value); // Safe because Map doesn't use prototype chain for properties
        });
        
        res.json({ success: true, data: Object.fromEntries(data) });
    });
}
// {/fact}

// Example 5: Using Object.hasOwn to check property existence
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_5() {
    const app = express();
    
    app.post('/api/updateSettings', (req, res) => {
        const settings = {};
        const source = req.body.settings;
        
        for (const key in source) {
            // ok: typescript-prototype-pollution-assignment
            if (Object.hasOwn(source, key) && key !== '__proto__' && key !== 'constructor') {
                settings[key] = source[key];
            }
        }
        
        res.json({ success: true, settings });
    });
}
// {/fact}

// Example 6: Using a custom sanitization function
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_6() {
    const app = express();
    
    app.post('/api/deepMerge', (req, res) => {
        const target = {};
        const source = req.body.data;
        
        function isSafeKey(key: string): boolean {
            return key !== '__proto__' && 
                   key !== 'constructor' && 
                   key !== 'prototype' &&
                   !key.startsWith('__');
        }
        
        function safeMerge(target: any, source: any) {
            for (const key in source) {
                // ok: typescript-prototype-pollution-assignment
                if (isSafeKey(key)) {
                    if (typeof source[key] === 'object' && source[key] !== null) {
                        if (!target[key]) target[key] = {};
                        safeMerge(target[key], source[key]);
                    } else {
                        target[key] = source[key];
                    }
                }
            }
        }
        
        safeMerge(target, source);
        res.json({ success: true, result: target });
    });
}
// {/fact}

// Example 7: Using Object.defineProperty with validated key
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_7() {
    const app = express();
    
    app.post('/api/defineProperty', (req, res) => {
        const obj = {};
        const key = req.body.key;
        const value = req.body.value;
        
        const dangerousProps = ['__proto__', 'constructor', 'prototype'];
        
        // ok: typescript-prototype-pollution-assignment
        if (typeof key === 'string' && !dangerousProps.includes(key)) {
            Object.defineProperty(obj, key, {
                value: value,
                writable: true,
                enumerable: true
            });
        }
        
        res.json({ success: true, object: obj });
    });
}
// {/fact}

// Example 8: Using a prefix for all user-supplied keys
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_8() {
    const app = express();
    
    app.get('/api/setFromUrl', (req, res) => {
        const obj = {};
        
        for (const param in req.query) {
            // ok: typescript-prototype-pollution-assignment
            obj[`user_${param}`] = req.query[param]; // Safe because of prefix
        }
        
        res.json({ success: true, object: obj });
    });
}
// {/fact}

// Example 9: Using predefined schema validation
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_9() {
    const app = express();
    
    app.post('/api/updateConfig', (req, res) => {
        const globalConfig: Record<string, any> = {};
        const { section, key, value } = req.body;
        
        // Define allowed sections and keys
        const allowedConfig: Record<string, string[]> = {
            'appearance': ['theme', 'fontSize', 'colorScheme'],
            'privacy': ['cookieConsent', 'dataSharing'],
            'notifications': ['email', 'push', 'sms']
        };
        
        // ok: typescript-prototype-pollution-assignment
        if (allowedConfig[section] && allowedConfig[section].includes(key)) {
            if (!globalConfig[section]) {
                globalConfig[section] = {};
            }
            globalConfig[section][key] = value;
        }
        
        res.json({ success: true, config: globalConfig });
    });
}
// {/fact}

// Example 10: Using JSON schema validation
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_10() {
    const app = express();
    
    app.post('/api/setNestedValue', (req, res) => {
        const data = {};
        const path = req.body.path as string;
        const value = req.body.value;
        
        // Validate path format
        const isValidPath = /^[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*$/.test(path);
        
        if (isValidPath) {
            function setValueAtPath(obj: any, path: string, value: any) {
                const keys = path.split('.');
                let current = obj;
                
                for (let i = 0; i < keys.length - 1; i++) {
                    const key = keys[i];
                    // ok: typescript-prototype-pollution-assignment
                    if (!current[key]) {
                        current[key] = {};
                    }
                    current = current[key];
                }
                
                current[keys[keys.length - 1]] = value;
            }
            
            setValueAtPath(data, path, value);
        }
        
        res.json({ success: true, data });
    });
}
// {/fact}

// Example 11: Using a safe object creation utility
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_11() {
    const app = express();
    
    app.post('/api/updateWithComputed', (req, res) => {
        function createSafeObject() {
            return Object.create(null);
        }
        
        const obj = createSafeObject();
        const prefix = req.body.prefix;
        const key = req.body.key;
        const value = req.body.value;
        
        // ok: typescript-prototype-pollution-assignment
        obj[`${prefix}_${key}`] = value; // Safe because obj has no prototype
        
        res.json({ success: true, object: obj });
    });
}
// {/fact}

// Example 12: Using Reflect.set with key validation
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_12() {
    const app = express();
    
    app.post('/api/reflectSet', (req, res) => {
        const obj = {};
        const key = req.body.key;
        const value = req.body.value;
        
        function isValidKey(k: string): boolean {
            const invalidKeys = ['__proto__', 'constructor', 'prototype'];
            return typeof k === 'string' && !invalidKeys.includes(k);
        }
        
        // ok: typescript-prototype-pollution-assignment
        if (isValidKey(key)) {
            Reflect.set(obj, key, value);
        }
        
        res.json({ success: true, object: obj });
    });
}
// {/fact}

// Example 13: Using a safe wrapper for object property assignment
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_13() {
    const app = express();
    
    app.get('/api/headerConfig', (req, res) => {
        const config = {};
        const headerKey = req.headers['x-config-key'] as string;
        const headerValue = req.headers['x-config-value'];
        
        function safeAssign(obj: any, key: string, value: any): void {
            if (key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
                obj[key] = value;
            }
        }
        
        if (headerKey && headerValue) {
            // ok: typescript-prototype-pollution-assignment
            safeAssign(config, headerKey, headerValue);
        }
        
        res.json({ success: true, config });
    });
}
// {/fact}

// Example 14: Using a safe data mapper for external API data
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_14() {
    const app = express();
    
    app.post('/api/externalData', async (req, res) => {
        try {
            const externalApiUrl = req.body.apiUrl;
            const response = await axios.get(externalApiUrl);
            const data = {};
            
            const mappingKey = req.body.mappingKey;
            const safeKeys: string[] = [];
            
            // First pass: collect and validate keys
            response.data.items.forEach((item: any) => {
                const key = item[mappingKey];
                if (typeof key === 'string' && 
                    key !== '__proto__' && 
                    key !== 'constructor' && 
                    key !== 'prototype') {
                    safeKeys.push(key);
                }
            });
            
            // Second pass: safely assign values
            response.data.items.forEach((item: any) => {
                const key = item[mappingKey];
                // ok: typescript-prototype-pollution-assignment
                if (safeKeys.includes(key)) {
                    data[key] = item;
                }
            });
            
            res.json({ success: true, data });
        } catch (error) {
            res.status(500).json({ error: 'Failed to fetch data' });
        }
    });
}
// {/fact}

// Example 15: Using TypeScript interfaces and property validation
// {fact rule=prototype-pollution@v1.0 defects=0}
function good_case_15() {
    const app = express();
    
    interface PropertyDefinition {
        key: string;
        value: any;
    }
    
    interface SafeObject {
        [key: string]: any;
    }
    
    app.post('/api/buildObject', (req, res) => {
        const properties = req.body.properties as PropertyDefinition[];
        const result: SafeObject = {};
        
        function isSafeProperty(prop: PropertyDefinition): boolean {
            return typeof prop.key === 'string' && 
                   !['__proto__', 'constructor', 'prototype'].includes(prop.key);
        }
        
        function buildSafeObject(obj: SafeObject, props: PropertyDefinition[]): SafeObject {
            props.filter(isSafeProperty).forEach(prop => {
                // ok: typescript-prototype-pollution-assignment
                obj[prop.key] = prop.value;
            });
            return obj;
        }
        
        const builtObject = buildSafeObject(result, properties);
        res.json({ success: true, object: builtObject });
    });
}
// {/fact}