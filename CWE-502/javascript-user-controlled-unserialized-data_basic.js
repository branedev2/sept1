// Import necessary modules
const express = require('express');
const bodyParser = require('body-parser');
const jsYaml = require('js-yaml');
const serialize = require('serialize-javascript');
const yaml = require('yaml');
const BSON = require('bson');
const msgpack = require('msgpack');
const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// TRUE POSITIVES - Vulnerable code examples

// Example 1: Using js-yaml.load with user input from query parameter
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_1(req, res) {
    const userInput = req.query.data;
    try {
        // ruleid: javascript-user-controlled-unserialized-data
        const parsedData = jsYaml.load(userInput);
        res.json({ result: parsedData });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}
// {/fact}

// Example 2: Using js-yaml.load with user input from request body
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_2(req, res) {
    const userInput = req.body.yamlData;
    try {
        // ruleid: javascript-user-controlled-unserialized-data
        const parsedData = jsYaml.load(userInput, { schema: jsYaml.DEFAULT_SCHEMA });
        res.json({ success: true, data: parsedData });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
}
// {/fact}

// Example 3: Using eval-based deserialization with user input
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_3(req, res) {
    const serializedData = req.body.serialized;
    try {
        // ruleid: javascript-user-controlled-unserialized-data
        const obj = eval('(' + serializedData + ')');
        res.json({ result: obj });
    } catch (error) {
        res.status(400).json({ error: 'Invalid data format' });
    }
}
// {/fact}

// Example 4: Using JSON.parse with user input and Function constructor
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_4(req, res) {
    const userInput = req.query.jsonData;
    try {
        const data = JSON.parse(userInput);
        if (data.code) {
            // ruleid: javascript-user-controlled-unserialized-data
            const dynamicFunction = new Function(data.code);
            const result = dynamicFunction();
            res.json({ output: result });
        }
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}
// {/fact}

// Example 5: Using YAML.parse with user input from headers
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_5(req, res) {
    const yamlData = req.headers['x-yaml-data'];
    try {
        // ruleid: javascript-user-controlled-unserialized-data
        const parsedData = yaml.parse(yamlData);
        res.json({ result: parsedData });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}
// {/fact}

// Example 6: Using BSON deserialize with user input
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_6(req, res) {
    const bsonData = Buffer.from(req.body.bsonData, 'base64');
    try {
        // ruleid: javascript-user-controlled-unserialized-data
        const deserializedData = BSON.deserialize(bsonData);
        res.json({ result: deserializedData });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}
// {/fact}

// Example 7: Using msgpack decode with user input
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_7(req, res) {
    const packedData = Buffer.from(req.body.packedData, 'base64');
    try {
        // ruleid: javascript-user-controlled-unserialized-data
        const unpackedData = msgpack.decode(packedData);
        res.json({ result: unpackedData });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}
// {/fact}

// Example 8: Using js-yaml.safeLoad with user input and unsafe options
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_8(req, res) {
    const userInput = req.query.config;
    try {
        // ruleid: javascript-user-controlled-unserialized-data
        const config = jsYaml.load(userInput, { schema: jsYaml.DEFAULT_FULL_SCHEMA });
        res.json({ config });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}
// {/fact}

// Example 9: Using js-yaml.load with user input from cookies
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_9(req, res) {
    const yamlData = req.cookies.userData;
    try {
        // ruleid: javascript-user-controlled-unserialized-data
        const userData = jsYaml.load(yamlData);
        res.json({ user: userData });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}
// {/fact}

// Example 10: Using custom deserialization function with user input
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_10(req, res) {
    const serializedData = req.body.data;
    
    function customDeserialize(data) {
        // ruleid: javascript-user-controlled-unserialized-data
        return eval('(' + data + ')');
    }
    
    try {
        const result = customDeserialize(serializedData);
        res.json({ result });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}
// {/fact}

// Example 11: Using js-yaml.load with user input in a complex flow
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_11(req, res) {
    const userConfig = req.body.config;
    let configData;
    
    if (userConfig && typeof userConfig === 'string') {
        try {
            // ruleid: javascript-user-controlled-unserialized-data
            configData = jsYaml.load(userConfig);
            if (configData.debug) {
                console.log('Debug mode enabled');
            }
            res.json({ success: true, config: configData });
        } catch (error) {
            res.status(400).json({ error: 'Invalid configuration format' });
        }
    } else {
        res.status(400).json({ error: 'Configuration data required' });
    }
}
// {/fact}

// Example 12: Using js-yaml.load with user input from URL parameters
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_12(req, res) {
    const encodedYaml = req.params.config;
    const decodedYaml = Buffer.from(encodedYaml, 'base64').toString('utf-8');
    
    try {
        // ruleid: javascript-user-controlled-unserialized-data
        const config = jsYaml.load(decodedYaml);
        res.json({ success: true, config });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}
// {/fact}

// Example 13: Using js-yaml.load with user input in an async function
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
async function bad_case_13(req, res) {
    const yamlUrl = req.query.yamlUrl;
    
    try {
        const response = await axios.get(yamlUrl);
        const yamlContent = response.data;
        
        // ruleid: javascript-user-controlled-unserialized-data
        const parsedData = jsYaml.load(yamlContent);
        res.json({ result: parsedData });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
}
// {/fact}

// Example 14: Using js-yaml.load with user input in a conditional block
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_14(req, res) {
    const format = req.query.format;
    const data = req.body.data;
    
    if (format === 'yaml') {
        try {
            // ruleid: javascript-user-controlled-unserialized-data
            const parsedData = jsYaml.load(data);
            res.json({ result: parsedData });
        } catch (error) {
            res.status(400).json({ error: 'Invalid YAML format' });
        }
    } else {
        res.status(400).json({ error: 'Unsupported format' });
    }
}
// {/fact}

// Example 15: Using js-yaml.load with user input in a loop
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_15(req, res) {
    const yamlDocuments = req.body.documents || [];
    const results = [];
    
    for (let i = 0; i < yamlDocuments.length; i++) {
        try {
            // ruleid: javascript-user-controlled-unserialized-data
            const parsedDoc = jsYaml.load(yamlDocuments[i]);
            results.push(parsedDoc);
        } catch (error) {
            results.push({ error: `Document ${i}: ${error.message}` });
        }
    }
    
    res.json({ results });
}
// {/fact}

// TRUE NEGATIVES - Safe code examples

// Example 1: Using js-yaml.load with hardcoded data
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_1(req, res) {
    const yamlData = `
    name: John Doe
    age: 30
    roles:
      - user
      - admin
    `;
    
    try {
        // ok: javascript-user-controlled-unserialized-data
        const parsedData = jsYaml.load(yamlData);
        res.json({ result: parsedData });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
}
// {/fact}

// Example 2: Using js-yaml.safeLoad instead of load for user input
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_2(req, res) {
    const userInput = req.body.yamlData;
    try {
        // ok: javascript-user-controlled-unserialized-data
        const parsedData = jsYaml.safeLoad(userInput);
        res.json({ success: true, data: parsedData });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
}
// {/fact}

// Example 3: Using JSON.parse for safe deserialization
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_3(req, res) {
    const jsonData = req.body.jsonData;
    try {
        // ok: javascript-user-controlled-unserialized-data
        const parsedData = JSON.parse(jsonData);
        res.json({ result: parsedData });
    } catch (error) {
        res.status(400).json({ error: 'Invalid JSON format' });
    }
}
// {/fact}

// Example 4: Using js-yaml with schema validation for user input
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_4(req, res) {
    const userInput = req.body.yamlData;
    
    // Define a restricted schema
    const restrictedSchema = jsYaml.Schema.create([
        new jsYaml.Type('!custom', {
            kind: 'scalar',
            construct: function(data) {
                return data;
            }
        })
    ]);
    
    try {
        // ok: javascript-user-controlled-unserialized-data
        const parsedData = jsYaml.load(userInput, { schema: restrictedSchema });
        res.json({ result: parsedData });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}
// {/fact}

// Example 5: Using a whitelist approach for YAML deserialization
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_5(req, res) {
    const userInput = req.body.yamlData;
    
    try {
        // Parse with safe schema first
        // ok: javascript-user-controlled-unserialized-data
        const parsedData = jsYaml.safeLoad(userInput);
        
        // Validate the structure against a whitelist
        const validatedData = validateYamlStructure(parsedData);
        res.json({ result: validatedData });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}
// {/fact}

function validateYamlStructure(data) {
    // Only allow specific fields and types
    const allowedStructure = {
        name: String,
        age: Number,
        email: String,
        preferences: Object
    };
    
    const validated = {};
    
    for (const key in allowedStructure) {
        if (data[key] !== undefined && data[key].constructor === allowedStructure[key]) {
            validated[key] = data[key];
        }
    }
    
    return validated;
}

// Example 6: Using js-yaml.load with trusted data from a secure source
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_6(req, res) {
    // Data from a trusted configuration file
    const configPath = './config/app-config.yaml';
    
    try {
        const yamlData = fs.readFileSync(configPath, 'utf8');
        // ok: javascript-user-controlled-unserialized-data
        const config = jsYaml.load(yamlData);
        res.json({ config });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
}
// {/fact}

// Example 7: Using a custom safe deserialization function
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_7(req, res) {
    const userInput = req.body.data;
    
    function safeDeserialize(input) {
        // ok: javascript-user-controlled-unserialized-data
        return JSON.parse(input);
    }
    
    try {
        const result = safeDeserialize(userInput);
        res.json({ result });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}
// {/fact}

// Example 8: Using js-yaml with input validation
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_8(req, res) {
    const userInput = req.body.yamlData;
    
    // Validate input format before processing
    if (!isValidYamlFormat(userInput)) {
        return res.status(400).json({ error: 'Invalid YAML format' });
    }
    
    try {
        // ok: javascript-user-controlled-unserialized-data
        const parsedData = jsYaml.safeLoad(userInput);
        res.json({ result: parsedData });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}
// {/fact}

function isValidYamlFormat(input) {
    // Basic validation to ensure input is a string and doesn't contain suspicious patterns
    if (typeof input !== 'string') return false;
    
    // Check for potentially dangerous patterns
    const dangerousPatterns = [
        '!!js/function',
        '!!js/regexp',
        '!!js/undefined',
        '!!python/object',
        '!!perl/code'
    ];
    
    return !dangerousPatterns.some(pattern => input.includes(pattern));
}

// Example 9: Using a sanitization function before deserialization
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_9(req, res) {
    let userInput = req.body.yamlData;
    
    // Sanitize the input
    userInput = sanitizeYamlInput(userInput);
    
    try {
        // ok: javascript-user-controlled-unserialized-data
        const parsedData = jsYaml.safeLoad(userInput);
        res.json({ result: parsedData });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}
// {/fact}

function sanitizeYamlInput(input) {
    if (typeof input !== 'string') return '';
    
    // Remove potentially dangerous tags
    return input.replace(/!!\w+\/\w+/g, '');
}

// Example 10: Using js-yaml with content verification
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_10(req, res) {
    const userInput = req.body.yamlData;
    
    try {
        // Parse with safe schema
        // ok: javascript-user-controlled-unserialized-data
        const parsedData = jsYaml.safeLoad(userInput);
        
        // Verify the content structure
        if (!isValidUserConfig(parsedData)) {
            return res.status(400).json({ error: 'Invalid configuration structure' });
        }
        
        res.json({ result: parsedData });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}
// {/fact}

function isValidUserConfig(config) {
    // Check if the config has the expected structure
    return (
        config &&
        typeof config === 'object' &&
        typeof config.name === 'string' &&
        Array.isArray(config.permissions)
    );
}

// Example 11: Using JSON.parse with reviver function for safe deserialization
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_11(req, res) {
    const jsonData = req.body.jsonData;
    
    try {
        // ok: javascript-user-controlled-unserialized-data
        const parsedData = JSON.parse(jsonData, (key, value) => {
            // Prevent prototype pollution
            if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
                return undefined;
            }
            return value;
        });
        
        res.json({ result: parsedData });
    } catch (error) {
        res.status(400).json({ error: 'Invalid JSON format' });
    }
}
// {/fact}

// Example 12: Using js-yaml with type checking after deserialization
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_12(req, res) {
    const userInput = req.body.yamlData;
    
    try {
        // ok: javascript-user-controlled-unserialized-data
        const parsedData = jsYaml.safeLoad(userInput);
        
        // Type checking to prevent unexpected behavior
        const validatedData = {};
        
        if (parsedData && typeof parsedData === 'object') {
            if (typeof parsedData.name === 'string') {
                validatedData.name = parsedData.name;
            }
            
            if (typeof parsedData.age === 'number') {
                validatedData.age = parsedData.age;
            }
            
            if (Array.isArray(parsedData.interests)) {
                validatedData.interests = parsedData.interests.filter(item => typeof item === 'string');
            }
        }
        
        res.json({ result: validatedData });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}
// {/fact}

// Example 13: Using a secure configuration approach
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_13(req, res) {
    // Get the environment name from a request parameter
    const env = req.query.environment || 'development';
    
    // Only allow specific environment names
    const allowedEnvironments = ['development', 'testing', 'production'];
    
    if (!allowedEnvironments.includes(env)) {
        return res.status(400).json({ error: 'Invalid environment' });
    }
    
    try {
        // Load configuration from a trusted file based on environment
        const configPath = `./config/${env}.yaml`;
        const yamlData = fs.readFileSync(configPath, 'utf8');
        
        // ok: javascript-user-controlled-unserialized-data
        const config = jsYaml.load(yamlData);
        res.json({ config });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
}
// {/fact}

// Example 14: Using js-yaml with input length validation
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_14(req, res) {
    const userInput = req.body.yamlData;
    
    // Validate input length to prevent DoS attacks
    if (typeof userInput !== 'string' || userInput.length > 10000) {
        return res.status(400).json({ error: 'Input too large or invalid format' });
    }
    
    try {
        // ok: javascript-user-controlled-unserialized-data
        const parsedData = jsYaml.safeLoad(userInput);
        res.json({ result: parsedData });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}
// {/fact}

// Example 15: Using a schema validation library before deserialization
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_15(req, res) {
    const userInput = req.body.yamlData;
    
    try {
        // First parse with safe schema
        // ok: javascript-user-controlled-unserialized-data
        const parsedData = jsYaml.safeLoad(userInput);
        
        // Validate against a schema (simplified example)
        const validationResult = validateSchema(parsedData);
        
        if (!validationResult.valid) {
            return res.status(400).json({ error: validationResult.errors });
        }
        
        res.json({ result: parsedData });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
}
// {/fact}

function validateSchema(data) {
    // Simple schema validation (in a real app, use a library like Joi or Ajv)
    const errors = [];
    
    if (!data || typeof data !== 'object') {
        return { valid: false, errors: ['Data must be an object'] };
    }
    
    if (typeof data.name !== 'string') {
        errors.push('name must be a string');
    }
    
    if (typeof data.version !== 'string') {
        errors.push('version must be a string');
    }
    
    if (!Array.isArray(data.features)) {
        errors.push('features must be an array');
    }
    
    return {
        valid: errors.length === 0,
        errors
    };
}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});