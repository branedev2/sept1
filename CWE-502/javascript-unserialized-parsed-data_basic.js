// Demonstrating vulnerable and safe uses of JSON.parse() with user input
const express = require('express');
const app = express();
const fs = require('fs');
const axios = require('axios');
const bodyParser = require('body-parser');
const crypto = require('crypto');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// TRUE POSITIVES - Vulnerable code examples

// Example 1: Parsing JSON from query parameters
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_1(req, res) {
    const userInput = req.query.data;
    try {
        // ruleid: javascript-unserialized-parsed-data
        const parsedData = JSON.parse(userInput);
        res.json({ success: true, data: parsedData });
    } catch (e) {
        res.status(400).json({ error: 'Invalid JSON' });
    }
}
// {/fact}

// Example 2: Parsing JSON from request body
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_2(req, res) {
    const userInput = req.body.jsonData;
    try {
        // ruleid: javascript-unserialized-parsed-data
        const userData = JSON.parse(userInput);
        const username = userData.username;
        res.send(`Hello, ${username}!`);
    } catch (e) {
        res.status(400).send('Invalid JSON format');
    }
}
// {/fact}

// Example 3: Parsing JSON from cookies
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_3(req, res) {
    const userPrefs = req.cookies.preferences;
    try {
        // ruleid: javascript-unserialized-parsed-data
        const preferences = JSON.parse(userPrefs);
        res.render('dashboard', { theme: preferences.theme });
    } catch (e) {
        res.status(400).send('Invalid preferences format');
    }
}
// {/fact}

// Example 4: Parsing JSON from headers
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_4(req, res) {
    const metadataHeader = req.headers['x-user-metadata'];
    if (metadataHeader) {
        try {
            // ruleid: javascript-unserialized-parsed-data
            const metadata = JSON.parse(metadataHeader);
            req.userMetadata = metadata;
            next();
        } catch (e) {
            res.status(400).send('Invalid metadata format');
        }
    } else {
        next();
    }
}
// {/fact}

// Example 5: Parsing JSON from URL path parameter
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_5(req, res) {
    const encodedData = req.params.encodedJson;
    const decodedData = decodeURIComponent(encodedData);
    try {
        // ruleid: javascript-unserialized-parsed-data
        const parsedData = JSON.parse(decodedData);
        res.json({ processed: true, data: parsedData });
    } catch (e) {
        res.status(400).send('Could not parse JSON data');
    }
}
// {/fact}

// Example 6: Parsing JSON from form data
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_6(req, res) {
    const formJson = req.body.jsonField;
    try {
        // ruleid: javascript-unserialized-parsed-data
        const config = JSON.parse(formJson);
        applyConfiguration(config);
        res.send('Configuration applied');
    } catch (e) {
        res.status(400).send('Invalid configuration format');
    }
}
// {/fact}

// Example 7: Parsing JSON with variable assignment before parsing
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_7(req, res) {
    let dataString = req.query.settings;
    dataString = dataString.trim();
    try {
        // ruleid: javascript-unserialized-parsed-data
        const settings = JSON.parse(dataString);
        updateUserSettings(settings);
        res.send('Settings updated');
    } catch (e) {
        res.status(400).send('Invalid settings format');
    }
}
// {/fact}

// Example 8: Parsing JSON inside a promise chain
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_8(req, res) {
    const userDataPromise = Promise.resolve(req.body.userData);
    
    userDataPromise
        .then(data => {
            // ruleid: javascript-unserialized-parsed-data
            return JSON.parse(data);
        })
        .then(parsedData => {
            res.json({ success: true, user: parsedData });
        })
        .catch(err => {
            res.status(400).send('Error processing user data');
        });
}
// {/fact}

// Example 9: Parsing JSON in an async function
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
async function bad_case_9(req, res) {
    try {
        const inputData = req.query.jsonData;
        // ruleid: javascript-unserialized-parsed-data
        const parsedData = JSON.parse(inputData);
        const result = await processUserData(parsedData);
        res.json(result);
    } catch (e) {
        res.status(400).send('Error processing data');
    }
}
// {/fact}

// Example 10: Parsing JSON with string concatenation
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_10(req, res) {
    const partialJson = req.query.partialData;
    const fullJson = '{"prefix":' + partialJson + '}';
    try {
        // ruleid: javascript-unserialized-parsed-data
        const data = JSON.parse(fullJson);
        res.json({ processed: data });
    } catch (e) {
        res.status(400).send('Invalid JSON structure');
    }
}
// {/fact}

// Example 11: Parsing JSON from WebSocket message
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_11(ws, req) {
    ws.on('message', (message) => {
        try {
            // ruleid: javascript-unserialized-parsed-data
            const messageData = JSON.parse(message);
            handleWebSocketCommand(messageData, ws);
        } catch (e) {
            ws.send(JSON.stringify({ error: 'Invalid message format' }));
        }
    });
}
// {/fact}

// Example 12: Parsing JSON from file upload content
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_12(req, res) {
    const fileContent = req.files.configFile.data.toString('utf8');
    try {
        // ruleid: javascript-unserialized-parsed-data
        const config = JSON.parse(fileContent);
        applySystemConfig(config);
        res.send('Configuration uploaded successfully');
    } catch (e) {
        res.status(400).send('Invalid configuration file');
    }
}
// {/fact}

// Example 13: Parsing JSON with template literals
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_13(req, res) {
    const userInput = req.query.data;
    const jsonString = `{"userProvided": ${userInput}}`;
    try {
        // ruleid: javascript-unserialized-parsed-data
        const parsedData = JSON.parse(jsonString);
        res.json({ success: true, data: parsedData });
    } catch (e) {
        res.status(400).json({ error: 'Invalid input' });
    }
}
// {/fact}

// Example 14: Parsing JSON from base64 encoded request parameter
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_14(req, res) {
    const base64Data = req.query.encodedData;
    const decodedString = Buffer.from(base64Data, 'base64').toString('utf8');
    try {
        // ruleid: javascript-unserialized-parsed-data
        const parsedData = JSON.parse(decodedString);
        res.json({ success: true, data: parsedData });
    } catch (e) {
        res.status(400).send('Invalid encoded data');
    }
}
// {/fact}

// Example 15: Parsing JSON from URL fragment via client-side code sent to server
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=1}
function bad_case_15(req, res) {
    const fragmentData = req.body.fragmentData; // Sent from client-side
    try {
        // ruleid: javascript-unserialized-parsed-data
        const parsedFragment = JSON.parse(fragmentData);
        saveUserPreferences(parsedFragment);
        res.send('Preferences saved');
    } catch (e) {
        res.status(400).send('Invalid preference data');
    }
}
// {/fact}

// TRUE NEGATIVES - Safe code examples

// Example 1: Using JSON schema validation before parsing
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_1(req, res) {
    const userInput = req.query.data;
    const Ajv = require('ajv');
    const ajv = new Ajv();
    
    const schema = {
        type: "object",
        properties: {
            name: { type: "string" },
            age: { type: "number" }
        },
        required: ["name", "age"],
        additionalProperties: false
    };
    
    try {
        // First validate the JSON string format
        if (!/^[\],:{}\s]*$/.test(userInput.replace(/\\["\\\/bfnrtu]/g, '@')
            .replace(/"[^"\\\n\r]*"|true|false|null|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?/g, ']')
            .replace(/(?:^|:|,)(?:\s*\[)+/g, ''))) {
            throw new Error("Invalid JSON format");
        }
        
        // ok: javascript-unserialized-parsed-data
        const parsedData = JSON.parse(userInput);
        
        // Validate against schema
        const valid = ajv.validate(schema, parsedData);
        if (!valid) {
            throw new Error("Schema validation failed");
        }
        
        res.json({ success: true, data: parsedData });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
}
// {/fact}

// Example 2: Using a safe parsing library
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_2(req, res) {
    const userInput = req.body.jsonData;
    
    // Using a hypothetical safe JSON parsing library that prevents prototype pollution
    const safeJson = require('safe-json-parse');
    
    try {
        // ok: javascript-unserialized-parsed-data
        safeJson.parse(userInput, (err, data) => {
            if (err) {
                res.status(400).send('Invalid JSON format');
                return;
            }
            res.send(`Hello, ${data.username}!`);
        });
    } catch (e) {
        res.status(400).send('Error processing input');
    }
}
// {/fact}

// Example 3: Using JSON.parse with known safe data
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_3(req, res) {
    // Using hardcoded or server-generated JSON, not user input
    const safeJsonString = '{"theme":"dark","fontSize":14}';
    try {
        // ok: javascript-unserialized-parsed-data
        const preferences = JSON.parse(safeJsonString);
        res.render('dashboard', { theme: preferences.theme });
    } catch (e) {
        res.status(500).send('Server configuration error');
    }
}
// {/fact}

// Example 4: Using JSON.parse with server-side configuration
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_4(req, res) {
    // Reading from a server-side configuration file, not user input
    fs.readFile('./config.json', 'utf8', (err, data) => {
        if (err) {
            res.status(500).send('Error reading configuration');
            return;
        }
        
        try {
            // ok: javascript-unserialized-parsed-data
            const config = JSON.parse(data);
            res.json({ serverConfig: config.publicSettings });
        } catch (e) {
            res.status(500).send('Invalid server configuration');
        }
    });
}
// {/fact}

// Example 5: Using JSON.parse with environment variables
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_5(req, res) {
    // Using environment variables, not user input
    const configJson = process.env.APP_CONFIG;
    try {
        // ok: javascript-unserialized-parsed-data
        const config = JSON.parse(configJson);
        res.json({ appName: config.name, version: config.version });
    } catch (e) {
        res.status(500).send('Invalid environment configuration');
    }
}
// {/fact}

// Example 6: Using reviver function with JSON.parse for sanitization
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_6(req, res) {
    const userInput = req.body.jsonField;
    
    // Define a reviver function that sanitizes the parsed values
    function sanitizingReviver(key, value) {
        // Only allow strings and numbers, convert everything else to null
        if (typeof value === 'string') {
            // Sanitize strings
            return value.replace(/[<>]/g, '');
        } else if (typeof value === 'number') {
            return value;
        } else if (Array.isArray(value)) {
            return value;
        } else if (value === null) {
            return null;
        } else if (typeof value === 'object') {
            return value;
        }
        return null;
    }
    
    try {
        // ok: javascript-unserialized-parsed-data
        const sanitizedData = JSON.parse(userInput, sanitizingReviver);
        res.json({ processed: true, data: sanitizedData });
    } catch (e) {
        res.status(400).send('Invalid JSON format');
    }
}
// {/fact}

// Example 7: Using JSON.parse with server-generated data
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_7(req, res) {
    // Generate safe JSON on the server side
    const userId = req.session.userId; // From authenticated session
    const timestamp = Date.now();
    const serverGeneratedJson = `{"userId":${userId},"timestamp":${timestamp}}`;
    
    try {
        // ok: javascript-unserialized-parsed-data
        const data = JSON.parse(serverGeneratedJson);
        res.json({ userData: data });
    } catch (e) {
        res.status(500).send('Server error');
    }
}
// {/fact}

// Example 8: Using JSON.parse with data from trusted API
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_8(req, res) {
    // Fetch data from a trusted internal API
    axios.get('https://internal-api.company.com/config')
        .then(response => {
            // ok: javascript-unserialized-parsed-data
            const config = JSON.parse(response.data);
            res.json({ apiConfig: config });
        })
        .catch(error => {
            res.status(500).send('Error fetching configuration');
        });
}
// {/fact}

// Example 9: Using JSON.parse with whitelisted values
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_9(req, res) {
    const userTheme = req.query.theme;
    
    // Whitelist of allowed themes
    const allowedThemes = ['light', 'dark', 'blue', 'high-contrast'];
    
    if (!allowedThemes.includes(userTheme)) {
        res.status(400).send('Invalid theme selection');
        return;
    }
    
    // Construct JSON with validated input
    const safeJson = `{"theme":"${userTheme}"}`;
    
    try {
        // ok: javascript-unserialized-parsed-data
        const preferences = JSON.parse(safeJson);
        res.render('dashboard', { theme: preferences.theme });
    } catch (e) {
        res.status(500).send('Server error');
    }
}
// {/fact}

// Example 10: Using JSON.parse with database-retrieved data
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_10(req, res) {
    const db = require('./database'); // Hypothetical database module
    
    // Get data from database, not user input
    db.getConfigById(1)
        .then(configData => {
            try {
                // ok: javascript-unserialized-parsed-data
                const config = JSON.parse(configData.jsonValue);
                res.json({ dbConfig: config });
            } catch (e) {
                res.status(500).send('Invalid database configuration');
            }
        })
        .catch(err => {
            res.status(500).send('Database error');
        });
}
// {/fact}

// Example 11: Using JSON.parse with cryptographically signed data
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_11(req, res) {
    const signedData = req.body.signedData;
    const signature = req.body.signature;
    
    // Verify the signature
    const publicKey = fs.readFileSync('./public_key.pem');
    const verify = crypto.createVerify('SHA256');
    verify.update(signedData);
    const isValid = verify.verify(publicKey, signature, 'base64');
    
    if (isValid) {
        try {
            // ok: javascript-unserialized-parsed-data
            const data = JSON.parse(signedData);
            res.json({ verified: true, data: data });
        } catch (e) {
            res.status(400).send('Invalid JSON format');
        }
    } else {
        res.status(401).send('Invalid signature');
    }
}
// {/fact}

// Example 12: Using JSON.parse with numeric validation
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_12(req, res) {
    let userValue = req.query.value;
    
    // Validate that the input is a number
    if (!/^\d+$/.test(userValue)) {
        res.status(400).send('Input must be a number');
        return;
    }
    
    // Convert to number and create safe JSON
    userValue = parseInt(userValue, 10);
    const safeJson = `{"value":${userValue}}`;
    
    try {
        // ok: javascript-unserialized-parsed-data
        const data = JSON.parse(safeJson);
        res.json({ processedValue: data.value * 2 });
    } catch (e) {
        res.status(500).send('Server error');
    }
}
// {/fact}

// Example 13: Using JSON.parse with constant data
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_13(req, res) {
    // Using constant data, not user input
    const PRODUCT_CATEGORIES = '[{"id":1,"name":"Electronics"},{"id":2,"name":"Books"}]';
    
    try {
        // ok: javascript-unserialized-parsed-data
        const categories = JSON.parse(PRODUCT_CATEGORIES);
        res.json({ categories: categories });
    } catch (e) {
        res.status(500).send('Server configuration error');
    }
}
// {/fact}

// Example 14: Using JSON.parse with Object.freeze to prevent prototype pollution
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_14(req, res) {
    const userInput = req.body.data;
    
    try {
        // Parse the JSON
        // ok: javascript-unserialized-parsed-data
        const parsedData = JSON.parse(userInput);
        
        // Freeze the object to prevent modifications
        Object.freeze(parsedData);
        
        // Additional validation
        if (typeof parsedData !== 'object' || Array.isArray(parsedData)) {
            throw new Error('Expected an object');
        }
        
        // Check for allowed properties only
        const allowedProps = ['name', 'email', 'age'];
        const hasInvalidProps = Object.keys(parsedData).some(key => !allowedProps.includes(key));
        
        if (hasInvalidProps) {
            throw new Error('Object contains invalid properties');
        }
        
        res.json({ valid: true, data: parsedData });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
}
// {/fact}

// Example 15: Using JSON.parse with strict type checking
// {fact rule=object-input-stream-insecure-deserialization@v1.0 defects=0}
function good_case_15(req, res) {
    const userInput = req.query.config;
    
    try {
        // ok: javascript-unserialized-parsed-data
        const config = JSON.parse(userInput);
        
        // Perform strict type checking
        if (typeof config !== 'object' || config === null || Array.isArray(config)) {
            throw new Error('Expected a non-null object');
        }
        
        if (typeof config.name !== 'string' || config.name.length > 50) {
            throw new Error('Invalid name property');
        }
        
        if (typeof config.enabled !== 'boolean') {
            throw new Error('Enabled must be a boolean');
        }
        
        if (typeof config.count !== 'number' || isNaN(config.count) || config.count < 0) {
            throw new Error('Count must be a non-negative number');
        }
        
        res.json({ valid: true, config: config });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});