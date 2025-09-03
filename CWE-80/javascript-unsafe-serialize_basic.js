// Import required modules
const express = require('express');
const serialize = require('serialize-javascript');
const app = express();
app.use(express.json());

// BAD CASES - Vulnerable code examples

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_1(req, res) {
    const userData = req.query.user;
    // ruleid: javascript-unsafe-serialize
    const serialized = serialize(userData, { unsafe: true });
    res.send(`<script>var userInfo = ${serialized};</script>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_2(req, res) {
    const userInput = req.body.data;
    // ruleid: javascript-unsafe-serialize
    const serializedData = serialize(userInput, { unsafe: true });
    res.render('template', { data: serializedData });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_3(req, res) {
    const userProfile = {
        name: req.query.name,
        id: req.query.id,
        preferences: JSON.parse(req.query.prefs || '{}')
    };
    // ruleid: javascript-unsafe-serialize
    const serialized = serialize(userProfile, { unsafe: true });
    res.send(`<div data-user='${serialized}'></div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_4(req, res) {
    const options = { unsafe: true, space: 2 };
    const userData = req.params.id;
    // ruleid: javascript-unsafe-serialize
    res.send(`<script>window.USER = ${serialize(userData, options)};</script>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_5(req, res) {
    const headerData = req.headers['x-custom-data'];
    // ruleid: javascript-unsafe-serialize
    const serialized = serialize(headerData, { unsafe: true });
    res.send(`<script>var adminData = ${serialized};</script>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_6(req, res) {
    const cookieValue = req.cookies.userSettings;
    // ruleid: javascript-unsafe-serialize
    const serialized = serialize(JSON.parse(cookieValue), { unsafe: true });
    res.send(`<script>var settings = ${serialized};</script>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_7(req, res) {
    let unsafe = true;
    const userData = req.body;
    // ruleid: javascript-unsafe-serialize
    const serialized = serialize(userData, { unsafe });
    res.send(`<script>var userData = ${serialized};</script>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_8(req, res) {
    const config = {
        unsafe: true,
        space: 4
    };
    const userInput = req.query.config;
    // ruleid: javascript-unsafe-serialize
    const serialized = serialize(userInput, config);
    res.send(`<script>var appConfig = ${serialized};</script>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_9(req, res) {
    const formData = req.body.formData;
    const serializeOptions = { unsafe: true };
    
    // ruleid: javascript-unsafe-serialize
    const serializedForm = serialize(formData, serializeOptions);
    res.send(`
        <div id="form-data" data-content='${serializedForm}'></div>
        <script>initForm()</script>
    `);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_10(req, res) {
    const searchParams = new URLSearchParams(req.url.split('?')[1]);
    const queryData = {};
    for (const [key, value] of searchParams) {
        queryData[key] = value;
    }
    
    // ruleid: javascript-unsafe-serialize
    const serialized = serialize(queryData, { unsafe: true });
    res.send(`<script>var searchData = ${serialized};</script>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_11(req, res) {
    const userFiles = req.files.map(file => ({
        name: file.originalname,
        size: file.size,
        type: file.mimetype
    }));
    
    // ruleid: javascript-unsafe-serialize
    const serializedFiles = serialize(userFiles, { unsafe: true });
    res.send(`<script>var uploadedFiles = ${serializedFiles};</script>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_12(req, res) {
    // Dynamic options based on environment
    const options = { 
        unsafe: process.env.NODE_ENV === 'development',
        space: 2
    };
    
    // In development mode, this will be unsafe
    if (options.unsafe) {
        const userData = req.body.user;
        // ruleid: javascript-unsafe-serialize
        const serialized = serialize(userData, options);
        res.send(`<script>var debugUser = ${serialized};</script>`);
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_13(req, res) {
    const userInput = req.query.data;
    let serializeOptions;
    
    if (req.query.pretty === 'true') {
        serializeOptions = { unsafe: true, space: 2 };
    } else {
        serializeOptions = { unsafe: true };
    }
    
    // ruleid: javascript-unsafe-serialize
    const serialized = serialize(userInput, serializeOptions);
    res.send(`<script>var inputData = ${serialized};</script>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_14(req, res) {
    function processUserData(data) {
        // ruleid: javascript-unsafe-serialize
        return serialize(data, { unsafe: true });
    }
    
    const userData = req.body;
    const serialized = processUserData(userData);
    res.send(`<script>var processedData = ${serialized};</script>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=1}
function bad_case_15(req, res) {
    const multipartData = {};
    
    // Simulating multipart form data processing
    for (const key in req.body) {
        try {
            multipartData[key] = JSON.parse(req.body[key]);
        } catch (e) {
            multipartData[key] = req.body[key];
        }
    }
    
    // ruleid: javascript-unsafe-serialize
    const serialized = serialize(multipartData, { unsafe: true });
    res.send(`<script>var formData = ${serialized};</script>`);
}
// {/fact}

// GOOD CASES - Secure code examples

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_1(req, res) {
    const userData = req.query.user;
    // ok: javascript-unsafe-serialize
    const serialized = serialize(userData); // Default is safe (unsafe: false)
    res.send(`<script>var userInfo = ${serialized};</script>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_2(req, res) {
    const userInput = req.body.data;
    // ok: javascript-unsafe-serialize
    const serializedData = serialize(userInput, { space: 2 }); // No unsafe option
    res.render('template', { data: serializedData });
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_3(req, res) {
    const userProfile = {
        name: req.query.name,
        id: req.query.id,
        preferences: JSON.parse(req.query.prefs || '{}')
    };
    // ok: javascript-unsafe-serialize
    const serialized = serialize(userProfile, { unsafe: false });
    res.send(`<div data-user='${serialized}'></div>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_4(req, res) {
    const options = { unsafe: false, space: 2 };
    const userData = req.params.id;
    // ok: javascript-unsafe-serialize
    res.send(`<script>window.USER = ${serialize(userData, options)};</script>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_5(req, res) {
    const headerData = req.headers['x-custom-data'];
    // Validate and sanitize input
    const sanitizedData = sanitizeInput(headerData);
    // ok: javascript-unsafe-serialize
    const serialized = serialize(sanitizedData);
    res.send(`<script>var adminData = ${serialized};</script>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_6(req, res) {
    const cookieValue = req.cookies.userSettings;
    try {
        const parsedSettings = JSON.parse(cookieValue);
        // ok: javascript-unsafe-serialize
        const serialized = serialize(parsedSettings);
        res.send(`<script>var settings = ${serialized};</script>`);
    } catch (e) {
        res.status(400).send('Invalid settings format');
    }
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_7(req, res) {
    let unsafe = false; // Explicitly set to false
    const userData = req.body;
    // ok: javascript-unsafe-serialize
    const serialized = serialize(userData, { unsafe });
    res.send(`<script>var userData = ${serialized};</script>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_8(req, res) {
    // Using a safe alternative
    const userInput = req.query.config;
    // ok: javascript-unsafe-serialize
    const safeJSON = JSON.stringify(userInput);
    res.send(`<script>var appConfig = JSON.parse(${safeJSON});</script>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_9(req, res) {
    const formData = req.body.formData;
    // Explicitly set unsafe to false
    // ok: javascript-unsafe-serialize
    const serializedForm = serialize(formData, { unsafe: false, space: 2 });
    res.send(`
        <div id="form-data" data-content='${serializedForm}'></div>
        <script>initForm()</script>
    `);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_10(req, res) {
    // Static data, not user input
    const staticConfig = {
        version: "1.0.0",
        features: ["search", "filter", "sort"]
    };
    
    // ok: javascript-unsafe-serialize
    const serialized = serialize(staticConfig);
    res.send(`<script>var appConfig = ${serialized};</script>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_11(req, res) {
    const userFiles = req.files.map(file => ({
        name: file.originalname,
        size: file.size,
        type: file.mimetype
    }));
    
    // Sanitize the data before serializing
    const sanitizedFiles = userFiles.map(file => ({
        name: sanitizeString(file.name),
        size: parseInt(file.size, 10),
        type: sanitizeString(file.type)
    }));
    
    // ok: javascript-unsafe-serialize
    const serializedFiles = serialize(sanitizedFiles);
    res.send(`<script>var uploadedFiles = ${serializedFiles};</script>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_12(req, res) {
    // Using a different serialization approach for user data
    const userData = req.body.user;
    
    // ok: javascript-unsafe-serialize
    const safeData = JSON.stringify(userData);
    res.send(`
        <script>
            // Parse the JSON on the client side
            var userObj = JSON.parse(${safeData});
            displayUser(userObj);
        </script>
    `);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_13(req, res) {
    // Using HTML data attributes instead of inline scripts
    const userInput = req.query.data;
    
    // ok: javascript-unsafe-serialize
    const serialized = serialize(userInput);
    res.send(`
        <div id="user-data" data-user='${serialized}'></div>
        <script>
            // Get the data from the attribute
            const userData = JSON.parse(
                document.getElementById('user-data').getAttribute('data-user')
            );
        </script>
    `);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_14(req, res) {
    // Using the serialize function with safe defaults
    function processUserData(data) {
        // ok: javascript-unsafe-serialize
        return serialize(data); // Default is safe
    }
    
    const userData = req.body;
    const serialized = processUserData(userData);
    res.send(`<script>var processedData = ${serialized};</script>`);
}
// {/fact}

// {fact rule=cross-site-scripting@v1.0 defects=0}
function good_case_15(req, res) {
    // Using a combination of validation and safe serialization
    const userConfig = req.body.config;
    
    // Validate the configuration object
    if (!isValidConfig(userConfig)) {
        return res.status(400).send('Invalid configuration');
    }
    
    // ok: javascript-unsafe-serialize
    const serialized = serialize(userConfig, { space: 2 }); // No unsafe option
    res.send(`<script>var appConfig = ${serialized};</script>`);
}
// {/fact}

// Helper functions
function sanitizeInput(input) {
    // Implementation of input sanitization
    return typeof input === 'string' ? input.replace(/[<>]/g, '') : input;
}

function sanitizeString(str) {
    return typeof str === 'string' ? str.replace(/[<>]/g, '') : '';
}

function isValidConfig(config) {
    // Implementation of configuration validation
    return config && typeof config === 'object';
}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});