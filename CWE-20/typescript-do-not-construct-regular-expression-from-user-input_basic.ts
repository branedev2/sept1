import express from 'express';
import * as http from 'http';
import axios from 'axios';
import { Request, Response } from 'express';
import * as fs from 'fs';
import * as path from 'path';

// True Positive Examples (Vulnerable Code)

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_1(req: express.Request, res: express.Response) {
    const userPattern = req.query.pattern as string;
    
    try {
        // ruleid: typescript-do-not-construct-regular-expression-from-user-input
        const regex = new RegExp(userPattern);
        const text = "Some text to test against";
        const result = regex.test(text);
        res.send({ result });
    } catch (error) {
        res.status(500).send({ error: "Invalid regex pattern" });
    }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_2(req: express.Request, res: express.Response) {
    const searchTerm = req.body.search;
    
    try {
        // ruleid: typescript-do-not-construct-regular-expression-from-user-input
        const regex = RegExp(searchTerm, 'i');
        const data = ["apple", "banana", "cherry"];
        const matches = data.filter(item => regex.test(item));
        res.json({ matches });
    } catch (error) {
        res.status(500).send("Error processing search");
    }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_3(req: express.Request, res: express.Response) {
    const userInput = req.params.pattern;
    const flags = req.query.flags as string || 'g';
    
    // ruleid: typescript-do-not-construct-regular-expression-from-user-input
    const regex = new RegExp(userInput, flags);
    const text = fs.readFileSync('data.txt', 'utf8');
    const matches = text.match(regex);
    
    res.json({ matches });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_4(req: express.Request, res: express.Response) {
    const headerPattern = req.headers['x-search-pattern'] as string;
    
    if (headerPattern) {
        try {
            // ruleid: typescript-do-not-construct-regular-expression-from-user-input
            const regex = new RegExp(headerPattern);
            const users = [
                { name: "John", email: "john@example.com" },
                { name: "Jane", email: "jane@example.com" }
            ];
            
            const filteredUsers = users.filter(user => 
                regex.test(user.name) || regex.test(user.email)
            );
            
            res.json(filteredUsers);
        } catch (error) {
            res.status(400).send("Invalid search pattern");
        }
    } else {
        res.status(400).send("Search pattern required");
    }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_5(req: express.Request, res: express.Response) {
    const cookie = req.cookies.searchPattern;
    
    if (!cookie) {
        return res.status(400).send("No search pattern provided");
    }
    
    try {
        // ruleid: typescript-do-not-construct-regular-expression-from-user-input
        const regex = RegExp(cookie);
        const content = "This is some sample content to search through";
        const found = regex.test(content);
        
        res.json({ found });
    } catch (error) {
        res.status(500).send("Error processing pattern");
    }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_6(req: express.Request, res: express.Response) {
    const userPattern = req.query.pattern as string;
    const userText = req.query.text as string;
    
    if (!userPattern || !userText) {
        return res.status(400).send("Missing parameters");
    }
    
    try {
        // ruleid: typescript-do-not-construct-regular-expression-from-user-input
        const regex = new RegExp(userPattern, 'g');
        const matches = userText.match(regex);
        res.json({ matches: matches || [] });
    } catch (error) {
        res.status(500).send("Invalid regex pattern");
    }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_7(req: express.Request, res: express.Response) {
    const formData = req.body;
    
    if (!formData.regexPattern) {
        return res.status(400).send("Pattern required");
    }
    
    try {
        // ruleid: typescript-do-not-construct-regular-expression-from-user-input
        const regex = new RegExp(formData.regexPattern);
        const validationResult = regex.test(formData.testString || "");
        res.json({ valid: validationResult });
    } catch (error) {
        res.status(500).send("Error in pattern validation");
    }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_8(req: express.Request, res: express.Response) {
    const searchConfig = {
        pattern: req.query.pattern as string,
        flags: req.query.flags as string || 'i',
        text: "This is the text we're searching in"
    };
    
    try {
        // ruleid: typescript-do-not-construct-regular-expression-from-user-input
        const regex = new RegExp(searchConfig.pattern, searchConfig.flags);
        const results = searchConfig.text.match(regex);
        res.json({ results: results || [] });
    } catch (error) {
        res.status(500).send("Search configuration error");
    }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_9(req: express.Request, res: express.Response) {
    const userInput = JSON.parse(req.body.data || '{}');
    
    if (!userInput.pattern) {
        return res.status(400).send("Pattern required");
    }
    
    try {
        // ruleid: typescript-do-not-construct-regular-expression-from-user-input
        const regex = RegExp(userInput.pattern);
        const dataSet = ["test1", "test2", "example1", "example2"];
        const filtered = dataSet.filter(item => regex.test(item));
        res.json({ filtered });
    } catch (error) {
        res.status(500).send("Error processing filter");
    }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_10(req: express.Request, res: express.Response) {
    const patternParts = [
        req.query.start as string || '',
        req.query.middle as string || '.*',
        req.query.end as string || ''
    ];
    
    const combinedPattern = patternParts.join('');
    
    try {
        // ruleid: typescript-do-not-construct-regular-expression-from-user-input
        const regex = new RegExp(combinedPattern);
        const testString = "This is a test string";
        const result = regex.test(testString);
        res.json({ matches: result });
    } catch (error) {
        res.status(500).send("Error creating pattern");
    }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_11(req: express.Request, res: express.Response) {
    http.get('http://example.com/api/pattern', (response) => {
        let data = '';
        
        response.on('data', (chunk) => {
            data += chunk;
        });
        
        response.on('end', () => {
            const pattern = JSON.parse(data).pattern;
            
            try {
                // ruleid: typescript-do-not-construct-regular-expression-from-user-input
                const regex = new RegExp(pattern);
                const testResult = regex.test("Sample text");
                res.json({ result: testResult });
            } catch (error) {
                res.status(500).send("Error processing pattern");
            }
        });
    }).on('error', (error) => {
        res.status(500).send("Error fetching pattern");
    });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_12(req: express.Request, res: express.Response) {
    const searchQuery = req.query.q as string;
    
    if (!searchQuery) {
        return res.status(400).send("Search query required");
    }
    
    // Construct a pattern based on user input
    const searchPattern = `^${searchQuery}.*`;
    
    try {
        // ruleid: typescript-do-not-construct-regular-expression-from-user-input
        const regex = new RegExp(searchPattern, 'i');
        const items = ["apple", "banana", "orange", "pear"];
        const results = items.filter(item => regex.test(item));
        res.json({ results });
    } catch (error) {
        res.status(500).send("Error processing search");
    }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_13(req: express.Request, res: express.Response) {
    const userConfig = req.body.config || {};
    
    if (!userConfig.validationPattern) {
        return res.status(400).send("Validation pattern required");
    }
    
    try {
        // ruleid: typescript-do-not-construct-regular-expression-from-user-input
        const validationRegex = RegExp(userConfig.validationPattern);
        const isValid = validationRegex.test(userConfig.testValue || "");
        res.json({ valid: isValid });
    } catch (error) {
        res.status(500).send("Invalid validation configuration");
    }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_14(req: express.Request, res: express.Response) {
    async function processRequest() {
        try {
            const response = await axios.get('https://api.example.com/patterns');
            const pattern = response.data.pattern;
            
            // ruleid: typescript-do-not-construct-regular-expression-from-user-input
            const regex = new RegExp(pattern);
            const testString = "This is a test string";
            const matches = testString.match(regex);
            
            res.json({ matches: matches || [] });
        } catch (error) {
            res.status(500).send("Error processing pattern");
        }
    }
    
    processRequest();
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_15(req: express.Request, res: express.Response) {
    const fileName = req.query.file as string;
    
    if (!fileName) {
        return res.status(400).send("File name required");
    }
    
    try {
        const fileContent = fs.readFileSync(path.join(__dirname, 'patterns', fileName), 'utf8');
        const patternData = JSON.parse(fileContent);
        
        // ruleid: typescript-do-not-construct-regular-expression-from-user-input
        const regex = new RegExp(patternData.pattern);
        const testResult = regex.test("Sample text to test against");
        
        res.json({ result: testResult });
    } catch (error) {
        res.status(500).send("Error processing pattern file");
    }
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_1(req: express.Request, res: express.Response) {
    const userPattern = req.query.pattern as string;
    
    // Define a whitelist of allowed patterns
    const allowedPatterns = {
        "email": "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$",
        "phone": "^\\d{3}-\\d{3}-\\d{4}$",
        "zipcode": "^\\d{5}(-\\d{4})?$"
    };
    
    if (!userPattern || !allowedPatterns[userPattern]) {
        return res.status(400).send("Invalid or missing pattern name");
    }
    
    // ok: typescript-do-not-construct-regular-expression-from-user-input
    const regex = new RegExp(allowedPatterns[userPattern]);
    const text = req.query.text as string || "";
    const result = regex.test(text);
    
    res.json({ result });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_2(req: express.Request, res: express.Response) {
    const searchTerm = req.body.search;
    
    if (!searchTerm || typeof searchTerm !== 'string') {
        return res.status(400).send("Invalid search term");
    }
    
    // Escape the user input to make it safe for regex
    const escapedTerm = searchTerm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    
    // ok: typescript-do-not-construct-regular-expression-from-user-input
    const regex = new RegExp(escapedTerm, 'i');
    const data = ["apple", "banana", "cherry"];
    const matches = data.filter(item => regex.test(item));
    
    res.json({ matches });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_3(req: express.Request, res: express.Response) {
    // Use a predefined regex pattern instead of user input
    const patternType = req.params.type;
    
    let pattern: string;
    switch (patternType) {
        case 'email':
            pattern = '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$';
            break;
        case 'url':
            pattern = '^(https?:\\/\\/)?([\\da-z.-]+)\\.([a-z.]{2,6})([/\\w .-]*)*\\/?$';
            break;
        case 'date':
            pattern = '^\\d{4}-\\d{2}-\\d{2}$';
            break;
        default:
            return res.status(400).send("Invalid pattern type");
    }
    
    // ok: typescript-do-not-construct-regular-expression-from-user-input
    const regex = new RegExp(pattern);
    const text = req.query.text as string || "";
    const isValid = regex.test(text);
    
    res.json({ isValid });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_4(req: express.Request, res: express.Response) {
    const searchType = req.headers['x-search-type'] as string;
    
    // Use an enum-like approach with predefined patterns
    const patterns = {
        name: /^[a-zA-Z\s]{2,30}$/,
        email: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
        phone: /^\d{3}-\d{3}-\d{4}$/
    };
    
    if (!searchType || !patterns[searchType]) {
        return res.status(400).send("Invalid search type");
    }
    
    // ok: typescript-do-not-construct-regular-expression-from-user-input
    const regex = patterns[searchType];
    const users = [
        { name: "John Doe", email: "john@example.com", phone: "555-123-4567" },
        { name: "Jane Smith", email: "jane@example.com", phone: "555-987-6543" }
    ];
    
    const filteredUsers = users.filter(user => regex.test(user[searchType]));
    res.json(filteredUsers);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_5(req: express.Request, res: express.Response) {
    // Use a fixed set of regex patterns
    const patternId = parseInt(req.cookies.patternId || "0");
    
    const safePatterns = [
        /^[a-z]+$/i,                     // letters only
        /^[0-9]+$/,                      // numbers only
        /^[a-z0-9]+$/i,                  // alphanumeric
        /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i  // email
    ];
    
    if (isNaN(patternId) || patternId < 0 || patternId >= safePatterns.length) {
        return res.status(400).send("Invalid pattern ID");
    }
    
    // ok: typescript-do-not-construct-regular-expression-from-user-input
    const regex = safePatterns[patternId];
    const content = req.query.content as string || "";
    const isMatch = regex.test(content);
    
    res.json({ isMatch });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_6(req: express.Request, res: express.Response) {
    const searchText = req.query.text as string || "";
    
    // Use a hardcoded regex pattern
    // ok: typescript-do-not-construct-regular-expression-from-user-input
    const wordBoundaryRegex = new RegExp("\\b" + "fixed" + "\\b", "gi");
    const matches = searchText.match(wordBoundaryRegex);
    
    res.json({ matches: matches || [] });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_7(req: express.Request, res: express.Response) {
    const validationMode = req.body.mode;
    
    // Use a validation strategy pattern with predefined regexes
    const validationStrategies = {
        username: {
            pattern: /^[a-zA-Z0-9_]{3,16}$/,
            message: "Username must be 3-16 characters and contain only letters, numbers, and underscores"
        },
        password: {
            pattern: /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/,
            message: "Password must be at least 8 characters and contain at least one letter and one number"
        },
        email: {
            pattern: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
            message: "Please enter a valid email address"
        }
    };
    
    if (!validationMode || !validationStrategies[validationMode]) {
        return res.status(400).send("Invalid validation mode");
    }
    
    const strategy = validationStrategies[validationMode];
    const inputValue = req.body.value || "";
    
    // ok: typescript-do-not-construct-regular-expression-from-user-input
    const isValid = strategy.pattern.test(inputValue);
    
    res.json({
        valid: isValid,
        message: isValid ? "Validation passed" : strategy.message
    });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_8(req: express.Request, res: express.Response) {
    const searchConfig = {
        field: req.query.field as string || "name",
        value: req.query.value as string || ""
    };
    
    // Validate the field parameter against a whitelist
    const allowedFields = ["name", "email", "phone", "address"];
    if (!allowedFields.includes(searchConfig.field)) {
        return res.status(400).send("Invalid search field");
    }
    
    // Escape the search value to make it safe for regex
    const escapedValue = searchConfig.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    
    // ok: typescript-do-not-construct-regular-expression-from-user-input
    const regex = new RegExp(escapedValue, 'i');
    
    const users = [
        { name: "John", email: "john@example.com", phone: "123-456-7890", address: "123 Main St" },
        { name: "Jane", email: "jane@example.com", phone: "987-654-3210", address: "456 Oak Ave" }
    ];
    
    const results = users.filter(user => regex.test(user[searchConfig.field]));
    res.json({ results });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_9(req: express.Request, res: express.Response) {
    const userInput = JSON.parse(req.body.data || '{}');
    
    // Use a pattern builder with safe, predefined components
    const patternBuilder = {
        startsWith: (prefix: string) => `^${prefix}`,
        endsWith: (suffix: string) => `${suffix}$`,
        contains: (text: string) => text,
        exactly: (text: string) => `^${text}$`
    };
    
    // Validate user's choice of pattern type
    const patternType = userInput.type || "contains";
    if (!Object.keys(patternBuilder).includes(patternType)) {
        return res.status(400).send("Invalid pattern type");
    }
    
    // Use a predefined set of allowed search terms
    const allowedTerms = {
        "apple": "apple",
        "banana": "banana",
        "cherry": "cherry",
        "date": "date"
    };
    
    const searchTerm = userInput.term || "";
    if (!allowedTerms[searchTerm]) {
        return res.status(400).send("Invalid search term");
    }
    
    // ok: typescript-do-not-construct-regular-expression-from-user-input
    const pattern = patternBuilder[patternType](allowedTerms[searchTerm]);
    const regex = new RegExp(pattern, 'i');
    
    const dataSet = ["apple pie", "banana split", "cherry cola", "date night"];
    const filtered = dataSet.filter(item => regex.test(item));
    
    res.json({ filtered });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_10(req: express.Request, res: express.Response) {
    // Use predefined regex patterns based on a configuration
    const patternConfigs = {
        simple: {
            pattern: "^[a-z]+$",
            flags: "i"
        },
        numeric: {
            pattern: "^[0-9]+$",
            flags: ""
        },
        mixed: {
            pattern: "^[a-z0-9]+$",
            flags: "i"
        }
    };
    
    const configName = req.query.config as string;
    
    if (!configName || !patternConfigs[configName]) {
        return res.status(400).send("Invalid configuration name");
    }
    
    const config = patternConfigs[configName];
    
    // ok: typescript-do-not-construct-regular-expression-from-user-input
    const regex = new RegExp(config.pattern, config.flags);
    const testString = req.query.test as string || "";
    const result = regex.test(testString);
    
    res.json({ matches: result });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_11(req: express.Request, res: express.Response) {
    // Use a regex factory with predefined patterns
    const regexFactory = {
        email: () => new RegExp('^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'),
        phone: () => new RegExp('^\\d{3}-\\d{3}-\\d{4}$'),
        zipcode: () => new RegExp('^\\d{5}(-\\d{4})?$'),
        date: () => new RegExp('^\\d{4}-\\d{2}-\\d{2}$')
    };
    
    const patternType = req.query.type as string;
    
    if (!patternType || !regexFactory[patternType]) {
        return res.status(400).send("Invalid pattern type");
    }
    
    // ok: typescript-do-not-construct-regular-expression-from-user-input
    const regex = regexFactory[patternType]();
    const inputValue = req.query.value as string || "";
    const isValid = regex.test(inputValue);
    
    res.json({ valid: isValid });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_12(req: express.Request, res: express.Response) {
    const searchQuery = req.query.q as string || "";
    
    // Instead of using user input for regex pattern, use it for direct string comparison
    const items = ["apple", "banana", "orange", "pear"];
    
    // ok: typescript-do-not-construct-regular-expression-from-user-input
    const results = items.filter(item => item.includes(searchQuery));
    
    res.json({ results });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_13(req: express.Request, res: express.Response) {
    const userConfig = req.body.config || {};
    
    // Use a validation schema with predefined patterns
    const validationSchemas = {
        username: /^[a-zA-Z0-9_]{3,16}$/,
        email: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
        url: /^(https?:\/\/)?([\da-z.-]+)\.([a-z.]{2,6})([\/\w .-]*)*\/?$/
    };
    
    const schemaName = userConfig.schema;
    
    if (!schemaName || !validationSchemas[schemaName]) {
        return res.status(400).send("Invalid schema name");
    }
    
    // ok: typescript-do-not-construct-regular-expression-from-user-input
    const validationRegex = validationSchemas[schemaName];
    const isValid = validationRegex.test(userConfig.value || "");
    
    res.json({ valid: isValid });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_14(req: express.Request, res: express.Response) {
    // Use a set of predefined regex patterns from a "database"
    const patternDatabase = {
        1: "^[a-z]+$",
        2: "^[0-9]+$",
        3: "^[a-z0-9]+$",
        4: "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
    };
    
    const patternId = req.query.id as string;
    
    if (!patternId || !patternDatabase[patternId]) {
        return res.status(400).send("Invalid pattern ID");
    }
    
    // ok: typescript-do-not-construct-regular-expression-from-user-input
    const regex = new RegExp(patternDatabase[patternId], 'i');
    const testString = req.query.test as string || "";
    const matches = testString.match(regex);
    
    res.json({ matches: matches || [] });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_15(req: express.Request, res: express.Response) {
    const fileName = req.query.file as string;
    
    // Use a whitelist of allowed files
    const allowedFiles = ["email-patterns.json", "phone-patterns.json", "date-patterns.json"];
    
    if (!fileName || !allowedFiles.includes(fileName)) {
        return res.status(400).send("Invalid file name");
    }
    
    try {
        // Load a predefined pattern from a trusted file
        const fileContent = fs.readFileSync(path.join(__dirname, 'safe-patterns', fileName), 'utf8');
        const patternData = JSON.parse(fileContent);
        
        if (!patternData.pattern || typeof patternData.pattern !== 'string') {
            return res.status(500).send("Invalid pattern format in file");
        }
        
        // ok: typescript-do-not-construct-regular-expression-from-user-input
        const regex = new RegExp(patternData.pattern);
        const testValue = req.query.test as string || "";
        const testResult = regex.test(testValue);
        
        res.json({ result: testResult });
    } catch (error) {
        res.status(500).send("Error processing pattern file");
    }
}
// {/fact}

// Export the functions for testing
export {
    bad_case_1, bad_case_2, bad_case_3, bad_case_4, bad_case_5,
    bad_case_6, bad_case_7, bad_case_8, bad_case_9, bad_case_10,
    bad_case_11, bad_case_12, bad_case_13, bad_case_14, bad_case_15,
    good_case_1, good_case_2, good_case_3, good_case_4, good_case_5,
    good_case_6, good_case_7, good_case_8, good_case_9, good_case_10,
    good_case_11, good_case_12, good_case_13, good_case_14, good_case_15
};