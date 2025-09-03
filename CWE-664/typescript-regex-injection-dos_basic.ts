// regex-injection-dos-ts-rule test cases
import express from 'express';
import * as http from 'http';
import axios from 'axios';
import { Request, Response } from 'express';
import * as fs from 'fs';
import * as readline from 'readline';
import { URL } from 'url';
import * as querystring from 'querystring';

// True Positive Examples (Vulnerable Code)

// Example 1: Basic regex injection from query parameter
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_1() {
    const app = express();
    
    app.get('/search', (req: Request, res: Response) => {
        const userInput = req.query.pattern as string;
        try {
            // ruleid: regex-injection-dos-ts-rule
            const regex = new RegExp(userInput);
            const text = "Some text to search through";
            const matches = text.match(regex);
            res.json({ matches });
        } catch (error) {
            res.status(500).send('Invalid regex pattern');
        }
    });
}
// {/fact}

// Example 2: Regex injection from POST body
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_2() {
    const app = express();
    app.use(express.json());
    
    app.post('/validate', (req: Request, res: Response) => {
        const pattern = req.body.pattern;
        const textToValidate = req.body.text;
        
        try {
            // ruleid: regex-injection-dos-ts-rule
            const regex = new RegExp(pattern, 'g');
            const isValid = regex.test(textToValidate);
            res.json({ isValid });
        } catch (error) {
            res.status(400).send('Invalid regex');
        }
    });
}
// {/fact}

// Example 3: Regex injection from URL parameter with minimal processing
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_3() {
    const app = express();
    
    app.get('/filter/:pattern', (req: Request, res: Response) => {
        const userPattern = req.params.pattern;
        const dataToFilter = ["apple", "banana", "cherry", "date"];
        
        try {
            // ruleid: regex-injection-dos-ts-rule
            const filterRegex = new RegExp(userPattern, 'i');
            const filteredData = dataToFilter.filter(item => filterRegex.test(item));
            res.json(filteredData);
        } catch (error) {
            res.status(500).send('Error filtering data');
        }
    });
}
// {/fact}

// Example 4: Regex injection from request header
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_4() {
    const app = express();
    
    app.get('/header-search', (req: Request, res: Response) => {
        const searchPattern = req.header('X-Search-Pattern');
        const content = "This is some content to search through";
        
        if (searchPattern) {
            try {
                // ruleid: regex-injection-dos-ts-rule
                const regex = new RegExp(searchPattern);
                const found = regex.test(content);
                res.json({ found });
            } catch (error) {
                res.status(400).send('Invalid search pattern');
            }
        } else {
            res.status(400).send('Missing search pattern header');
        }
    });
}
// {/fact}

// Example 5: Regex injection with string concatenation
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_5() {
    const app = express();
    
    app.get('/search-prefix', (req: Request, res: Response) => {
        const userSuffix = req.query.suffix as string;
        
        try {
            // ruleid: regex-injection-dos-ts-rule
            const regex = new RegExp("^start_" + userSuffix);
            const testString = "start_something_important";
            const matches = testString.match(regex);
            res.json({ matches });
        } catch (error) {
            res.status(500).send('Error in regex processing');
        }
    });
}
// {/fact}

// Example 6: Regex injection with template literals
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_6() {
    const app = express();
    
    app.get('/template-search', (req: Request, res: Response) => {
        const userInput = req.query.term as string;
        
        try {
            // ruleid: regex-injection-dos-ts-rule
            const regex = new RegExp(`${userInput}\\w+`);
            const text = "Testing with words like testing123 and example456";
            const matches = text.match(regex);
            res.json({ matches });
        } catch (error) {
            res.status(500).send('Invalid search term');
        }
    });
}
// {/fact}

// Example 7: Regex injection from cookie
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_7() {
    const app = express();
    
    app.get('/cookie-search', (req: Request, res: Response) => {
        const pattern = req.cookies?.searchPattern;
        
        if (pattern) {
            try {
                // ruleid: regex-injection-dos-ts-rule
                const regex = new RegExp(pattern);
                const text = "Text to search through for cookie-based patterns";
                const matches = text.match(regex);
                res.json({ matches });
            } catch (error) {
                res.status(400).send('Invalid pattern in cookie');
            }
        } else {
            res.status(400).send('Missing search pattern cookie');
        }
    });
}
// {/fact}

// Example 8: Regex injection with flags from user input
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_8() {
    const app = express();
    
    app.get('/advanced-search', (req: Request, res: Response) => {
        const pattern = req.query.pattern as string;
        const flags = req.query.flags as string;
        
        try {
            // ruleid: regex-injection-dos-ts-rule
            const regex = new RegExp(pattern, flags);
            const text = "Text for advanced searching capabilities";
            const matches = text.match(regex);
            res.json({ matches });
        } catch (error) {
            res.status(400).send('Invalid regex configuration');
        }
    });
}
// {/fact}

// Example 9: Regex injection with async/await
// {fact rule=resource-leak@v1.0 defects=1}
async function bad_case_9() {
    const app = express();
    
    app.get('/async-search', async (req: Request, res: Response) => {
        const userPattern = req.query.pattern as string;
        
        try {
            // Simulate fetching some data
            const data = await Promise.resolve("Some data to search through");
            
            // ruleid: regex-injection-dos-ts-rule
            const regex = new RegExp(userPattern);
            const matches = data.match(regex);
            res.json({ matches });
        } catch (error) {
            res.status(500).send('Error processing search');
        }
    });
}
// {/fact}

// Example 10: Regex injection with multiple inputs combined
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_10() {
    const app = express();
    
    app.get('/combined-search', (req: Request, res: Response) => {
        const prefix = req.query.prefix as string;
        const suffix = req.query.suffix as string;
        
        try {
            // ruleid: regex-injection-dos-ts-rule
            const regex = new RegExp(prefix + ".*" + suffix);
            const text = "This is a test string for combined prefix and suffix searching";
            const matches = text.match(regex);
            res.json({ matches });
        } catch (error) {
            res.status(400).send('Invalid search parameters');
        }
    });
}
// {/fact}

// Example 11: Regex injection with URL parsing
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_11() {
    const app = express();
    
    app.get('/url-pattern', (req: Request, res: Response) => {
        const urlString = req.query.url as string;
        
        try {
            const url = new URL(urlString);
            const pathPattern = url.pathname.substring(1); // Remove leading slash
            
            // ruleid: regex-injection-dos-ts-rule
            const regex = new RegExp(pathPattern);
            const testPaths = ["/api/users", "/api/products", "/admin/settings"];
            const matchingPaths = testPaths.filter(path => regex.test(path));
            
            res.json({ matchingPaths });
        } catch (error) {
            res.status(400).send('Invalid URL or pattern');
        }
    });
}
// {/fact}

// Example 12: Regex injection with conditional logic
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_12() {
    const app = express();
    
    app.get('/conditional-search', (req: Request, res: Response) => {
        const userInput = req.query.q as string;
        const useWildcard = req.query.wildcard === 'true';
        
        let pattern = userInput;
        if (useWildcard) {
            pattern = pattern + '.*';
        }
        
        try {
            // ruleid: regex-injection-dos-ts-rule
            const regex = new RegExp(pattern, 'i');
            const data = ["apple", "banana", "cherry", "date"];
            const results = data.filter(item => regex.test(item));
            res.json({ results });
        } catch (error) {
            res.status(400).send('Invalid search query');
        }
    });
}
// {/fact}

// Example 13: Regex injection with input transformation
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_13() {
    const app = express();
    
    app.get('/transform-search', (req: Request, res: Response) => {
        const rawInput = req.query.term as string;
        
        // Transform input (but still vulnerable)
        const transformedInput = rawInput.toLowerCase().replace(/\s+/g, '\\s+');
        
        try {
            // ruleid: regex-injection-dos-ts-rule
            const regex = new RegExp(transformedInput, 'g');
            const text = "This is a sample text for searching with transformed input";
            const matches = text.match(regex);
            res.json({ matches });
        } catch (error) {
            res.status(400).send('Invalid search term');
        }
    });
}
// {/fact}

// Example 14: Regex injection with input from parsed JSON
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_14() {
    const app = express();
    app.use(express.json());
    
    app.post('/json-search', (req: Request, res: Response) => {
        const searchConfig = req.body.search;
        
        if (searchConfig && searchConfig.pattern) {
            try {
                // ruleid: regex-injection-dos-ts-rule
                const regex = new RegExp(searchConfig.pattern, searchConfig.flags || '');
                const data = "Text to search through with JSON-based configuration";
                const matches = data.match(regex);
                res.json({ matches });
            } catch (error) {
                res.status(400).send('Invalid search configuration');
            }
        } else {
            res.status(400).send('Missing search configuration');
        }
    });
}
// {/fact}

// Example 15: Regex injection with query parameter array
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_15() {
    const app = express();
    
    app.get('/multi-pattern', (req: Request, res: Response) => {
        const patterns = req.query.patterns as string[];
        const results: any = {};
        
        if (Array.isArray(patterns)) {
            const text = "Text to search through with multiple patterns";
            
            patterns.forEach((pattern, index) => {
                try {
                    // ruleid: regex-injection-dos-ts-rule
                    const regex = new RegExp(pattern);
                    results[`pattern${index}`] = regex.test(text);
                } catch (error) {
                    results[`pattern${index}`] = { error: 'Invalid pattern' };
                }
            });
            
            res.json(results);
        } else {
            res.status(400).send('Patterns must be provided as an array');
        }
    });
}
// {/fact}

// True Negative Examples (Safe Code)

// Example 1: Using predefined regex patterns
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_1() {
    const app = express();
    
    app.get('/search', (req: Request, res: Response) => {
        const searchType = req.query.type as string;
        let regex;
        
        // ok: regex-injection-dos-ts-rule
        switch (searchType) {
            case 'email':
                regex = new RegExp('^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$');
                break;
            case 'phone':
                regex = new RegExp('^\\+?[0-9]{10,15}$');
                break;
            case 'zipcode':
                regex = new RegExp('^[0-9]{5}(?:-[0-9]{4})?$');
                break;
            default:
                regex = new RegExp('\\w+');
        }
        
        const text = req.query.text as string;
        const isValid = regex.test(text);
        res.json({ isValid });
    });
}
// {/fact}

// Example 2: Using a whitelist of allowed patterns
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_2() {
    const app = express();
    
    app.get('/filter', (req: Request, res: Response) => {
        const patternKey = req.query.pattern as string;
        const text = req.query.text as string;
        
        const allowedPatterns: Record<string, string> = {
            'digits': '\\d+',
            'letters': '[a-zA-Z]+',
            'alphanumeric': '[a-zA-Z0-9]+',
            'email': '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}'
        };
        
        if (patternKey && allowedPatterns[patternKey]) {
            // ok: regex-injection-dos-ts-rule
            const regex = new RegExp(allowedPatterns[patternKey]);
            const matches = text.match(regex);
            res.json({ matches });
        } else {
            res.status(400).send('Invalid or missing pattern key');
        }
    });
}
// {/fact}

// Example 3: Using hardcoded regex pattern with user-provided flags
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_3() {
    const app = express();
    
    app.get('/search-with-flags', (req: Request, res: Response) => {
        const flags = req.query.flags as string;
        const text = req.query.text as string;
        
        // Validate flags to only allow safe options
        const validFlags = flags.replace(/[^gimuy]/g, '');
        
        // ok: regex-injection-dos-ts-rule
        const regex = new RegExp('\\w+', validFlags);
        const matches = text.match(regex);
        res.json({ matches });
    });
}
// {/fact}

// Example 4: Using RegExp.escape (hypothetical) for user input
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_4() {
    const app = express();
    
    app.get('/literal-search', (req: Request, res: Response) => {
        const searchTerm = req.query.term as string;
        
        // Escape the user input to treat it as a literal string
        // This is a hypothetical function similar to what other languages provide
        function escapeRegExp(string: string): string {
            return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        }
        
        // ok: regex-injection-dos-ts-rule
        const regex = new RegExp(escapeRegExp(searchTerm));
        const text = "Text to search through for literal matches";
        const matches = text.match(regex);
        res.json({ matches });
    });
}
// {/fact}

// Example 5: Using a regex builder with validation
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_5() {
    const app = express();
    
    app.get('/safe-builder', (req: Request, res: Response) => {
        const prefix = req.query.prefix as string;
        const suffix = req.query.suffix as string;
        
        // Validate and sanitize inputs
        const safePrefix = prefix ? prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') : '';
        const safeSuffix = suffix ? suffix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') : '';
        
        // ok: regex-injection-dos-ts-rule
        const regex = new RegExp(`^${safePrefix}.*${safeSuffix}$`);
        const testString = "start_something_end";
        const isMatch = regex.test(testString);
        res.json({ isMatch });
    });
}
// {/fact}

// Example 6: Using predefined regex components
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_6() {
    const app = express();
    
    app.get('/component-search', (req: Request, res: Response) => {
        const component = req.query.component as string;
        
        const regexComponents: Record<string, string> = {
            'username': '[a-zA-Z0-9_]{3,16}',
            'date': '\\d{4}-\\d{2}-\\d{2}',
            'time': '\\d{2}:\\d{2}:\\d{2}',
            'ip': '\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}'
        };
        
        if (component && regexComponents[component]) {
            // ok: regex-injection-dos-ts-rule
            const regex = new RegExp(regexComponents[component]);
            const text = req.query.text as string;
            const isValid = regex.test(text);
            res.json({ isValid });
        } else {
            res.status(400).send('Invalid or unsupported component');
        }
    });
}
// {/fact}

// Example 7: Using a safe regex factory function
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_7() {
    const app = express();
    
    app.get('/factory-regex', (req: Request, res: Response) => {
        const type = req.query.type as string;
        const text = req.query.text as string;
        
        function getRegexForType(type: string): RegExp {
            switch (type) {
                case 'email':
                    return new RegExp('^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$');
                case 'url':
                    return new RegExp('^https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}(/[\\w.-]*)*$');
                case 'date':
                    return new RegExp('^\\d{4}-\\d{2}-\\d{2}$');
                default:
                    return new RegExp('\\w+');
            }
        }
        
        // ok: regex-injection-dos-ts-rule
        const regex = getRegexForType(type);
        const isValid = regex.test(text);
        res.json({ isValid });
    });
}
// {/fact}

// Example 8: Using constant regex patterns
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_8() {
    const app = express();
    
    // Define regex patterns as constants
    const EMAIL_REGEX = new RegExp('^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$');
    const URL_REGEX = new RegExp('^https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}(/[\\w.-]*)*$');
    const PHONE_REGEX = new RegExp('^\\+?[0-9]{10,15}$');
    
    app.post('/validate-input', (req: Request, res: Response) => {
        const { email, url, phone } = req.body;
        
        // ok: regex-injection-dos-ts-rule
        const results = {
            isValidEmail: email ? EMAIL_REGEX.test(email) : false,
            isValidUrl: url ? URL_REGEX.test(url) : false,
            isValidPhone: phone ? PHONE_REGEX.test(phone) : false
        };
        
        res.json(results);
    });
}
// {/fact}

// Example 9: Using regex literals instead of constructor
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_9() {
    const app = express();
    
    app.get('/literal-regex', (req: Request, res: Response) => {
        const searchType = req.query.type as string;
        const text = req.query.text as string;
        
        let regex;
        // ok: regex-injection-dos-ts-rule
        switch (searchType) {
            case 'email':
                regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
                break;
            case 'phone':
                regex = /^\+?[0-9]{10,15}$/;
                break;
            default:
                regex = /\w+/;
        }
        
        const isValid = regex.test(text);
        res.json({ isValid });
    });
}
// {/fact}

// Example 10: Using a validation function before creating regex
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_10() {
    const app = express();
    
    app.get('/validated-regex', (req: Request, res: Response) => {
        const pattern = req.query.pattern as string;
        
        // Validate the pattern is safe
        function isPatternSafe(pattern: string): boolean {
            // Check pattern length to prevent catastrophic backtracking
            if (pattern.length > 100) return false;
            
            // Check for potentially dangerous patterns
            if (/(\*\+|\+\*|\{\d+,\}\*|\*\{\d+,\})/.test(pattern)) return false;
            
            // Additional checks could be added here
            return true;
        }
        
        if (pattern && isPatternSafe(pattern)) {
            try {
                // ok: regex-injection-dos-ts-rule
                const regex = new RegExp(pattern);
                const text = "Text to search through after validation";
                const matches = text.match(regex);
                res.json({ matches });
            } catch (error) {
                res.status(400).send('Invalid regex pattern');
            }
        } else {
            res.status(400).send('Pattern failed safety validation');
        }
    });
}
// {/fact}

// Example 11: Using a mapping of safe regex patterns
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_11() {
    const app = express();
    
    app.get('/mapped-patterns', (req: Request, res: Response) => {
        const patternId = parseInt(req.query.id as string);
        const text = req.query.text as string;
        
        // Map of safe regex patterns by ID
        const patterns = [
            '\\d+',                                      // digits
            '[a-zA-Z]+',                                // letters
            '[a-zA-Z0-9]+',                             // alphanumeric
            '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'  // email
        ];
        
        if (patternId >= 0 && patternId < patterns.length) {
            // ok: regex-injection-dos-ts-rule
            const regex = new RegExp(patterns[patternId]);
            const matches = text.match(regex);
            res.json({ matches });
        } else {
            res.status(400).send('Invalid pattern ID');
        }
    });
}
// {/fact}

// Example 12: Using enum for safe regex selection
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_12() {
    const app = express();
    
    enum PatternType {
        DIGITS = 'digits',
        LETTERS = 'letters',
        ALPHANUMERIC = 'alphanumeric',
        EMAIL = 'email'
    }
    
    app.get('/enum-patterns', (req: Request, res: Response) => {
        const patternType = req.query.type as string;
        const text = req.query.text as string;
        
        let pattern: string;
        
        switch (patternType) {
            case PatternType.DIGITS:
                pattern = '\\d+';
                break;
            case PatternType.LETTERS:
                pattern = '[a-zA-Z]+';
                break;
            case PatternType.ALPHANUMERIC:
                pattern = '[a-zA-Z0-9]+';
                break;
            case PatternType.EMAIL:
                pattern = '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$';
                break;
            default:
                res.status(400).send('Invalid pattern type');
                return;
        }
        
        // ok: regex-injection-dos-ts-rule
        const regex = new RegExp(pattern);
        const isMatch = regex.test(text);
        res.json({ isMatch });
    });
}
// {/fact}

// Example 13: Using a regex template with safe placeholders
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_13() {
    const app = express();
    
    app.get('/template-regex', (req: Request, res: Response) => {
        const word = req.query.word as string;
        
        // Only allow alphanumeric words
        if (word && /^[a-zA-Z0-9]+$/.test(word)) {
            // ok: regex-injection-dos-ts-rule
            const regex = new RegExp(`\\b${word}\\b`);
            const text = "This is a sample text containing various words";
            const containsWord = regex.test(text);
            res.json({ containsWord });
        } else {
            res.status(400).send('Invalid word parameter');
        }
    });
}
// {/fact}

// Example 14: Using a regex builder with strict validation
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_14() {
    const app = express();
    
    app.get('/strict-builder', (req: Request, res: Response) => {
        const min = parseInt(req.query.min as string);
        const max = parseInt(req.query.max as string);
        
        // Validate numeric ranges
        if (isNaN(min) || isNaN(max) || min < 1 || max > 100 || min > max) {
            res.status(400).send('Invalid range parameters');
            return;
        }
        
        // Build a safe regex for numeric range
        // ok: regex-injection-dos-ts-rule
        const regex = new RegExp(`^\\d{${min},${max}}$`);
        const text = req.query.text as string;
        const isValid = regex.test(text);
        res.json({ isValid });
    });
}
// {/fact}

// Example 15: Using predefined regex patterns with configuration
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_15() {
    const app = express();
    
    app.post('/configured-regex', (req: Request, res: Response) => {
        const { type, options } = req.body;
        
        // Define base patterns
        const basePatterns: Record<string, string> = {
            'username': '[a-zA-Z0-9_]',
            'password': '[a-zA-Z0-9!@#$%^&*]',
            'name': '[a-zA-Z\\s]'
        };
        
        if (type && basePatterns[type]) {
            let pattern = basePatterns[type];
            
            // Apply safe configurations
            const minLength = options?.minLength && !isNaN(options.minLength) ? 
                Math.min(Math.max(1, options.minLength), 50) : 1;
            
            const maxLength = options?.maxLength && !isNaN(options.maxLength) ? 
                Math.min(Math.max(minLength, options.maxLength), 100) : 50;
            
            // ok: regex-injection-dos-ts-rule
            const regex = new RegExp(`^${pattern}{${minLength},${maxLength}}$`);
            const text = req.body.text;
            const isValid = regex.test(text);
            res.json({ isValid });
        } else {
            res.status(400).send('Invalid pattern type');
        }
    });
}
// {/fact}