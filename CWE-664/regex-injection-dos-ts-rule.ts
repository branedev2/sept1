// regex-injection-dos-ts-rule test cases
import express from 'express';
import http from 'http';
import axios from 'axios';
import { Request, Response } from 'express';
import * as fs from 'fs';
import * as readline from 'readline';

// True Positive Examples (Vulnerable Code)

// Example 1: Basic regex injection from query parameter
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_1() {
    const app = express();
    
    app.get('/search', (req: Request, res: Response) => {
        const userPattern = req.query.pattern as string;
        
        try {
            // ruleid: regex-injection-dos-ts-rule
            const regex = new RegExp(userPattern);
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
            res.status(400).send('Validation error');
        }
    });
}
// {/fact}

// Example 3: Regex injection from URL parameter with flags
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_3() {
    const app = express();
    
    app.get('/users/:pattern', (req: Request, res: Response) => {
        const userPattern = req.params.pattern;
        const flags = req.query.flags as string || 'i';
        
        // ruleid: regex-injection-dos-ts-rule
        const regex = new RegExp(userPattern, flags);
        const users = ['john', 'jane', 'bob', 'alice'];
        
        const matchingUsers = users.filter(user => regex.test(user));
        res.json({ matchingUsers });
    });
}
// {/fact}

// Example 4: Regex injection from request header
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_4() {
    const app = express();
    
    app.get('/filter', (req: Request, res: Response) => {
        const filterPattern = req.header('X-Filter-Pattern');
        
        if (filterPattern) {
            try {
                // ruleid: regex-injection-dos-ts-rule
                const regex = new RegExp(filterPattern);
                const items = ['apple', 'banana', 'cherry', 'date'];
                
                const filteredItems = items.filter(item => regex.test(item));
                res.json({ filteredItems });
            } catch (error) {
                res.status(400).send('Invalid filter pattern');
            }
        } else {
            res.status(400).send('Filter pattern required');
        }
    });
}
// {/fact}

// Example 5: Regex injection from cookie
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_5() {
    const app = express();
    
    app.get('/preferences', (req: Request, res: Response) => {
        const displayPattern = req.cookies.displayPattern;
        
        if (displayPattern) {
            try {
                // ruleid: regex-injection-dos-ts-rule
                const regex = new RegExp(displayPattern, 'i');
                const preferences = ['dark mode', 'light mode', 'high contrast', 'default'];
                
                const matchingPreferences = preferences.filter(pref => regex.test(pref));
                res.json({ matchingPreferences });
            } catch (error) {
                res.status(400).send('Invalid display pattern');
            }
        } else {
            res.json({ preferences: ['default'] });
        }
    });
}
// {/fact}

// Example 6: Regex injection with string concatenation
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_6() {
    const app = express();
    
    app.get('/search-prefix', (req: Request, res: Response) => {
        const searchTerm = req.query.term as string;
        
        try {
            // ruleid: regex-injection-dos-ts-rule
            const regex = new RegExp('^' + searchTerm);
            const words = ['apple', 'application', 'apartment', 'banana'];
            
            const matches = words.filter(word => regex.test(word));
            res.json({ matches });
        } catch (error) {
            res.status(500).send('Search error');
        }
    });
}
// {/fact}

// Example 7: Regex injection with template literals
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_7() {
    const app = express();
    
    app.get('/search-custom', (req: Request, res: Response) => {
        const start = req.query.start as string;
        const end = req.query.end as string;
        
        try {
            // ruleid: regex-injection-dos-ts-rule
            const regex = new RegExp(`${start}.*${end}`);
            const text = "This is a sample text for searching patterns";
            
            const hasMatch = regex.test(text);
            res.json({ hasMatch });
        } catch (error) {
            res.status(500).send('Invalid search pattern');
        }
    });
}
// {/fact}

// Example 8: Regex injection with variable assignment
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_8() {
    const app = express();
    
    app.get('/validate-email', (req: Request, res: Response) => {
        const customDomain = req.query.domain as string;
        const patternString = `^[a-zA-Z0-9._%+-]+@${customDomain}$`;
        
        try {
            // ruleid: regex-injection-dos-ts-rule
            const emailRegex = new RegExp(patternString);
            const email = "user@example.com";
            
            const isValid = emailRegex.test(email);
            res.json({ isValid });
        } catch (error) {
            res.status(500).send('Validation error');
        }
    });
}
// {/fact}

// Example 9: Regex injection with multiple user inputs
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_9() {
    const app = express();
    
    app.get('/complex-search', (req: Request, res: Response) => {
        const prefix = req.query.prefix as string || '';
        const suffix = req.query.suffix as string || '';
        const flags = req.query.flags as string || 'g';
        
        try {
            // ruleid: regex-injection-dos-ts-rule
            const regex = new RegExp(prefix + '.*' + suffix, flags);
            const text = "This is a sample text for searching with complex patterns";
            
            const matches = text.match(regex);
            res.json({ matches });
        } catch (error) {
            res.status(500).send('Search error');
        }
    });
}
// {/fact}

// Example 10: Regex injection with conditional logic
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_10() {
    const app = express();
    
    app.get('/conditional-search', (req: Request, res: Response) => {
        const pattern = req.query.pattern as string;
        const useGlobalFlag = req.query.global === 'true';
        
        let regexPattern = pattern;
        let flags = 'i';
        
        if (useGlobalFlag) {
            flags += 'g';
        }
        
        try {
            // ruleid: regex-injection-dos-ts-rule
            const regex = new RegExp(regexPattern, flags);
            const text = "Sample text for conditional search testing";
            
            const matches = text.match(regex);
            res.json({ matches });
        } catch (error) {
            res.status(500).send('Search error');
        }
    });
}
// {/fact}

// Example 11: Regex injection with async/await
// {fact rule=resource-leak@v1.0 defects=1}
async function bad_case_11() {
    const app = express();
    
    app.get('/async-search', async (req: Request, res: Response) => {
        const pattern = req.query.pattern as string;
        
        try {
            // Simulate fetching some data
            const data = await Promise.resolve("Text to search through");
            
            // ruleid: regex-injection-dos-ts-rule
            const regex = new RegExp(pattern);
            const hasMatch = regex.test(data);
            
            res.json({ hasMatch });
        } catch (error) {
            res.status(500).send('Search error');
        }
    });
}
// {/fact}

// Example 12: Regex injection with error handling
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_12() {
    const app = express();
    
    app.get('/safe-search', (req: Request, res: Response) => {
        const pattern = req.query.pattern as string;
        
        if (!pattern || pattern.length > 100) {
            res.status(400).send('Pattern is required and must be less than 100 characters');
            return;
        }
        
        try {
            // ruleid: regex-injection-dos-ts-rule
            const regex = new RegExp(pattern);
            const text = "Text to search through safely";
            
            const hasMatch = regex.test(text);
            res.json({ hasMatch });
        } catch (error) {
            res.status(400).send('Invalid regex pattern');
        }
    });
}
// {/fact}

// Example 13: Regex injection with multiple regex operations
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_13() {
    const app = express();
    
    app.get('/multi-regex', (req: Request, res: Response) => {
        const includePattern = req.query.include as string;
        const excludePattern = req.query.exclude as string;
        
        const items = ['apple', 'banana', 'cherry', 'date'];
        let filteredItems = [...items];
        
        try {
            if (includePattern) {
                // ruleid: regex-injection-dos-ts-rule
                const includeRegex = new RegExp(includePattern, 'i');
                filteredItems = filteredItems.filter(item => includeRegex.test(item));
            }
            
            if (excludePattern) {
                // This is another instance but we only need one ruleid per function
                const excludeRegex = new RegExp(excludePattern, 'i');
                filteredItems = filteredItems.filter(item => !excludeRegex.test(item));
            }
            
            res.json({ filteredItems });
        } catch (error) {
            res.status(400).send('Invalid regex pattern');
        }
    });
}
// {/fact}

// Example 14: Regex injection with user input processing
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_14() {
    const app = express();
    
    app.get('/processed-search', (req: Request, res: Response) => {
        let pattern = req.query.pattern as string;
        
        // Some processing that doesn't make it safe
        pattern = pattern.toLowerCase().trim();
        
        try {
            // ruleid: regex-injection-dos-ts-rule
            const regex = new RegExp(pattern);
            const text = "Text to search through with processed pattern";
            
            const hasMatch = regex.test(text);
            res.json({ hasMatch });
        } catch (error) {
            res.status(400).send('Invalid regex pattern');
        }
    });
}
// {/fact}

// Example 15: Regex injection with dynamic flag construction
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_15() {
    const app = express();
    
    app.get('/dynamic-flags', (req: Request, res: Response) => {
        const pattern = req.query.pattern as string;
        const caseSensitive = req.query.caseSensitive === 'true';
        const global = req.query.global === 'true';
        
        let flags = '';
        if (!caseSensitive) flags += 'i';
        if (global) flags += 'g';
        
        try {
            // ruleid: regex-injection-dos-ts-rule
            const regex = new RegExp(pattern, flags);
            const text = "Text to search with dynamic flags";
            
            const matches = text.match(regex);
            res.json({ matches });
        } catch (error) {
            res.status(400).send('Invalid regex pattern');
        }
    });
}
// {/fact}

// True Negative Examples (Safe Code)

// Example 1: Using a hardcoded regex pattern
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_1() {
    const app = express();
    
    app.get('/search', (req: Request, res: Response) => {
        const searchTerm = req.query.term as string;
        
        // ok: regex-injection-dos-ts-rule
        const regex = new RegExp('^[a-zA-Z0-9]+$');
        const isAlphanumeric = regex.test(searchTerm);
        
        res.json({ isAlphanumeric });
    });
}
// {/fact}

// Example 2: Using a predefined set of patterns
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_2() {
    const app = express();
    
    app.get('/validate', (req: Request, res: Response) => {
        const patternType = req.query.type as string;
        const textToValidate = req.query.text as string;
        
        const patterns = {
            email: '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$',
            phone: '^\\d{10}$',
            zipcode: '^\\d{5}(-\\d{4})?$'
        };
        
        if (!patterns[patternType]) {
            return res.status(400).send('Invalid pattern type');
        }
        
        // ok: regex-injection-dos-ts-rule
        const regex = new RegExp(patterns[patternType]);
        const isValid = regex.test(textToValidate);
        
        res.json({ isValid });
    });
}
// {/fact}

// Example 3: Using regex literal instead of constructor
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_3() {
    const app = express();
    
    app.get('/search', (req: Request, res: Response) => {
        const searchTerm = req.query.term as string;
        
        // ok: regex-injection-dos-ts-rule
        const regex = /^[a-zA-Z0-9\s]+$/;
        const isValid = regex.test(searchTerm);
        
        res.json({ isValid });
    });
}
// {/fact}

// Example 4: Using a whitelist approach for regex patterns
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_4() {
    const app = express();
    
    app.get('/search', (req: Request, res: Response) => {
        const patternId = req.query.patternId as string;
        const text = req.query.text as string;
        
        const allowedPatterns = {
            'alphanumeric': '^[a-zA-Z0-9]+$',
            'email': '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$',
            'date': '^\\d{4}-\\d{2}-\\d{2}$'
        };
        
        if (!allowedPatterns[patternId]) {
            return res.status(400).send('Invalid pattern ID');
        }
        
        // ok: regex-injection-dos-ts-rule
        const regex = new RegExp(allowedPatterns[patternId]);
        const isMatch = regex.test(text);
        
        res.json({ isMatch });
    });
}
// {/fact}

// Example 5: Using a function to create safe regex patterns
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_5() {
    const app = express();
    
    app.get('/search', (req: Request, res: Response) => {
        const searchType = req.query.type as string;
        const searchTerm = req.query.term as string;
        
        function getSafeRegexPattern(type: string): string {
            switch (type) {
                case 'username':
                    return '^[a-zA-Z0-9_]{3,16}$';
                case 'email':
                    return '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$';
                default:
                    return '^[a-zA-Z0-9\\s]+$';
            }
        }
        
        // ok: regex-injection-dos-ts-rule
        const regex = new RegExp(getSafeRegexPattern(searchType));
        const isValid = regex.test(searchTerm);
        
        res.json({ isValid });
    });
}
// {/fact}

// Example 6: Using a map of predefined regex objects
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_6() {
    const app = express();
    
    app.get('/validate', (req: Request, res: Response) => {
        const validationType = req.query.type as string;
        const input = req.query.input as string;
        
        const validationRegexes = {
            email: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
            phone: /^\d{10}$/,
            zipcode: /^\d{5}(-\d{4})?$/
        };
        
        if (!validationRegexes[validationType]) {
            return res.status(400).send('Invalid validation type');
        }
        
        // ok: regex-injection-dos-ts-rule
        const isValid = validationRegexes[validationType].test(input);
        
        res.json({ isValid });
    });
}
// {/fact}

// Example 7: Using template literals with hardcoded values
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_7() {
    const app = express();
    
    app.get('/search', (req: Request, res: Response) => {
        const searchTerm = req.query.term as string;
        const searchField = req.query.field as string;
        
        // These are hardcoded values, not user input
        const prefix = '^';
        const suffix = '$';
        
        // ok: regex-injection-dos-ts-rule
        const regex = new RegExp(`${prefix}[a-zA-Z0-9]+${suffix}`);
        const isValid = regex.test(searchTerm);
        
        res.json({ field: searchField, isValid });
    });
}
// {/fact}

// Example 8: Using regex with safe user input handling
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_8() {
    const app = express();
    
    app.get('/search', (req: Request, res: Response) => {
        const searchTerm = req.query.term as string;
        
        // Escaping user input for literal matching
        const escapedTerm = searchTerm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        
        // ok: regex-injection-dos-ts-rule
        const regex = new RegExp(`\\b${escapedTerm}\\b`, 'i');
        const text = "This is a sample text for searching";
        
        const hasMatch = regex.test(text);
        res.json({ hasMatch });
    });
}
// {/fact}

// Example 9: Using a safe regex builder function
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_9() {
    const app = express();
    
    app.get('/search', (req: Request, res: Response) => {
        const searchType = req.query.type as string;
        const searchTerm = req.query.term as string;
        
        function buildSafeRegex(type: string): RegExp {
            switch (type) {
                case 'username':
                    // ok: regex-injection-dos-ts-rule
                    return new RegExp('^[a-zA-Z0-9_]{3,16}$');
                case 'email':
                    return new RegExp('^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$');
                default:
                    return new RegExp('^[a-zA-Z0-9\\s]+$');
            }
        }
        
        const regex = buildSafeRegex(searchType);
        const isValid = regex.test(searchTerm);
        
        res.json({ isValid });
    });
}
// {/fact}

// Example 10: Using a validation library with safe regex
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_10() {
    const app = express();
    
    app.get('/validate', (req: Request, res: Response) => {
        const email = req.query.email as string;
        
        class Validator {
            static isEmail(input: string): boolean {
                // ok: regex-injection-dos-ts-rule
                const emailRegex = new RegExp('^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$');
                return emailRegex.test(input);
            }
        }
        
        const isValidEmail = Validator.isEmail(email);
        res.json({ isValidEmail });
    });
}
// {/fact}

// Example 11: Using regex constants
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_11() {
    const app = express();
    
    app.get('/validate', (req: Request, res: Response) => {
        const input = req.query.input as string;
        const type = req.query.type as string;
        
        const EMAIL_PATTERN = '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$';
        const USERNAME_PATTERN = '^[a-zA-Z0-9_]{3,16}$';
        const ZIP_PATTERN = '^\\d{5}(-\\d{4})?$';
        
        let pattern: string;
        
        switch (type) {
            case 'email':
                pattern = EMAIL_PATTERN;
                break;
            case 'username':
                pattern = USERNAME_PATTERN;
                break;
            case 'zip':
                pattern = ZIP_PATTERN;
                break;
            default:
                return res.status(400).send('Invalid validation type');
        }
        
        // ok: regex-injection-dos-ts-rule
        const regex = new RegExp(pattern);
        const isValid = regex.test(input);
        
        res.json({ isValid });
    });
}
// {/fact}

// Example 12: Using regex with safe input transformation
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_12() {
    const app = express();
    
    app.get('/search', (req: Request, res: Response) => {
        const searchTerm = req.query.term as string;
        
        // Transform user input into a safe pattern for literal matching
        const words = searchTerm.split(' ').filter(word => /^[a-zA-Z0-9]+$/.test(word));
        const safePattern = words.map(word => `\\b${word}\\b`).join('|');
        
        if (safePattern) {
            // ok: regex-injection-dos-ts-rule
            const regex = new RegExp(safePattern, 'gi');
            const text = "This is a sample text for searching";
            
            const matches = text.match(regex) || [];
            res.json({ matches });
        } else {
            res.json({ matches: [] });
        }
    });
}
// {/fact}

// Example 13: Using a factory function for creating safe regexes
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_13() {
    const app = express();
    
    app.get('/validate', (req: Request, res: Response) => {
        const validationType = req.query.type as string;
        const input = req.query.input as string;
        
        class RegexFactory {
            static createRegex(type: string): RegExp | null {
                const patterns = {
                    email: '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$',
                    phone: '^\\d{10}$',
                    zipcode: '^\\d{5}(-\\d{4})?$'
                };
                
                if (!patterns[type]) return null;
                
                // ok: regex-injection-dos-ts-rule
                return new RegExp(patterns[type]);
            }
        }
        
        const regex = RegexFactory.createRegex(validationType);
        
        if (!regex) {
            return res.status(400).send('Invalid validation type');
        }
        
        const isValid = regex.test(input);
        res.json({ isValid });
    });
}
// {/fact}

// Example 14: Using a configuration object for regex patterns
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_14() {
    const app = express();
    
    app.get('/validate', (req: Request, res: Response) => {
        const validationType = req.query.type as string;
        const input = req.query.input as string;
        
        const config = {
            validationPatterns: {
                email: '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$',
                phone: '^\\d{10}$',
                zipcode: '^\\d{5}(-\\d{4})?$'
            }
        };
        
        if (!config.validationPatterns[validationType]) {
            return res.status(400).send('Invalid validation type');
        }
        
        // ok: regex-injection-dos-ts-rule
        const regex = new RegExp(config.validationPatterns[validationType]);
        const isValid = regex.test(input);
        
        res.json({ isValid });
    });
}
// {/fact}

// Example 15: Using a class-based approach for validation
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_15() {
    const app = express();
    
    app.get('/validate', (req: Request, res: Response) => {
        const validationType = req.query.type as string;
        const input = req.query.input as string;
        
        class InputValidator {
            private static patterns = {
                email: '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$',
                phone: '^\\d{10}$',
                zipcode: '^\\d{5}(-\\d{4})?$'
            };
            
            static validate(type: string, input: string): boolean {
                if (!this.patterns[type]) return false;
                
                // ok: regex-injection-dos-ts-rule
                const regex = new RegExp(this.patterns[type]);
                return regex.test(input);
            }
        }
        
        if (!InputValidator.validate(validationType, input)) {
            return res.status(400).send('Validation failed');
        }
        
        res.json({ success: true });
    });
}
// {/fact}