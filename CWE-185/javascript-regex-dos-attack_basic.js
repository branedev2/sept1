// JavaScript Regular Expression Denial of Service (ReDoS) Examples
// Rule ID: javascript-regex-dos-attack

// Import necessary modules for HTTP handling
const express = require('express');
const http = require('http');
const url = require('url');

// ==================== TRUE POSITIVES (VULNERABLE CODE) ====================

// Example 1: Basic ReDoS with user input from query parameter
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_1() {
    const app = express();
    
    app.get('/search', (req, res) => {
        const userInput = req.query.term;
        const regex = new RegExp(userInput);
        const testString = "This is a test string to match against";
        
        // ruleid: javascript-regex-dos-attack
        const isMatch = regex.test(testString);
        
        res.send({ matched: isMatch });
    });
}
// {/fact}

// Example 2: ReDoS with user input from POST body
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_2() {
    const app = express();
    app.use(express.json());
    
    app.post('/validate', (req, res) => {
        const pattern = req.body.pattern;
        const regex = new RegExp(pattern, 'i');
        const textToCheck = "Validating this text with user regex";
        
        // ruleid: javascript-regex-dos-attack
        const matches = regex.exec(textToCheck);
        
        res.json({ matches: matches !== null });
    });
}
// {/fact}

// Example 3: ReDoS with user input from URL parameter and complex regex options
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_3() {
    const app = express();
    
    app.get('/users/:pattern', (req, res) => {
        const userPattern = req.params.pattern;
        const regex = new RegExp(userPattern, 'gm');
        const dataToSearch = "Multiple\nlines\nof\ntext\nto\nsearch";
        
        // ruleid: javascript-regex-dos-attack
        const result = regex.test(dataToSearch);
        
        res.send({ result });
    });
}
// {/fact}

// Example 4: ReDoS with user input from headers
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_4() {
    const app = express();
    
    app.get('/validate-header', (req, res) => {
        const customPattern = req.headers['x-custom-pattern'];
        const regex = new RegExp(customPattern);
        const content = "Content to validate against header-provided pattern";
        
        // ruleid: javascript-regex-dos-attack
        const matches = regex.exec(content);
        
        res.json({ valid: matches !== null });
    });
}
// {/fact}

// Example 5: ReDoS with user input from cookies
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_5() {
    const app = express();
    app.use(require('cookie-parser')());
    
    app.get('/cookie-pattern', (req, res) => {
        const savedPattern = req.cookies.savedPattern;
        const regex = new RegExp(savedPattern);
        const textToMatch = "Text to match against cookie-stored pattern";
        
        // ruleid: javascript-regex-dos-attack
        const isMatch = regex.test(textToMatch);
        
        res.send({ matched: isMatch });
    });
}
// {/fact}

// Example 6: ReDoS with user input processed before regex creation
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_6() {
    const app = express();
    
    app.get('/process-pattern', (req, res) => {
        let userPattern = req.query.pattern;
        // Some processing that doesn't sanitize the ReDoS vulnerability
        userPattern = userPattern.replace(/\s+/g, '');
        
        const regex = new RegExp(userPattern);
        const content = "Content to check against processed pattern";
        
        // ruleid: javascript-regex-dos-attack
        const result = regex.exec(content);
        
        res.json({ matched: result !== null });
    });
}
// {/fact}

// Example 7: ReDoS with user input in a more complex flow
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_7() {
    const app = express();
    app.use(express.json());
    
    app.post('/advanced-search', (req, res) => {
        const searchConfig = req.body.config;
        const searchText = req.body.text;
        
        if (searchConfig && searchConfig.pattern) {
            try {
                const regex = new RegExp(searchConfig.pattern, searchConfig.flags || '');
                const dataToSearch = "Text corpus to search through with user pattern";
                
                // ruleid: javascript-regex-dos-attack
                const matches = regex.test(dataToSearch);
                
                res.json({ success: true, matches });
            } catch (error) {
                res.status(400).json({ error: "Invalid regex pattern" });
            }
        } else {
            res.status(400).json({ error: "Missing search configuration" });
        }
    });
}
// {/fact}

// Example 8: ReDoS with user input from query parameter in a callback
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_8() {
    const app = express();
    
    app.get('/delayed-check', (req, res) => {
        const pattern = req.query.pattern;
        
        setTimeout(() => {
            const regex = new RegExp(pattern, 'i');
            const textToCheck = "Text to check after delay";
            
            // ruleid: javascript-regex-dos-attack
            const isMatch = regex.test(textToCheck);
            
            res.json({ matched: isMatch });
        }, 1000);
    });
}
// {/fact}

// Example 9: ReDoS with user input in a promise chain
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_9() {
    const app = express();
    app.use(express.json());
    
    app.post('/async-validate', (req, res) => {
        const userInput = req.body.pattern;
        
        Promise.resolve(userInput)
            .then(pattern => {
                const regex = new RegExp(pattern);
                const content = "Content to validate asynchronously";
                
                // ruleid: javascript-regex-dos-attack
                return regex.exec(content);
            })
            .then(result => {
                res.json({ valid: result !== null });
            })
            .catch(error => {
                res.status(500).json({ error: error.message });
            });
    });
}
// {/fact}

// Example 10: ReDoS with user input in an async/await function
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_10() {
    const app = express();
    
    app.get('/async-search', async (req, res) => {
        try {
            const searchPattern = req.query.q;
            const regex = new RegExp(searchPattern, 'g');
            const textCorpus = "Large text corpus to search through";
            
            // ruleid: javascript-regex-dos-attack
            const hasMatch = regex.test(textCorpus);
            
            res.json({ found: hasMatch });
        } catch (error) {
            res.status(500).send(error.message);
        }
    });
}
// {/fact}

// Example 11: ReDoS with user input in a switch statement
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_11() {
    const app = express();
    
    app.get('/conditional-check', (req, res) => {
        const mode = req.query.mode;
        const pattern = req.query.pattern;
        const textToCheck = "Text to check conditionally";
        let result;
        
        switch (mode) {
            case 'test':
                const testRegex = new RegExp(pattern);
                // ruleid: javascript-regex-dos-attack
                result = testRegex.test(textToCheck);
                break;
            case 'exec':
                const execRegex = new RegExp(pattern);
                // ruleid: javascript-regex-dos-attack
                result = execRegex.exec(textToCheck);
                break;
            default:
                result = false;
        }
        
        res.json({ result });
    });
}
// {/fact}

// Example 12: ReDoS with user input from multiple sources combined
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_12() {
    const app = express();
    app.use(express.json());
    
    app.post('/combined-pattern', (req, res) => {
        const prefix = req.query.prefix || '';
        const main = req.body.pattern || '';
        const suffix = req.headers['x-pattern-suffix'] || '';
        
        const combinedPattern = prefix + main + suffix;
        const regex = new RegExp(combinedPattern, 'i');
        const content = "Content to check against combined pattern";
        
        // ruleid: javascript-regex-dos-attack
        const matches = regex.test(content);
        
        res.json({ matches });
    });
}
// {/fact}

// Example 13: ReDoS with user input in a more complex regex construction
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_13() {
    const app = express();
    
    app.get('/complex-pattern', (req, res) => {
        const userPattern = req.query.pattern;
        // Creating a more complex regex with user input
        const regex = new RegExp(`^start(${userPattern})end$`, 'im');
        const textToCheck = "startSomeTextend";
        
        // ruleid: javascript-regex-dos-attack
        const result = regex.exec(textToCheck);
        
        res.json({ matched: result !== null });
    });
}
// {/fact}

// Example 14: ReDoS with user input in an error handler
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_14() {
    const app = express();
    
    app.get('/error-pattern', (req, res) => {
        try {
            throw new Error("Simulated error");
        } catch (error) {
            const fallbackPattern = req.query.fallback;
            const regex = new RegExp(fallbackPattern);
            const errorMessage = error.message;
            
            // ruleid: javascript-regex-dos-attack
            const hasMatch = regex.test(errorMessage);
            
            res.status(500).json({ error: error.message, patternMatched: hasMatch });
        }
    });
}
// {/fact}

// Example 15: ReDoS with user input in a loop
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_15() {
    const app = express();
    
    app.get('/batch-check', (req, res) => {
        const patterns = req.query.patterns.split(',');
        const results = [];
        const textToCheck = "Text to check against multiple patterns";
        
        for (let i = 0; i < patterns.length; i++) {
            const regex = new RegExp(patterns[i]);
            // ruleid: javascript-regex-dos-attack
            results.push(regex.test(textToCheck));
        }
        
        res.json({ results });
    });
}
// {/fact}

// ==================== TRUE NEGATIVES (SAFE CODE) ====================

// Example 1: Using a hardcoded regex pattern (not user-controlled)
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_1() {
    const app = express();
    
    app.get('/search', (req, res) => {
        const userInput = req.query.term;
        // ok: javascript-regex-dos-attack
        const regex = /^[a-zA-Z0-9]{1,20}$/;
        const isMatch = regex.test(userInput);
        
        res.send({ matched: isMatch });
    });
}
// {/fact}

// Example 2: Using a safe regex library for user input
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_2() {
    const app = express();
    app.use(express.json());
    const safeRegex = require('safe-regex-test'); // Hypothetical safe regex library
    
    app.post('/validate', (req, res) => {
        const pattern = req.body.pattern;
        const textToCheck = "Validating this text with user regex";
        
        // ok: javascript-regex-dos-attack
        const isMatch = safeRegex(pattern, textToCheck);
        
        res.json({ matches: isMatch });
    });
}
// {/fact}

// Example 3: Validating user input before using in regex
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_3() {
    const app = express();
    
    app.get('/users/:pattern', (req, res) => {
        const userPattern = req.params.pattern;
        
        // ok: javascript-regex-dos-attack
        // Validate that the pattern is safe before using it
        if (!/^[a-zA-Z0-9]{1,20}$/.test(userPattern)) {
            return res.status(400).send('Invalid pattern');
        }
        
        const regex = new RegExp(userPattern, 'gm');
        const dataToSearch = "Multiple\nlines\nof\ntext\nto\nsearch";
        const result = regex.test(dataToSearch);
        
        res.send({ result });
    });
}
// {/fact}

// Example 4: Using a whitelist of allowed patterns
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_4() {
    const app = express();
    
    app.get('/validate-header', (req, res) => {
        const patternKey = req.headers['x-pattern-key'];
        
        // ok: javascript-regex-dos-attack
        // Use a predefined set of safe patterns
        const safePatterns = {
            'email': /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
            'phone': /^\d{10}$/,
            'zipcode': /^\d{5}(-\d{4})?$/
        };
        
        const selectedPattern = safePatterns[patternKey];
        if (!selectedPattern) {
            return res.status(400).send('Invalid pattern key');
        }
        
        const content = "test@example.com";
        const isMatch = selectedPattern.test(content);
        
        res.json({ valid: isMatch });
    });
}
// {/fact}

// Example 5: Using regex literals instead of RegExp constructor with user input
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_5() {
    const app = express();
    app.use(require('cookie-parser')());
    
    app.get('/cookie-pattern', (req, res) => {
        const patternType = req.cookies.patternType;
        let regex;
        
        // ok: javascript-regex-dos-attack
        // Use predefined regex literals based on a user selection
        switch (patternType) {
            case 'email':
                regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
                break;
            case 'url':
                regex = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/;
                break;
            default:
                regex = /^[a-zA-Z0-9]+$/;
        }
        
        const textToMatch = "Text to match against predefined pattern";
        const isMatch = regex.test(textToMatch);
        
        res.send({ matched: isMatch });
    });
}
// {/fact}

// Example 6: Using a regex validator before creating RegExp
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_6() {
    const app = express();
    
    // Hypothetical function to check if a regex pattern is safe
    function isRegexSafe(pattern) {
        // Check for common ReDoS patterns like nested repetition
        return !/(.*){2,}.*\1/.test(pattern) && pattern.length < 100;
    }
    
    app.get('/process-pattern', (req, res) => {
        let userPattern = req.query.pattern;
        
        // ok: javascript-regex-dos-attack
        if (!isRegexSafe(userPattern)) {
            return res.status(400).send('Potentially unsafe regex pattern');
        }
        
        const regex = new RegExp(userPattern);
        const content = "Content to check against validated pattern";
        const result = regex.exec(content);
        
        res.json({ matched: result !== null });
    });
}
// {/fact}

// Example 7: Using timeout to prevent long-running regex operations
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_7() {
    const app = express();
    app.use(express.json());
    
    app.post('/advanced-search', (req, res) => {
        const searchConfig = req.body.config;
        
        if (searchConfig && searchConfig.pattern) {
            try {
                // ok: javascript-regex-dos-attack
                // Use a safe, predefined pattern instead of user input
                const safePattern = /^[a-zA-Z0-9\s]{1,100}$/;
                const dataToSearch = searchConfig.text || "";
                
                const matches = safePattern.test(dataToSearch);
                res.json({ success: true, matches });
            } catch (error) {
                res.status(400).json({ error: "Invalid search configuration" });
            }
        } else {
            res.status(400).json({ error: "Missing search configuration" });
        }
    });
}
// {/fact}

// Example 8: Using string methods instead of regex for user input
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_8() {
    const app = express();
    
    app.get('/delayed-check', (req, res) => {
        const searchTerm = req.query.term;
        
        setTimeout(() => {
            const textToCheck = "Text to check after delay";
            
            // ok: javascript-regex-dos-attack
            // Use string methods instead of regex for user input
            const isMatch = textToCheck.includes(searchTerm);
            
            res.json({ matched: isMatch });
        }, 1000);
    });
}
// {/fact}

// Example 9: Using a regex tester with complexity limits
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_9() {
    const app = express();
    app.use(express.json());
    
    // Hypothetical function to test regex with a timeout
    function safeRegexTest(pattern, input, timeoutMs = 100) {
        let result = false;
        let completed = false;
        
        try {
            const regex = new RegExp(pattern);
            const worker = new Worker('regex-worker.js'); // Hypothetical worker
            
            worker.postMessage({ regex, input });
            worker.onmessage = (e) => {
                result = e.data.result;
                completed = true;
            };
            
            setTimeout(() => {
                if (!completed) {
                    worker.terminate();
                    throw new Error('Regex execution timed out');
                }
            }, timeoutMs);
            
            return result;
        } catch (e) {
            return false;
        }
    }
    
    app.post('/async-validate', (req, res) => {
        const userInput = req.body.pattern;
        
        // ok: javascript-regex-dos-attack
        Promise.resolve()
            .then(() => {
                return safeRegexTest(userInput, "Content to validate asynchronously");
            })
            .then(result => {
                res.json({ valid: result });
            })
            .catch(error => {
                res.status(500).json({ error: error.message });
            });
    });
}
// {/fact}

// Example 10: Using predefined regex patterns based on user selection
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_10() {
    const app = express();
    
    app.get('/async-search', async (req, res) => {
        try {
            const patternType = req.query.type;
            let regex;
            
            // ok: javascript-regex-dos-attack
            // Select from predefined patterns based on user choice
            switch (patternType) {
                case 'email':
                    regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
                    break;
                case 'phone':
                    regex = /^\d{10}$/;
                    break;
                case 'date':
                    regex = /^\d{4}-\d{2}-\d{2}$/;
                    break;
                default:
                    regex = /^[a-zA-Z0-9]+$/;
            }
            
            const textCorpus = "Large text corpus to search through";
            const hasMatch = regex.test(textCorpus);
            
            res.json({ found: hasMatch });
        } catch (error) {
            res.status(500).send(error.message);
        }
    });
}
// {/fact}

// Example 11: Using a regex validator library
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_11() {
    const app = express();
    
    // Hypothetical regex validator
    function validateRegex(pattern) {
        // Check for common ReDoS patterns
        if (pattern.length > 100) return false;
        if (/(.*)\{[0-9]+,\}.*\1/.test(pattern)) return false;
        return true;
    }
    
    app.get('/conditional-check', (req, res) => {
        const mode = req.query.mode;
        const pattern = req.query.pattern;
        const textToCheck = "Text to check conditionally";
        let result;
        
        // ok: javascript-regex-dos-attack
        if (!validateRegex(pattern)) {
            return res.status(400).send('Potentially unsafe regex pattern');
        }
        
        switch (mode) {
            case 'test':
                const testRegex = new RegExp(pattern);
                result = testRegex.test(textToCheck);
                break;
            case 'exec':
                const execRegex = new RegExp(pattern);
                result = execRegex.exec(textToCheck);
                break;
            default:
                result = false;
        }
        
        res.json({ result });
    });
}
// {/fact}

// Example 12: Using predefined regex components
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_12() {
    const app = express();
    app.use(express.json());
    
    app.post('/combined-pattern', (req, res) => {
        const type = req.query.type || 'default';
        
        // ok: javascript-regex-dos-attack
        // Use predefined regex components
        const safePatterns = {
            'username': /^[a-zA-Z0-9_]{3,16}$/,
            'email': /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
            'default': /^[a-zA-Z0-9]+$/
        };
        
        const selectedPattern = safePatterns[type] || safePatterns.default;
        const content = req.body.content || '';
        const matches = selectedPattern.test(content);
        
        res.json({ matches });
    });
}
// {/fact}

// Example 13: Using a regex complexity analyzer
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_13() {
    const app = express();
    
    // Hypothetical function to analyze regex complexity
    function analyzeRegexComplexity(pattern) {
        // Check for nested quantifiers, backreferences, etc.
        const nestedQuantifiers = /\{[0-9,]+\}.*\{[0-9,]+\}/.test(pattern);
        const backreferences = /\\\d+/.test(pattern);
        const complexGrouping = /\(.*\(.*\).*\)/.test(pattern);
        
        return {
            safe: !(nestedQuantifiers || backreferences || complexGrouping),
            issues: {
                nestedQuantifiers,
                backreferences,
                complexGrouping
            }
        };
    }
    
    app.get('/complex-pattern', (req, res) => {
        const userPattern = req.query.pattern;
        
        // ok: javascript-regex-dos-attack
        const analysis = analyzeRegexComplexity(userPattern);
        if (!analysis.safe) {
            return res.status(400).json({
                error: 'Potentially unsafe regex pattern',
                issues: analysis.issues
            });
        }
        
        const regex = new RegExp(userPattern);
        const textToCheck = "Text to check against analyzed pattern";
        const result = regex.test(textToCheck);
        
        res.json({ matched: result });
    });
}
// {/fact}

// Example 14: Using a regex sandbox with time limits
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_14() {
    const app = express();
    
    // Hypothetical function to execute regex with a time limit
    function sandboxedRegexTest(pattern, input, timeLimit = 50) {
        let timedOut = false;
        const timeout = setTimeout(() => {
            timedOut = true;
        }, timeLimit);
        
        try {
            const regex = new RegExp(pattern);
            const result = regex.test(input);
            clearTimeout(timeout);
            return timedOut ? null : result;
        } catch (error) {
            clearTimeout(timeout);
            return null;
        }
    }
    
    app.get('/error-pattern', (req, res) => {
        try {
            throw new Error("Simulated error");
        } catch (error) {
            const fallbackPattern = req.query.fallback;
            const errorMessage = error.message;
            
            // ok: javascript-regex-dos-attack
            const result = sandboxedRegexTest(fallbackPattern, errorMessage);
            
            if (result === null) {
                res.status(400).json({ error: "Regex execution failed or timed out" });
            } else {
                res.status(500).json({ error: error.message, patternMatched: result });
            }
        }
    });
}
// {/fact}

// Example 15: Using a pattern whitelist
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_15() {
    const app = express();
    
    app.get('/batch-check', (req, res) => {
        const patternKeys = req.query.patterns.split(',');
        const results = [];
        const textToCheck = "Text to check against multiple patterns";
        
        // ok: javascript-regex-dos-attack
        // Use a whitelist of predefined patterns
        const safePatterns = {
            'alpha': /^[a-zA-Z]+$/,
            'numeric': /^[0-9]+$/,
            'alphanumeric': /^[a-zA-Z0-9]+$/,
            'email': /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
            'date': /^\d{4}-\d{2}-\d{2}$/
        };
        
        for (let i = 0; i < patternKeys.length; i++) {
            const regex = safePatterns[patternKeys[i]];
            if (regex) {
                results.push(regex.test(textToCheck));
            } else {
                results.push(null); // Invalid pattern key
            }
        }
        
        res.json({ results });
    });
}
// {/fact}