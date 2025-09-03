import * as http from 'http';
import * as url from 'url';
import * as express from 'express';
import * as querystring from 'querystring';

// True Positive Examples (Vulnerable Code)

// Example 1: Basic regex DoS with user input from query parameter
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_1() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const userInput = parsedUrl.query.input as string;
        
        if (userInput) {
            const regex = new RegExp(`^(${userInput})+$`);
            // ruleid: typescript-regex-dos-attack
            const isMatch = regex.test("test string");
            
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end(`Match result: ${isMatch}`);
        }
    });
    server.listen(3000);
}
// {/fact}

// Example 2: Using exec with user input from POST data
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_2() {
    const server = http.createServer((req, res) => {
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
        });
        
        req.on('end', () => {
            const postData = querystring.parse(body);
            const pattern = postData.pattern as string;
            
            const regex = new RegExp(pattern);
            // ruleid: typescript-regex-dos-attack
            const result = regex.exec("test string");
            
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end(`Match result: ${result}`);
        });
    });
    server.listen(3000);
}
// {/fact}

// Example 3: Using regex with user input from HTTP headers
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_3() {
    const server = http.createServer((req, res) => {
        const userPattern = req.headers['x-custom-pattern'] as string;
        
        if (userPattern) {
            const regex = new RegExp(userPattern, 'g');
            // ruleid: typescript-regex-dos-attack
            const isMatch = regex.test("test string");
            
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end(`Match result: ${isMatch}`);
        }
    });
    server.listen(3000);
}
// {/fact}

// Example 4: Using regex with user input in Express
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_4() {
    const app = express();
    
    app.get('/validate', (req, res) => {
        const userPattern = req.query.pattern as string;
        const textToMatch = req.query.text as string || "default text";
        
        const regex = new RegExp(userPattern);
        // ruleid: typescript-regex-dos-attack
        const matches = regex.exec(textToMatch);
        
        res.send({ matches });
    });
    
    app.listen(3000);
}
// {/fact}

// Example 5: Using regex with concatenated user input
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_5() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const prefix = parsedUrl.query.prefix as string || '';
        const suffix = parsedUrl.query.suffix as string || '';
        
        const pattern = prefix + '.*' + suffix;
        const regex = new RegExp(pattern);
        // ruleid: typescript-regex-dos-attack
        const isMatch = regex.test("test string");
        
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(`Match result: ${isMatch}`);
    });
    server.listen(3000);
}
// {/fact}

// Example 6: Using regex with user input after some processing
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_6() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        let userInput = parsedUrl.query.input as string;
        
        // Some processing that doesn't sanitize the regex vulnerability
        userInput = userInput.toLowerCase().trim();
        
        const regex = new RegExp(userInput);
        // ruleid: typescript-regex-dos-attack
        const isMatch = regex.test("test string");
        
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(`Match result: ${isMatch}`);
    });
    server.listen(3000);
}
// {/fact}

// Example 7: Using regex with user input in a loop
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_7() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const userPattern = parsedUrl.query.pattern as string;
        const testStrings = ["test1", "test2", "test3"];
        
        const regex = new RegExp(userPattern);
        const results = [];
        
        for (const str of testStrings) {
            // ruleid: typescript-regex-dos-attack
            const isMatch = regex.test(str);
            results.push(isMatch);
        }
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(results));
    });
    server.listen(3000);
}
// {/fact}

// Example 8: Using regex with user input in a conditional
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_8() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const userPattern = parsedUrl.query.pattern as string;
        const testString = parsedUrl.query.test as string || "default";
        
        if (userPattern && userPattern.length > 0) {
            const regex = new RegExp(userPattern);
            // ruleid: typescript-regex-dos-attack
            if (regex.test(testString)) {
                res.writeHead(200, { 'Content-Type': 'text/plain' });
                res.end("Pattern matched!");
            } else {
                res.writeHead(200, { 'Content-Type': 'text/plain' });
                res.end("Pattern did not match.");
            }
        }
    });
    server.listen(3000);
}
// {/fact}

// Example 9: Using regex with user input in a callback
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_9() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const userPattern = parsedUrl.query.pattern as string;
        
        processPattern(userPattern, (regex) => {
            // ruleid: typescript-regex-dos-attack
            const isMatch = regex.test("test string");
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end(`Match result: ${isMatch}`);
        });
    });
    
    function processPattern(pattern: string, callback: (regex: RegExp) => void) {
        const regex = new RegExp(pattern);
        callback(regex);
    }
    
    server.listen(3000);
}
// {/fact}

// Example 10: Using regex with user input in a promise
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_10() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const userPattern = parsedUrl.query.pattern as string;
        
        createRegex(userPattern)
            .then(regex => {
                // ruleid: typescript-regex-dos-attack
                const isMatch = regex.exec("test string");
                res.writeHead(200, { 'Content-Type': 'text/plain' });
                res.end(`Match result: ${isMatch !== null}`);
            })
            .catch(err => {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end(`Error: ${err.message}`);
            });
    });
    
    function createRegex(pattern: string): Promise<RegExp> {
        return new Promise((resolve, reject) => {
            try {
                const regex = new RegExp(pattern);
                resolve(regex);
            } catch (err) {
                reject(err);
            }
        });
    }
    
    server.listen(3000);
}
// {/fact}

// Example 11: Using regex with user input in an async function
// {fact rule=incorrect-expression@v1.0 defects=1}
async function bad_case_11() {
    const server = http.createServer(async (req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const userPattern = parsedUrl.query.pattern as string;
        
        try {
            const regex = new RegExp(userPattern);
            // ruleid: typescript-regex-dos-attack
            const isMatch = regex.test("test string");
            
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end(`Match result: ${isMatch}`);
        } catch (err) {
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end(`Error: ${err.message}`);
        }
    });
    server.listen(3000);
}
// {/fact}

// Example 12: Using regex with user input from cookies
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_12() {
    const server = http.createServer((req, res) => {
        const cookies = req.headers.cookie || '';
        const cookieParts = cookies.split(';');
        let patternCookie = '';
        
        for (const cookie of cookieParts) {
            const [name, value] = cookie.trim().split('=');
            if (name === 'pattern') {
                patternCookie = value;
                break;
            }
        }
        
        if (patternCookie) {
            const regex = new RegExp(patternCookie);
            // ruleid: typescript-regex-dos-attack
            const isMatch = regex.test("test string");
            
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end(`Match result: ${isMatch}`);
        }
    });
    server.listen(3000);
}
// {/fact}

// Example 13: Using regex with user input in a switch statement
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_13() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const userPattern = parsedUrl.query.pattern as string;
        const mode = parsedUrl.query.mode as string || 'test';
        
        const regex = new RegExp(userPattern);
        
        switch (mode) {
            case 'test':
                // ruleid: typescript-regex-dos-attack
                const isMatch = regex.test("test string");
                res.writeHead(200, { 'Content-Type': 'text/plain' });
                res.end(`Test result: ${isMatch}`);
                break;
            case 'exec':
                // ruleid: typescript-regex-dos-attack
                const execResult = regex.exec("test string");
                res.writeHead(200, { 'Content-Type': 'text/plain' });
                res.end(`Exec result: ${execResult !== null}`);
                break;
            default:
                res.writeHead(400, { 'Content-Type': 'text/plain' });
                res.end("Invalid mode");
        }
    });
    server.listen(3000);
}
// {/fact}

// Example 14: Using regex with user input in a try-catch block
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_14() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const userPattern = parsedUrl.query.pattern as string;
        
        try {
            const regex = new RegExp(userPattern);
            // ruleid: typescript-regex-dos-attack
            const isMatch = regex.test("test string");
            
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end(`Match result: ${isMatch}`);
        } catch (err) {
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end(`Error creating regex: ${err.message}`);
        }
    });
    server.listen(3000);
}
// {/fact}

// Example 15: Using regex with user input in a class method
// {fact rule=incorrect-expression@v1.0 defects=1}
function bad_case_15() {
    class PatternMatcher {
        private pattern: string;
        
        constructor(pattern: string) {
            this.pattern = pattern;
        }
        
        public test(input: string): boolean {
            const regex = new RegExp(this.pattern);
            // ruleid: typescript-regex-dos-attack
            return regex.test(input);
        }
    }
    
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const userPattern = parsedUrl.query.pattern as string;
        
        const matcher = new PatternMatcher(userPattern);
        const isMatch = matcher.test("test string");
        
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(`Match result: ${isMatch}`);
    });
    server.listen(3000);
}
// {/fact}

// True Negative Examples (Safe Code)

// Example 1: Using a hardcoded regex pattern
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_1() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const testString = parsedUrl.query.test as string || '';
        
        // ok: typescript-regex-dos-attack
        const regex = new RegExp('^[a-zA-Z0-9]+$');
        const isMatch = regex.test(testString);
        
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(`Match result: ${isMatch}`);
    });
    server.listen(3000);
}
// {/fact}

// Example 2: Using a safe regex pattern with user input
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_2() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const userInput = parsedUrl.query.input as string;
        
        // Validate user input before using it
        if (!/^[a-zA-Z0-9]+$/.test(userInput)) {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            res.end("Invalid input");
            return;
        }
        
        // ok: typescript-regex-dos-attack
        const regex = new RegExp(`^${userInput}$`);
        const isMatch = regex.test("test string");
        
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(`Match result: ${isMatch}`);
    });
    server.listen(3000);
}
// {/fact}

// Example 3: Using regex.test with a timeout to prevent DoS
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_3() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const userPattern = parsedUrl.query.pattern as string;
        
        // Set a timeout to prevent long-running regex operations
        const timeoutMs = 100;
        let isMatch = false;
        
        const timeoutId = setTimeout(() => {
            res.writeHead(408, { 'Content-Type': 'text/plain' });
            res.end("Regex execution timed out");
        }, timeoutMs);
        
        try {
            // ok: typescript-regex-dos-attack
            // Using a safe pattern with limited repetition
            const safePattern = userPattern.replace(/[*+?]{2,}/g, '*');
            const regex = new RegExp(safePattern);
            isMatch = regex.test("test string");
            
            clearTimeout(timeoutId);
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end(`Match result: ${isMatch}`);
        } catch (err) {
            clearTimeout(timeoutId);
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end(`Error: ${err.message}`);
        }
    });
    server.listen(3000);
}
// {/fact}

// Example 4: Using a whitelist of allowed patterns
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_4() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const patternId = parsedUrl.query.patternId as string;
        
        // Whitelist of allowed patterns
        const allowedPatterns: Record<string, string> = {
            'email': '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$',
            'phone': '^\\d{3}-\\d{3}-\\d{4}$',
            'zipcode': '^\\d{5}(-\\d{4})?$'
        };
        
        if (patternId && patternId in allowedPatterns) {
            // ok: typescript-regex-dos-attack
            const regex = new RegExp(allowedPatterns[patternId]);
            const testString = parsedUrl.query.test as string || '';
            const isMatch = regex.test(testString);
            
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end(`Match result: ${isMatch}`);
        } else {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            res.end("Invalid pattern ID");
        }
    });
    server.listen(3000);
}
// {/fact}

// Example 5: Using a regex validator before using user input
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_5() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const userPattern = parsedUrl.query.pattern as string;
        
        // Check if the pattern is safe (no excessive repetition)
        if (!/^[^*+?{}]*(([*+?]|\{\d+\}|\{\d+,\d*\})[^*+?{}]*)*$/.test(userPattern)) {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            res.end("Potentially unsafe regex pattern");
            return;
        }
        
        try {
            // ok: typescript-regex-dos-attack
            const regex = new RegExp(userPattern);
            const isMatch = regex.test("test string");
            
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end(`Match result: ${isMatch}`);
        } catch (err) {
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end(`Error: ${err.message}`);
        }
    });
    server.listen(3000);
}
// {/fact}

// Example 6: Using a regex library with DoS protection
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_6() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const userPattern = parsedUrl.query.pattern as string;
        
        // This is a hypothetical safe regex library that prevents DoS
        class SafeRegex {
            private pattern: string;
            
            constructor(pattern: string) {
                this.pattern = pattern;
            }
            
            public test(input: string): boolean {
                // Implementation with timeout and complexity checks
                const maxSteps = 1000;
                let steps = 0;
                
                // Simple simulation of a safe regex engine
                try {
                    const regex = new RegExp(this.pattern);
                    // ok: typescript-regex-dos-attack
                    // Using a safe wrapper around the regex
                    return regex.test(input);
                } catch (err) {
                    return false;
                }
            }
        }
        
        const safeRegex = new SafeRegex(userPattern);
        const isMatch = safeRegex.test("test string");
        
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(`Match result: ${isMatch}`);
    });
    server.listen(3000);
}
// {/fact}

// Example 7: Using a regex with length limits
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_7() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const userPattern = parsedUrl.query.pattern as string;
        const testString = parsedUrl.query.test as string || "test string";
        
        // Limit the length of both pattern and test string
        if (userPattern && userPattern.length <= 50 && testString.length <= 100) {
            try {
                // ok: typescript-regex-dos-attack
                const regex = new RegExp(`^${userPattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`);
                const isMatch = regex.test(testString);
                
                res.writeHead(200, { 'Content-Type': 'text/plain' });
                res.end(`Match result: ${isMatch}`);
            } catch (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end(`Error: ${err.message}`);
            }
        } else {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            res.end("Pattern or test string too long");
        }
    });
    server.listen(3000);
}
// {/fact}

// Example 8: Using regex with a predefined set of options
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_8() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const patternType = parsedUrl.query.type as string;
        const testString = parsedUrl.query.test as string || "";
        
        let pattern: string;
        
        switch (patternType) {
            case 'email':
                pattern = '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$';
                break;
            case 'phone':
                pattern = '^\\d{3}-\\d{3}-\\d{4}$';
                break;
            case 'date':
                pattern = '^\\d{4}-\\d{2}-\\d{2}$';
                break;
            default:
                res.writeHead(400, { 'Content-Type': 'text/plain' });
                res.end("Invalid pattern type");
                return;
        }
        
        // ok: typescript-regex-dos-attack
        const regex = new RegExp(pattern);
        const isMatch = regex.test(testString);
        
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(`Match result: ${isMatch}`);
    });
    server.listen(3000);
}
// {/fact}

// Example 9: Using string methods instead of regex for simple matching
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_9() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const searchTerm = parsedUrl.query.search as string || "";
        const testString = parsedUrl.query.test as string || "";
        
        // ok: typescript-regex-dos-attack
        // Using string methods instead of regex for simple matching
        const isMatch = testString.includes(searchTerm);
        
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(`Match result: ${isMatch}`);
    });
    server.listen(3000);
}
// {/fact}

// Example 10: Using a safe regex pattern builder
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_10() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const userInput = parsedUrl.query.input as string || "";
        
        // Function to create a safe regex pattern from user input
        function createSafePattern(input: string): string {
            // Escape special characters and limit repetition
            return input.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
                        .replace(/\{(\d+)(,\d*)?\}/g, '{1}');
        }
        
        const safePattern = createSafePattern(userInput);
        // ok: typescript-regex-dos-attack
        const regex = new RegExp(safePattern);
        const isMatch = regex.test("test string");
        
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(`Match result: ${isMatch}`);
    });
    server.listen(3000);
}
// {/fact}

// Example 11: Using a regex with a complexity check
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_11() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const userPattern = parsedUrl.query.pattern as string;
        
        // Function to check regex complexity
        function isComplexRegex(pattern: string): boolean {
            // Check for nested repetition, which can cause exponential backtracking
            return /(\*|\+|\{[0-9]+,?[0-9]*\}).*(\*|\+|\{[0-9]+,?[0-9]*\})/.test(pattern);
        }
        
        if (userPattern && !isComplexRegex(userPattern)) {
            try {
                // ok: typescript-regex-dos-attack
                const regex = new RegExp(userPattern);
                const isMatch = regex.test("test string");
                
                res.writeHead(200, { 'Content-Type': 'text/plain' });
                res.end(`Match result: ${isMatch}`);
            } catch (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end(`Error: ${err.message}`);
            }
        } else {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            res.end("Pattern too complex or invalid");
        }
    });
    server.listen(3000);
}
// {/fact}

// Example 12: Using regex with a worker thread for isolation
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_12() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const userPattern = parsedUrl.query.pattern as string;
        
        // This is a simplified example. In a real implementation, you would use worker_threads
        // to isolate the regex execution
        function safeRegexTest(pattern: string, input: string, timeoutMs: number): Promise<boolean> {
            return new Promise((resolve, reject) => {
                const timeoutId = setTimeout(() => {
                    reject(new Error("Regex execution timed out"));
                }, timeoutMs);
                
                try {
                    // ok: typescript-regex-dos-attack
                    // In a real implementation, this would be executed in a worker thread
                    const regex = new RegExp(pattern);
                    const result = regex.test(input);
                    clearTimeout(timeoutId);
                    resolve(result);
                } catch (err) {
                    clearTimeout(timeoutId);
                    reject(err);
                }
            });
        }
        
        safeRegexTest(userPattern, "test string", 100)
            .then(result => {
                res.writeHead(200, { 'Content-Type': 'text/plain' });
                res.end(`Match result: ${result}`);
            })
            .catch(err => {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end(`Error: ${err.message}`);
            });
    });
    server.listen(3000);
}
// {/fact}

// Example 13: Using a safe subset of regex features
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_13() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const userInput = parsedUrl.query.input as string;
        
        // Function to create a safe pattern using only a subset of regex features
        function createSafePattern(input: string): string {
            // Remove all quantifiers and use only literal characters
            return input.replace(/[.*+?^${}()|[\]\\]/g, '');
        }
        
        if (userInput) {
            const safePattern = createSafePattern(userInput);
            // ok: typescript-regex-dos-attack
            const regex = new RegExp(safePattern);
            const isMatch = regex.test("test string");
            
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end(`Match result: ${isMatch}`);
        }
    });
    server.listen(3000);
}
// {/fact}

// Example 14: Using a lookup table instead of dynamic regex
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_14() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const patternKey = parsedUrl.query.key as string;
        const testString = parsedUrl.query.test as string || "";
        
        // Predefined patterns in a lookup table
        const patternTable: Record<string, RegExp> = {
            'email': /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
            'phone': /^\d{3}-\d{3}-\d{4}$/,
            'zipcode': /^\d{5}(-\d{4})?$/,
            'username': /^[a-zA-Z0-9_]{3,20}$/
        };
        
        if (patternKey && patternKey in patternTable) {
            // ok: typescript-regex-dos-attack
            const isMatch = patternTable[patternKey].test(testString);
            
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end(`Match result: ${isMatch}`);
        } else {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            res.end("Invalid pattern key");
        }
    });
    server.listen(3000);
}
// {/fact}

// Example 15: Using a validation library instead of direct regex
// {fact rule=incorrect-expression@v1.0 defects=0}
function good_case_15() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        const email = parsedUrl.query.email as string;
        
        // Hypothetical validation library that uses safe regex patterns internally
        class Validator {
            static isEmail(input: string): boolean {
                // ok: typescript-regex-dos-attack
                // Using a safe, predefined pattern
                return /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(input);
            }
            
            static isPhone(input: string): boolean {
                return /^\d{3}-\d{3}-\d{4}$/.test(input);
            }
            
            static isZipCode(input: string): boolean {
                return /^\d{5}(-\d{4})?$/.test(input);
            }
        }
        
        const isValidEmail = Validator.isEmail(email);
        
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(`Email validation result: ${isValidEmail}`);
    });
    server.listen(3000);
}
// {/fact}