// File: loop_injection_examples.ts

import * as http from 'http';
import * as url from 'url';
import * as querystring from 'querystring';
import * as express from 'express';

// TRUE POSITIVES (Vulnerable Code)

// Example 1: Basic for-in loop over user input without validation
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_1(req: http.IncomingMessage, res: http.ServerResponse) {
    const parsedUrl = url.parse(req.url || '', true);
    const userObject = parsedUrl.query.data;
    
    // ruleid: typescript-loop-injection
    for (const key in userObject) {
        console.log(`Key: ${key}, Value: ${userObject[key]}`);
    }
    
    res.end('Processing complete');
}
// {/fact}

// Example 2: Using Object.keys on user input without validation
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_2(req: http.IncomingMessage, res: http.ServerResponse) {
    const body = '';
    req.on('data', chunk => {
        body += chunk.toString();
    });
    
    req.on('end', () => {
        const userData = JSON.parse(body);
        
        // ruleid: typescript-loop-injection
        Object.keys(userData).forEach(key => {
            console.log(`Processing ${key}: ${userData[key]}`);
        });
        
        res.end('Data processed');
    });
}
// {/fact}

// Example 3: Using Object.entries on user input without validation
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_3(req: http.IncomingMessage, res: http.ServerResponse) {
    const parsedUrl = url.parse(req.url || '', true);
    const userConfig = parsedUrl.query.config;
    
    // ruleid: typescript-loop-injection
    for (const [key, value] of Object.entries(userConfig)) {
        console.log(`Config ${key} set to ${value}`);
    }
    
    res.end('Configuration applied');
}
// {/fact}

// Example 4: Using Object.values on user input without validation
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_4(req: http.IncomingMessage, res: http.ServerResponse) {
    let body = '';
    req.on('data', chunk => {
        body += chunk.toString();
    });
    
    req.on('end', () => {
        const userPreferences = JSON.parse(body);
        
        // ruleid: typescript-loop-injection
        Object.values(userPreferences).forEach(value => {
            console.log(`Processing preference: ${value}`);
        });
        
        res.end('Preferences updated');
    });
}
// {/fact}

// Example 5: Using for-of loop with Object.keys on user input
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_5(req: http.IncomingMessage, res: http.ServerResponse) {
    const parsedUrl = url.parse(req.url || '', true);
    const userSettings = parsedUrl.query.settings;
    
    // ruleid: typescript-loop-injection
    for (const key of Object.keys(userSettings)) {
        console.log(`Setting ${key} = ${userSettings[key]}`);
    }
    
    res.end('Settings applied');
}
// {/fact}

// Example 6: Using while loop with Object.keys on user input
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_6(req: http.IncomingMessage, res: http.ServerResponse) {
    const parsedUrl = url.parse(req.url || '', true);
    const userParams = parsedUrl.query.params;
    
    const keys = Object.keys(userParams);
    let i = 0;
    
    // ruleid: typescript-loop-injection
    while (i < keys.length) {
        const key = keys[i];
        console.log(`Parameter ${key}: ${userParams[key]}`);
        i++;
    }
    
    res.end('Parameters processed');
}
// {/fact}

// Example 7: Using do-while loop with Object.keys on user input
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_7(req: http.IncomingMessage, res: http.ServerResponse) {
    let body = '';
    req.on('data', chunk => {
        body += chunk.toString();
    });
    
    req.on('end', () => {
        const userData = JSON.parse(body);
        const keys = Object.keys(userData);
        let i = 0;
        
        // ruleid: typescript-loop-injection
        do {
            const key = keys[i];
            console.log(`Processing ${key}: ${userData[key]}`);
            i++;
        } while (i < keys.length);
        
        res.end('Data processed');
    });
}
// {/fact}

// Example 8: Using map function on Object.entries of user input
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_8(req: http.IncomingMessage, res: http.ServerResponse) {
    const parsedUrl = url.parse(req.url || '', true);
    const userFilters = parsedUrl.query.filters;
    
    // ruleid: typescript-loop-injection
    const processedFilters = Object.entries(userFilters).map(([key, value]) => {
        return `${key}:${value}`;
    });
    
    res.end(`Filters applied: ${processedFilters.join(', ')}`);
}
// {/fact}

// Example 9: Using reduce function on Object.keys of user input
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_9(req: http.IncomingMessage, res: http.ServerResponse) {
    let body = '';
    req.on('data', chunk => {
        body += chunk.toString();
    });
    
    req.on('end', () => {
        const userCounts = JSON.parse(body);
        
        // ruleid: typescript-loop-injection
        const total = Object.keys(userCounts).reduce((sum, key) => {
            return sum + Number(userCounts[key]);
        }, 0);
        
        res.end(`Total count: ${total}`);
    });
}
// {/fact}

// Example 10: Using for-in loop with nested objects from user input
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_10(req: http.IncomingMessage, res: http.ServerResponse) {
    const parsedUrl = url.parse(req.url || '', true);
    const userNestedObject = parsedUrl.query.nestedData;
    
    // ruleid: typescript-loop-injection
    for (const category in userNestedObject) {
        for (const item in userNestedObject[category]) {
            console.log(`${category} - ${item}: ${userNestedObject[category][item]}`);
        }
    }
    
    res.end('Nested data processed');
}
// {/fact}

// Example 11: Using Object.entries with destructuring on user input
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_11(req: http.IncomingMessage, res: http.ServerResponse) {
    let body = '';
    req.on('data', chunk => {
        body += chunk.toString();
    });
    
    req.on('end', () => {
        const userMetrics = JSON.parse(body);
        
        // ruleid: typescript-loop-injection
        Object.entries(userMetrics).forEach(([metric, value]) => {
            console.log(`Metric ${metric} has value ${value}`);
        });
        
        res.end('Metrics processed');
    });
}
// {/fact}

// Example 12: Using for-in loop with header data
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_12(req: http.IncomingMessage, res: http.ServerResponse) {
    const userHeaders = req.headers;
    
    // ruleid: typescript-loop-injection
    for (const header in userHeaders) {
        console.log(`Header ${header}: ${userHeaders[header]}`);
    }
    
    res.end('Headers processed');
}
// {/fact}

// Example 13: Using for-in loop with cookie data
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_13(req: http.IncomingMessage, res: http.ServerResponse) {
    const cookieHeader = req.headers.cookie || '';
    const cookies: {[key: string]: string} = {};
    
    cookieHeader.split(';').forEach(cookie => {
        const parts = cookie.split('=');
        const key = parts.shift()?.trim() || '';
        const value = parts.join('=');
        cookies[key] = value;
    });
    
    // ruleid: typescript-loop-injection
    for (const cookieName in cookies) {
        console.log(`Cookie ${cookieName} = ${cookies[cookieName]}`);
    }
    
    res.end('Cookies processed');
}
// {/fact}

// Example 14: Using Object.keys with Express request
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_14(req: express.Request, res: express.Response) {
    const userData = req.body;
    
    // ruleid: typescript-loop-injection
    Object.keys(userData).forEach(key => {
        console.log(`Processing user data: ${key} = ${userData[key]}`);
    });
    
    res.send('User data processed');
}
// {/fact}

// Example 15: Using for-in loop with query parameters in Express
// {fact rule=resource-leak@v1.0 defects=1}
function bad_case_15(req: express.Request, res: express.Response) {
    const queryParams = req.query;
    
    // ruleid: typescript-loop-injection
    for (const param in queryParams) {
        console.log(`Query parameter ${param} = ${queryParams[param]}`);
    }
    
    res.send('Query parameters processed');
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// Example 1: Using for-in loop with type checking
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_1(req: http.IncomingMessage, res: http.ServerResponse) {
    const parsedUrl = url.parse(req.url || '', true);
    const userObject = parsedUrl.query.data;
    
    // ok: typescript-loop-injection
    if (userObject && typeof userObject === 'object' && !Array.isArray(userObject)) {
        const keys = Object.keys(userObject).slice(0, 100); // Limit to 100 keys
        for (const key of keys) {
            console.log(`Key: ${key}, Value: ${userObject[key]}`);
        }
    }
    
    res.end('Processing complete');
}
// {/fact}

// Example 2: Using Object.keys with validation and limits
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_2(req: http.IncomingMessage, res: http.ServerResponse) {
    let body = '';
    req.on('data', chunk => {
        body += chunk.toString();
    });
    
    req.on('end', () => {
        try {
            const userData = JSON.parse(body);
            
            // ok: typescript-loop-injection
            if (userData && typeof userData === 'object' && !Array.isArray(userData)) {
                const keys = Object.keys(userData);
                const maxKeys = Math.min(keys.length, 50); // Limit to 50 keys
                
                for (let i = 0; i < maxKeys; i++) {
                    const key = keys[i];
                    console.log(`Processing ${key}: ${userData[key]}`);
                }
            }
            
            res.end('Data processed');
        } catch (e) {
            res.end('Invalid data');
        }
    });
}
// {/fact}

// Example 3: Using Object.entries with type checking and limits
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_3(req: http.IncomingMessage, res: http.ServerResponse) {
    const parsedUrl = url.parse(req.url || '', true);
    const userConfig = parsedUrl.query.config;
    
    // ok: typescript-loop-injection
    if (userConfig && typeof userConfig === 'object' && !Array.isArray(userConfig)) {
        const entries = Object.entries(userConfig).slice(0, 20); // Limit to 20 entries
        for (const [key, value] of entries) {
            console.log(`Config ${key} set to ${value}`);
        }
    }
    
    res.end('Configuration applied');
}
// {/fact}

// Example 4: Using Object.values with validation and counter
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_4(req: http.IncomingMessage, res: http.ServerResponse) {
    let body = '';
    req.on('data', chunk => {
        body += chunk.toString();
    });
    
    req.on('end', () => {
        try {
            const userPreferences = JSON.parse(body);
            
            // ok: typescript-loop-injection
            if (userPreferences && typeof userPreferences === 'object' && !Array.isArray(userPreferences)) {
                const values = Object.values(userPreferences);
                let count = 0;
                const maxCount = 30; // Maximum of 30 values to process
                
                for (const value of values) {
                    if (count >= maxCount) break;
                    console.log(`Processing preference: ${value}`);
                    count++;
                }
            }
            
            res.end('Preferences updated');
        } catch (e) {
            res.end('Invalid data');
        }
    });
}
// {/fact}

// Example 5: Using for-of loop with Object.keys, validation and limits
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_5(req: http.IncomingMessage, res: http.ServerResponse) {
    const parsedUrl = url.parse(req.url || '', true);
    const userSettings = parsedUrl.query.settings;
    
    // ok: typescript-loop-injection
    if (userSettings instanceof Object && !Array.isArray(userSettings)) {
        const keys = Object.keys(userSettings).slice(0, 25); // Limit to 25 keys
        for (const key of keys) {
            console.log(`Setting ${key} = ${userSettings[key]}`);
        }
    }
    
    res.end('Settings applied');
}
// {/fact}

// Example 6: Using while loop with Object.keys, validation and counter
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_6(req: http.IncomingMessage, res: http.ServerResponse) {
    const parsedUrl = url.parse(req.url || '', true);
    const userParams = parsedUrl.query.params;
    
    // ok: typescript-loop-injection
    if (userParams && typeof userParams === 'object' && !Array.isArray(userParams)) {
        const keys = Object.keys(userParams);
        let i = 0;
        const maxIterations = Math.min(keys.length, 40); // Maximum of 40 iterations
        
        while (i < maxIterations) {
            const key = keys[i];
            console.log(`Parameter ${key}: ${userParams[key]}`);
            i++;
        }
    }
    
    res.end('Parameters processed');
}
// {/fact}

// Example 7: Using do-while loop with Object.keys, validation and counter
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_7(req: http.IncomingMessage, res: http.ServerResponse) {
    let body = '';
    req.on('data', chunk => {
        body += chunk.toString();
    });
    
    req.on('end', () => {
        try {
            const userData = JSON.parse(body);
            
            // ok: typescript-loop-injection
            if (userData && typeof userData === 'object' && !Array.isArray(userData)) {
                const keys = Object.keys(userData);
                let i = 0;
                const maxIterations = Math.min(keys.length, 30); // Maximum of 30 iterations
                
                if (maxIterations > 0) {
                    do {
                        const key = keys[i];
                        console.log(`Processing ${key}: ${userData[key]}`);
                        i++;
                    } while (i < maxIterations);
                }
            }
            
            res.end('Data processed');
        } catch (e) {
            res.end('Invalid data');
        }
    });
}
// {/fact}

// Example 8: Using map function with Object.entries, validation and limits
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_8(req: http.IncomingMessage, res: http.ServerResponse) {
    const parsedUrl = url.parse(req.url || '', true);
    const userFilters = parsedUrl.query.filters;
    
    // ok: typescript-loop-injection
    if (userFilters && typeof userFilters === 'object' && !Array.isArray(userFilters)) {
        const entries = Object.entries(userFilters).slice(0, 15); // Limit to 15 entries
        const processedFilters = entries.map(([key, value]) => {
            return `${key}:${value}`;
        });
        
        res.end(`Filters applied: ${processedFilters.join(', ')}`);
    } else {
        res.end('No valid filters provided');
    }
}
// {/fact}

// Example 9: Using reduce function with Object.keys, validation and limits
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_9(req: http.IncomingMessage, res: http.ServerResponse) {
    let body = '';
    req.on('data', chunk => {
        body += chunk.toString();
    });
    
    req.on('end', () => {
        try {
            const userCounts = JSON.parse(body);
            
            // ok: typescript-loop-injection
            if (userCounts && typeof userCounts === 'object' && !Array.isArray(userCounts)) {
                const keys = Object.keys(userCounts).slice(0, 50); // Limit to 50 keys
                const total = keys.reduce((sum, key) => {
                    const value = Number(userCounts[key]) || 0;
                    return sum + value;
                }, 0);
                
                res.end(`Total count: ${total}`);
            } else {
                res.end('Invalid count data');
            }
        } catch (e) {
            res.end('Invalid data format');
        }
    });
}
// {/fact}

// Example 10: Using for-in loop with nested objects, validation and limits
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_10(req: http.IncomingMessage, res: http.ServerResponse) {
    const parsedUrl = url.parse(req.url || '', true);
    const userNestedObject = parsedUrl.query.nestedData;
    
    // ok: typescript-loop-injection
    if (userNestedObject && typeof userNestedObject === 'object' && !Array.isArray(userNestedObject)) {
        const categories = Object.keys(userNestedObject).slice(0, 10); // Limit to 10 categories
        
        for (const category of categories) {
            const nestedObj = userNestedObject[category];
            
            if (nestedObj && typeof nestedObj === 'object' && !Array.isArray(nestedObj)) {
                const items = Object.keys(nestedObj).slice(0, 5); // Limit to 5 items per category
                
                for (const item of items) {
                    console.log(`${category} - ${item}: ${nestedObj[item]}`);
                }
            }
        }
    }
    
    res.end('Nested data processed');
}
// {/fact}

// Example 11: Using Object.entries with destructuring, validation and limits
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_11(req: http.IncomingMessage, res: http.ServerResponse) {
    let body = '';
    req.on('data', chunk => {
        body += chunk.toString();
    });
    
    req.on('end', () => {
        try {
            const userMetrics = JSON.parse(body);
            
            // ok: typescript-loop-injection
            if (userMetrics && typeof userMetrics === 'object' && !Array.isArray(userMetrics)) {
                const entries = Object.entries(userMetrics).slice(0, 20); // Limit to 20 entries
                
                entries.forEach(([metric, value]) => {
                    console.log(`Metric ${metric} has value ${value}`);
                });
            }
            
            res.end('Metrics processed');
        } catch (e) {
            res.end('Invalid metrics data');
        }
    });
}
// {/fact}

// Example 12: Using for-in loop with header data, validation and limits
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_12(req: http.IncomingMessage, res: http.ServerResponse) {
    const userHeaders = req.headers;
    
    // ok: typescript-loop-injection
    if (userHeaders && typeof userHeaders === 'object') {
        const headerNames = Object.keys(userHeaders).slice(0, 30); // Limit to 30 headers
        
        for (const header of headerNames) {
            console.log(`Header ${header}: ${userHeaders[header]}`);
        }
    }
    
    res.end('Headers processed');
}
// {/fact}

// Example 13: Using for-in loop with cookie data, validation and limits
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_13(req: http.IncomingMessage, res: http.ServerResponse) {
    const cookieHeader = req.headers.cookie || '';
    const cookies: {[key: string]: string} = {};
    
    cookieHeader.split(';').forEach(cookie => {
        const parts = cookie.split('=');
        const key = parts.shift()?.trim() || '';
        const value = parts.join('=');
        cookies[key] = value;
    });
    
    // ok: typescript-loop-injection
    if (cookies && typeof cookies === 'object') {
        const cookieNames = Object.keys(cookies).slice(0, 20); // Limit to 20 cookies
        
        for (const cookieName of cookieNames) {
            console.log(`Cookie ${cookieName} = ${cookies[cookieName]}`);
        }
    }
    
    res.end('Cookies processed');
}
// {/fact}

// Example 14: Using Object.keys with Express request, validation and limits
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_14(req: express.Request, res: express.Response) {
    const userData = req.body;
    
    // ok: typescript-loop-injection
    if (userData && typeof userData === 'object' && !Array.isArray(userData)) {
        const keys = Object.keys(userData).slice(0, 25); // Limit to 25 keys
        let count = 0;
        
        keys.forEach(key => {
            if (count < 25) { // Double-check the limit
                console.log(`Processing user data: ${key} = ${userData[key]}`);
                count++;
            }
        });
    }
    
    res.send('User data processed');
}
// {/fact}

// Example 15: Using for-in loop with query parameters in Express, validation and limits
// {fact rule=resource-leak@v1.0 defects=0}
function good_case_15(req: express.Request, res: express.Response) {
    const queryParams = req.query;
    
    // ok: typescript-loop-injection
    if (queryParams && typeof queryParams === 'object' && !Array.isArray(queryParams)) {
        const paramNames = Object.keys(queryParams).slice(0, 15); // Limit to 15 parameters
        
        for (const param of paramNames) {
            console.log(`Query parameter ${param} = ${queryParams[param]}`);
        }
    }
    
    res.send('Query parameters processed');
}
// {/fact}