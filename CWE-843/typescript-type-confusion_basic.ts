import express from 'express';
import axios from 'axios';
import { Request, Response } from 'express';

// TRUE POSITIVES (Vulnerable Code)

// Bad case 1: Using includes directly on request parameter
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_1(req: Request, res: Response) {
    const userId = req.query.id;
    // ruleid: typescript-type-confusion
    if (userId.includes('admin')) {
        res.send('Admin access granted');
    } else {
        res.send('Regular user access');
    }
}
// {/fact}

// Bad case 2: Using indexOf on request parameter without type checking
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_2(req: Request, res: Response) {
    const searchTerm = req.query.term;
    // ruleid: typescript-type-confusion
    if (searchTerm.indexOf('password') !== -1) {
        res.status(400).send('Invalid search term');
    } else {
        res.send('Search results for: ' + searchTerm);
    }
}
// {/fact}

// Bad case 3: Using lastIndexOf on request body data
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_3(req: Request, res: Response) {
    const userInput = req.body.text;
    // ruleid: typescript-type-confusion
    const lastDotPosition = userInput.lastIndexOf('.');
    const extension = userInput.substring(lastDotPosition);
    res.send(`File extension: ${extension}`);
}
// {/fact}

// Bad case 4: Using includes on request header
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_4(req: Request, res: Response) {
    const userAgent = req.headers['user-agent'];
    // ruleid: typescript-type-confusion
    if (userAgent.includes('Mozilla')) {
        res.send('Browser detected');
    } else {
        res.send('Unknown client');
    }
}
// {/fact}

// Bad case 5: Using indexOf with request parameter in a loop
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_5(req: Request, res: Response) {
    const keywords = req.query.keywords;
    const blockedWords = ['password', 'admin', 'root'];
    
    for (const word of blockedWords) {
        // ruleid: typescript-type-confusion
        if (keywords.indexOf(word) !== -1) {
            res.status(403).send('Forbidden keyword detected');
            return;
        }
    }
    res.send('Content approved');
}
// {/fact}

// Bad case 6: Using lastIndexOf with cookie value
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_6(req: Request, res: Response) {
    const sessionData = req.cookies.session;
    // ruleid: typescript-type-confusion
    const separatorPos = sessionData.lastIndexOf(':');
    const userId = sessionData.substring(0, separatorPos);
    const timestamp = sessionData.substring(separatorPos + 1);
    
    res.send(`User ID: ${userId}, Login time: ${timestamp}`);
}
// {/fact}

// Bad case 7: Using includes with request parameter in conditional
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_7(req: Request, res: Response) {
    const role = req.query.role;
    // ruleid: typescript-type-confusion
    if (role.includes('admin') || role.includes('superuser')) {
        res.send('Welcome, administrator!');
    } else {
        res.send('Welcome, user!');
    }
}
// {/fact}

// Bad case 8: Using indexOf with request parameter in template literal
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_8(req: Request, res: Response) {
    const filename = req.query.file;
    // ruleid: typescript-type-confusion
    const extension = filename.substring(filename.indexOf('.'));
    res.send(`File has extension: ${extension}`);
}
// {/fact}

// Bad case 9: Using includes with request parameter in switch statement
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_9(req: Request, res: Response) {
    const command = req.query.cmd;
    let action = '';
    
    switch(true) {
        // ruleid: typescript-type-confusion
        case command.includes('create'):
            action = 'Creating new item';
            break;
        // ruleid: typescript-type-confusion
        case command.includes('delete'):
            action = 'Deleting item';
            break;
        default:
            action = 'Unknown command';
    }
    
    res.send(`Action: ${action}`);
}
// {/fact}

// Bad case 10: Using indexOf with request parameter in ternary operator
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_10(req: Request, res: Response) {
    const email = req.body.email;
    // ruleid: typescript-type-confusion
    const domain = email.indexOf('@gmail.com') !== -1 ? 'Gmail user' : 'Other email provider';
    res.send(`User has: ${domain}`);
}
// {/fact}

// Bad case 11: Using lastIndexOf with request parameter in function call
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_11(req: Request, res: Response) {
    const path = req.query.path;
    // ruleid: typescript-type-confusion
    const filename = path.substring(path.lastIndexOf('/') + 1);
    processFile(filename);
    res.send(`Processing file: ${filename}`);
    
    function processFile(name: string) {
        // Process the file
        console.log(`Processing ${name}`);
    }
}
// {/fact}

// Bad case 12: Using includes with request parameter from API response
// {fact rule=type-confusion@v1.0 defects=1}
async function bad_case_12(req: Request, res: Response) {
    const apiEndpoint = req.query.api;
    try {
        const response = await axios.get(`https://api.example.com/${apiEndpoint}`);
        const data = response.data;
        // ruleid: typescript-type-confusion
        if (data.includes('error')) {
            res.status(500).send('External API error');
        } else {
            res.send(data);
        }
    } catch (error) {
        res.status(500).send('Error fetching data');
    }
}
// {/fact}

// Bad case 13: Using indexOf with multiple request parameters
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_13(req: Request, res: Response) {
    const username = req.query.username;
    const password = req.query.password;
    
    // ruleid: typescript-type-confusion
    if (username.indexOf('admin') !== -1 && password.indexOf('123') !== -1) {
        res.status(403).send('Weak credentials detected');
    } else {
        res.send('Credentials checked');
    }
}
// {/fact}

// Bad case 14: Using lastIndexOf with request parameter in error handling
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_14(req: Request, res: Response) {
    try {
        const input = req.query.input;
        // ruleid: typescript-type-confusion
        const position = input.lastIndexOf('#');
        if (position === -1) {
            throw new Error('Invalid format');
        }
        res.send(`Position found: ${position}`);
    } catch (error) {
        res.status(400).send(`Error: ${error.message}`);
    }
}
// {/fact}

// Bad case 15: Using includes with request parameter in nested condition
// {fact rule=type-confusion@v1.0 defects=1}
function bad_case_15(req: Request, res: Response) {
    const permission = req.query.perm;
    const action = req.query.action;
    
    if (action === 'edit') {
        // ruleid: typescript-type-confusion
        if (permission.includes('write')) {
            res.send('Edit permission granted');
        } else {
            res.status(403).send('Permission denied');
        }
    } else {
        res.send('No edit requested');
    }
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// Good case 1: Type checking before using includes
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_1(req: Request, res: Response) {
    const userId = req.query.id;
    // ok: typescript-type-confusion
    if (typeof userId === 'string' && userId.includes('admin')) {
        res.send('Admin access granted');
    } else {
        res.send('Regular user access');
    }
}
// {/fact}

// Good case 2: Converting to string before using indexOf
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_2(req: Request, res: Response) {
    const searchTerm = req.query.term;
    // ok: typescript-type-confusion
    if (String(searchTerm).indexOf('password') !== -1) {
        res.status(400).send('Invalid search term');
    } else {
        res.send('Search results for: ' + searchTerm);
    }
}
// {/fact}

// Good case 3: Checking if input is string before using lastIndexOf
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_3(req: Request, res: Response) {
    const userInput = req.body.text;
    // ok: typescript-type-confusion
    if (typeof userInput === 'string') {
        const lastDotPosition = userInput.lastIndexOf('.');
        const extension = userInput.substring(lastDotPosition);
        res.send(`File extension: ${extension}`);
    } else {
        res.status(400).send('Invalid input type');
    }
}
// {/fact}

// Good case 4: Using toString() before includes
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_4(req: Request, res: Response) {
    const userAgent = req.headers['user-agent'];
    // ok: typescript-type-confusion
    if (userAgent && userAgent.toString().includes('Mozilla')) {
        res.send('Browser detected');
    } else {
        res.send('Unknown client');
    }
}
// {/fact}

// Good case 5: Using default value with || operator
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_5(req: Request, res: Response) {
    const keywords = req.query.keywords;
    const blockedWords = ['password', 'admin', 'root'];
    
    // ok: typescript-type-confusion
    const safeKeywords = (typeof keywords === 'string') ? keywords : '';
    
    for (const word of blockedWords) {
        if (safeKeywords.indexOf(word) !== -1) {
            res.status(403).send('Forbidden keyword detected');
            return;
        }
    }
    res.send('Content approved');
}
// {/fact}

// Good case 6: Using nullish coalescing for safe default
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_6(req: Request, res: Response) {
    const sessionData = req.cookies.session;
    // ok: typescript-type-confusion
    const safeSessionData = String(sessionData ?? '');
    const separatorPos = safeSessionData.lastIndexOf(':');
    const userId = safeSessionData.substring(0, separatorPos);
    const timestamp = safeSessionData.substring(separatorPos + 1);
    
    res.send(`User ID: ${userId}, Login time: ${timestamp}`);
}
// {/fact}

// Good case 7: Using type assertion with validation
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_7(req: Request, res: Response) {
    const role = req.query.role;
    // ok: typescript-type-confusion
    const safeRole = typeof role === 'string' ? role : '';
    
    if (safeRole.includes('admin') || safeRole.includes('superuser')) {
        res.send('Welcome, administrator!');
    } else {
        res.send('Welcome, user!');
    }
}
// {/fact}

// Good case 8: Using optional chaining and nullish coalescing
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_8(req: Request, res: Response) {
    const filename = req.query.file;
    // ok: typescript-type-confusion
    const safeFilename = (filename as string | undefined)?.toString() ?? '';
    const extension = safeFilename.substring(safeFilename.indexOf('.'));
    res.send(`File has extension: ${extension}`);
}
// {/fact}

// Good case 9: Using Array.includes instead of string method
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_9(req: Request, res: Response) {
    const command = req.query.cmd;
    const createCommands = ['create', 'new', 'add'];
    const deleteCommands = ['delete', 'remove', 'destroy'];
    
    let action = '';
    
    // ok: typescript-type-confusion
    if (typeof command === 'string') {
        if (createCommands.includes(command)) {
            action = 'Creating new item';
        } else if (deleteCommands.includes(command)) {
            action = 'Deleting item';
        } else {
            action = 'Unknown command';
        }
    } else {
        action = 'Invalid command type';
    }
    
    res.send(`Action: ${action}`);
}
// {/fact}

// Good case 10: Using regex test instead of indexOf
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_10(req: Request, res: Response) {
    const email = req.body.email;
    // ok: typescript-type-confusion
    const isGmailUser = typeof email === 'string' && /gmail\.com$/i.test(email);
    const domain = isGmailUser ? 'Gmail user' : 'Other email provider';
    res.send(`User has: ${domain}`);
}
// {/fact}

// Good case 11: Using path module instead of string methods
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_11(req: Request, res: Response) {
    const path = req.query.path;
    const pathModule = require('path');
    
    // ok: typescript-type-confusion
    const safePath = typeof path === 'string' ? path : '';
    const filename = pathModule.basename(safePath);
    
    processFile(filename);
    res.send(`Processing file: ${filename}`);
    
    function processFile(name: string) {
        // Process the file
        console.log(`Processing ${name}`);
    }
}
// {/fact}

// Good case 12: Proper type checking for API response
// {fact rule=type-confusion@v1.0 defects=0}
async function good_case_12(req: Request, res: Response) {
    const apiEndpoint = req.query.api;
    try {
        const response = await axios.get(`https://api.example.com/${apiEndpoint}`);
        const data = response.data;
        // ok: typescript-type-confusion
        if (typeof data === 'string' && data.includes('error')) {
            res.status(500).send('External API error');
        } else {
            res.send(data);
        }
    } catch (error) {
        res.status(500).send('Error fetching data');
    }
}
// {/fact}

// Good case 13: Using explicit type casting
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_13(req: Request, res: Response) {
    const username = req.query.username;
    const password = req.query.password;
    
    // ok: typescript-type-confusion
    const safeUsername = String(username || '');
    const safePassword = String(password || '');
    
    if (safeUsername.indexOf('admin') !== -1 && safePassword.indexOf('123') !== -1) {
        res.status(403).send('Weak credentials detected');
    } else {
        res.send('Credentials checked');
    }
}
// {/fact}

// Good case 14: Using try-catch with type checking
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_14(req: Request, res: Response) {
    try {
        const input = req.query.input;
        // ok: typescript-type-confusion
        if (typeof input !== 'string') {
            throw new Error('Input must be a string');
        }
        
        const position = input.lastIndexOf('#');
        if (position === -1) {
            throw new Error('Invalid format');
        }
        res.send(`Position found: ${position}`);
    } catch (error) {
        res.status(400).send(`Error: ${error.message}`);
    }
}
// {/fact}

// Good case 15: Using default parameters and type guards
// {fact rule=type-confusion@v1.0 defects=0}
function good_case_15(req: Request, res: Response) {
    const permission = req.query.perm;
    const action = req.query.action;
    
    // ok: typescript-type-confusion
    function isString(value: any): value is string {
        return typeof value === 'string';
    }
    
    if (action === 'edit') {
        if (isString(permission) && permission.includes('write')) {
            res.send('Edit permission granted');
        } else {
            res.status(403).send('Permission denied');
        }
    } else {
        res.send('No edit requested');
    }
}
// {/fact}

// Helper function for processing files
function processFile(filename: string) {
    // Implementation details
}