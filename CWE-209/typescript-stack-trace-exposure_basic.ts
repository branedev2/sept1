import express from 'express';
import { Request, Response } from 'express';
import * as fs from 'fs';
import * as path from 'path';
import * as mysql from 'mysql';
import axios from 'axios';
import winston from 'winston';
import { MongoClient } from 'mongodb';
import { S3 } from 'aws-sdk';
import nodemailer from 'nodemailer';

// True Positive Examples (Bad Cases)

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_1(req: Request, res: Response) {
    try {
        const userId = req.query.id;
        if (!userId) {
            throw new Error('User ID is required');
        }
        // Some processing that might throw an error
        const result = processUserData(userId.toString());
        res.json({ success: true, data: result });
    } catch (error) {
        // ruleid: typescript-stack-trace-exposure
        res.status(500).json({ error: error.stack });
    }
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_2(req: Request, res: Response) {
    try {
        const filePath = req.query.path as string;
        const data = fs.readFileSync(filePath, 'utf8');
        res.send(data);
    } catch (error) {
        // ruleid: typescript-stack-trace-exposure
        res.status(500).send(`An error occurred: ${error.stack}`);
    }
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_3(req: Request, res: Response) {
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'password',
        database: 'mydb'
    });
    
    connection.query(`SELECT * FROM users WHERE id = ${req.params.id}`, (error, results) => {
        if (error) {
            // ruleid: typescript-stack-trace-exposure
            res.status(500).send(`Database error: ${error.stack}`);
            return;
        }
        res.json(results);
    });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_4(req: Request, res: Response) {
    const apiUrl = req.query.url as string;
    
    axios.get(apiUrl)
        .then(response => {
            res.json(response.data);
        })
        .catch(error => {
            // ruleid: typescript-stack-trace-exposure
            res.status(500).json({
                message: 'Failed to fetch data',
                error: error.toString(),
                stack: error.stack
            });
        });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_5(req: Request, res: Response) {
    try {
        const data = JSON.parse(req.body.data);
        res.json({ processed: data });
    } catch (error) {
        // ruleid: typescript-stack-trace-exposure
        res.render('error', { 
            message: 'Failed to process data', 
            error: error,
            stack: error.stack 
        });
    }
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_6(req: Request, res: Response) {
    const app = express();
    
    app.use((err: any, req: Request, res: Response, next: any) => {
        // ruleid: typescript-stack-trace-exposure
        res.status(500).send(`<html><body><h1>Error</h1><pre>${err.stack}</pre></body></html>`);
    });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_7(req: Request, res: Response) {
    try {
        const username = req.body.username;
        const password = req.body.password;
        
        if (!authenticateUser(username, password)) {
            throw new Error('Authentication failed');
        }
        
        res.json({ success: true });
    } catch (error) {
        console.error(error);
        // ruleid: typescript-stack-trace-exposure
        res.status(401).json({ 
            success: false, 
            message: 'Authentication failed',
            debug: process.env.NODE_ENV === 'development' ? error.stack : undefined
        });
    }
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_8(req: Request, res: Response) {
    const fileName = req.params.file;
    
    try {
        const filePath = path.join(__dirname, 'uploads', fileName);
        const fileContent = fs.readFileSync(filePath, 'utf8');
        res.send(fileContent);
    } catch (error) {
        // ruleid: typescript-stack-trace-exposure
        const errorHtml = `
            <html>
                <head><title>Error</title></head>
                <body>
                    <h1>File not found</h1>
                    <div class="error-details">
                        ${error.stack}
                    </div>
                </body>
            </html>
        `;
        res.status(404).send(errorHtml);
    }
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_9(req: Request, res: Response) {
    const userInput = req.query.input as string;
    
    try {
        // Some risky operation with user input
        const result = eval(userInput);
        res.json({ result });
    } catch (error) {
        // ruleid: typescript-stack-trace-exposure
        res.status(500).json({
            error: {
                message: error.message,
                stack: error.stack,
                code: error.code || 'UNKNOWN_ERROR'
            }
        });
    }
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_10(req: Request, res: Response) {
    const s3 = new S3({
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    });
    
    s3.getObject({
        Bucket: req.query.bucket as string,
        Key: req.query.key as string
    }, (err, data) => {
        if (err) {
            // ruleid: typescript-stack-trace-exposure
            res.status(500).send(`<p>Error fetching from S3:</p><pre>${err.stack}</pre>`);
            return;
        }
        res.send(data.Body);
    });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_11(req: Request, res: Response) {
    try {
        const searchTerm = req.query.q as string;
        if (!searchTerm) {
            throw new Error('Search term is required');
        }
        
        const results = performSearch(searchTerm);
        res.json(results);
    } catch (error) {
        // Log the error for internal use
        console.error('Search error:', error);
        
        // ruleid: typescript-stack-trace-exposure
        res.status(400).json({
            success: false,
            error: {
                type: error.name,
                details: error.stack.split('\n')
            }
        });
    }
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_12(req: Request, res: Response) {
    const uri = "mongodb://localhost:27017";
    const client = new MongoClient(uri);
    
    client.connect()
        .then(() => {
            const db = client.db("testdb");
            return db.collection("users").findOne({ username: req.params.username });
        })
        .then(result => {
            res.json(result);
        })
        .catch(error => {
            // ruleid: typescript-stack-trace-exposure
            const errorResponse = {
                timestamp: new Date().toISOString(),
                path: req.path,
                error: error.message,
                trace: error.stack
            };
            res.status(500).json(errorResponse);
        })
        .finally(() => {
            client.close();
        });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_13(req: Request, res: Response) {
    const transporter = nodemailer.createTransport({
        host: 'smtp.example.com',
        port: 587,
        secure: false,
        auth: {
            user: 'user@example.com',
            pass: 'password123'
        }
    });
    
    try {
        const mailOptions = {
            from: 'sender@example.com',
            to: req.body.recipient,
            subject: req.body.subject,
            text: req.body.message
        };
        
        transporter.sendMail(mailOptions);
        res.json({ success: true });
    } catch (error) {
        // ruleid: typescript-stack-trace-exposure
        res.status(500).send(`
            <div class="error-container">
                <h2>Failed to send email</h2>
                <details>
                    <summary>Technical Details</summary>
                    <code>${error.stack}</code>
                </details>
            </div>
        `);
    }
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_14(req: Request, res: Response) {
    const app = express();
    
    // Global error handler
    app.use((err: Error, req: Request, res: Response, next: any) => {
        const errorId = generateErrorId();
        console.error(`Error ${errorId}:`, err);
        
        // ruleid: typescript-stack-trace-exposure
        if (req.xhr || req.headers.accept?.includes('application/json')) {
            res.status(500).json({
                errorId,
                message: 'An unexpected error occurred',
                details: err.stack
            });
        } else {
            res.status(500).send(`
                <h1>Server Error</h1>
                <p>Error ID: ${errorId}</p>
                <pre>${err.stack}</pre>
            `);
        }
    });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=1}
function bad_case_15(req: Request, res: Response) {
    try {
        const config = JSON.parse(fs.readFileSync(req.query.configPath as string, 'utf8'));
        res.json({ success: true, config });
    } catch (error) {
        // ruleid: typescript-stack-trace-exposure
        const responseObj = {
            success: false,
            error: {
                name: error.name,
                message: error.message,
                stack: error.stack,
                code: error.code
            }
        };
        
        res.status(500).json(responseObj);
    }
}
// {/fact}

// True Negative Examples (Good Cases)

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_1(req: Request, res: Response) {
    try {
        const userId = req.query.id;
        if (!userId) {
            throw new Error('User ID is required');
        }
        // Some processing that might throw an error
        const result = processUserData(userId.toString());
        res.json({ success: true, data: result });
    } catch (error) {
        console.error('Error processing user data:', error);
        // ok: typescript-stack-trace-exposure
        res.status(500).json({ error: 'An internal server error occurred' });
    }
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_2(req: Request, res: Response) {
    try {
        const filePath = req.query.path as string;
        const data = fs.readFileSync(filePath, 'utf8');
        res.send(data);
    } catch (error) {
        console.error('File read error:', error);
        // ok: typescript-stack-trace-exposure
        res.status(500).send('Failed to read the requested file');
    }
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_3(req: Request, res: Response) {
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'password',
        database: 'mydb'
    });
    
    connection.query(`SELECT * FROM users WHERE id = ${req.params.id}`, (error, results) => {
        if (error) {
            console.error('Database query error:', error);
            // ok: typescript-stack-trace-exposure
            res.status(500).send('Database error occurred');
            return;
        }
        res.json(results);
    });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_4(req: Request, res: Response) {
    const apiUrl = req.query.url as string;
    
    axios.get(apiUrl)
        .then(response => {
            res.json(response.data);
        })
        .catch(error => {
            console.error('API request failed:', error);
            // ok: typescript-stack-trace-exposure
            res.status(500).json({
                message: 'Failed to fetch data from external API'
            });
        });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_5(req: Request, res: Response) {
    try {
        const data = JSON.parse(req.body.data);
        res.json({ processed: data });
    } catch (error) {
        console.error('JSON parse error:', error);
        // ok: typescript-stack-trace-exposure
        res.render('error', { 
            message: 'Failed to process data. Please check your input format.' 
        });
    }
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_6(req: Request, res: Response) {
    const app = express();
    
    app.use((err: any, req: Request, res: Response, next: any) => {
        console.error('Application error:', err);
        // ok: typescript-stack-trace-exposure
        res.status(500).send(`<html><body><h1>Error</h1><p>An unexpected error occurred</p></body></html>`);
    });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_7(req: Request, res: Response) {
    try {
        const username = req.body.username;
        const password = req.body.password;
        
        if (!authenticateUser(username, password)) {
            throw new Error('Authentication failed');
        }
        
        res.json({ success: true });
    } catch (error) {
        console.error('Authentication error:', error);
        // ok: typescript-stack-trace-exposure
        res.status(401).json({ 
            success: false, 
            message: 'Authentication failed. Please check your credentials.'
        });
    }
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_8(req: Request, res: Response) {
    const fileName = req.params.file;
    
    try {
        const filePath = path.join(__dirname, 'uploads', fileName);
        const fileContent = fs.readFileSync(filePath, 'utf8');
        res.send(fileContent);
    } catch (error) {
        console.error('File not found:', error);
        // ok: typescript-stack-trace-exposure
        const errorHtml = `
            <html>
                <head><title>Error</title></head>
                <body>
                    <h1>File not found</h1>
                    <p>The requested file could not be found on the server.</p>
                </body>
            </html>
        `;
        res.status(404).send(errorHtml);
    }
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_9(req: Request, res: Response) {
    const userInput = req.query.input as string;
    
    try {
        // Some risky operation with user input
        const result = eval(userInput);
        res.json({ result });
    } catch (error) {
        const errorId = generateErrorId();
        console.error(`Error ${errorId}:`, error);
        // ok: typescript-stack-trace-exposure
        res.status(500).json({
            error: {
                message: 'An error occurred while processing your request',
                errorId: errorId
            }
        });
    }
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_10(req: Request, res: Response) {
    const s3 = new S3({
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    });
    
    s3.getObject({
        Bucket: req.query.bucket as string,
        Key: req.query.key as string
    }, (err, data) => {
        if (err) {
            console.error('S3 error:', err);
            // ok: typescript-stack-trace-exposure
            res.status(500).send(`<p>Error fetching the requested object from storage</p>`);
            return;
        }
        res.send(data.Body);
    });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_11(req: Request, res: Response) {
    const logger = winston.createLogger({
        level: 'error',
        format: winston.format.json(),
        transports: [
            new winston.transports.File({ filename: 'error.log' })
        ]
    });
    
    try {
        const searchTerm = req.query.q as string;
        if (!searchTerm) {
            throw new Error('Search term is required');
        }
        
        const results = performSearch(searchTerm);
        res.json(results);
    } catch (error) {
        // Log the error with full details for debugging
        logger.error('Search error:', { error });
        
        // ok: typescript-stack-trace-exposure
        res.status(400).json({
            success: false,
            error: {
                message: 'Search failed. Please try with a different query.'
            }
        });
    }
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_12(req: Request, res: Response) {
    const uri = "mongodb://localhost:27017";
    const client = new MongoClient(uri);
    
    client.connect()
        .then(() => {
            const db = client.db("testdb");
            return db.collection("users").findOne({ username: req.params.username });
        })
        .then(result => {
            res.json(result);
        })
        .catch(error => {
            console.error('MongoDB error:', error);
            // ok: typescript-stack-trace-exposure
            const errorResponse = {
                timestamp: new Date().toISOString(),
                path: req.path,
                message: 'Database operation failed'
            };
            res.status(500).json(errorResponse);
        })
        .finally(() => {
            client.close();
        });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_13(req: Request, res: Response) {
    const transporter = nodemailer.createTransport({
        host: 'smtp.example.com',
        port: 587,
        secure: false,
        auth: {
            user: 'user@example.com',
            pass: 'password123'
        }
    });
    
    try {
        const mailOptions = {
            from: 'sender@example.com',
            to: req.body.recipient,
            subject: req.body.subject,
            text: req.body.message
        };
        
        transporter.sendMail(mailOptions);
        res.json({ success: true });
    } catch (error) {
        console.error('Email sending failed:', error);
        // ok: typescript-stack-trace-exposure
        res.status(500).send(`
            <div class="error-container">
                <h2>Failed to send email</h2>
                <p>Please try again later or contact support if the problem persists.</p>
            </div>
        `);
    }
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_14(req: Request, res: Response) {
    const app = express();
    
    // Global error handler
    app.use((err: Error, req: Request, res: Response, next: any) => {
        const errorId = generateErrorId();
        console.error(`Error ${errorId}:`, err);
        
        // ok: typescript-stack-trace-exposure
        if (req.xhr || req.headers.accept?.includes('application/json')) {
            res.status(500).json({
                errorId,
                message: 'An unexpected error occurred'
            });
        } else {
            res.status(500).send(`
                <h1>Server Error</h1>
                <p>Error ID: ${errorId}</p>
                <p>Our team has been notified. Please try again later.</p>
            `);
        }
    });
}
// {/fact}

// {fact rule=stack-trace-exposure@v1.0 defects=0}
function good_case_15(req: Request, res: Response) {
    try {
        const config = JSON.parse(fs.readFileSync(req.query.configPath as string, 'utf8'));
        res.json({ success: true, config });
    } catch (error) {
        console.error('Config loading error:', error);
        // ok: typescript-stack-trace-exposure
        const responseObj = {
            success: false,
            error: {
                message: 'Failed to load configuration file'
            }
        };
        
        res.status(500).json(responseObj);
    }
}
// {/fact}

// Helper functions to make the examples work
function processUserData(userId: string) {
    return { id: userId, name: 'User ' + userId };
}

function authenticateUser(username: string, password: string): boolean {
    return username === 'admin' && password === 'password';
}

function performSearch(term: string) {
    return [{ id: 1, name: `Result for ${term}` }];
}

function generateErrorId(): string {
    return Math.random().toString(36).substring(2, 10);
}