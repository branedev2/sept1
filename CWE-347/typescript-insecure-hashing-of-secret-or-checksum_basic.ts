import * as crypto from 'crypto';
import * as bcrypt from 'bcrypt';
import * as scrypt from 'scrypt-js';
import * as fs from 'fs';
import * as express from 'express';
import { Request, Response } from 'express';
import { createHash } from 'crypto';
import * as argon2 from 'argon2';

// TRUE POSITIVES (Vulnerable Code Examples)

// Example 1: Using MD5 to hash a password
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_1(password: string): string {
    // ruleid: typescript-insecure-hashing-of-secret-or-checksum
    const hash = crypto.createHash('md5').update(password).digest('hex');
    return hash;
}
// {/fact}

// Example 2: Using SHA-1 for password storage
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_2(): void {
    const userPassword = "securePassword123";
    // ruleid: typescript-insecure-hashing-of-secret-or-checksum
    const hashedPassword = crypto.createHash('sha1').update(userPassword).digest('hex');
    console.log(`Stored hashed password: ${hashedPassword}`);
}
// {/fact}

// Example 3: Using MD5 for file checksum verification
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_3(filePath: string): string {
    const fileData = fs.readFileSync(filePath);
    // ruleid: typescript-insecure-hashing-of-secret-or-checksum
    const checksum = crypto.createHash('md5').update(fileData).digest('hex');
    return checksum;
}
// {/fact}

// Example 4: Using SHA-1 in an authentication system
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_4(username: string, password: string): boolean {
    // Mock database lookup
    const storedHash = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"; // SHA-1 hash
    
    // ruleid: typescript-insecure-hashing-of-secret-or-checksum
    const inputHash = crypto.createHash('sha1').update(password).digest('hex');
    
    return inputHash === storedHash;
}
// {/fact}

// Example 5: Using MD5 in a password reset function
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_5(app: express.Application): void {
    app.post('/reset-password', (req: Request, res: Response) => {
        const { username, newPassword } = req.body;
        
        // ruleid: typescript-insecure-hashing-of-secret-or-checksum
        const hashedPassword = crypto.createHash('md5').update(newPassword).digest('hex');
        
        // Mock database update
        console.log(`Updating password for ${username} to ${hashedPassword}`);
        res.send('Password updated successfully');
    });
}
// {/fact}

// Example 6: Using SHA-1 in a token generation function
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_6(userId: string, secret: string): string {
    const timestamp = Date.now().toString();
    // ruleid: typescript-insecure-hashing-of-secret-or-checksum
    return crypto.createHash('sha1').update(userId + timestamp + secret).digest('hex');
}
// {/fact}

// Example 7: Using MD5 for API key verification
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_7(apiKey: string): boolean {
    const storedKeyHash = "098f6bcd4621d373cade4e832627b4f6"; // MD5 hash
    
    // ruleid: typescript-insecure-hashing-of-secret-or-checksum
    const keyHash = crypto.createHash('md5').update(apiKey).digest('base64');
    
    return Buffer.from(keyHash, 'base64').toString('hex') === storedKeyHash;
}
// {/fact}

// Example 8: Using SHA-1 with a salt (still insecure)
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_8(password: string): string {
    const salt = crypto.randomBytes(16).toString('hex');
    
    // ruleid: typescript-insecure-hashing-of-secret-or-checksum
    const hash = crypto.createHash('sha1').update(salt + password).digest('hex');
    
    return `${salt}:${hash}`;
}
// {/fact}

// Example 9: Using MD5 in a file integrity check system
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_9(): void {
    const files = ['file1.txt', 'file2.txt', 'file3.txt'];
    
    for (const file of files) {
        const content = fs.readFileSync(file);
        // ruleid: typescript-insecure-hashing-of-secret-or-checksum
        const checksum = crypto.createHash('md5').update(content).digest('hex');
        console.log(`${file}: ${checksum}`);
    }
}
// {/fact}

// Example 10: Using SHA-1 for session token generation
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_10(app: express.Application): void {
    app.post('/login', (req: Request, res: Response) => {
        const { username, password } = req.body;
        
        // Authentication logic here...
        
        const sessionData = username + Date.now().toString();
        // ruleid: typescript-insecure-hashing-of-secret-or-checksum
        const sessionToken = crypto.createHash('sha1').update(sessionData).digest('hex');
        
        res.cookie('session', sessionToken);
        res.send('Logged in successfully');
    });
}
// {/fact}

// Example 11: Using MD5 with a custom wrapper function
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_11(): void {
    function hashPassword(password: string): string {
        // ruleid: typescript-insecure-hashing-of-secret-or-checksum
        return crypto.createHash('md5').update(password).digest('hex');
    }
    
    const userPassword = "mySecretPassword";
    const hashedPassword = hashPassword(userPassword);
    console.log(`Hashed password: ${hashedPassword}`);
}
// {/fact}

// Example 12: Using SHA-1 in a URL shortener service
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_12(url: string): string {
    // ruleid: typescript-insecure-hashing-of-secret-or-checksum
    const urlHash = crypto.createHash('sha1').update(url).digest('hex').substring(0, 8);
    return `https://short.url/${urlHash}`;
}
// {/fact}

// Example 13: Using MD5 for cache key generation
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_13(data: object): string {
    const dataString = JSON.stringify(data);
    // ruleid: typescript-insecure-hashing-of-secret-or-checksum
    return crypto.createHash('md5').update(dataString).digest('hex');
}
// {/fact}

// Example 14: Using SHA-1 for password verification in a login handler
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_14(app: express.Application): void {
    app.post('/login', (req: Request, res: Response) => {
        const { username, password } = req.body;
        
        // Mock database query
        const storedHash = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"; // SHA-1 hash
        
        // ruleid: typescript-insecure-hashing-of-secret-or-checksum
        const inputHash = crypto.createHash('sha1').update(password).digest('hex');
        
        if (inputHash === storedHash) {
            res.send('Login successful');
        } else {
            res.status(401).send('Invalid credentials');
        }
    });
}
// {/fact}

// Example 15: Using MD5 for generating unique identifiers from sensitive data
// {fact rule=insecure-jwt-parsing@v1.0 defects=1}
function bad_case_15(userEmail: string, dob: string): string {
    const sensitiveData = `${userEmail}|${dob}`;
    // ruleid: typescript-insecure-hashing-of-secret-or-checksum
    return crypto.createHash('md5').update(sensitiveData).digest('hex');
}
// {/fact}

// TRUE NEGATIVES (Secure Code Examples)

// Example 1: Using SHA256 for password hashing
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_1(password: string): string {
    // ok: typescript-insecure-hashing-of-secret-or-checksum
    const hash = crypto.createHash('sha256').update(password).digest('hex');
    return hash;
}
// {/fact}

// Example 2: Using bcrypt for password storage
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_2(password: string): Promise<string> {
    const saltRounds = 10;
    // ok: typescript-insecure-hashing-of-secret-or-checksum
    return bcrypt.hash(password, saltRounds);
}
// {/fact}

// Example 3: Using SHA512 for file checksum
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_3(filePath: string): string {
    const fileData = fs.readFileSync(filePath);
    // ok: typescript-insecure-hashing-of-secret-or-checksum
    const checksum = crypto.createHash('sha512').update(fileData).digest('hex');
    return checksum;
}
// {/fact}

// Example 4: Using scrypt for password hashing
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_4(password: string): Promise<Buffer> {
    const salt = crypto.randomBytes(16);
    const N = 1024, r = 8, p = 1;
    const dkLen = 32;
    const passwordBuffer = Buffer.from(password);
    
    // ok: typescript-insecure-hashing-of-secret-or-checksum
    return new Promise((resolve, reject) => {
        crypto.scrypt(password, salt, dkLen, { N, r, p }, (err, derivedKey) => {
            if (err) reject(err);
            resolve(derivedKey);
        });
    });
}
// {/fact}

// Example 5: Using SHA384 in a password reset function
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_5(app: express.Application): void {
    app.post('/reset-password', (req: Request, res: Response) => {
        const { username, newPassword } = req.body;
        
        // ok: typescript-insecure-hashing-of-secret-or-checksum
        const hashedPassword = crypto.createHash('sha384').update(newPassword).digest('hex');
        
        // Mock database update
        console.log(`Updating password for ${username} to ${hashedPassword}`);
        res.send('Password updated successfully');
    });
}
// {/fact}

// Example 6: Using argon2 for password hashing
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_6(password: string): Promise<string> {
    // ok: typescript-insecure-hashing-of-secret-or-checksum
    return argon2.hash(password);
}
// {/fact}

// Example 7: Using SHA256 for API key verification
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_7(apiKey: string): boolean {
    const storedKeyHash = "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"; // SHA-256 hash
    
    // ok: typescript-insecure-hashing-of-secret-or-checksum
    const keyHash = crypto.createHash('sha256').update(apiKey).digest('hex');
    
    return keyHash === storedKeyHash;
}
// {/fact}

// Example 8: Using bcrypt with proper salt rounds
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_8(app: express.Application): void {
    app.post('/signup', async (req: Request, res: Response) => {
        const { username, password } = req.body;
        const saltRounds = 12;
        
        try {
            // ok: typescript-insecure-hashing-of-secret-or-checksum
            const hashedPassword = await bcrypt.hash(password, saltRounds);
            
            // Mock database insert
            console.log(`Storing user ${username} with hashed password ${hashedPassword}`);
            res.status(201).send('User created successfully');
        } catch (error) {
            res.status(500).send('Error creating user');
        }
    });
}
// {/fact}

// Example 9: Using SHA512 in a file integrity check system
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_9(): void {
    const files = ['file1.txt', 'file2.txt', 'file3.txt'];
    
    for (const file of files) {
        const content = fs.readFileSync(file);
        // ok: typescript-insecure-hashing-of-secret-or-checksum
        const checksum = crypto.createHash('sha512').update(content).digest('hex');
        console.log(`${file}: ${checksum}`);
    }
}
// {/fact}

// Example 10: Using SHA256 for session token generation
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_10(app: express.Application): void {
    app.post('/login', (req: Request, res: Response) => {
        const { username, password } = req.body;
        
        // Authentication logic here...
        
        const sessionData = username + Date.now().toString();
        // ok: typescript-insecure-hashing-of-secret-or-checksum
        const sessionToken = crypto.createHash('sha256').update(sessionData).digest('hex');
        
        res.cookie('session', sessionToken);
        res.send('Logged in successfully');
    });
}
// {/fact}

// Example 11: Using scrypt with a custom wrapper function
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_11(): void {
    async function hashPassword(password: string): Promise<string> {
        const salt = crypto.randomBytes(16);
        
        // ok: typescript-insecure-hashing-of-secret-or-checksum
        return new Promise((resolve, reject) => {
            crypto.scrypt(password, salt, 64, (err, derivedKey) => {
                if (err) reject(err);
                resolve(salt.toString('hex') + ':' + derivedKey.toString('hex'));
            });
        });
    }
    
    hashPassword("mySecretPassword").then(hash => {
        console.log(`Hashed password: ${hash}`);
    });
}
// {/fact}

// Example 12: Using SHA384 in a URL shortener service
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_12(url: string): string {
    // ok: typescript-insecure-hashing-of-secret-or-checksum
    const urlHash = crypto.createHash('sha384').update(url).digest('hex').substring(0, 8);
    return `https://short.url/${urlHash}`;
}
// {/fact}

// Example 13: Using SHA256 for cache key generation
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_13(data: object): string {
    const dataString = JSON.stringify(data);
    // ok: typescript-insecure-hashing-of-secret-or-checksum
    return crypto.createHash('sha256').update(dataString).digest('hex');
}
// {/fact}

// Example 14: Using bcrypt for password verification in a login handler
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_14(app: express.Application): void {
    app.post('/login', async (req: Request, res: Response) => {
        const { username, password } = req.body;
        
        // Mock database query
        const storedHash = "$2b$10$rPiEAgSYQx5H6RCY5wgE3.ZOr.NqEBcJY7Xa7gonnLyLcEU9jMEHy"; // bcrypt hash
        
        try {
            // ok: typescript-insecure-hashing-of-secret-or-checksum
            const match = await bcrypt.compare(password, storedHash);
            
            if (match) {
                res.send('Login successful');
            } else {
                res.status(401).send('Invalid credentials');
            }
        } catch (error) {
            res.status(500).send('Server error');
        }
    });
}
// {/fact}

// Example 15: Using SHA512 for generating unique identifiers from sensitive data
// {fact rule=insecure-jwt-parsing@v1.0 defects=0}
function good_case_15(userEmail: string, dob: string): string {
    const sensitiveData = `${userEmail}|${dob}`;
    // ok: typescript-insecure-hashing-of-secret-or-checksum
    return crypto.createHash('sha512').update(sensitiveData).digest('hex');
}
// {/fact}