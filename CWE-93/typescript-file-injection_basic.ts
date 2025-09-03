import * as fs from 'fs';
import * as path from 'path';
import * as http from 'http';
import * as express from 'express';
import * as sanitize from 'sanitize-filename';
import * as crypto from 'crypto';

// True Positive Examples (Vulnerable Code)

// Example 1: Direct file write with user input from query parameter
// {fact rule=file-injection@v1.0 defects=1}
function bad_case_1() {
    const server = http.createServer((req, res) => {
        const url = new URL(req.url || '', `http://${req.headers.host}`);
        const fileName = url.searchParams.get('fileName') || 'default.txt';
        const content = url.searchParams.get('content') || '';
        
        // ruleid: typescript-file-injection
        fs.writeFileSync(fileName, content);
        
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('File written successfully');
    });
    
    server.listen(3000);
}
// {/fact}

// Example 2: Using path.join but still vulnerable with user input
// {fact rule=file-injection@v1.0 defects=1}
function bad_case_2() {
    const app = express();
    
    app.get('/write', (req, res) => {
        const fileName = req.query.fileName as string;
        const content = req.query.content as string;
        const filePath = path.join('./uploads', fileName);
        
        // ruleid: typescript-file-injection
        fs.writeFile(filePath, content, (err) => {
            if (err) {
                res.status(500).send('Error writing file');
                return;
            }
            res.send('File written successfully');
        });
    });
}
// {/fact}

// Example 3: Using promises with fs but still vulnerable
// {fact rule=file-injection@v1.0 defects=1}
function bad_case_3() {
    const app = express();
    
    app.post('/save', async (req, res) => {
        try {
            const fileName = req.body.fileName;
            const data = req.body.data;
            
            // ruleid: typescript-file-injection
            await fs.promises.writeFile(fileName, data);
            
            res.json({ success: true });
        } catch (error) {
            res.status(500).json({ error: 'Failed to write file' });
        }
    });
}
// {/fact}

// Example 4: Vulnerable with string concatenation
// {fact rule=file-injection@v1.0 defects=1}
function bad_case_4() {
    const server = http.createServer((req, res) => {
        const url = new URL(req.url || '', `http://${req.headers.host}`);
        const userDir = url.searchParams.get('dir') || '';
        const fileName = url.searchParams.get('file') || 'data.txt';
        const content = url.searchParams.get('content') || '';
        
        const filePath = './storage/' + userDir + '/' + fileName;
        
        // ruleid: typescript-file-injection
        fs.writeFileSync(filePath, content);
        
        res.writeHead(200);
        res.end('Success');
    });
}
// {/fact}

// Example 5: Vulnerable with template literals
// {fact rule=file-injection@v1.0 defects=1}
function bad_case_5() {
    const app = express();
    
    app.post('/log', (req, res) => {
        const username = req.body.username;
        const logMessage = req.body.message;
        
        // ruleid: typescript-file-injection
        fs.writeFileSync(`./logs/${username}_log.txt`, logMessage);
        
        res.send('Log saved');
    });
}
// {/fact}

// Example 6: Vulnerable with appendFile
// {fact rule=file-injection@v1.0 defects=1}
function bad_case_6() {
    const server = http.createServer((req, res) => {
        const url = new URL(req.url || '', `http://${req.headers.host}`);
        const fileName = url.searchParams.get('file') || 'log.txt';
        const logEntry = url.searchParams.get('entry') || '';
        
        // ruleid: typescript-file-injection
        fs.appendFileSync(fileName, logEntry + '\n');
        
        res.writeHead(200);
        res.end('Log entry added');
    });
}
// {/fact}

// Example 7: Vulnerable with writeStream
// {fact rule=file-injection@v1.0 defects=1}
function bad_case_7() {
    const app = express();
    
    app.post('/upload', (req, res) => {
        const fileName = req.headers['x-filename'] as string;
        const content = req.body.content;
        
        // ruleid: typescript-file-injection
        const writeStream = fs.createWriteStream(fileName);
        writeStream.write(content);
        writeStream.end();
        
        res.send('File uploaded');
    });
}
// {/fact}

// Example 8: Vulnerable with cookie data
// {fact rule=file-injection@v1.0 defects=1}
function bad_case_8() {
    const app = express();
    
    app.get('/export', (req, res) => {
        const userProfile = req.cookies.userProfile;
        const fileName = req.cookies.exportFileName || 'export.json';
        
        // ruleid: typescript-file-injection
        fs.writeFileSync(fileName, JSON.stringify(userProfile));
        
        res.send('Profile exported');
    });
}
// {/fact}

// Example 9: Vulnerable with multiple inputs combined
// {fact rule=file-injection@v1.0 defects=1}
function bad_case_9() {
    const app = express();
    
    app.post('/save-config', (req, res) => {
        const projectName = req.body.project;
        const environment = req.body.environment;
        const configData = req.body.config;
        
        const filePath = `./configs/${projectName}/${environment}.json`;
        
        // ruleid: typescript-file-injection
        fs.writeFileSync(filePath, JSON.stringify(configData));
        
        res.json({ success: true });
    });
}
// {/fact}

// Example 10: Vulnerable with URL parameters in complex path
// {fact rule=file-injection@v1.0 defects=1}
function bad_case_10() {
    const server = http.createServer((req, res) => {
        const url = new URL(req.url || '', `http://${req.headers.host}`);
        const year = url.searchParams.get('year') || '2023';
        const month = url.searchParams.get('month') || '01';
        const day = url.searchParams.get('day') || '01';
        const fileName = url.searchParams.get('name') || 'data.txt';
        const content = url.searchParams.get('content') || '';
        
        const filePath = path.join('./archives', year, month, day, fileName);
        
        // ruleid: typescript-file-injection
        fs.writeFileSync(filePath, content);
        
        res.writeHead(200);
        res.end('Archived');
    });
}
// {/fact}

// Example 11: Vulnerable with header data
// {fact rule=file-injection@v1.0 defects=1}
function bad_case_11() {
    const app = express();
    
    app.post('/store', (req, res) => {
        const sessionId = req.headers['session-id'] as string;
        const data = req.body.data;
        
        // ruleid: typescript-file-injection
        fs.writeFileSync(`./sessions/${sessionId}.json`, JSON.stringify(data));
        
        res.send('Session stored');
    });
}
// {/fact}

// Example 12: Vulnerable with indirect assignment
// {fact rule=file-injection@v1.0 defects=1}
function bad_case_12() {
    const server = http.createServer((req, res) => {
        const url = new URL(req.url || '', `http://${req.headers.host}`);
        let fileName = 'default.txt';
        
        if (url.searchParams.has('file')) {
            fileName = url.searchParams.get('file') as string;
        }
        
        const content = url.searchParams.get('content') || '';
        
        // ruleid: typescript-file-injection
        fs.writeFileSync(fileName, content);
        
        res.writeHead(200);
        res.end('Written');
    });
}
// {/fact}

// Example 13: Vulnerable with conditional path construction
// {fact rule=file-injection@v1.0 defects=1}
function bad_case_13() {
    const app = express();
    
    app.post('/save-draft', (req, res) => {
        const userId = req.body.userId;
        const draftId = req.body.draftId;
        const content = req.body.content;
        
        let filePath;
        if (draftId) {
            filePath = `./drafts/${userId}/${draftId}.txt`;
        } else {
            filePath = `./drafts/${userId}/new_draft.txt`;
        }
        
        // ruleid: typescript-file-injection
        fs.writeFileSync(filePath, content);
        
        res.json({ success: true });
    });
}
// {/fact}

// Example 14: Vulnerable with object destructuring
// {fact rule=file-injection@v1.0 defects=1}
function bad_case_14() {
    const app = express();
    
    app.post('/save-settings', (req, res) => {
        const { username, settingsFile, settingsData } = req.body;
        
        // ruleid: typescript-file-injection
        fs.writeFileSync(`./users/${username}/${settingsFile}`, JSON.stringify(settingsData));
        
        res.send('Settings saved');
    });
}
// {/fact}

// Example 15: Vulnerable with array mapping
// {fact rule=file-injection@v1.0 defects=1}
function bad_case_15() {
    const app = express();
    
    app.post('/batch-save', (req, res) => {
        const files = req.body.files;
        
        files.forEach((file: { name: string, content: string }) => {
            // ruleid: typescript-file-injection
            fs.writeFileSync(file.name, file.content);
        });
        
        res.send('Batch saved');
    });
}
// {/fact}

// True Negative Examples (Safe Code)

// Example 1: Using sanitized filename
// {fact rule=file-injection@v1.0 defects=0}
function good_case_1() {
    const server = http.createServer((req, res) => {
        const url = new URL(req.url || '', `http://${req.headers.host}`);
        const unsafeFileName = url.searchParams.get('fileName') || 'default.txt';
        const content = url.searchParams.get('content') || '';
        
        // ok: typescript-file-injection
        const safeFileName = sanitize(unsafeFileName);
        fs.writeFileSync(`./uploads/${safeFileName}`, content);
        
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('File written successfully');
    });
}
// {/fact}

// Example 2: Using whitelisted filenames
// {fact rule=file-injection@v1.0 defects=0}
function good_case_2() {
    const app = express();
    
    app.get('/write', (req, res) => {
        const requestedFile = req.query.fileName as string;
        const content = req.query.content as string;
        
        const allowedFiles = ['config.txt', 'data.json', 'log.txt'];
        
        if (!allowedFiles.includes(requestedFile)) {
            res.status(403).send('Unauthorized file access');
            return;
        }
        
        // ok: typescript-file-injection
        fs.writeFile(`./safe/${requestedFile}`, content, (err) => {
            if (err) {
                res.status(500).send('Error writing file');
                return;
            }
            res.send('File written successfully');
        });
    });
}
// {/fact}

// Example 3: Using fixed file paths
// {fact rule=file-injection@v1.0 defects=0}
function good_case_3() {
    const app = express();
    
    app.post('/save', async (req, res) => {
        try {
            const userId = req.body.userId;
            const data = req.body.data;
            
            // Validate userId is a number
            const userIdNum = parseInt(userId, 10);
            if (isNaN(userIdNum)) {
                res.status(400).json({ error: 'Invalid user ID' });
                return;
            }
            
            // ok: typescript-file-injection
            const filePath = `./userdata/user_${userIdNum}.json`;
            await fs.promises.writeFile(filePath, JSON.stringify(data));
            
            res.json({ success: true });
        } catch (error) {
            res.status(500).json({ error: 'Failed to write file' });
        }
    });
}
// {/fact}

// Example 4: Using UUID for filename
// {fact rule=file-injection@v1.0 defects=0}
function good_case_4() {
    const server = http.createServer((req, res) => {
        const url = new URL(req.url || '', `http://${req.headers.host}`);
        const content = url.searchParams.get('content') || '';
        
        // Generate a random filename instead of using user input
        // ok: typescript-file-injection
        const safeFileName = crypto.randomUUID() + '.txt';
        fs.writeFileSync(`./uploads/${safeFileName}`, content);
        
        res.writeHead(200);
        res.end(`File saved as ${safeFileName}`);
    });
}
// {/fact}

// Example 5: Using hardcoded file path
// {fact rule=file-injection@v1.0 defects=0}
function good_case_5() {
    const app = express();
    
    app.post('/log', (req, res) => {
        const logMessage = req.body.message;
        const timestamp = new Date().toISOString();
        
        // ok: typescript-file-injection
        fs.writeFileSync('./logs/application.log', `${timestamp}: ${logMessage}\n`, { flag: 'a' });
        
        res.send('Log saved');
    });
}
// {/fact}

// Example 6: Using regex validation
// {fact rule=file-injection@v1.0 defects=0}
function good_case_6() {
    const server = http.createServer((req, res) => {
        const url = new URL(req.url || '', `http://${req.headers.host}`);
        const fileName = url.searchParams.get('file') || '';
        const content = url.searchParams.get('content') || '';
        
        // Validate filename with regex (alphanumeric only)
        if (!fileName.match(/^[a-zA-Z0-9]+\.txt$/)) {
            res.writeHead(400);
            res.end('Invalid filename');
            return;
        }
        
        // ok: typescript-file-injection
        fs.writeFileSync(`./safe_files/${fileName}`, content);
        
        res.writeHead(200);
        res.end('File written');
    });
}
// {/fact}

// Example 7: Using a fixed set of file paths
// {fact rule=file-injection@v1.0 defects=0}
function good_case_7() {
    const app = express();
    
    app.post('/save-config', (req, res) => {
        const configType = req.body.type;
        const configData = req.body.data;
        
        const configMap: Record<string, string> = {
            'network': './configs/network.json',
            'security': './configs/security.json',
            'display': './configs/display.json'
        };
        
        if (!configMap[configType]) {
            res.status(400).send('Invalid config type');
            return;
        }
        
        // ok: typescript-file-injection
        fs.writeFileSync(configMap[configType], JSON.stringify(configData));
        
        res.send('Config saved');
    });
}
// {/fact}

// Example 8: Using a hash function for filename
// {fact rule=file-injection@v1.0 defects=0}
function good_case_8() {
    const app = express();
    
    app.post('/store', (req, res) => {
        const content = req.body.content;
        
        // Create a hash of the content for the filename
        const hash = crypto.createHash('sha256').update(content).digest('hex');
        
        // ok: typescript-file-injection
        fs.writeFileSync(`./storage/${hash}.bin`, content);
        
        res.json({ fileId: hash });
    });
}
// {/fact}

// Example 9: Using path validation with path.normalize
// {fact rule=file-injection@v1.0 defects=0}
function good_case_9() {
    const server = http.createServer((req, res) => {
        const url = new URL(req.url || '', `http://${req.headers.host}`);
        const fileName = url.searchParams.get('file') || 'default.txt';
        const content = url.searchParams.get('content') || '';
        
        // Normalize and validate path is within allowed directory
        const normalizedPath = path.normalize(`./uploads/${fileName}`);
        if (!normalizedPath.startsWith(path.normalize('./uploads/'))) {
            res.writeHead(403);
            res.end('Path traversal attempt detected');
            return;
        }
        
        // ok: typescript-file-injection
        fs.writeFileSync(normalizedPath, content);
        
        res.writeHead(200);
        res.end('File saved');
    });
}
// {/fact}

// Example 10: Using timestamp-based filenames
// {fact rule=file-injection@v1.0 defects=0}
function good_case_10() {
    const app = express();
    
    app.post('/upload', (req, res) => {
        const content = req.body.content;
        const timestamp = Date.now();
        
        // ok: typescript-file-injection
        fs.writeFileSync(`./uploads/file_${timestamp}.txt`, content);
        
        res.send(`File saved with timestamp ${timestamp}`);
    });
}
// {/fact}

// Example 11: Using a database to map IDs to filenames
// {fact rule=file-injection@v1.0 defects=0}
function good_case_11() {
    const app = express();
    
    app.post('/save-document', (req, res) => {
        const documentId = req.body.id;
        const content = req.body.content;
        
        // Validate document ID is a number
        const id = parseInt(documentId, 10);
        if (isNaN(id)) {
            res.status(400).send('Invalid document ID');
            return;
        }
        
        // In a real app, you'd verify this ID exists in your database
        // ok: typescript-file-injection
        fs.writeFileSync(`./documents/doc_${id}.txt`, content);
        
        res.send('Document saved');
    });
}
// {/fact}

// Example 12: Using a safe subdirectory with validated input
// {fact rule=file-injection@v1.0 defects=0}
function good_case_12() {
    const server = http.createServer((req, res) => {
        const url = new URL(req.url || '', `http://${req.headers.host}`);
        const category = url.searchParams.get('category') || '';
        const content = url.searchParams.get('content') || '';
        
        // Validate category is alphanumeric
        if (!category.match(/^[a-zA-Z0-9]+$/)) {
            res.writeHead(400);
            res.end('Invalid category');
            return;
        }
        
        // Generate a safe filename
        const timestamp = Date.now();
        
        // ok: typescript-file-injection
        fs.writeFileSync(`./categories/${category}/entry_${timestamp}.txt`, content);
        
        res.writeHead(200);
        res.end('Entry saved');
    });
}
// {/fact}

// Example 13: Using a file extension whitelist
// {fact rule=file-injection@v1.0 defects=0}
function good_case_13() {
    const app = express();
    
    app.post('/save-file', (req, res) => {
        const fileName = req.body.fileName;
        const content = req.body.content;
        
        // Extract and validate file extension
        const extension = path.extname(fileName).toLowerCase();
        const allowedExtensions = ['.txt', '.md', '.json'];
        
        if (!allowedExtensions.includes(extension)) {
            res.status(400).send('Unsupported file extension');
            return;
        }
        
        // Generate safe filename with validated extension
        const safeFileName = `file_${Date.now()}${extension}`;
        
        // ok: typescript-file-injection
        fs.writeFileSync(`./files/${safeFileName}`, content);
        
        res.send(`File saved as ${safeFileName}`);
    });
}
// {/fact}

// Example 14: Using a secure temporary file
// {fact rule=file-injection@v1.0 defects=0}
function good_case_14() {
    const app = express();
    
    app.post('/process-data', (req, res) => {
        const data = req.body.data;
        
        // Create a secure temporary file with random name
        const tempFileName = `tmp_${crypto.randomBytes(16).toString('hex')}`;
        const tempFilePath = path.join('./temp', tempFileName);
        
        // ok: typescript-file-injection
        fs.writeFileSync(tempFilePath, data);
        
        // Process the file...
        
        // Clean up
        fs.unlinkSync(tempFilePath);
        
        res.send('Data processed');
    });
}
// {/fact}

// Example 15: Using user ID with additional validation
// {fact rule=file-injection@v1.0 defects=0}
function good_case_15() {
    const app = express();
    
    app.post('/save-profile', (req, res) => {
        const userId = req.body.userId;
        const profileData = req.body.profile;
        
        // Validate user ID format (e.g., must be a UUID)
        if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(userId)) {
            res.status(400).send('Invalid user ID format');
            return;
        }
        
        // Additional authorization check would happen here in a real app
        
        // ok: typescript-file-injection
        fs.writeFileSync(`./profiles/${userId}.json`, JSON.stringify(profileData));
        
        res.send('Profile saved');
    });
}
// {/fact}