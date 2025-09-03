import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';
import * as express from 'express';
import * as http from 'http';

// True Positive Examples (Vulnerable Code)

// Example 1: Creating a file in /tmp with predictable name
// {fact rule=insecure-temporary-file@v1.0 defects=1}
function bad_case_1() {
    const username = "user123";
    // ruleid: typescript-insecure-publicly-writable-directories
    const tempFile = `/tmp/${username}_data.txt`;
    fs.writeFileSync(tempFile, "sensitive data", { mode: 0o644 });
    
    // Process the file
    const data = fs.readFileSync(tempFile, 'utf8');
    return data;
}
// {/fact}

// Example 2: Using /var/tmp for temporary storage with predictable name
// {fact rule=insecure-temporary-file@v1.0 defects=1}
function bad_case_2() {
    const processId = process.pid;
    // ruleid: typescript-insecure-publicly-writable-directories
    const logFile = `/var/tmp/app_${processId}.log`;
    fs.writeFileSync(logFile, "Application log data", { mode: 0o666 });
    
    // Use the log file
    return fs.existsSync(logFile);
}
// {/fact}

// Example 3: Creating a directory in /tmp with predictable pattern
// {fact rule=insecure-temporary-file@v1.0 defects=1}
function bad_case_3() {
    const timestamp = Date.now();
    // ruleid: typescript-insecure-publicly-writable-directories
    const tempDir = `/tmp/app_data_${timestamp}`;
    fs.mkdirSync(tempDir, { mode: 0o755 });
    
    // Use the directory
    fs.writeFileSync(path.join(tempDir, 'config.json'), JSON.stringify({ key: 'value' }));
    return tempDir;
}
// {/fact}

// Example 4: Using /dev/shm for temporary storage
// {fact rule=insecure-temporary-file@v1.0 defects=1}
function bad_case_4() {
    const userId = 1001;
    // ruleid: typescript-insecure-publicly-writable-directories
    const cacheFile = `/dev/shm/user_${userId}_cache.dat`;
    fs.writeFileSync(cacheFile, Buffer.from([0x01, 0x02, 0x03]), { mode: 0o644 });
    
    // Read from the cache file
    return fs.statSync(cacheFile).size;
}
// {/fact}

// Example 5: Creating a file with fixed name in /tmp from HTTP input
// {fact rule=insecure-temporary-file@v1.0 defects=1}
function bad_case_5() {
    const app = express();
    
    app.post('/save-profile', (req, res) => {
        const userId = req.body.userId;
        // ruleid: typescript-insecure-publicly-writable-directories
        const profilePath = `/tmp/profile_${userId}.json`;
        fs.writeFileSync(profilePath, JSON.stringify(req.body), { mode: 0o644 });
        
        res.send({ success: true, path: profilePath });
    });
}
// {/fact}

// Example 6: Using /tmp for lock files
// {fact rule=insecure-temporary-file@v1.0 defects=1}
function bad_case_6() {
    const appName = "myservice";
    // ruleid: typescript-insecure-publicly-writable-directories
    const lockFile = `/tmp/${appName}.lock`;
    
    if (!fs.existsSync(lockFile)) {
        fs.writeFileSync(lockFile, process.pid.toString(), { mode: 0o644 });
        console.log("Lock acquired");
    } else {
        console.log("Another process is running");
    }
    
    return fs.existsSync(lockFile);
}
// {/fact}

// Example 7: Creating a temporary directory with sequential naming
// {fact rule=insecure-temporary-file@v1.0 defects=1}
function bad_case_7() {
    let counter = 0;
    
    function createTempDir() {
        counter++;
        // ruleid: typescript-insecure-publicly-writable-directories
        const dirPath = `/tmp/app_session_${counter}`;
        fs.mkdirSync(dirPath, { mode: 0o755 });
        return dirPath;
    }
    
    const tempDir = createTempDir();
    fs.writeFileSync(path.join(tempDir, 'data.bin'), 'content');
    return tempDir;
}
// {/fact}

// Example 8: Using /tmp for storing uploaded files with user input
// {fact rule=insecure-temporary-file@v1.0 defects=1}
function bad_case_8() {
    const app = express();
    
    app.post('/upload', (req, res) => {
        const fileName = req.body.fileName;
        // ruleid: typescript-insecure-publicly-writable-directories
        const filePath = `/tmp/uploads/${fileName}`;
        
        // Ensure directory exists
        if (!fs.existsSync('/tmp/uploads')) {
            fs.mkdirSync('/tmp/uploads', { mode: 0o755 });
        }
        
        // Write file content
        fs.writeFileSync(filePath, req.body.content, { mode: 0o644 });
        res.send({ success: true });
    });
}
// {/fact}

// Example 9: Creating a temporary file with date-based naming
// {fact rule=insecure-temporary-file@v1.0 defects=1}
function bad_case_9() {
    const date = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
    // ruleid: typescript-insecure-publicly-writable-directories
    const reportFile = `/tmp/report_${date}.csv`;
    
    fs.writeFileSync(reportFile, 'Date,Value\n2023-01-01,100', { mode: 0o644 });
    return reportFile;
}
// {/fact}

// Example 10: Using /tmp for configuration files
// {fact rule=insecure-temporary-file@v1.0 defects=1}
function bad_case_10() {
    const configData = { apiKey: "secret_key", endpoint: "https://api.example.com" };
    // ruleid: typescript-insecure-publicly-writable-directories
    const configPath = `/tmp/app_config.json`;
    
    fs.writeFileSync(configPath, JSON.stringify(configData), { mode: 0o600 });
    return JSON.parse(fs.readFileSync(configPath, 'utf8'));
}
// {/fact}

// Example 11: Creating multiple files in /tmp with predictable names
// {fact rule=insecure-temporary-file@v1.0 defects=1}
function bad_case_11() {
    const users = ["alice", "bob", "charlie"];
    const files = [];
    
    for (const user of users) {
        // ruleid: typescript-insecure-publicly-writable-directories
        const userFile = `/tmp/${user}_preferences.json`;
        fs.writeFileSync(userFile, JSON.stringify({ theme: "dark" }), { mode: 0o644 });
        files.push(userFile);
    }
    
    return files;
}
// {/fact}

// Example 12: Using /tmp for socket files
// {fact rule=insecure-temporary-file@v1.0 defects=1}
function bad_case_12() {
    const appId = "backend-service";
    // ruleid: typescript-insecure-publicly-writable-directories
    const socketPath = `/tmp/${appId}.sock`;
    
    const server = http.createServer((req, res) => {
        res.writeHead(200);
        res.end('Hello World');
    });
    
    server.listen(socketPath);
    return socketPath;
}
// {/fact}

// Example 13: Creating a file in /run/user with fixed UID
// {fact rule=insecure-temporary-file@v1.0 defects=1}
function bad_case_13() {
    const uid = process.getuid ? process.getuid() : 1000;
    // ruleid: typescript-insecure-publicly-writable-directories
    const cacheDir = `/run/user/${uid}/app-cache`;
    
    if (!fs.existsSync(cacheDir)) {
        fs.mkdirSync(cacheDir, { recursive: true, mode: 0o700 });
    }
    
    const cacheFile = path.join(cacheDir, 'data.cache');
    fs.writeFileSync(cacheFile, 'cached data');
    return cacheFile;
}
// {/fact}

// Example 14: Using /tmp for storing session data
// {fact rule=insecure-temporary-file@v1.0 defects=1}
function bad_case_14() {
    const sessionId = "sess_" + Math.floor(Math.random() * 1000);
    // ruleid: typescript-insecure-publicly-writable-directories
    const sessionFile = `/tmp/${sessionId}.session`;
    
    const sessionData = {
        userId: 42,
        username: "john_doe",
        expires: Date.now() + 3600000
    };
    
    fs.writeFileSync(sessionFile, JSON.stringify(sessionData), { mode: 0o600 });
    return sessionFile;
}
// {/fact}

// Example 15: Creating a file in /tmp with environment variable
// {fact rule=insecure-temporary-file@v1.0 defects=1}
function bad_case_15() {
    const env = process.env.NODE_ENV || 'development';
    // ruleid: typescript-insecure-publicly-writable-directories
    const logFile = `/tmp/app_${env}.log`;
    
    fs.writeFileSync(logFile, `Application started in ${env} mode`, { mode: 0o644 });
    return fs.readFileSync(logFile, 'utf8');
}
// {/fact}

// True Negative Examples (Secure Code)

// Example 1: Using os.tmpdir() for temporary file creation with random name
// {fact rule=insecure-temporary-file@v1.0 defects=0}
function good_case_1() {
    const randomSuffix = crypto.randomBytes(16).toString('hex');
    // ok: typescript-insecure-publicly-writable-directories
    const tempFile = path.join(os.tmpdir(), `data_${randomSuffix}.txt`);
    fs.writeFileSync(tempFile, "sensitive data", { mode: 0o600 });
    
    // Process the file
    const data = fs.readFileSync(tempFile, 'utf8');
    fs.unlinkSync(tempFile); // Clean up
    return data;
}
// {/fact}

// Example 2: Using fs.mkdtemp for secure temporary directory creation
// {fact rule=insecure-temporary-file@v1.0 defects=0}
function good_case_2() {
    // ok: typescript-insecure-publicly-writable-directories
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'app-'));
    
    // Use the directory
    const configFile = path.join(tempDir, 'config.json');
    fs.writeFileSync(configFile, JSON.stringify({ key: 'value' }));
    
    // Clean up
    fs.unlinkSync(configFile);
    fs.rmdirSync(tempDir);
    return tempDir;
}
// {/fact}

// Example 3: Using crypto.randomBytes for unique filename in temp directory
// {fact rule=insecure-temporary-file@v1.0 defects=0}
function good_case_3() {
    const uniqueId = crypto.randomBytes(16).toString('hex');
    // ok: typescript-insecure-publicly-writable-directories
    const tempFile = path.join(os.tmpdir(), uniqueId);
    fs.writeFileSync(tempFile, "Application log data", { mode: 0o600 });
    
    // Use the file
    const exists = fs.existsSync(tempFile);
    fs.unlinkSync(tempFile); // Clean up
    return exists;
}
// {/fact}

// Example 4: Creating a secure temporary directory with proper permissions
// {fact rule=insecure-temporary-file@v1.0 defects=0}
function good_case_4() {
    // ok: typescript-insecure-publicly-writable-directories
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cache-'));
    fs.chmodSync(tempDir, 0o700); // Ensure only the owner can access
    
    const cacheFile = path.join(tempDir, 'user_cache.dat');
    fs.writeFileSync(cacheFile, Buffer.from([0x01, 0x02, 0x03]), { mode: 0o600 });
    
    // Clean up
    fs.unlinkSync(cacheFile);
    fs.rmdirSync(tempDir);
    return tempDir;
}
// {/fact}

// Example 5: Using a custom secure temp directory function
// {fact rule=insecure-temporary-file@v1.0 defects=0}
function good_case_5() {
    function createSecureTempFile(prefix: string, content: string): string {
        const randomId = crypto.randomBytes(16).toString('hex');
        // ok: typescript-insecure-publicly-writable-directories
        const filePath = path.join(os.tmpdir(), `${prefix}_${randomId}`);
        fs.writeFileSync(filePath, content, { mode: 0o600 });
        return filePath;
    }
    
    const tempFile = createSecureTempFile('profile', JSON.stringify({ name: 'John' }));
    // Use the file
    fs.unlinkSync(tempFile); // Clean up
    return tempFile;
}
// {/fact}

// Example 6: Using a lock file with secure random name
// {fact rule=insecure-temporary-file@v1.0 defects=0}
function good_case_6() {
    const appName = "myservice";
    const randomId = crypto.randomBytes(8).toString('hex');
    // ok: typescript-insecure-publicly-writable-directories
    const lockFile = path.join(os.tmpdir(), `${appName}_${randomId}.lock`);
    
    if (!fs.existsSync(lockFile)) {
        fs.writeFileSync(lockFile, process.pid.toString(), { mode: 0o600 });
        console.log("Lock acquired");
        
        // Register cleanup
        process.on('exit', () => {
            if (fs.existsSync(lockFile)) {
                fs.unlinkSync(lockFile);
            }
        });
    }
    
    return fs.existsSync(lockFile);
}
// {/fact}

// Example 7: Using UUID for unique directory names
// {fact rule=insecure-temporary-file@v1.0 defects=0}
function good_case_7() {
    function uuidv4() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            const r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }
    
    // ok: typescript-insecure-publicly-writable-directories
    const sessionDir = path.join(os.tmpdir(), `session-${uuidv4()}`);
    fs.mkdirSync(sessionDir, { mode: 0o700 });
    
    // Use the directory
    fs.writeFileSync(path.join(sessionDir, 'data.bin'), 'content', { mode: 0o600 });
    
    // Clean up
    fs.unlinkSync(path.join(sessionDir, 'data.bin'));
    fs.rmdirSync(sessionDir);
    return sessionDir;
}
// {/fact}

// Example 8: Handling file uploads securely
// {fact rule=insecure-temporary-file@v1.0 defects=0}
function good_case_8() {
    const app = express();
    
    app.post('/upload', (req, res) => {
        const randomId = crypto.randomBytes(16).toString('hex');
        // ok: typescript-insecure-publicly-writable-directories
        const uploadDir = path.join(os.tmpdir(), `upload-${randomId}`);
        fs.mkdirSync(uploadDir, { mode: 0o700 });
        
        const fileName = `file-${Date.now()}.dat`;
        const filePath = path.join(uploadDir, fileName);
        
        // Write file content
        fs.writeFileSync(filePath, req.body.content, { mode: 0o600 });
        
        // Process the file...
        
        // Clean up
        fs.unlinkSync(filePath);
        fs.rmdirSync(uploadDir);
        
        res.send({ success: true });
    });
}
// {/fact}

// Example 9: Using a timestamp with random data for unique filenames
// {fact rule=insecure-temporary-file@v1.0 defects=0}
function good_case_9() {
    const timestamp = Date.now();
    const random = Math.floor(Math.random() * 10000);
    // ok: typescript-insecure-publicly-writable-directories
    const reportFile = path.join(os.tmpdir(), `report_${timestamp}_${random}.csv`);
    
    fs.writeFileSync(reportFile, 'Date,Value\n2023-01-01,100', { mode: 0o600 });
    
    // Use the file
    const content = fs.readFileSync(reportFile, 'utf8');
    fs.unlinkSync(reportFile); // Clean up
    return content;
}
// {/fact}

// Example 10: Using a secure configuration file location
// {fact rule=insecure-temporary-file@v1.0 defects=0}
function good_case_10() {
    const configData = { apiKey: "secret_key", endpoint: "https://api.example.com" };
    const homeDir = process.env.HOME || process.env.USERPROFILE || os.homedir();
    // ok: typescript-insecure-publicly-writable-directories
    const configDir = path.join(homeDir, '.myapp');
    
    if (!fs.existsSync(configDir)) {
        fs.mkdirSync(configDir, { mode: 0o700 });
    }
    
    const configPath = path.join(configDir, 'config.json');
    fs.writeFileSync(configPath, JSON.stringify(configData), { mode: 0o600 });
    
    return JSON.parse(fs.readFileSync(configPath, 'utf8'));
}
// {/fact}

// Example 11: Creating user-specific files in a secure location
// {fact rule=insecure-temporary-file@v1.0 defects=0}
function good_case_11() {
    const users = ["alice", "bob", "charlie"];
    const files = [];
    const homeDir = process.env.HOME || process.env.USERPROFILE || os.homedir();
    // ok: typescript-insecure-publicly-writable-directories
    const appDir = path.join(homeDir, '.myapp');
    
    if (!fs.existsSync(appDir)) {
        fs.mkdirSync(appDir, { mode: 0o700 });
    }
    
    for (const user of users) {
        const userFile = path.join(appDir, `${user}_preferences.json`);
        fs.writeFileSync(userFile, JSON.stringify({ theme: "dark" }), { mode: 0o600 });
        files.push(userFile);
    }
    
    return files;
}
// {/fact}

// Example 12: Using a secure socket file location
// {fact rule=insecure-temporary-file@v1.0 defects=0}
function good_case_12() {
    const appId = "backend-service";
    const randomId = crypto.randomBytes(8).toString('hex');
    // ok: typescript-insecure-publicly-writable-directories
    const socketPath = path.join(os.tmpdir(), `${appId}-${randomId}.sock`);
    
    const server = http.createServer((req, res) => {
        res.writeHead(200);
        res.end('Hello World');
    });
    
    server.listen(socketPath);
    
    // Register cleanup
    process.on('exit', () => {
        if (fs.existsSync(socketPath)) {
            fs.unlinkSync(socketPath);
        }
    });
    
    return socketPath;
}
// {/fact}

// Example 13: Using a proper application cache directory
// {fact rule=insecure-temporary-file@v1.0 defects=0}
function good_case_13() {
    const homeDir = process.env.HOME || process.env.USERPROFILE || os.homedir();
    // ok: typescript-insecure-publicly-writable-directories
    const cacheDir = path.join(homeDir, '.cache', 'myapp');
    
    if (!fs.existsSync(cacheDir)) {
        fs.mkdirSync(cacheDir, { recursive: true, mode: 0o700 });
    }
    
    const cacheFile = path.join(cacheDir, 'data.cache');
    fs.writeFileSync(cacheFile, 'cached data', { mode: 0o600 });
    
    return cacheFile;
}
// {/fact}

// Example 14: Secure session storage with cleanup
// {fact rule=insecure-temporary-file@v1.0 defects=0}
function good_case_14() {
    const sessionId = crypto.randomBytes(16).toString('hex');
    // ok: typescript-insecure-publicly-writable-directories
    const sessionFile = path.join(os.tmpdir(), `sess_${sessionId}`);
    
    const sessionData = {
        userId: 42,
        username: "john_doe",
        expires: Date.now() + 3600000
    };
    
    fs.writeFileSync(sessionFile, JSON.stringify(sessionData), { mode: 0o600 });
    
    // Set up cleanup
    setTimeout(() => {
        if (fs.existsSync(sessionFile)) {
            fs.unlinkSync(sessionFile);
        }
    }, 3600000); // 1 hour
    
    return sessionFile;
}
// {/fact}

// Example 15: Using environment-specific secure directory
// {fact rule=insecure-temporary-file@v1.0 defects=0}
function good_case_15() {
    const env = process.env.NODE_ENV || 'development';
    const randomId = crypto.randomBytes(8).toString('hex');
    // ok: typescript-insecure-publicly-writable-directories
    const logFile = path.join(os.tmpdir(), `app_${env}_${randomId}.log`);
    
    fs.writeFileSync(logFile, `Application started in ${env} mode`, { mode: 0o600 });
    
    const content = fs.readFileSync(logFile, 'utf8');
    fs.unlinkSync(logFile); // Clean up
    return content;
}
// {/fact}