const fs = require('fs');
const path = require('path');
const express = require('express');
const app = express();
const http = require('http');
const url = require('url');
const sanitize = require('sanitize-filename');
const crypto = require('crypto');

// True Positive Examples (Vulnerable Code)

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_1() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url, true);
        const fileName = parsedUrl.query.file;
        
        // ruleid: javascript-path-injection-in-io-calls
        fs.readFile(fileName, (err, data) => {
            if (err) {
                res.writeHead(404);
                res.end('File not found');
                return;
            }
            res.writeHead(200);
            res.end(data);
        });
    });
    server.listen(3000);
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_2() {
    app.get('/download', (req, res) => {
        const userFile = req.query.filename;
        
        // ruleid: javascript-path-injection-in-io-calls
        const fileContent = fs.readFileSync(userFile);
        res.send(fileContent);
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_3() {
    app.post('/save-notes', express.json(), (req, res) => {
        const noteId = req.body.noteId;
        const content = req.body.content;
        
        // ruleid: javascript-path-injection-in-io-calls
        fs.writeFile(`./notes/${noteId}.txt`, content, (err) => {
            if (err) {
                return res.status(500).send('Error saving note');
            }
            res.send('Note saved successfully');
        });
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_4() {
    app.get('/logs', (req, res) => {
        const date = req.query.date;
        
        // ruleid: javascript-path-injection-in-io-calls
        fs.readdir(`./logs/${date}`, (err, files) => {
            if (err) {
                return res.status(500).send('Error reading logs');
            }
            res.json(files);
        });
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_5() {
    app.get('/view-file', (req, res) => {
        const filePath = req.query.path;
        
        // ruleid: javascript-path-injection-in-io-calls
        const stats = fs.statSync(filePath);
        if (stats.isFile()) {
            const content = fs.readFileSync(filePath, 'utf8');
            res.send(content);
        } else {
            res.status(400).send('Not a file');
        }
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_6() {
    app.delete('/delete-file', (req, res) => {
        const fileToDelete = req.query.file;
        
        // ruleid: javascript-path-injection-in-io-calls
        fs.unlink(fileToDelete, (err) => {
            if (err) {
                return res.status(500).send('Error deleting file');
            }
            res.send('File deleted successfully');
        });
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_7() {
    app.post('/create-directory', express.json(), (req, res) => {
        const dirName = req.body.directory;
        
        // ruleid: javascript-path-injection-in-io-calls
        fs.mkdir(dirName, { recursive: true }, (err) => {
            if (err) {
                return res.status(500).send('Error creating directory');
            }
            res.send('Directory created successfully');
        });
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_8() {
    app.get('/append-log', (req, res) => {
        const logFile = req.query.logfile;
        const message = req.query.message;
        
        // ruleid: javascript-path-injection-in-io-calls
        fs.appendFile(logFile, message + '\n', (err) => {
            if (err) {
                return res.status(500).send('Error appending to log');
            }
            res.send('Log updated');
        });
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_9() {
    app.get('/check-exists', (req, res) => {
        const checkPath = req.query.path;
        
        // ruleid: javascript-path-injection-in-io-calls
        fs.access(checkPath, fs.constants.F_OK, (err) => {
            res.json({ exists: !err });
        });
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_10() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url, true);
        const dirPath = parsedUrl.query.dir;
        
        // ruleid: javascript-path-injection-in-io-calls
        fs.readdir(dirPath, (err, files) => {
            if (err) {
                res.writeHead(500);
                res.end('Error reading directory');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(files));
        });
    });
    server.listen(3000);
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_11() {
    app.get('/copy-file', (req, res) => {
        const source = req.query.source;
        const destination = req.query.destination;
        
        // ruleid: javascript-path-injection-in-io-calls
        fs.copyFile(source, destination, (err) => {
            if (err) {
                return res.status(500).send('Error copying file');
            }
            res.send('File copied successfully');
        });
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_12() {
    app.get('/file-info', (req, res) => {
        const filePath = req.query.file;
        
        // ruleid: javascript-path-injection-in-io-calls
        fs.lstat(filePath, (err, stats) => {
            if (err) {
                return res.status(500).send('Error getting file info');
            }
            res.json({
                size: stats.size,
                isDirectory: stats.isDirectory(),
                modified: stats.mtime
            });
        });
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_13() {
    app.post('/rename', express.json(), (req, res) => {
        const oldPath = req.body.oldPath;
        const newPath = req.body.newPath;
        
        // ruleid: javascript-path-injection-in-io-calls
        fs.rename(oldPath, newPath, (err) => {
            if (err) {
                return res.status(500).send('Error renaming file');
            }
            res.send('File renamed successfully');
        });
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_14() {
    app.get('/truncate-file', (req, res) => {
        const filePath = req.query.file;
        const length = parseInt(req.query.length) || 0;
        
        // ruleid: javascript-path-injection-in-io-calls
        fs.truncate(filePath, length, (err) => {
            if (err) {
                return res.status(500).send('Error truncating file');
            }
            res.send('File truncated successfully');
        });
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_15() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url, true);
        const userPath = parsedUrl.query.path;
        
        try {
            // ruleid: javascript-path-injection-in-io-calls
            const fileStream = fs.createReadStream(userPath);
            fileStream.pipe(res);
        } catch (err) {
            res.writeHead(500);
            res.end('Error streaming file');
        }
    });
    server.listen(3000);
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_1() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url, true);
        const fileName = parsedUrl.query.file;
        
        // Validate the filename is just a basename without path traversal
        const sanitizedName = sanitize(fileName);
        
        // ok: javascript-path-injection-in-io-calls
        fs.readFile(`./uploads/${sanitizedName}`, (err, data) => {
            if (err) {
                res.writeHead(404);
                res.end('File not found');
                return;
            }
            res.writeHead(200);
            res.end(data);
        });
    });
    server.listen(3000);
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_2() {
    app.get('/download', (req, res) => {
        const userFile = req.query.filename;
        
        // Restrict to a specific directory and sanitize filename
        const allowedDir = path.resolve('./public/downloads');
        const sanitizedName = sanitize(userFile);
        const filePath = path.join(allowedDir, sanitizedName);
        
        // Ensure the path is within the allowed directory
        if (!filePath.startsWith(allowedDir)) {
            return res.status(403).send('Access denied');
        }
        
        // ok: javascript-path-injection-in-io-calls
        const fileContent = fs.readFileSync(filePath);
        res.send(fileContent);
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_3() {
    app.post('/save-notes', express.json(), (req, res) => {
        const noteId = req.body.noteId;
        const content = req.body.content;
        
        // Sanitize the noteId to prevent path traversal
        const sanitizedId = sanitize(noteId);
        
        // ok: javascript-path-injection-in-io-calls
        fs.writeFile(`./notes/${sanitizedId}.txt`, content, (err) => {
            if (err) {
                return res.status(500).send('Error saving note');
            }
            res.send('Note saved successfully');
        });
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_4() {
    app.get('/logs', (req, res) => {
        const date = req.query.date;
        
        // Validate date format (YYYY-MM-DD)
        if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
            return res.status(400).send('Invalid date format');
        }
        
        // ok: javascript-path-injection-in-io-calls
        fs.readdir(`./logs/${date}`, (err, files) => {
            if (err) {
                return res.status(500).send('Error reading logs');
            }
            res.json(files);
        });
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_5() {
    app.get('/view-file', (req, res) => {
        // Use a whitelist of allowed files
        const allowedFiles = {
            'config': './config/public-config.json',
            'readme': './README.md',
            'changelog': './CHANGELOG.md'
        };
        
        const fileKey = req.query.file;
        
        if (!allowedFiles[fileKey]) {
            return res.status(403).send('File access not allowed');
        }
        
        // ok: javascript-path-injection-in-io-calls
        const content = fs.readFileSync(allowedFiles[fileKey], 'utf8');
        res.send(content);
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_6() {
    app.delete('/delete-file', (req, res) => {
        const fileToDelete = req.query.file;
        const sanitizedName = sanitize(fileToDelete);
        const uploadsDir = path.resolve('./uploads');
        const filePath = path.join(uploadsDir, sanitizedName);
        
        // Ensure the path is within the allowed directory
        if (!filePath.startsWith(uploadsDir)) {
            return res.status(403).send('Access denied');
        }
        
        // ok: javascript-path-injection-in-io-calls
        fs.unlink(filePath, (err) => {
            if (err) {
                return res.status(500).send('Error deleting file');
            }
            res.send('File deleted successfully');
        });
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_7() {
    app.post('/create-directory', express.json(), (req, res) => {
        const dirName = req.body.directory;
        
        // Sanitize directory name
        const sanitizedName = sanitize(dirName);
        const userDataDir = path.resolve('./user-data');
        const dirPath = path.join(userDataDir, sanitizedName);
        
        // Ensure the path is within the allowed directory
        if (!dirPath.startsWith(userDataDir)) {
            return res.status(403).send('Access denied');
        }
        
        // ok: javascript-path-injection-in-io-calls
        fs.mkdir(dirPath, { recursive: true }, (err) => {
            if (err) {
                return res.status(500).send('Error creating directory');
            }
            res.send('Directory created successfully');
        });
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_8() {
    app.get('/append-log', (req, res) => {
        const logType = req.query.type;
        const message = req.query.message;
        
        // Use a whitelist for log types
        const allowedLogTypes = {
            'access': './logs/access.log',
            'error': './logs/error.log',
            'debug': './logs/debug.log'
        };
        
        if (!allowedLogTypes[logType]) {
            return res.status(400).send('Invalid log type');
        }
        
        // ok: javascript-path-injection-in-io-calls
        fs.appendFile(allowedLogTypes[logType], message + '\n', (err) => {
            if (err) {
                return res.status(500).send('Error appending to log');
            }
            res.send('Log updated');
        });
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_9() {
    app.get('/check-exists', (req, res) => {
        const fileId = req.query.id;
        
        // Validate ID format
        if (!/^[a-zA-Z0-9-_]+$/.test(fileId)) {
            return res.status(400).send('Invalid file ID');
        }
        
        const filePath = path.join('./public/files', fileId + '.txt');
        
        // ok: javascript-path-injection-in-io-calls
        fs.access(filePath, fs.constants.F_OK, (err) => {
            res.json({ exists: !err });
        });
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_10() {
    const server = http.createServer((req, res) => {
        // Use fixed directories only, no user input for directory path
        const staticDir = './public';
        
        // ok: javascript-path-injection-in-io-calls
        fs.readdir(staticDir, (err, files) => {
            if (err) {
                res.writeHead(500);
                res.end('Error reading directory');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(files));
        });
    });
    server.listen(3000);
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_11() {
    app.get('/copy-template', (req, res) => {
        const templateName = req.query.template;
        const userId = req.query.userId;
        
        // Sanitize inputs
        const sanitizedTemplate = sanitize(templateName);
        const sanitizedUserId = sanitize(userId);
        
        const templatesDir = path.resolve('./templates');
        const userDir = path.resolve('./user-files');
        
        const sourcePath = path.join(templatesDir, sanitizedTemplate + '.txt');
        const destPath = path.join(userDir, sanitizedUserId, sanitizedTemplate + '.txt');
        
        // Ensure paths are within allowed directories
        if (!sourcePath.startsWith(templatesDir) || !destPath.startsWith(userDir)) {
            return res.status(403).send('Access denied');
        }
        
        // ok: javascript-path-injection-in-io-calls
        fs.copyFile(sourcePath, destPath, (err) => {
            if (err) {
                return res.status(500).send('Error copying template');
            }
            res.send('Template copied successfully');
        });
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_12() {
    app.get('/file-info', (req, res) => {
        // Use a UUID for file identification instead of paths
        const fileId = req.query.id;
        
        // Validate UUID format
        if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(fileId)) {
            return res.status(400).send('Invalid file ID');
        }
        
        // Map ID to actual file path
        const fileMapping = {
            // This would typically come from a database
            '123e4567-e89b-12d3-a456-426614174000': './uploads/document.pdf',
            '123e4567-e89b-12d3-a456-426614174001': './uploads/image.jpg'
        };
        
        const filePath = fileMapping[fileId];
        if (!filePath) {
            return res.status(404).send('File not found');
        }
        
        // ok: javascript-path-injection-in-io-calls
        fs.lstat(filePath, (err, stats) => {
            if (err) {
                return res.status(500).send('Error getting file info');
            }
            res.json({
                size: stats.size,
                isDirectory: stats.isDirectory(),
                modified: stats.mtime
            });
        });
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_13() {
    app.post('/rename-upload', express.json(), (req, res) => {
        const fileId = req.body.fileId;
        const newName = req.body.newName;
        
        // Sanitize inputs
        const sanitizedNewName = sanitize(newName);
        
        // Validate file ID
        if (!/^[0-9]+$/.test(fileId)) {
            return res.status(400).send('Invalid file ID');
        }
        
        // Map ID to file path (would typically come from database)
        const uploadsDir = path.resolve('./uploads');
        const oldPath = path.join(uploadsDir, `file_${fileId}.txt`);
        const newPath = path.join(uploadsDir, sanitizedNewName + '.txt');
        
        // Ensure paths are within allowed directory
        if (!oldPath.startsWith(uploadsDir) || !newPath.startsWith(uploadsDir)) {
            return res.status(403).send('Access denied');
        }
        
        // ok: javascript-path-injection-in-io-calls
        fs.rename(oldPath, newPath, (err) => {
            if (err) {
                return res.status(500).send('Error renaming file');
            }
            res.send('File renamed successfully');
        });
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_14() {
    app.get('/truncate-log', (req, res) => {
        // Use a whitelist for log files
        const logType = req.query.type;
        const allowedLogs = {
            'access': './logs/access.log',
            'error': './logs/error.log'
        };
        
        if (!allowedLogs[logType]) {
            return res.status(400).send('Invalid log type');
        }
        
        // ok: javascript-path-injection-in-io-calls
        fs.truncate(allowedLogs[logType], 0, (err) => {
            if (err) {
                return res.status(500).send('Error truncating log');
            }
            res.send('Log truncated successfully');
        });
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_15() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url, true);
        const fileId = parsedUrl.query.id;
        
        // Generate a hash of the file ID to use as filename
        const hash = crypto.createHash('sha256').update(fileId).digest('hex');
        const filePath = path.join('./secure-files', hash.substring(0, 10) + '.txt');
        
        try {
            // ok: javascript-path-injection-in-io-calls
            const fileStream = fs.createReadStream(filePath);
            fileStream.pipe(res);
        } catch (err) {
            res.writeHead(500);
            res.end('Error streaming file');
        }
    });
    server.listen(3000);
}
// {/fact}