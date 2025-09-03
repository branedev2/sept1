import * as fs from 'fs';
import * as path from 'path';
import * as express from 'express';
import { Request, Response } from 'express';
import * as http from 'http';
import * as url from 'url';
import * as crypto from 'crypto';

// True Positive Examples (Vulnerable Code)

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_1(req: express.Request, res: express.Response) {
    const fileName = req.query.fileName as string;
    
    // ruleid: typescript-path-injection-in-io-calls
    fs.readFile(fileName, (err, data) => {
        if (err) {
            res.status(500).send('Error reading file');
            return;
        }
        res.send(data);
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_2(req: express.Request, res: express.Response) {
    const filePath = req.params.path;
    
    // ruleid: typescript-path-injection-in-io-calls
    const fileContent = fs.readFileSync(filePath, 'utf8');
    res.send(fileContent);
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_3(req: express.Request, res: express.Response) {
    const userDir = req.query.dir as string;
    
    // ruleid: typescript-path-injection-in-io-calls
    fs.readdir(userDir, (err, files) => {
        if (err) {
            res.status(500).send('Error reading directory');
            return;
        }
        res.json(files);
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_4(req: express.Request, res: express.Response) {
    const userFile = req.body.file;
    const content = req.body.content;
    
    // ruleid: typescript-path-injection-in-io-calls
    fs.writeFile(userFile, content, (err) => {
        if (err) {
            res.status(500).send('Error writing file');
            return;
        }
        res.send('File written successfully');
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_5(req: express.Request, res: express.Response) {
    const userPath = req.headers['x-file-path'] as string;
    
    // ruleid: typescript-path-injection-in-io-calls
    if (fs.existsSync(userPath)) {
        res.send('File exists');
    } else {
        res.send('File does not exist');
    }
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_6(req: express.Request, res: express.Response) {
    const fileName = req.query.file as string;
    const newFileName = req.query.newName as string;
    
    // ruleid: typescript-path-injection-in-io-calls
    fs.rename(fileName, newFileName, (err) => {
        if (err) {
            res.status(500).send('Error renaming file');
            return;
        }
        res.send('File renamed successfully');
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_7(req: express.Request, res: express.Response) {
    const dirName = req.query.directory as string;
    
    // ruleid: typescript-path-injection-in-io-calls
    fs.mkdir(dirName, { recursive: true }, (err) => {
        if (err) {
            res.status(500).send('Error creating directory');
            return;
        }
        res.send('Directory created successfully');
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_8(req: express.Request, res: express.Response) {
    const filePath = req.cookies.filePath;
    
    try {
        // ruleid: typescript-path-injection-in-io-calls
        const stats = fs.statSync(filePath);
        res.json({
            size: stats.size,
            isFile: stats.isFile(),
            isDirectory: stats.isDirectory()
        });
    } catch (err) {
        res.status(500).send('Error getting file stats');
    }
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_9(req: express.Request, res: express.Response) {
    const userFile = req.query.file as string;
    const appendContent = req.body.content;
    
    // ruleid: typescript-path-injection-in-io-calls
    fs.appendFile(userFile, appendContent, (err) => {
        if (err) {
            res.status(500).send('Error appending to file');
            return;
        }
        res.send('Content appended successfully');
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_10(req: express.Request, res: express.Response) {
    const srcPath = req.query.source as string;
    const destPath = req.query.destination as string;
    
    // ruleid: typescript-path-injection-in-io-calls
    fs.copyFile(srcPath, destPath, (err) => {
        if (err) {
            res.status(500).send('Error copying file');
            return;
        }
        res.send('File copied successfully');
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_11(req: express.Request, res: express.Response) {
    const userPath = req.query.path as string;
    
    // ruleid: typescript-path-injection-in-io-calls
    const fileStream = fs.createReadStream(userPath);
    fileStream.pipe(res);
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_12(req: express.Request, res: express.Response) {
    const userPath = req.query.path as string;
    
    // ruleid: typescript-path-injection-in-io-calls
    const writeStream = fs.createWriteStream(userPath);
    req.pipe(writeStream);
    writeStream.on('finish', () => {
        res.send('File uploaded successfully');
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_13(req: express.Request, res: express.Response) {
    const dirPath = req.query.directory as string;
    
    // ruleid: typescript-path-injection-in-io-calls
    fs.rmdir(dirPath, { recursive: true }, (err) => {
        if (err) {
            res.status(500).send('Error removing directory');
            return;
        }
        res.send('Directory removed successfully');
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_14(req: express.Request, res: express.Response) {
    const filePath = req.query.file as string;
    
    // ruleid: typescript-path-injection-in-io-calls
    fs.unlink(filePath, (err) => {
        if (err) {
            res.status(500).send('Error deleting file');
            return;
        }
        res.send('File deleted successfully');
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_15(req: express.Request, res: express.Response) {
    const dirPath = req.query.dir as string;
    const options = { encoding: 'utf8', withFileTypes: true };
    
    // ruleid: typescript-path-injection-in-io-calls
    fs.readdir(dirPath, options, (err, files) => {
        if (err) {
            res.status(500).send('Error reading directory');
            return;
        }
        res.json(files);
    });
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_1(req: express.Request, res: express.Response) {
    const fileName = req.query.fileName as string;
    
    // Validate file name using whitelist approach
    const allowedFiles = ['report.pdf', 'document.txt', 'image.png'];
    
    if (allowedFiles.includes(fileName)) {
        // ok: typescript-path-injection-in-io-calls
        fs.readFile(`./safe_directory/${fileName}`, (err, data) => {
            if (err) {
                res.status(500).send('Error reading file');
                return;
            }
            res.send(data);
        });
    } else {
        res.status(403).send('Access denied');
    }
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_2(req: express.Request, res: express.Response) {
    const fileId = req.params.id;
    
    // Use ID to look up safe file path from database or mapping
    const safeFilePath = getSafeFilePathById(fileId);
    
    if (safeFilePath) {
        // ok: typescript-path-injection-in-io-calls
        const fileContent = fs.readFileSync(safeFilePath, 'utf8');
        res.send(fileContent);
    } else {
        res.status(404).send('File not found');
    }
}
// {/fact}

function getSafeFilePathById(id: string): string {
    // In a real app, this would query a database or secure mapping
    const fileMappings: Record<string, string> = {
        '1': './files/document1.txt',
        '2': './files/document2.txt'
    };
    return fileMappings[id];
}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_3(req: express.Request, res: express.Response) {
    const userDir = req.query.dir as string;
    
    // Normalize and restrict to safe directory
    const basePath = path.resolve('./public');
    const normalizedPath = path.normalize(path.join(basePath, userDir));
    
    // Ensure the path doesn't escape the base directory
    if (!normalizedPath.startsWith(basePath)) {
        return res.status(403).send('Access denied');
    }
    
    // ok: typescript-path-injection-in-io-calls
    fs.readdir(normalizedPath, (err, files) => {
        if (err) {
            res.status(500).send('Error reading directory');
            return;
        }
        res.json(files);
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_4(req: express.Request, res: express.Response) {
    const fileName = req.body.file;
    const content = req.body.content;
    
    // Validate file name with regex
    if (!/^[a-zA-Z0-9_-]+\.[a-zA-Z0-9]+$/.test(fileName)) {
        return res.status(400).send('Invalid file name');
    }
    
    const safePath = path.join('./uploads', fileName);
    
    // ok: typescript-path-injection-in-io-calls
    fs.writeFile(safePath, content, (err) => {
        if (err) {
            res.status(500).send('Error writing file');
            return;
        }
        res.send('File written successfully');
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_5(req: express.Request, res: express.Response) {
    // Use a fixed path instead of user input
    const configPath = './config/app-settings.json';
    
    // ok: typescript-path-injection-in-io-calls
    if (fs.existsSync(configPath)) {
        const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        res.json(config);
    } else {
        res.status(404).send('Configuration not found');
    }
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_6(req: express.Request, res: express.Response) {
    const fileId = req.query.id as string;
    
    // Map ID to safe file paths
    const fileMap: Record<string, {old: string, new: string}> = {
        '1': {old: './temp/draft.txt', new: './published/final.txt'}
    };
    
    const filePaths = fileMap[fileId];
    if (!filePaths) {
        return res.status(404).send('File not found');
    }
    
    // ok: typescript-path-injection-in-io-calls
    fs.rename(filePaths.old, filePaths.new, (err) => {
        if (err) {
            res.status(500).send('Error renaming file');
            return;
        }
        res.send('File renamed successfully');
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_7(req: express.Request, res: express.Response) {
    const userId = req.user?.id;
    
    if (!userId) {
        return res.status(401).send('Unauthorized');
    }
    
    // Create user-specific directory with sanitized ID
    const sanitizedId = userId.replace(/[^a-zA-Z0-9]/g, '');
    const userDirPath = path.join('./user_data', sanitizedId);
    
    // ok: typescript-path-injection-in-io-calls
    fs.mkdir(userDirPath, { recursive: true }, (err) => {
        if (err) {
            res.status(500).send('Error creating directory');
            return;
        }
        res.send('Directory created successfully');
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_8(req: express.Request, res: express.Response) {
    // Use a hardcoded path instead of user input
    const logFilePath = './logs/app.log';
    
    try {
        // ok: typescript-path-injection-in-io-calls
        const stats = fs.statSync(logFilePath);
        res.json({
            size: stats.size,
            modified: stats.mtime
        });
    } catch (err) {
        res.status(500).send('Error getting log stats');
    }
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_9(req: express.Request, res: express.Response) {
    const logMessage = req.body.message;
    
    // Use a fixed path for the log file
    const logFile = './logs/application.log';
    
    // ok: typescript-path-injection-in-io-calls
    fs.appendFile(logFile, `${new Date().toISOString()}: ${logMessage}\n`, (err) => {
        if (err) {
            res.status(500).send('Error writing to log');
            return;
        }
        res.send('Log entry added');
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_10(req: express.Request, res: express.Response) {
    // Use fixed paths instead of user input
    const srcPath = './templates/default.html';
    const destPath = './generated/user-template.html';
    
    // ok: typescript-path-injection-in-io-calls
    fs.copyFile(srcPath, destPath, (err) => {
        if (err) {
            res.status(500).send('Error copying template');
            return;
        }
        res.send('Template copied successfully');
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_11(req: express.Request, res: express.Response) {
    const fileId = req.query.id as string;
    
    // Validate ID format
    if (!/^\d+$/.test(fileId)) {
        return res.status(400).send('Invalid file ID');
    }
    
    const safePath = path.join('./downloads', `file-${fileId}.pdf`);
    
    // ok: typescript-path-injection-in-io-calls
    const fileStream = fs.createReadStream(safePath);
    fileStream.on('error', () => {
        res.status(404).send('File not found');
    });
    res.setHeader('Content-Type', 'application/pdf');
    fileStream.pipe(res);
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_12(req: express.Request, res: express.Response) {
    const userId = req.user?.id;
    
    if (!userId) {
        return res.status(401).send('Unauthorized');
    }
    
    // Generate a safe path with UUID to prevent conflicts
    const fileName = `${userId}-${crypto.randomUUID()}.upload`;
    const safePath = path.join('./uploads', fileName);
    
    // ok: typescript-path-injection-in-io-calls
    const writeStream = fs.createWriteStream(safePath);
    req.pipe(writeStream);
    writeStream.on('finish', () => {
        res.send({ success: true, fileId: fileName });
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_13(req: express.Request, res: express.Response) {
    // Use a fixed temporary directory path
    const tempDirPath = './temp/session_files';
    
    // ok: typescript-path-injection-in-io-calls
    fs.rmdir(tempDirPath, { recursive: true }, (err) => {
        if (err) {
            res.status(500).send('Error cleaning temporary files');
            return;
        }
        res.send('Temporary files cleaned successfully');
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_14(req: express.Request, res: express.Response) {
    const fileType = req.query.type as string;
    
    // Map file type to specific paths
    const allowedTypes: Record<string, string> = {
        'temp': './temp/temp.txt',
        'log': './logs/debug.log'
    };
    
    const filePath = allowedTypes[fileType];
    if (!filePath) {
        return res.status(400).send('Invalid file type');
    }
    
    // ok: typescript-path-injection-in-io-calls
    fs.unlink(filePath, (err) => {
        if (err) {
            res.status(500).send('Error deleting file');
            return;
        }
        res.send('File deleted successfully');
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_15(req: express.Request, res: express.Response) {
    // Use a fixed directory path
    const publicAssetsDir = './public/assets';
    const options = { encoding: 'utf8', withFileTypes: true };
    
    // ok: typescript-path-injection-in-io-calls
    fs.readdir(publicAssetsDir, options, (err, files) => {
        if (err) {
            res.status(500).send('Error reading assets directory');
            return;
        }
        res.json(files);
    });
}
// {/fact}