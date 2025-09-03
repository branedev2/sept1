import * as express from 'express';
import * as fs from 'fs';
import * as path from 'path';
import { Request, Response } from 'express';
import * as sanitize from 'sanitize-filename';
import * as crypto from 'crypto';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// True Positive Examples (Vulnerable Code)

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_1(req: Request, res: Response) {
    const fileName = req.query.file as string;
    // ruleid: typescript-express-path-traversal
    const filePath = path.join(__dirname, 'files', fileName);
    const content = fs.readFileSync(filePath, 'utf8');
    res.send(content);
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_2(req: Request, res: Response) {
    const userId = req.params.id;
    // ruleid: typescript-express-path-traversal
    const userFile = `./users/${userId}/profile.json`;
    fs.readFile(userFile, (err, data) => {
        if (err) {
            res.status(404).send('User not found');
        } else {
            res.json(JSON.parse(data.toString()));
        }
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_3(req: Request, res: Response) {
    const template = req.query.template as string;
    // ruleid: typescript-express-path-traversal
    const templatePath = `./templates/${template}.html`;
    try {
        const content = fs.readFileSync(templatePath);
        res.type('html').send(content);
    } catch (err) {
        res.status(404).send('Template not found');
    }
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_4(req: Request, res: Response) {
    const logFile = req.headers['x-log-file'] as string;
    // ruleid: typescript-express-path-traversal
    fs.appendFile(`./logs/${logFile}`, new Date().toISOString() + ' - Access\n', (err) => {
        if (err) {
            res.status(500).send('Error writing to log');
        } else {
            res.send('Log updated');
        }
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_5(req: Request, res: Response) {
    const reportId = req.body.reportId;
    // ruleid: typescript-express-path-traversal
    const reportPath = path.resolve(`/var/reports/${reportId}`);
    fs.stat(reportPath, (err, stats) => {
        if (err) {
            res.status(404).send('Report not found');
        } else {
            res.download(reportPath);
        }
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_6(req: Request, res: Response) {
    const configName = req.query.config as string;
    // ruleid: typescript-express-path-traversal
    const configPath = path.normalize(`./configs/${configName}.json`);
    try {
        const config = require(configPath);
        res.json(config);
    } catch (err) {
        res.status(404).send('Configuration not found');
    }
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_7(req: Request, res: Response) {
    const imageName = req.params.image;
    let imageDir = req.query.dir as string || 'public';
    // ruleid: typescript-express-path-traversal
    const imagePath = `${imageDir}/${imageName}.jpg`;
    fs.access(imagePath, fs.constants.R_OK, (err) => {
        if (err) {
            res.status(404).send('Image not found');
        } else {
            res.sendFile(path.resolve(imagePath));
        }
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_8(req: Request, res: Response) {
    const docId = req.cookies.document;
    // ruleid: typescript-express-path-traversal
    const docPath = path.join(process.cwd(), 'documents', docId);
    fs.readdir(docPath, (err, files) => {
        if (err) {
            res.status(500).send('Error accessing document directory');
        } else {
            res.json(files);
        }
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_9(req: Request, res: Response) {
    const module = req.query.module as string;
    // ruleid: typescript-express-path-traversal
    const modulePath = `./modules/${module}/index.js`;
    try {
        delete require.cache[require.resolve(modulePath)];
        const moduleObj = require(modulePath);
        res.json(moduleObj.info());
    } catch (err) {
        res.status(404).send('Module not found');
    }
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_10(req: Request, res: Response) {
    const fileName = req.body.fileName;
    const fileContent = req.body.content;
    // ruleid: typescript-express-path-traversal
    fs.writeFile(`./user_files/${fileName}`, fileContent, (err) => {
        if (err) {
            res.status(500).send('Error writing file');
        } else {
            res.send('File saved successfully');
        }
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_11(req: Request, res: Response) {
    const backupFile = req.query.backup as string;
    // ruleid: typescript-express-path-traversal
    const backupPath = path.join('/var/backups', backupFile);
    fs.createReadStream(backupPath).pipe(res);
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_12(req: Request, res: Response) {
    const theme = req.query.theme as string;
    const page = req.query.page as string;
    // ruleid: typescript-express-path-traversal
    const templateFile = `./themes/${theme}/${page}.html`;
    fs.readFile(templateFile, 'utf8', (err, data) => {
        if (err) {
            res.status(404).send('Template not found');
        } else {
            res.type('html').send(data);
        }
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_13(req: Request, res: Response) {
    const assetPath = req.params[0]; // Using wildcard parameter
    // ruleid: typescript-express-path-traversal
    const fullPath = path.join('./public/assets', assetPath);
    res.sendFile(path.resolve(fullPath));
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_14(req: Request, res: Response) {
    const username = req.session?.username;
    const projectName = req.query.project as string;
    // ruleid: typescript-express-path-traversal
    const projectPath = `./projects/${username}/${projectName}`;
    fs.readdir(projectPath, (err, files) => {
        if (err) {
            res.status(404).send('Project not found');
        } else {
            res.json({ files });
        }
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_15(req: Request, res: Response) {
    const relativePath = req.body.path || '';
    // ruleid: typescript-express-path-traversal
    const filePath = path.join('/var/www/html', relativePath);
    try {
        const stats = fs.statSync(filePath);
        res.json({
            size: stats.size,
            modified: stats.mtime,
            created: stats.birthtime
        });
    } catch (err) {
        res.status(404).send('File not found');
    }
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_1(req: Request, res: Response) {
    const fileName = req.query.file as string;
    // Validate file name to prevent path traversal
    if (!fileName || fileName.includes('..') || fileName.includes('/')) {
        return res.status(400).send('Invalid file name');
    }
    // ok: typescript-express-path-traversal
    const filePath = path.join(__dirname, 'files', fileName);
    const content = fs.readFileSync(filePath, 'utf8');
    res.send(content);
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_2(req: Request, res: Response) {
    const userId = req.params.id;
    // Sanitize user ID to prevent path traversal
    const sanitizedId = userId.replace(/[^a-zA-Z0-9]/g, '');
    // ok: typescript-express-path-traversal
    const userFile = `./users/${sanitizedId}/profile.json`;
    fs.readFile(userFile, (err, data) => {
        if (err) {
            res.status(404).send('User not found');
        } else {
            res.json(JSON.parse(data.toString()));
        }
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_3(req: Request, res: Response) {
    const template = req.query.template as string;
    // Whitelist of allowed templates
    const allowedTemplates = ['welcome', 'about', 'contact', 'privacy'];
    if (!allowedTemplates.includes(template)) {
        return res.status(400).send('Invalid template');
    }
    // ok: typescript-express-path-traversal
    const templatePath = `./templates/${template}.html`;
    try {
        const content = fs.readFileSync(templatePath);
        res.type('html').send(content);
    } catch (err) {
        res.status(404).send('Template not found');
    }
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_4(req: Request, res: Response) {
    const logFile = req.headers['x-log-file'] as string;
    // Use sanitize-filename library to prevent path traversal
    const sanitizedLogFile = sanitize(logFile);
    // ok: typescript-express-path-traversal
    fs.appendFile(`./logs/${sanitizedLogFile}`, new Date().toISOString() + ' - Access\n', (err) => {
        if (err) {
            res.status(500).send('Error writing to log');
        } else {
            res.send('Log updated');
        }
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_5(req: Request, res: Response) {
    const reportId = req.body.reportId;
    // Validate report ID format (assuming UUIDs)
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(reportId)) {
        return res.status(400).send('Invalid report ID');
    }
    // ok: typescript-express-path-traversal
    const reportPath = path.resolve(`/var/reports/${reportId}`);
    fs.stat(reportPath, (err, stats) => {
        if (err) {
            res.status(404).send('Report not found');
        } else {
            res.download(reportPath);
        }
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_6(req: Request, res: Response) {
    const configName = req.query.config as string;
    // Whitelist of allowed configurations
    const allowedConfigs = ['app', 'server', 'database', 'cache'];
    if (!allowedConfigs.includes(configName)) {
        return res.status(400).send('Invalid configuration');
    }
    // ok: typescript-express-path-traversal
    const configPath = path.normalize(`./configs/${configName}.json`);
    try {
        const config = require(configPath);
        res.json(config);
    } catch (err) {
        res.status(404).send('Configuration not found');
    }
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_7(req: Request, res: Response) {
    const imageName = req.params.image;
    // Sanitize image name
    const sanitizedImageName = sanitize(imageName);
    // Whitelist of allowed directories
    const allowedDirs = ['public', 'shared', 'common'];
    let imageDir = req.query.dir as string || 'public';
    if (!allowedDirs.includes(imageDir)) {
        imageDir = 'public';
    }
    // ok: typescript-express-path-traversal
    const imagePath = `${imageDir}/${sanitizedImageName}.jpg`;
    fs.access(imagePath, fs.constants.R_OK, (err) => {
        if (err) {
            res.status(404).send('Image not found');
        } else {
            res.sendFile(path.resolve(imagePath));
        }
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_8(req: Request, res: Response) {
    const docId = req.cookies.document;
    // Validate document ID format
    if (!docId || !/^[a-zA-Z0-9_-]+$/.test(docId)) {
        return res.status(400).send('Invalid document ID');
    }
    // ok: typescript-express-path-traversal
    const docPath = path.join(process.cwd(), 'documents', docId);
    fs.readdir(docPath, (err, files) => {
        if (err) {
            res.status(500).send('Error accessing document directory');
        } else {
            res.json(files);
        }
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_9(req: Request, res: Response) {
    const module = req.query.module as string;
    // Whitelist of allowed modules
    const allowedModules = ['user', 'product', 'order', 'payment'];
    if (!allowedModules.includes(module)) {
        return res.status(400).send('Invalid module');
    }
    // ok: typescript-express-path-traversal
    const modulePath = `./modules/${module}/index.js`;
    try {
        delete require.cache[require.resolve(modulePath)];
        const moduleObj = require(modulePath);
        res.json(moduleObj.info());
    } catch (err) {
        res.status(404).send('Module not found');
    }
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_10(req: Request, res: Response) {
    const fileName = req.body.fileName;
    const fileContent = req.body.content;
    
    // Sanitize file name and prevent directory traversal
    const sanitizedFileName = path.basename(sanitize(fileName));
    
    // ok: typescript-express-path-traversal
    fs.writeFile(`./user_files/${sanitizedFileName}`, fileContent, (err) => {
        if (err) {
            res.status(500).send('Error writing file');
        } else {
            res.send('File saved successfully');
        }
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_11(req: Request, res: Response) {
    const backupFile = req.query.backup as string;
    
    // Generate a hash of the filename to avoid path traversal
    const hashedName = crypto.createHash('md5').update(backupFile).digest('hex');
    
    // ok: typescript-express-path-traversal
    const backupPath = path.join('/var/backups', hashedName);
    fs.createReadStream(backupPath).pipe(res);
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_12(req: Request, res: Response) {
    const theme = req.query.theme as string;
    const page = req.query.page as string;
    
    // Whitelist validation
    const allowedThemes = ['light', 'dark', 'blue'];
    const allowedPages = ['home', 'about', 'contact'];
    
    if (!allowedThemes.includes(theme) || !allowedPages.includes(page)) {
        return res.status(400).send('Invalid theme or page');
    }
    
    // ok: typescript-express-path-traversal
    const templateFile = `./themes/${theme}/${page}.html`;
    fs.readFile(templateFile, 'utf8', (err, data) => {
        if (err) {
            res.status(404).send('Template not found');
        } else {
            res.type('html').send(data);
        }
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_13(req: Request, res: Response) {
    const assetPath = req.params[0]; // Using wildcard parameter
    
    // Validate path to prevent traversal
    if (assetPath.includes('..') || assetPath.startsWith('/')) {
        return res.status(400).send('Invalid asset path');
    }
    
    // ok: typescript-express-path-traversal
    const fullPath = path.join('./public/assets', assetPath);
    res.sendFile(path.resolve(fullPath));
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_14(req: Request, res: Response) {
    const username = req.session?.username;
    const projectName = req.query.project as string;
    
    // Sanitize inputs
    const sanitizedUsername = username?.replace(/[^a-zA-Z0-9_-]/g, '');
    const sanitizedProject = sanitize(projectName);
    
    if (!sanitizedUsername || !sanitizedProject) {
        return res.status(400).send('Invalid username or project');
    }
    
    // ok: typescript-express-path-traversal
    const projectPath = `./projects/${sanitizedUsername}/${sanitizedProject}`;
    fs.readdir(projectPath, (err, files) => {
        if (err) {
            res.status(404).send('Project not found');
        } else {
            res.json({ files });
        }
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_15(req: Request, res: Response) {
    const relativePath = req.body.path || '';
    
    // Validate path to prevent traversal
    if (relativePath.includes('..') || !relativePath.match(/^[a-zA-Z0-9_\/-]+$/)) {
        return res.status(400).send('Invalid path');
    }
    
    // ok: typescript-express-path-traversal
    const filePath = path.join('/var/www/html', relativePath);
    try {
        const stats = fs.statSync(filePath);
        res.json({
            size: stats.size,
            modified: stats.mtime,
            created: stats.birthtime
        });
    } catch (err) {
        res.status(404).send('File not found');
    }
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});