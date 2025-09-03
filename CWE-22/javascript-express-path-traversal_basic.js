const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
const sanitize = require('sanitize-filename');
const { check, validationResult } = require('express-validator');

// True Positive Examples (Vulnerable Code)

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_1() {
  app.get('/download', (req, res) => {
    const fileName = req.query.file;
    // ruleid: javascript-express-path-traversal
    const filePath = path.join(__dirname, 'files', fileName);
    
    fs.readFile(filePath, (err, data) => {
      if (err) {
        return res.status(404).send('File not found');
      }
      res.send(data);
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_2() {
  app.get('/view-file', (req, res) => {
    const userFile = req.query.path;
    // ruleid: javascript-express-path-traversal
    const filePath = __dirname + '/documents/' + userFile;
    
    fs.readFile(filePath, 'utf8', (err, content) => {
      if (err) {
        return res.status(500).send('Error loading file');
      }
      res.send(content);
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_3() {
  app.post('/read-log', (req, res) => {
    const logName = req.body.logFile;
    // ruleid: javascript-express-path-traversal
    const logPath = path.resolve('./logs/' + logName);
    
    fs.readFile(logPath, 'utf8', (err, data) => {
      if (err) {
        return res.status(500).send('Could not read log');
      }
      res.json({ content: data });
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_4() {
  app.get('/images/:imageName', (req, res) => {
    const imageName = req.params.imageName;
    // ruleid: javascript-express-path-traversal
    const imagePath = `${__dirname}/public/images/${imageName}`;
    
    fs.access(imagePath, fs.constants.R_OK, (err) => {
      if (err) {
        return res.status(404).send('Image not found');
      }
      res.sendFile(imagePath);
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_5() {
  app.get('/config', (req, res) => {
    const configFile = req.query.name || 'default';
    // ruleid: javascript-express-path-traversal
    const configPath = path.join(process.cwd(), 'configs', configFile + '.json');
    
    fs.readFile(configPath, 'utf8', (err, data) => {
      if (err) {
        return res.status(404).send('Config not found');
      }
      res.json(JSON.parse(data));
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_6() {
  app.get('/template', (req, res) => {
    const template = req.query.name;
    // ruleid: javascript-express-path-traversal
    const templatePath = path.normalize(`./templates/${template}.html`);
    
    fs.readFile(templatePath, 'utf8', (err, content) => {
      if (err) {
        return res.status(404).send('Template not found');
      }
      res.send(content);
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_7() {
  app.post('/save-notes', (req, res) => {
    const { fileName, content } = req.body;
    // ruleid: javascript-express-path-traversal
    const notePath = path.join(__dirname, 'user-notes', fileName);
    
    fs.writeFile(notePath, content, (err) => {
      if (err) {
        return res.status(500).send('Failed to save note');
      }
      res.send('Note saved successfully');
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_8() {
  app.get('/serve-static', (req, res) => {
    const requestedPath = req.query.resource;
    // ruleid: javascript-express-path-traversal
    res.sendFile(path.join(__dirname, 'static', requestedPath));
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_9() {
  app.post('/upload-profile', upload.single('avatar'), (req, res) => {
    const userId = req.body.userId;
    const targetDir = req.body.directory;
    // ruleid: javascript-express-path-traversal
    const userDir = path.join(__dirname, 'profiles', targetDir);
    
    if (!fs.existsSync(userDir)) {
      fs.mkdirSync(userDir, { recursive: true });
    }
    
    const targetPath = path.join(userDir, req.file.originalname);
    fs.copyFileSync(req.file.path, targetPath);
    fs.unlinkSync(req.file.path);
    
    res.json({ success: true, path: targetPath });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_10() {
  app.get('/backup', (req, res) => {
    const backupFile = req.headers['x-backup-file'];
    // ruleid: javascript-express-path-traversal
    const backupPath = path.join('/var/backups', backupFile);
    
    fs.readFile(backupPath, (err, data) => {
      if (err) {
        return res.status(404).send('Backup not found');
      }
      res.send(data);
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_11() {
  app.get('/read-markdown', (req, res) => {
    const fileName = req.cookies.lastFile;
    // ruleid: javascript-express-path-traversal
    const filePath = `./content/markdown/${fileName}.md`;
    
    fs.readFile(filePath, 'utf8', (err, content) => {
      if (err) {
        return res.status(404).send('File not found');
      }
      res.send(content);
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_12() {
  app.post('/include-partial', (req, res) => {
    const partialName = req.body.partial;
    // ruleid: javascript-express-path-traversal
    const partialPath = path.join(process.cwd(), 'views', 'partials', partialName);
    
    fs.readFile(partialPath, 'utf8', (err, content) => {
      if (err) {
        return res.status(500).send('Could not load partial');
      }
      res.send({ content });
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_13() {
  app.get('/download-report', (req, res) => {
    let reportPath = req.query.report;
    if (!reportPath.endsWith('.pdf')) {
      reportPath += '.pdf';
    }
    // ruleid: javascript-express-path-traversal
    const fullPath = path.join(__dirname, 'reports', reportPath);
    
    res.download(fullPath, (err) => {
      if (err) {
        res.status(404).send('Report not found');
      }
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_14() {
  app.get('/view-source', (req, res) => {
    const file = req.query.file || 'index.js';
    // ruleid: javascript-express-path-traversal
    const srcPath = path.resolve('./src/' + file);
    
    fs.readFile(srcPath, 'utf8', (err, source) => {
      if (err) {
        return res.status(500).send('Error reading source');
      }
      res.send(`<pre>${source}</pre>`);
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_15() {
  app.delete('/remove-temp', (req, res) => {
    const tempFile = req.query.file;
    // ruleid: javascript-express-path-traversal
    const tempPath = path.join(os.tmpdir(), tempFile);
    
    fs.unlink(tempPath, (err) => {
      if (err) {
        return res.status(500).send('Failed to delete file');
      }
      res.send('File deleted successfully');
    });
  });
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_1() {
  app.get('/download', (req, res) => {
    const fileName = req.query.file;
    // Sanitize the filename to prevent path traversal
    const sanitizedName = sanitize(fileName);
    // ok: javascript-express-path-traversal
    const filePath = path.join(__dirname, 'files', sanitizedName);
    
    fs.readFile(filePath, (err, data) => {
      if (err) {
        return res.status(404).send('File not found');
      }
      res.send(data);
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_2() {
  app.get('/view-file', (req, res) => {
    const userFile = req.query.path;
    // Validate against a whitelist of allowed files
    const allowedFiles = ['report.txt', 'welcome.html', 'info.md'];
    if (!allowedFiles.includes(userFile)) {
      return res.status(403).send('Access denied');
    }
    // ok: javascript-express-path-traversal
    const filePath = path.join(__dirname, 'documents', userFile);
    
    fs.readFile(filePath, 'utf8', (err, content) => {
      if (err) {
        return res.status(500).send('Error loading file');
      }
      res.send(content);
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_3() {
  app.post('/read-log', [
    check('logFile').isAlphanumeric().withMessage('Log file must be alphanumeric')
  ], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const logName = req.body.logFile;
    // ok: javascript-express-path-traversal
    const logPath = path.join('./logs', logName + '.log');
    
    fs.readFile(logPath, 'utf8', (err, data) => {
      if (err) {
        return res.status(500).send('Could not read log');
      }
      res.json({ content: data });
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_4() {
  app.get('/images/:imageName', (req, res) => {
    const imageName = req.params.imageName;
    // Validate file extension
    const validExtensions = ['.jpg', '.png', '.gif'];
    const ext = path.extname(imageName).toLowerCase();
    if (!validExtensions.includes(ext)) {
      return res.status(400).send('Invalid image format');
    }
    
    // ok: javascript-express-path-traversal
    const imagePath = path.join(__dirname, 'public', 'images', path.basename(imageName));
    
    fs.access(imagePath, fs.constants.R_OK, (err) => {
      if (err) {
        return res.status(404).send('Image not found');
      }
      res.sendFile(imagePath);
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_5() {
  app.get('/config', (req, res) => {
    const configFile = req.query.name || 'default';
    // Validate config name with regex
    if (!/^[a-zA-Z0-9_-]+$/.test(configFile)) {
      return res.status(400).send('Invalid config name');
    }
    
    // ok: javascript-express-path-traversal
    const configPath = path.join(process.cwd(), 'configs', configFile + '.json');
    
    fs.readFile(configPath, 'utf8', (err, data) => {
      if (err) {
        return res.status(404).send('Config not found');
      }
      res.json(JSON.parse(data));
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_6() {
  app.get('/template', (req, res) => {
    const template = req.query.name;
    // Use a map of allowed templates instead of direct file access
    const templateMap = {
      'welcome': 'welcome.html',
      'error': 'error.html',
      'login': 'login.html'
    };
    
    const templateFile = templateMap[template];
    if (!templateFile) {
      return res.status(404).send('Template not found');
    }
    
    // ok: javascript-express-path-traversal
    const templatePath = path.join('./templates', templateFile);
    
    fs.readFile(templatePath, 'utf8', (err, content) => {
      if (err) {
        return res.status(404).send('Template not found');
      }
      res.send(content);
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_7() {
  app.post('/save-notes', (req, res) => {
    const { fileName, content } = req.body;
    // Sanitize filename
    const sanitizedName = sanitize(fileName);
    if (sanitizedName !== fileName) {
      return res.status(400).send('Invalid filename');
    }
    
    // ok: javascript-express-path-traversal
    const notePath = path.join(__dirname, 'user-notes', sanitizedName);
    
    fs.writeFile(notePath, content, (err) => {
      if (err) {
        return res.status(500).send('Failed to save note');
      }
      res.send('Note saved successfully');
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_8() {
  app.get('/serve-static', (req, res) => {
    const requestedPath = req.query.resource;
    // Validate against a regex pattern
    if (!/^[a-zA-Z0-9_\-\/]+\.(js|css|html|png|jpg|gif)$/.test(requestedPath)) {
      return res.status(400).send('Invalid resource path');
    }
    
    // ok: javascript-express-path-traversal
    const safePath = path.normalize(requestedPath).replace(/^(\.\.(\/|\\|$))+/, '');
    res.sendFile(path.join(__dirname, 'static', safePath));
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_9() {
  app.post('/upload-profile', upload.single('avatar'), (req, res) => {
    const userId = req.body.userId;
    // Use a fixed directory structure based on user ID
    if (!/^[a-zA-Z0-9_-]+$/.test(userId)) {
      return res.status(400).send('Invalid user ID');
    }
    
    // ok: javascript-express-path-traversal
    const userDir = path.join(__dirname, 'profiles', userId);
    
    if (!fs.existsSync(userDir)) {
      fs.mkdirSync(userDir, { recursive: true });
    }
    
    const targetPath = path.join(userDir, sanitize(req.file.originalname));
    fs.copyFileSync(req.file.path, targetPath);
    fs.unlinkSync(req.file.path);
    
    res.json({ success: true, path: targetPath });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_10() {
  app.get('/backup', (req, res) => {
    const backupFile = req.headers['x-backup-file'];
    // Use a UUID or hash to reference files instead of direct paths
    const backupMap = {
      'daily': 'daily-backup.zip',
      'weekly': 'weekly-backup.zip',
      'monthly': 'monthly-backup.zip'
    };
    
    const safeFileName = backupMap[backupFile];
    if (!safeFileName) {
      return res.status(404).send('Backup not found');
    }
    
    // ok: javascript-express-path-traversal
    const backupPath = path.join('/var/backups', safeFileName);
    
    fs.readFile(backupPath, (err, data) => {
      if (err) {
        return res.status(404).send('Backup not found');
      }
      res.send(data);
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_11() {
  app.get('/read-markdown', (req, res) => {
    const fileName = req.cookies.lastFile;
    // Validate with a strict pattern
    if (!/^[a-zA-Z0-9_-]+$/.test(fileName)) {
      return res.status(400).send('Invalid filename');
    }
    
    // ok: javascript-express-path-traversal
    const filePath = path.join('./content/markdown', fileName + '.md');
    
    // Ensure the file is within the intended directory
    const realPath = path.resolve(filePath);
    const contentDir = path.resolve('./content/markdown');
    if (!realPath.startsWith(contentDir)) {
      return res.status(403).send('Access denied');
    }
    
    fs.readFile(filePath, 'utf8', (err, content) => {
      if (err) {
        return res.status(404).send('File not found');
      }
      res.send(content);
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_12() {
  app.post('/include-partial', (req, res) => {
    const partialName = req.body.partial;
    // Use a predefined list of allowed partials
    const allowedPartials = ['header', 'footer', 'sidebar', 'nav'];
    
    if (!allowedPartials.includes(partialName)) {
      return res.status(403).send('Partial not allowed');
    }
    
    // ok: javascript-express-path-traversal
    const partialPath = path.join(process.cwd(), 'views', 'partials', partialName + '.html');
    
    fs.readFile(partialPath, 'utf8', (err, content) => {
      if (err) {
        return res.status(500).send('Could not load partial');
      }
      res.send({ content });
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_13() {
  app.get('/download-report', (req, res) => {
    let reportId = req.query.report;
    // Use a database to map IDs to filenames
    const reportMap = {
      'q1-2023': 'quarterly_report_q1_2023.pdf',
      'q2-2023': 'quarterly_report_q2_2023.pdf',
      'annual-2022': 'annual_report_2022.pdf'
    };
    
    const reportFile = reportMap[reportId];
    if (!reportFile) {
      return res.status(404).send('Report not found');
    }
    
    // ok: javascript-express-path-traversal
    const fullPath = path.join(__dirname, 'reports', reportFile);
    
    res.download(fullPath, (err) => {
      if (err) {
        res.status(404).send('Report not found');
      }
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_14() {
  app.get('/view-source', (req, res) => {
    const file = req.query.file || 'index.js';
    // Validate file extension and path
    if (!file.endsWith('.js') || file.includes('/') || file.includes('\\')) {
      return res.status(400).send('Invalid file');
    }
    
    // ok: javascript-express-path-traversal
    const srcPath = path.join('./src', file);
    
    // Additional path validation
    const realPath = path.resolve(srcPath);
    const srcDir = path.resolve('./src');
    if (!realPath.startsWith(srcDir)) {
      return res.status(403).send('Access denied');
    }
    
    fs.readFile(srcPath, 'utf8', (err, source) => {
      if (err) {
        return res.status(500).send('Error reading source');
      }
      res.send(`<pre>${source}</pre>`);
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_15() {
  app.delete('/remove-temp', (req, res) => {
    const tempFile = req.query.file;
    // Ensure the file has a specific prefix for safety
    if (!tempFile.startsWith('temp_') || tempFile.includes('/') || tempFile.includes('\\')) {
      return res.status(400).send('Invalid temp file');
    }
    
    // ok: javascript-express-path-traversal
    const tempPath = path.join(os.tmpdir(), 'app_temp', sanitize(tempFile));
    
    // Additional path validation
    const realPath = path.resolve(tempPath);
    const tempDir = path.resolve(path.join(os.tmpdir(), 'app_temp'));
    if (!realPath.startsWith(tempDir)) {
      return res.status(403).send('Access denied');
    }
    
    fs.unlink(tempPath, (err) => {
      if (err) {
        return res.status(500).send('Failed to delete file');
      }
      res.send('File deleted successfully');
    });
  });
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});