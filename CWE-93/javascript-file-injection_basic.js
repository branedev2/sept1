const fs = require('fs');
const path = require('path');
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const sanitizeFilename = require('sanitize-filename');
const validator = require('validator');
const crypto = require('crypto');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// True Positive Examples (Vulnerable Code)

// {fact rule=file-injection@v1.0 defects=1}
function bad_case_1(req, res) {
    const userInput = req.query.filename;
    
    // ruleid: javascript-file-injection
    fs.writeFileSync(`./logs/${userInput}.txt`, 'Log entry created');
    
    res.send('Log created');
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=1}
function bad_case_2(req, res) {
    const userData = req.body.data;
    const fileName = req.body.fileName;
    
    // ruleid: javascript-file-injection
    fs.writeFile(fileName, userData, (err) => {
        if (err) {
            res.status(500).send('Error writing file');
        } else {
            res.send('File written successfully');
        }
    });
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=1}
function bad_case_3(req, res) {
    const content = req.body.content;
    const filePath = `./user_files/${req.params.id}.json`;
    
    // ruleid: javascript-file-injection
    fs.appendFileSync(filePath, content);
    
    res.send('Content appended to file');
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=1}
function bad_case_4(req, res) {
    const userConfig = JSON.stringify(req.body.config);
    const configName = req.query.configName;
    
    // ruleid: javascript-file-injection
    fs.writeFile(`./configs/${configName}.json`, userConfig, 'utf8', (err) => {
        if (err) throw err;
        res.send('Configuration saved');
    });
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=1}
function bad_case_5(req, res) {
    const logEntry = req.headers['x-custom-log'];
    const logFile = req.cookies.preferredLog || 'default.log';
    
    // ruleid: javascript-file-injection
    fs.appendFile(`./logs/${logFile}`, logEntry + '\n', (err) => {
        if (err) console.error(err);
        res.send('Log entry added');
    });
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=1}
function bad_case_6(req, res) {
    const username = req.body.username;
    
    // ruleid: javascript-file-injection
    const stream = fs.createWriteStream(`./users/${username}.dat`);
    stream.write('User profile created');
    stream.end();
    
    res.send('User profile created');
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=1}
function bad_case_7(req, res) {
    const reportData = req.body.reportData;
    const reportName = req.query.name;
    
    // ruleid: javascript-file-injection
    require('fs').writeFileSync(
        path.join(__dirname, 'reports', reportName),
        reportData
    );
    
    res.send('Report saved');
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=1}
function bad_case_8(req, res) {
    const userNote = req.body.note;
    const noteId = req.params.id;
    
    // ruleid: javascript-file-injection
    fs.writeFile(`notes_${noteId}.txt`, userNote, {
        encoding: 'utf8',
        flag: 'w'
    }, (err) => {
        if (err) throw err;
        res.send('Note saved');
    });
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=1}
function bad_case_9(req, res) {
    const csvData = req.body.csvContent;
    const fileName = req.headers['x-filename'];
    
    // ruleid: javascript-file-injection
    const fileStream = fs.createWriteStream(`./exports/${fileName}`);
    fileStream.write(csvData);
    fileStream.end();
    
    res.send('CSV exported');
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=1}
function bad_case_10(req, res) {
    const backupData = JSON.stringify(req.body);
    const backupName = req.query.backup || 'default';
    
    // ruleid: javascript-file-injection
    fs.writeFileSync(path.join('backups', `${backupName}.bak`), backupData);
    
    res.send('Backup created');
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=1}
function bad_case_11(req, res) {
    const templateContent = req.body.template;
    const templateName = req.body.name;
    
    // ruleid: javascript-file-injection
    fs.writeFile(`./templates/${templateName}.html`, templateContent, (err) => {
        if (err) {
            res.status(500).send('Failed to save template');
        } else {
            res.send('Template saved');
        }
    });
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=1}
function bad_case_12(req, res) {
    const logData = `${new Date().toISOString()} - ${req.ip} - ${req.method} - ${req.path}\n`;
    const logFileName = req.query.logType || 'access';
    
    // ruleid: javascript-file-injection
    fs.appendFileSync(`./logs/${logFileName}.log`, logData);
    
    res.send('Request logged');
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=1}
function bad_case_13(req, res) {
    const userScript = req.body.script;
    const scriptName = req.body.scriptName;
    
    // ruleid: javascript-file-injection
    fs.writeFile(`./scripts/${scriptName}.js`, userScript, {
        encoding: 'utf8'
    }, (err) => {
        if (err) throw err;
        res.send('Script saved');
    });
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=1}
function bad_case_14(req, res) {
    const configData = JSON.stringify(req.body.settings);
    const appName = req.params.app;
    
    // ruleid: javascript-file-injection
    fs.writeFileSync(`./config/${appName}_config.json`, configData);
    
    res.send('Configuration updated');
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=1}
function bad_case_15(req, res) {
    const userData = req.body.userData;
    const userId = req.cookies.userId;
    
    // ruleid: javascript-file-injection
    const filePath = path.join('users', `${userId}_profile.json`);
    fs.writeFile(filePath, JSON.stringify(userData), (err) => {
        if (err) throw err;
        res.send('Profile updated');
    });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=file-injection@v1.0 defects=0}
function good_case_1(req, res) {
    const userInput = req.query.filename;
    const sanitizedFilename = sanitizeFilename(userInput);
    
    // ok: javascript-file-injection
    fs.writeFileSync(`./logs/${sanitizedFilename}.txt`, 'Log entry created');
    
    res.send('Log created');
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=0}
function good_case_2(req, res) {
    const userData = req.body.data;
    const fileName = req.body.fileName;
    
    if (!validator.isAlphanumeric(fileName)) {
        return res.status(400).send('Invalid filename');
    }
    
    // ok: javascript-file-injection
    fs.writeFile(`./safe_files/${fileName}.txt`, userData, (err) => {
        if (err) {
            res.status(500).send('Error writing file');
        } else {
            res.send('File written successfully');
        }
    });
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=0}
function good_case_3(req, res) {
    const content = req.body.content;
    const userId = req.params.id;
    
    // Using a fixed path with validated user ID
    if (!validator.isUUID(userId)) {
        return res.status(400).send('Invalid user ID');
    }
    
    // ok: javascript-file-injection
    fs.appendFileSync(`./user_files/${userId}.json`, content);
    
    res.send('Content appended to file');
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=0}
function good_case_4(req, res) {
    const userConfig = JSON.stringify(req.body.config);
    const configName = req.query.configName;
    
    // Whitelist approach for config names
    const allowedConfigNames = ['app', 'system', 'user', 'network'];
    if (!allowedConfigNames.includes(configName)) {
        return res.status(400).send('Invalid configuration name');
    }
    
    // ok: javascript-file-injection
    fs.writeFile(`./configs/${configName}.json`, userConfig, 'utf8', (err) => {
        if (err) throw err;
        res.send('Configuration saved');
    });
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=0}
function good_case_5(req, res) {
    const logEntry = req.headers['x-custom-log'];
    
    // Using a fixed filename instead of user input
    const logFile = 'system.log';
    
    // ok: javascript-file-injection
    fs.appendFile(`./logs/${logFile}`, logEntry + '\n', (err) => {
        if (err) console.error(err);
        res.send('Log entry added');
    });
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=0}
function good_case_6(req, res) {
    const username = req.body.username;
    
    // Generate a safe filename using hash
    const hashedFilename = crypto.createHash('md5').update(username).digest('hex');
    
    // ok: javascript-file-injection
    const stream = fs.createWriteStream(`./users/${hashedFilename}.dat`);
    stream.write('User profile created');
    stream.end();
    
    res.send('User profile created');
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=0}
function good_case_7(req, res) {
    const reportData = req.body.reportData;
    const reportName = req.query.name;
    
    // Sanitize the filename
    const safeReportName = sanitizeFilename(reportName);
    
    // ok: javascript-file-injection
    require('fs').writeFileSync(
        path.join(__dirname, 'reports', safeReportName),
        reportData
    );
    
    res.send('Report saved');
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=0}
function good_case_8(req, res) {
    const userNote = req.body.note;
    const noteId = req.params.id;
    
    // Validate ID is numeric
    if (!validator.isNumeric(noteId)) {
        return res.status(400).send('Invalid note ID');
    }
    
    // ok: javascript-file-injection
    fs.writeFile(`notes_${noteId}.txt`, userNote, {
        encoding: 'utf8',
        flag: 'w'
    }, (err) => {
        if (err) throw err;
        res.send('Note saved');
    });
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=0}
function good_case_9(req, res) {
    const csvData = req.body.csvContent;
    const fileName = req.headers['x-filename'];
    
    // Generate a safe filename with timestamp
    const timestamp = Date.now();
    const safeFileName = `export_${timestamp}.csv`;
    
    // ok: javascript-file-injection
    const fileStream = fs.createWriteStream(`./exports/${safeFileName}`);
    fileStream.write(csvData);
    fileStream.end();
    
    res.send('CSV exported');
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=0}
function good_case_10(req, res) {
    const backupData = JSON.stringify(req.body);
    
    // Use timestamp for filename instead of user input
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    
    // ok: javascript-file-injection
    fs.writeFileSync(path.join('backups', `backup_${timestamp}.bak`), backupData);
    
    res.send('Backup created');
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=0}
function good_case_11(req, res) {
    const templateContent = req.body.template;
    const templateName = req.body.name;
    
    // Validate template name with regex
    if (!/^[a-zA-Z0-9_-]+$/.test(templateName)) {
        return res.status(400).send('Invalid template name');
    }
    
    // ok: javascript-file-injection
    fs.writeFile(`./templates/${templateName}.html`, templateContent, (err) => {
        if (err) {
            res.status(500).send('Failed to save template');
        } else {
            res.send('Template saved');
        }
    });
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=0}
function good_case_12(req, res) {
    const logData = `${new Date().toISOString()} - ${req.ip} - ${req.method} - ${req.path}\n`;
    
    // Use a predefined set of log types
    const logTypes = {
        'access': 'access.log',
        'error': 'error.log',
        'debug': 'debug.log'
    };
    
    const logType = req.query.logType || 'access';
    const logFileName = logTypes[logType] || logTypes['access'];
    
    // ok: javascript-file-injection
    fs.appendFileSync(`./logs/${logFileName}`, logData);
    
    res.send('Request logged');
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=0}
function good_case_13(req, res) {
    const userScript = req.body.script;
    
    // Generate a unique filename instead of using user input
    const scriptId = crypto.randomUUID();
    
    // ok: javascript-file-injection
    fs.writeFile(`./scripts/${scriptId}.js`, userScript, {
        encoding: 'utf8'
    }, (err) => {
        if (err) throw err;
        res.send('Script saved');
    });
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=0}
function good_case_14(req, res) {
    const configData = JSON.stringify(req.body.settings);
    const appName = req.params.app;
    
    // Validate app name against a whitelist
    const validApps = ['frontend', 'backend', 'mobile', 'desktop'];
    if (!validApps.includes(appName)) {
        return res.status(400).send('Invalid application name');
    }
    
    // ok: javascript-file-injection
    fs.writeFileSync(`./config/${appName}_config.json`, configData);
    
    res.send('Configuration updated');
}
// {/fact}

// {fact rule=file-injection@v1.0 defects=0}
function good_case_15(req, res) {
    const userData = req.body.userData;
    const userId = req.cookies.userId;
    
    // Validate user ID format
    if (!validator.isUUID(userId)) {
        return res.status(400).send('Invalid user ID');
    }
    
    // ok: javascript-file-injection
    const filePath = path.join('users', `${userId}_profile.json`);
    fs.writeFile(filePath, JSON.stringify(userData), (err) => {
        if (err) throw err;
        res.send('Profile updated');
    });
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});