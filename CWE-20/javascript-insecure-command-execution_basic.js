const express = require('express');
const app = express();
const { exec, execSync, execFile, execFileSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// True Positives (Vulnerable Code)

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_1(req, res) {
    const fileName = req.query.fileName;
    // ruleid: javascript-insecure-command-execution
    exec(`ls -la ${fileName}`, (error, stdout, stderr) => {
        if (error) {
            res.status(500).send(`Error: ${error.message}`);
            return;
        }
        res.send(stdout);
    });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_2(req, res) {
    const userInput = req.body.command;
    // ruleid: javascript-insecure-command-execution
    exec(userInput, (error, stdout, stderr) => {
        if (error) {
            res.status(500).send(`Error: ${error.message}`);
            return;
        }
        res.send(stdout);
    });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_3(req, res) {
    const userId = req.params.id;
    const command = `grep "${userId}" /etc/passwd`;
    // ruleid: javascript-insecure-command-execution
    execSync(command, (error, stdout, stderr) => {
        if (error) {
            res.status(500).send(`Error: ${error.message}`);
            return;
        }
        res.send(stdout);
    });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_4(req, res) {
    const searchTerm = req.query.search;
    let command = 'find /var/www -name ';
    command += searchTerm;
    // ruleid: javascript-insecure-command-execution
    exec(command, (error, stdout, stderr) => {
        if (error) {
            res.status(500).send(`Error: ${error.message}`);
            return;
        }
        res.send(stdout);
    });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_5(req, res) {
    const ipAddress = req.query.ip;
    // ruleid: javascript-insecure-command-execution
    const pingResult = execSync(`ping -c 4 ${ipAddress}`);
    res.send(pingResult.toString());
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_6(req, res) {
    const domain = req.query.domain;
    try {
        // ruleid: javascript-insecure-command-execution
        const result = execSync(`nslookup ${domain}`);
        res.send(result.toString());
    } catch (error) {
        res.status(500).send(`Error: ${error.message}`);
    }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_7(req, res) {
    const username = req.body.username;
    // ruleid: javascript-insecure-command-execution
    exec(`id ${username}`, (error, stdout) => {
        if (error) {
            res.status(500).send('User not found');
            return;
        }
        res.send(`User info: ${stdout}`);
    });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_8(req, res) {
    const filename = req.params.filename;
    const directory = '/tmp';
    // ruleid: javascript-insecure-command-execution
    exec(`rm ${directory}/${filename}`, (error) => {
        if (error) {
            res.status(500).send(`Error deleting file: ${error.message}`);
            return;
        }
        res.send('File deleted successfully');
    });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_9(req, res) {
    const userDir = req.query.dir || '.';
    // ruleid: javascript-insecure-command-execution
    const result = execSync(`du -sh ${userDir}`);
    res.send(`Directory size: ${result}`);
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_10(req, res) {
    const scriptName = req.query.script;
    // ruleid: javascript-insecure-command-execution
    exec(`bash /scripts/${scriptName}`, (error, stdout) => {
        if (error) {
            res.status(500).send(`Script execution failed: ${error.message}`);
            return;
        }
        res.send(stdout);
    });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_11(req, res) {
    const date = new Date();
    const logFile = req.query.log;
    // ruleid: javascript-insecure-command-execution
    exec(`echo "${date.toISOString()} - Access" >> ${logFile}`, (error) => {
        if (error) {
            res.status(500).send(`Logging failed: ${error.message}`);
            return;
        }
        res.send('Log entry added');
    });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_12(req, res) {
    const userConfig = req.body.config;
    const configFile = 'config.json';
    // ruleid: javascript-insecure-command-execution
    exec(`echo '${userConfig}' > ${configFile}`, (error) => {
        if (error) {
            res.status(500).send(`Config update failed: ${error.message}`);
            return;
        }
        res.send('Configuration updated');
    });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_13(req, res) {
    const url = req.query.url;
    // ruleid: javascript-insecure-command-execution
    exec(`curl -s ${url}`, (error, stdout) => {
        if (error) {
            res.status(500).send(`Request failed: ${error.message}`);
            return;
        }
        res.send(stdout);
    });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_14(req, res) {
    const packageName = req.body.package;
    // ruleid: javascript-insecure-command-execution
    exec(`npm install ${packageName}`, (error, stdout, stderr) => {
        if (error) {
            res.status(500).send(`Installation failed: ${error.message}`);
            return;
        }
        res.send(`Installed ${packageName} successfully`);
    });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=1}
function bad_case_15(req, res) {
    const command = `find . -name "${req.query.pattern}" | sort`;
    // ruleid: javascript-insecure-command-execution
    const output = execSync(command);
    res.send(`Search results: ${output}`);
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_1(req, res) {
    const fileName = req.query.fileName;
    // ok: javascript-insecure-command-execution
    execFile('ls', ['-la', fileName], (error, stdout, stderr) => {
        if (error) {
            res.status(500).send(`Error: ${error.message}`);
            return;
        }
        res.send(stdout);
    });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_2(req, res) {
    // ok: javascript-insecure-command-execution
    const ls = spawn('ls', ['-la']);
    let output = '';
    
    ls.stdout.on('data', (data) => {
        output += data.toString();
    });
    
    ls.on('close', (code) => {
        res.send(`Process exited with code ${code}\n${output}`);
    });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_3(req, res) {
    const userId = req.params.id;
    // Validate userId to ensure it only contains alphanumeric characters
    if (!/^[a-zA-Z0-9]+$/.test(userId)) {
        res.status(400).send('Invalid user ID');
        return;
    }
    
    // ok: javascript-insecure-command-execution
    execFile('grep', [userId, '/etc/passwd'], (error, stdout, stderr) => {
        if (error) {
            res.status(500).send(`Error: ${error.message}`);
            return;
        }
        res.send(stdout);
    });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_4(req, res) {
    const searchTerm = req.query.search;
    // ok: javascript-insecure-command-execution
    execFile('find', ['/var/www', '-name', searchTerm], (error, stdout, stderr) => {
        if (error) {
            res.status(500).send(`Error: ${error.message}`);
            return;
        }
        res.send(stdout);
    });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_5(req, res) {
    const ipAddress = req.query.ip;
    // Validate IP address format
    if (!/^[0-9.]+$/.test(ipAddress)) {
        res.status(400).send('Invalid IP address');
        return;
    }
    
    // ok: javascript-insecure-command-execution
    const ping = spawn('ping', ['-c', '4', ipAddress]);
    let output = '';
    
    ping.stdout.on('data', (data) => {
        output += data.toString();
    });
    
    ping.on('close', (code) => {
        res.send(output);
    });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_6(req, res) {
    const domain = req.query.domain;
    try {
        // ok: javascript-insecure-command-execution
        const result = execFileSync('nslookup', [domain]);
        res.send(result.toString());
    } catch (error) {
        res.status(500).send(`Error: ${error.message}`);
    }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_7(req, res) {
    const username = req.body.username;
    // ok: javascript-insecure-command-execution
    execFile('id', [username], (error, stdout) => {
        if (error) {
            res.status(500).send('User not found');
            return;
        }
        res.send(`User info: ${stdout}`);
    });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_8(req, res) {
    const filename = req.params.filename;
    const directory = '/tmp';
    const filePath = path.join(directory, filename);
    
    // Ensure the path doesn't escape the intended directory
    const normalizedPath = path.normalize(filePath);
    if (!normalizedPath.startsWith(directory)) {
        res.status(400).send('Invalid filename');
        return;
    }
    
    try {
        // ok: javascript-insecure-command-execution
        fs.unlinkSync(normalizedPath);
        res.send('File deleted successfully');
    } catch (error) {
        res.status(500).send(`Error deleting file: ${error.message}`);
    }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_9(req, res) {
    const userDir = req.query.dir || '.';
    // ok: javascript-insecure-command-execution
    const du = spawn('du', ['-sh', userDir]);
    let output = '';
    
    du.stdout.on('data', (data) => {
        output += data.toString();
    });
    
    du.on('close', (code) => {
        res.send(`Directory size: ${output}`);
    });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_10(req, res) {
    const scriptName = req.query.script;
    // Validate script name to prevent directory traversal
    if (!/^[a-zA-Z0-9_-]+\.sh$/.test(scriptName)) {
        res.status(400).send('Invalid script name');
        return;
    }
    
    // ok: javascript-insecure-command-execution
    execFile('bash', [`/scripts/${scriptName}`], (error, stdout) => {
        if (error) {
            res.status(500).send(`Script execution failed: ${error.message}`);
            return;
        }
        res.send(stdout);
    });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_11(req, res) {
    const date = new Date();
    const logFile = req.query.log;
    
    try {
        // ok: javascript-insecure-command-execution
        fs.appendFileSync(logFile, `${date.toISOString()} - Access\n`);
        res.send('Log entry added');
    } catch (error) {
        res.status(500).send(`Logging failed: ${error.message}`);
    }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_12(req, res) {
    const userConfig = req.body.config;
    const configFile = 'config.json';
    
    try {
        // ok: javascript-insecure-command-execution
        fs.writeFileSync(configFile, userConfig);
        res.send('Configuration updated');
    } catch (error) {
        res.status(500).send(`Config update failed: ${error.message}`);
    }
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_13(req, res) {
    const url = req.query.url;
    // ok: javascript-insecure-command-execution
    const curl = spawn('curl', ['-s', url]);
    let output = '';
    
    curl.stdout.on('data', (data) => {
        output += data.toString();
    });
    
    curl.on('close', (code) => {
        res.send(output);
    });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_14(req, res) {
    const packageName = req.body.package;
    // ok: javascript-insecure-command-execution
    const npm = spawn('npm', ['install', packageName]);
    let output = '';
    
    npm.stdout.on('data', (data) => {
        output += data.toString();
    });
    
    npm.stderr.on('data', (data) => {
        output += data.toString();
    });
    
    npm.on('close', (code) => {
        if (code === 0) {
            res.send(`Installed ${packageName} successfully`);
        } else {
            res.status(500).send(`Installation failed: ${output}`);
        }
    });
}
// {/fact}

// {fact rule=improper-input-validation@v1.0 defects=0}
function good_case_15(req, res) {
    const pattern = req.query.pattern;
    // ok: javascript-insecure-command-execution
    const find = spawn('find', ['.', '-name', pattern]);
    let output = '';
    
    find.stdout.on('data', (data) => {
        output += data.toString();
    });
    
    find.on('close', (code) => {
        res.send(`Search results: ${output}`);
    });
}
// {/fact}

app.get('/bad1', bad_case_1);
app.post('/bad2', bad_case_2);
app.get('/bad3/:id', bad_case_3);
app.get('/bad4', bad_case_4);
app.get('/bad5', bad_case_5);
app.get('/bad6', bad_case_6);
app.post('/bad7', bad_case_7);
app.delete('/bad8/:filename', bad_case_8);
app.get('/bad9', bad_case_9);
app.get('/bad10', bad_case_10);
app.get('/bad11', bad_case_11);
app.post('/bad12', bad_case_12);
app.get('/bad13', bad_case_13);
app.post('/bad14', bad_case_14);
app.get('/bad15', bad_case_15);

app.get('/good1', good_case_1);
app.get('/good2', good_case_2);
app.get('/good3/:id', good_case_3);
app.get('/good4', good_case_4);
app.get('/good5', good_case_5);
app.get('/good6', good_case_6);
app.post('/good7', good_case_7);
app.delete('/good8/:filename', good_case_8);
app.get('/good9', good_case_9);
app.get('/good10', good_case_10);
app.get('/good11', good_case_11);
app.post('/good12', good_case_12);
app.get('/good13', good_case_13);
app.post('/good14', good_case_14);
app.get('/good15', good_case_15);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});