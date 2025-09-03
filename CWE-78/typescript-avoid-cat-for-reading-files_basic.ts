import * as fs from 'fs';
import * as child_process from 'child_process';
import { exec, execSync, spawn, spawnSync } from 'child_process';
import { Request, Response } from 'express';
import * as util from 'util';

// TRUE POSITIVES (Vulnerable Code)

// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_1(req: Request, res: Response) {
    const fileName = req.query.file as string;
    // ruleid: typescript-avoid-cat-for-reading-files
    const fileContent = execSync(`cat ${fileName}`).toString();
    res.send(fileContent);
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_2(req: Request, res: Response) {
    const logFile = req.params.logName;
    // ruleid: typescript-avoid-cat-for-reading-files
    exec(`cat /var/logs/${logFile}`, (error, stdout, stderr) => {
        if (error) {
            res.status(500).send('Error reading log file');
            return;
        }
        res.send(stdout);
    });
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_3(req: Request, res: Response) {
    const configFile = req.body.configName;
    // ruleid: typescript-avoid-cat-for-reading-files
    const output = child_process.execSync(`cat /etc/configs/${configFile}`);
    res.send(output.toString());
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_4(req: Request, res: Response) {
    const userFile = req.headers['x-file-path'] as string;
    // ruleid: typescript-avoid-cat-for-reading-files
    const catProcess = spawn('cat', [userFile]);
    let data = '';
    catProcess.stdout.on('data', (chunk) => {
        data += chunk;
    });
    catProcess.on('close', () => {
        res.send(data);
    });
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_5(req: Request, res: Response) {
    const reportId = req.query.id as string;
    // ruleid: typescript-avoid-cat-for-reading-files
    const result = spawnSync('cat', [`/var/reports/${reportId}.txt`]);
    res.send(result.stdout.toString());
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_6(req: Request, res: Response) {
    const fileName = req.query.file as string;
    // ruleid: typescript-avoid-cat-for-reading-files
    child_process.exec(`cat ${fileName} | grep "ERROR"`, (error, stdout) => {
        res.send(stdout);
    });
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_7(req: Request, res: Response) {
    const userId = req.params.id;
    // ruleid: typescript-avoid-cat-for-reading-files
    const userData = execSync(`cat /var/users/${userId}.json`);
    res.json(JSON.parse(userData.toString()));
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_8(req: Request, res: Response) {
    const template = req.query.template as string;
    // ruleid: typescript-avoid-cat-for-reading-files
    const execPromise = util.promisify(exec);
    execPromise(`cat ./templates/${template}.html`).then(({ stdout }) => {
        res.send(stdout);
    }).catch(err => {
        res.status(500).send('Error loading template');
    });
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_9(req: Request, res: Response) {
    const logDate = req.query.date as string;
    // ruleid: typescript-avoid-cat-for-reading-files
    const command = `cat /var/logs/app_${logDate}.log`;
    exec(command, (error, stdout) => {
        res.send(stdout);
    });
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_10(req: Request, res: Response) {
    const configName = req.body.config;
    // ruleid: typescript-avoid-cat-for-reading-files
    const catCmd = `cat ./configs/${configName}.json`;
    const configData = execSync(catCmd);
    res.json(JSON.parse(configData.toString()));
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_11() {
    const envFile = process.env.ENV_FILE || '.env.development';
    // ruleid: typescript-avoid-cat-for-reading-files
    const envContent = execSync(`cat ${envFile}`).toString();
    const envVars = envContent.split('\n').reduce((acc, line) => {
        const [key, value] = line.split('=');
        if (key && value) acc[key.trim()] = value.trim();
        return acc;
    }, {} as Record<string, string>);
    return envVars;
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_12(req: Request, res: Response) {
    const scriptName = req.query.script as string;
    // ruleid: typescript-avoid-cat-for-reading-files
    const scriptContent = child_process.execSync(`cat ./scripts/${scriptName}.js`);
    res.setHeader('Content-Type', 'application/javascript');
    res.send(scriptContent);
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_13(req: Request, res: Response) {
    const filePath = req.query.path as string;
    // ruleid: typescript-avoid-cat-for-reading-files
    const cmd = `cat ${filePath} | head -n 100`;
    exec(cmd, (error, stdout) => {
        if (error) {
            res.status(500).send('Error reading file');
            return;
        }
        res.send(stdout);
    });
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_14(req: Request, res: Response) {
    const fileName = req.query.name as string;
    const options = { encoding: 'utf8' as const };
    // ruleid: typescript-avoid-cat-for-reading-files
    const fileContent = execSync(`cat ./uploads/${fileName}`, options);
    res.send(fileContent);
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_15(req: Request, res: Response) {
    const fileId = req.params.id;
    // ruleid: typescript-avoid-cat-for-reading-files
    const catProcess = spawn('cat', [`/tmp/files/${fileId}`]);
    let fileData = '';
    catProcess.stdout.on('data', (chunk) => {
        fileData += chunk;
    });
    catProcess.on('close', () => {
        try {
            const parsedData = JSON.parse(fileData);
            res.json(parsedData);
        } catch (e) {
            res.status(500).send('Invalid JSON file');
        }
    });
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_1(req: Request, res: Response) {
    const fileName = req.query.file as string;
    // ok: typescript-avoid-cat-for-reading-files
    const fileContent = fs.readFileSync(fileName, 'utf8');
    res.send(fileContent);
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_2(req: Request, res: Response) {
    const logFile = req.params.logName;
    // ok: typescript-avoid-cat-for-reading-files
    fs.readFile(`/var/logs/${logFile}`, 'utf8', (err, data) => {
        if (err) {
            res.status(500).send('Error reading log file');
            return;
        }
        res.send(data);
    });
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_3(req: Request, res: Response) {
    const configFile = req.body.configName;
    try {
        // ok: typescript-avoid-cat-for-reading-files
        const configData = fs.readFileSync(`/etc/configs/${configFile}`, 'utf8');
        res.send(configData);
    } catch (error) {
        res.status(500).send('Error reading config file');
    }
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_4(req: Request, res: Response) {
    const userFile = req.headers['x-file-path'] as string;
    // ok: typescript-avoid-cat-for-reading-files
    fs.readFile(userFile, (err, data) => {
        if (err) {
            res.status(500).send('Error reading file');
            return;
        }
        res.send(data.toString());
    });
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_5(req: Request, res: Response) {
    const reportId = req.query.id as string;
    try {
        // ok: typescript-avoid-cat-for-reading-files
        const reportContent = fs.readFileSync(`/var/reports/${reportId}.txt`, 'utf8');
        res.send(reportContent);
    } catch (error) {
        res.status(404).send('Report not found');
    }
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_6(req: Request, res: Response) {
    const fileName = req.query.file as string;
    // ok: typescript-avoid-cat-for-reading-files
    fs.readFile(fileName, 'utf8', (err, data) => {
        if (err) {
            res.status(500).send('Error reading file');
            return;
        }
        // Filter for ERROR lines
        const errorLines = data.split('\n').filter(line => line.includes('ERROR'));
        res.send(errorLines.join('\n'));
    });
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_7(req: Request, res: Response) {
    const userId = req.params.id;
    try {
        // ok: typescript-avoid-cat-for-reading-files
        const userData = fs.readFileSync(`/var/users/${userId}.json`, 'utf8');
        res.json(JSON.parse(userData));
    } catch (error) {
        res.status(404).send('User not found');
    }
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_8(req: Request, res: Response) {
    const template = req.query.template as string;
    // ok: typescript-avoid-cat-for-reading-files
    const readFilePromise = util.promisify(fs.readFile);
    readFilePromise(`./templates/${template}.html`, 'utf8')
        .then(content => {
            res.send(content);
        })
        .catch(err => {
            res.status(500).send('Error loading template');
        });
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_9(req: Request, res: Response) {
    const logDate = req.query.date as string;
    // ok: typescript-avoid-cat-for-reading-files
    fs.readFile(`/var/logs/app_${logDate}.log`, 'utf8', (err, data) => {
        if (err) {
            res.status(500).send('Error reading log file');
            return;
        }
        res.send(data);
    });
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_10(req: Request, res: Response) {
    const configName = req.body.config;
    try {
        // ok: typescript-avoid-cat-for-reading-files
        const configData = fs.readFileSync(`./configs/${configName}.json`, 'utf8');
        res.json(JSON.parse(configData));
    } catch (error) {
        res.status(500).send('Error loading configuration');
    }
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_11() {
    const envFile = process.env.ENV_FILE || '.env.development';
    // ok: typescript-avoid-cat-for-reading-files
    const envContent = fs.readFileSync(envFile, 'utf8');
    const envVars = envContent.split('\n').reduce((acc, line) => {
        const [key, value] = line.split('=');
        if (key && value) acc[key.trim()] = value.trim();
        return acc;
    }, {} as Record<string, string>);
    return envVars;
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_12(req: Request, res: Response) {
    const scriptName = req.query.script as string;
    // ok: typescript-avoid-cat-for-reading-files
    fs.readFile(`./scripts/${scriptName}.js`, 'utf8', (err, data) => {
        if (err) {
            res.status(404).send('Script not found');
            return;
        }
        res.setHeader('Content-Type', 'application/javascript');
        res.send(data);
    });
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_13(req: Request, res: Response) {
    const filePath = req.query.path as string;
    // ok: typescript-avoid-cat-for-reading-files
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            res.status(500).send('Error reading file');
            return;
        }
        // Get first 100 lines
        const first100Lines = data.split('\n').slice(0, 100).join('\n');
        res.send(first100Lines);
    });
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_14(req: Request, res: Response) {
    const fileName = req.query.name as string;
    try {
        // ok: typescript-avoid-cat-for-reading-files
        const fileContent = fs.readFileSync(`./uploads/${fileName}`, 'utf8');
        res.send(fileContent);
    } catch (error) {
        res.status(500).send('Error reading file');
    }
}
// {/fact}

// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_15(req: Request, res: Response) {
    const fileId = req.params.id;
    // ok: typescript-avoid-cat-for-reading-files
    fs.readFile(`/tmp/files/${fileId}`, 'utf8', (err, data) => {
        if (err) {
            res.status(500).send('Error reading file');
            return;
        }
        try {
            const parsedData = JSON.parse(data);
            res.json(parsedData);
        } catch (e) {
            res.status(500).send('Invalid JSON file');
        }
    });
}
// {/fact}