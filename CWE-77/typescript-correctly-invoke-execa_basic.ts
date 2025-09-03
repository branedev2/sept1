import express from 'express';
import execa from 'execa';
import { sanitize } from 'sanitize-command';
import { execaCommand } from 'execa';
import path from 'path';

// True positives (vulnerable code)

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
async function bad_case_1() {
  const app = express();
  
  app.get('/execute', async (req, res) => {
    const userCommand = req.query.cmd as string;
    
    try {
      // ruleid: typescript-correctly-invoke-execa
      const result = await execa(userCommand);
      res.send(result.stdout);
    } catch (error) {
      res.status(500).send('Error executing command');
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
async function bad_case_2() {
  const app = express();
  
  app.post('/run-command', express.json(), async (req, res) => {
    const command = req.body.command;
    const args = req.body.args || [];
    
    try {
      // ruleid: typescript-correctly-invoke-execa
      const result = await execa(command, args);
      res.json({ output: result.stdout });
    } catch (error) {
      res.status(500).json({ error: 'Command execution failed' });
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
async function bad_case_3() {
  const app = express();
  
  app.get('/system-info', async (req, res) => {
    const format = req.query.format as string;
    const command = `systeminfo --format=${format}`;
    
    try {
      // ruleid: typescript-correctly-invoke-execa
      const { stdout } = await execaCommand(command);
      res.send(stdout);
    } catch (error) {
      res.status(500).send('Failed to get system info');
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
async function bad_case_4() {
  const app = express();
  
  app.get('/search-files', async (req, res) => {
    const searchTerm = req.query.term as string;
    
    try {
      // ruleid: typescript-correctly-invoke-execa
      const result = await execa('find', ['.', '-name', `*${searchTerm}*`]);
      res.send(result.stdout);
    } catch (error) {
      res.status(500).send('Search failed');
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
async function bad_case_5() {
  const app = express();
  
  app.get('/run-script', async (req, res) => {
    const scriptName = req.query.script as string;
    
    try {
      // ruleid: typescript-correctly-invoke-execa
      const result = await execa('sh', ['-c', scriptName]);
      res.send(result.stdout);
    } catch (error) {
      res.status(500).send('Script execution failed');
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
async function bad_case_6() {
  const app = express();
  
  app.get('/ping', async (req, res) => {
    const host = req.query.host as string;
    const pingCommand = `ping -c 4 ${host}`;
    
    try {
      // ruleid: typescript-correctly-invoke-execa
      const { stdout } = await execaCommand(pingCommand);
      res.send(stdout);
    } catch (error) {
      res.status(500).send('Ping failed');
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
async function bad_case_7() {
  const app = express();
  
  app.get('/exec-with-options', async (req, res) => {
    const cmd = req.query.cmd as string;
    const args = (req.query.args as string || '').split(',');
    
    try {
      // ruleid: typescript-correctly-invoke-execa
      const result = await execa(cmd, args, { shell: true });
      res.send(result.stdout);
    } catch (error) {
      res.status(500).send('Execution failed');
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
async function bad_case_8() {
  const app = express();
  
  app.get('/concat-command', async (req, res) => {
    const baseCmd = 'ls';
    const userFlag = req.query.flag as string;
    
    try {
      // ruleid: typescript-correctly-invoke-execa
      const result = await execa(baseCmd + userFlag);
      res.send(result.stdout);
    } catch (error) {
      res.status(500).send('Command failed');
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
async function bad_case_9() {
  const app = express();
  
  app.get('/template-command', async (req, res) => {
    const dir = req.query.dir as string;
    
    try {
      // ruleid: typescript-correctly-invoke-execa
      const result = await execa(`ls -la ${dir}`);
      res.send(result.stdout);
    } catch (error) {
      res.status(500).send('Command failed');
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
async function bad_case_10() {
  const app = express();
  
  app.get('/dynamic-command', async (req, res) => {
    const action = req.query.action as string;
    const target = req.query.target as string;
    
    let cmd = '';
    if (action === 'list') {
      cmd = 'ls';
    } else if (action === 'remove') {
      cmd = 'rm';
    } else {
      cmd = 'echo';
    }
    
    try {
      // ruleid: typescript-correctly-invoke-execa
      const result = await execa(cmd, [target]);
      res.send(result.stdout);
    } catch (error) {
      res.status(500).send('Command failed');
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
async function bad_case_11() {
  const app = express();
  
  app.get('/indirect-command', async (req, res) => {
    const userInput = req.query.input as string;
    const processedInput = userInput.trim().toLowerCase();
    
    try {
      // ruleid: typescript-correctly-invoke-execa
      const result = await execa(processedInput);
      res.send(result.stdout);
    } catch (error) {
      res.status(500).send('Command failed');
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
async function bad_case_12() {
  const app = express();
  
  app.get('/array-args', async (req, res) => {
    const cmd = 'echo';
    const userArgs = req.query.args as string;
    const argsArray = userArgs.split(' ');
    
    try {
      // ruleid: typescript-correctly-invoke-execa
      const result = await execa(cmd, argsArray);
      res.send(result.stdout);
    } catch (error) {
      res.status(500).send('Command failed');
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
async function bad_case_13() {
  const app = express();
  
  app.get('/command-with-header', async (req, res) => {
    const command = req.headers['x-command'] as string;
    
    try {
      // ruleid: typescript-correctly-invoke-execa
      const result = await execa(command);
      res.send(result.stdout);
    } catch (error) {
      res.status(500).send('Command failed');
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
async function bad_case_14() {
  const app = express();
  
  app.get('/multiple-inputs', async (req, res) => {
    const cmd = req.query.cmd as string || 'echo';
    const arg1 = req.query.arg1 as string || '';
    const arg2 = req.query.arg2 as string || '';
    
    try {
      // ruleid: typescript-correctly-invoke-execa
      const result = await execa(cmd, [arg1, arg2]);
      res.send(result.stdout);
    } catch (error) {
      res.status(500).send('Command failed');
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
async function bad_case_15() {
  const app = express();
  
  app.get('/command-with-cookie', async (req, res) => {
    const command = req.cookies.cmd;
    
    try {
      // ruleid: typescript-correctly-invoke-execa
      const result = await execa(command);
      res.send(result.stdout);
    } catch (error) {
      res.status(500).send('Command failed');
    }
  });
}
// {/fact}

// True negatives (safe code)

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
async function good_case_1() {
  const app = express();
  
  app.get('/execute-safe', async (req, res) => {
    // Using a whitelist of allowed commands
    const allowedCommands = ['ls', 'pwd', 'echo', 'date'];
    const userCommand = req.query.cmd as string;
    
    if (!allowedCommands.includes(userCommand)) {
      return res.status(400).send('Command not allowed');
    }
    
    try {
      // ok: typescript-correctly-invoke-execa
      const result = await execa(userCommand);
      res.send(result.stdout);
    } catch (error) {
      res.status(500).send('Error executing command');
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
async function good_case_2() {
  const app = express();
  
  app.get('/run-fixed-command', async (req, res) => {
    const param = req.query.param as string;
    
    try {
      // ok: typescript-correctly-invoke-execa
      const result = await execa('echo', [param]);
      res.send(result.stdout);
    } catch (error) {
      res.status(500).send('Command failed');
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
async function good_case_3() {
  const app = express();
  
  app.get('/list-files', async (req, res) => {
    try {
      // ok: typescript-correctly-invoke-execa
      const result = await execa('ls', ['-la']);
      res.send(result.stdout);
    } catch (error) {
      res.status(500).send('Failed to list files');
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
async function good_case_4() {
  const app = express();
  
  app.get('/sanitized-command', async (req, res) => {
    const userInput = req.query.input as string;
    
    // Sanitize the input
    const sanitizedInput = sanitize(userInput);
    
    try {
      // ok: typescript-correctly-invoke-execa
      const result = await execa('echo', [sanitizedInput]);
      res.send(result.stdout);
    } catch (error) {
      res.status(500).send('Command failed');
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
async function good_case_5() {
  const app = express();
  
  app.get('/validated-command', async (req, res) => {
    const action = req.query.action as string;
    
    // Validate input against a whitelist
    if (!['list', 'count', 'show'].includes(action)) {
      return res.status(400).send('Invalid action');
    }
    
    let cmd = '';
    let args: string[] = [];
    
    if (action === 'list') {
      cmd = 'ls';
      args = ['-l'];
    } else if (action === 'count') {
      cmd = 'wc';
      args = ['-l'];
    } else if (action === 'show') {
      cmd = 'cat';
      args = ['README.md'];
    }
    
    try {
      // ok: typescript-correctly-invoke-execa
      const result = await execa(cmd, args);
      res.send(result.stdout);
    } catch (error) {
      res.status(500).send('Command failed');
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
async function good_case_6() {
  const app = express();
  
  app.get('/safe-path', async (req, res) => {
    const fileName = req.query.file as string;
    
    // Ensure the path is safe by joining with a base directory
    const safePath = path.join('safe_directory', fileName);
    
    try {
      // ok: typescript-correctly-invoke-execa
      const result = await execa('cat', [safePath]);
      res.send(result.stdout);
    } catch (error) {
      res.status(500).send('Failed to read file');
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
async function good_case_7() {
  const app = express();
  
  app.get('/hardcoded-command', async (req, res) => {
    try {
      // ok: typescript-correctly-invoke-execa
      const result = await execaCommand('date +"%Y-%m-%d"');
      res.send(result.stdout);
    } catch (error) {
      res.status(500).send('Command failed');
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
async function good_case_8() {
  const app = express();
  
  app.get('/regex-validated', async (req, res) => {
    const fileName = req.query.file as string;
    
    // Validate with regex to ensure only alphanumeric filenames
    if (!/^[a-zA-Z0-9_\-\.]+$/.test(fileName)) {
      return res.status(400).send('Invalid filename');
    }
    
    try {
      // ok: typescript-correctly-invoke-execa
      const result = await execa('cat', [fileName]);
      res.send(result.stdout);
    } catch (error) {
      res.status(500).send('Failed to read file');
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
async function good_case_9() {
  const app = express();
  
  app.get('/numeric-validation', async (req, res) => {
    const count = req.query.count as string;
    
    // Ensure input is numeric
    if (!/^\d+$/.test(count)) {
      return res.status(400).send('Count must be a number');
    }
    
    try {
      // ok: typescript-correctly-invoke-execa
      const result = await execa('head', ['-n', count, 'file.txt']);
      res.send(result.stdout);
    } catch (error) {
      res.status(500).send('Command failed');
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
async function good_case_10() {
  const app = express();
  
  app.get('/fixed-options', async (req, res) => {
    try {
      // ok: typescript-correctly-invoke-execa
      const result = await execa('ls', ['-la'], { cwd: '/tmp' });
      res.send(result.stdout);
    } catch (error) {
      res.status(500).send('Command failed');
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
async function good_case_11() {
  const app = express();
  
  app.get('/enum-options', async (req, res) => {
    type SortOption = 'name' | 'date' | 'size';
    const sortBy = req.query.sort as SortOption;
    
    let sortFlag = '';
    
    switch (sortBy) {
      case 'name':
        sortFlag = '-n';
        break;
      case 'date':
        sortFlag = '-t';
        break;
      case 'size':
        sortFlag = '-S';
        break;
      default:
        sortFlag = '';
    }
    
    try {
      // ok: typescript-correctly-invoke-execa
      const result = await execa('ls', [sortFlag]);
      res.send(result.stdout);
    } catch (error) {
      res.status(500).send('Command failed');
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
async function good_case_12() {
  const app = express();
  
  app.get('/constant-command', async (req, res) => {
    const SAFE_COMMAND = 'uptime';
    
    try {
      // ok: typescript-correctly-invoke-execa
      const result = await execa(SAFE_COMMAND);
      res.send(result.stdout);
    } catch (error) {
      res.status(500).send('Command failed');
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
async function good_case_13() {
  const app = express();
  
  app.get('/mapped-command', async (req, res) => {
    const commandMap: Record<string, string[]> = {
      'list': ['ls', '-l'],
      'disk': ['df', '-h'],
      'memory': ['free', '-m']
    };
    
    const cmdKey = req.query.cmd as string;
    const commandConfig = commandMap[cmdKey];
    
    if (!commandConfig) {
      return res.status(400).send('Unknown command');
    }
    
    try {
      // ok: typescript-correctly-invoke-execa
      const result = await execa(commandConfig[0], commandConfig.slice(1));
      res.send(result.stdout);
    } catch (error) {
      res.status(500).send('Command failed');
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
async function good_case_14() {
  const app = express();
  
  app.get('/safe-template-string', async (req, res) => {
    // Using template string with hardcoded values is safe
    const directory = '/var/log';
    
    try {
      // ok: typescript-correctly-invoke-execa
      const result = await execa(`ls -la ${directory}`);
      res.send(result.stdout);
    } catch (error) {
      res.status(500).send('Command failed');
    }
  });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
async function good_case_15() {
  const app = express();
  
  app.get('/environment-config', async (req, res) => {
    // Using environment variables for configuration is safer than user input
    const logDir = process.env.LOG_DIRECTORY || '/var/log';
    
    try {
      // ok: typescript-correctly-invoke-execa
      const result = await execa('ls', ['-la', logDir]);
      res.send(result.stdout);
    } catch (error) {
      res.status(500).send('Command failed');
    }
  });
}
// {/fact}