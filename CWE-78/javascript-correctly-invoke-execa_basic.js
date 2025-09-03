// Test cases for javascript-correctly-invoke-execa rule
// This rule detects potential command injection vulnerabilities when using execa

const express = require('express');
const execa = require('execa');
const { exec, execSync } = require('child_process');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// True Positive Cases (Vulnerable)

// bad_case_1: Using template literals with user input in execa command
// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_1(req, res) {
    const userInput = req.query.command;
    
    // ruleid: javascript-correctly-invoke-execa
    execa(`ls ${userInput}`);
    
    res.send('Command executed');
}
// {/fact}

// bad_case_2: Concatenating user input directly into command
// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_2(req, res) {
    const userDir = req.query.dir;
    
    // ruleid: javascript-correctly-invoke-execa
    execa('find ' + userDir + ' -type f');
    
    res.send('Files found');
}
// {/fact}

// bad_case_3: Using user input from POST body
// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_3(req, res) {
    const searchTerm = req.body.search;
    
    // ruleid: javascript-correctly-invoke-execa
    execa(`grep -r "${searchTerm}" /var/log/`);
    
    res.send('Search completed');
}
// {/fact}

// bad_case_4: Using user input from headers
// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_4(req, res) {
    const sortOrder = req.headers['sort-order'];
    
    // ruleid: javascript-correctly-invoke-execa
    execa(`ls -la --sort=${sortOrder}`);
    
    res.send('Directory listed');
}
// {/fact}

// bad_case_5: Using user input in command with variable interpolation
// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_5(req, res) {
    const fileName = req.query.file;
    const command = `cat ${fileName}`;
    
    // ruleid: javascript-correctly-invoke-execa
    execa(command);
    
    res.send('File contents displayed');
}
// {/fact}

// bad_case_6: Using user input in a more complex command
// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_6(req, res) {
    const userPattern = req.query.pattern;
    const userFile = req.query.file;
    
    // ruleid: javascript-correctly-invoke-execa
    execa(`awk '/${userPattern}/ {print}' ${userFile}`);
    
    res.send('Pattern matched');
}
// {/fact}

// bad_case_7: Using user input in command with shell option enabled
// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_7(req, res) {
    const userCommand = req.query.cmd;
    
    // ruleid: javascript-correctly-invoke-execa
    execa(`echo ${userCommand}`, { shell: true });
    
    res.send('Command echoed');
}
// {/fact}

// bad_case_8: Using user input in command with multiple interpolations
// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_8(req, res) {
    const userFile = req.query.file;
    const userOutput = req.query.output;
    
    // ruleid: javascript-correctly-invoke-execa
    execa(`cp ${userFile} ${userOutput}`);
    
    res.send('File copied');
}
// {/fact}

// bad_case_9: Using user input from cookies
// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_9(req, res) {
    const userPreference = req.cookies.preference;
    
    // ruleid: javascript-correctly-invoke-execa
    execa(`echo "User preference: ${userPreference}" >> /tmp/preferences.log`);
    
    res.send('Preference logged');
}
// {/fact}

// bad_case_10: Using user input in command with execaSync
// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_10(req, res) {
    const userId = req.query.id;
    
    // ruleid: javascript-correctly-invoke-execa
    execa.sync(`id ${userId}`);
    
    res.send('User ID checked');
}
// {/fact}

// bad_case_11: Using user input in command with execaCommand
// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_11(req, res) {
    const userInput = req.query.input;
    
    // ruleid: javascript-correctly-invoke-execa
    execa.command(`echo ${userInput}`);
    
    res.send('Input echoed');
}
// {/fact}

// bad_case_12: Using user input in a command with string concatenation and variables
// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_12(req, res) {
    const userFile = req.query.file;
    const baseDir = '/var/www/';
    const fullCommand = 'cat ' + baseDir + userFile;
    
    // ruleid: javascript-correctly-invoke-execa
    execa(fullCommand);
    
    res.send('File read');
}
// {/fact}

// bad_case_13: Using user input in command with template literals in a variable
// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_13(req, res) {
    const userName = req.query.name;
    const command = `echo "Hello, ${userName}"`;
    
    // ruleid: javascript-correctly-invoke-execa
    execa(command);
    
    res.send('Greeting sent');
}
// {/fact}

// bad_case_14: Using user input in command with conditional logic
// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_14(req, res) {
    const userAction = req.query.action;
    const userTarget = req.query.target;
    
    const command = userAction === 'list' 
        ? `ls -la ${userTarget}` 
        : `find ${userTarget} -name "*.txt"`;
    
    // ruleid: javascript-correctly-invoke-execa
    execa(command);
    
    res.send('Action performed');
}
// {/fact}

// bad_case_15: Using user input in command with string methods
// {fact rule=os-command-injection@v1.0 defects=1}
function bad_case_15(req, res) {
    const userInput = req.query.input.trim();
    
    // ruleid: javascript-correctly-invoke-execa
    execa(`grep "${userInput}" /var/log/system.log`);
    
    res.send('Log searched');
}
// {/fact}

// True Negative Cases (Safe)

// good_case_1: Using array syntax for command and arguments
// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_1(req, res) {
    const userInput = req.query.command;
    
    // ok: javascript-correctly-invoke-execa
    execa('ls', [userInput]);
    
    res.send('Command executed safely');
}
// {/fact}

// good_case_2: Using array syntax for find command
// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_2(req, res) {
    const userDir = req.query.dir;
    
    // ok: javascript-correctly-invoke-execa
    execa('find', [userDir, '-type', 'f']);
    
    res.send('Files found safely');
}
// {/fact}

// good_case_3: Using array syntax with user input from POST body
// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_3(req, res) {
    const searchTerm = req.body.search;
    
    // ok: javascript-correctly-invoke-execa
    execa('grep', ['-r', searchTerm, '/var/log/']);
    
    res.send('Search completed safely');
}
// {/fact}

// good_case_4: Using array syntax with user input from headers
// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_4(req, res) {
    const sortOrder = req.headers['sort-order'];
    
    // ok: javascript-correctly-invoke-execa
    execa('ls', ['-la', `--sort=${sortOrder}`]);
    
    res.send('Directory listed safely');
}
// {/fact}

// good_case_5: Using hardcoded command string (no user input)
// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_5(req, res) {
    // ok: javascript-correctly-invoke-execa
    execa('ls -la /tmp');
    
    res.send('Directory listed safely');
}
// {/fact}

// good_case_6: Using array syntax for complex command
// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_6(req, res) {
    const userPattern = req.query.pattern;
    const userFile = req.query.file;
    
    // ok: javascript-correctly-invoke-execa
    execa('awk', [`/${userPattern}/ {print}`, userFile]);
    
    res.send('Pattern matched safely');
}
// {/fact}

// good_case_7: Using array syntax with shell option
// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_7(req, res) {
    const userCommand = req.query.cmd;
    
    // ok: javascript-correctly-invoke-execa
    execa('echo', [userCommand], { shell: true });
    
    res.send('Command echoed safely');
}
// {/fact}

// good_case_8: Using array syntax with multiple arguments
// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_8(req, res) {
    const userFile = req.query.file;
    const userOutput = req.query.output;
    
    // ok: javascript-correctly-invoke-execa
    execa('cp', [userFile, userOutput]);
    
    res.send('File copied safely');
}
// {/fact}

// good_case_9: Using array syntax with user input from cookies
// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_9(req, res) {
    const userPreference = req.cookies.preference;
    
    // ok: javascript-correctly-invoke-execa
    execa('bash', ['-c', `echo "User preference: ${userPreference}" >> /tmp/preferences.log`]);
    
    res.send('Preference logged safely');
}
// {/fact}

// good_case_10: Using array syntax with execaSync
// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_10(req, res) {
    const userId = req.query.id;
    
    // ok: javascript-correctly-invoke-execa
    execa.sync('id', [userId]);
    
    res.send('User ID checked safely');
}
// {/fact}

// good_case_11: Using execaCommand with proper array syntax
// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_11(req, res) {
    const userInput = req.query.input;
    
    // ok: javascript-correctly-invoke-execa
    execa('echo', [userInput]);
    
    res.send('Input echoed safely');
}
// {/fact}

// good_case_12: Using hardcoded command with no user input
// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_12(req, res) {
    // ok: javascript-correctly-invoke-execa
    execa('cat', ['/etc/hostname']);
    
    res.send('Hostname displayed');
}
// {/fact}

// good_case_13: Using array syntax with sanitized user input
// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_13(req, res) {
    let userName = req.query.name;
    // Simple sanitization example
    userName = userName.replace(/[^a-zA-Z0-9]/g, '');
    
    // ok: javascript-correctly-invoke-execa
    execa('echo', [`Hello, ${userName}`]);
    
    res.send('Greeting sent safely');
}
// {/fact}

// good_case_14: Using array syntax with conditional logic
// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_14(req, res) {
    const userAction = req.query.action;
    const userTarget = req.query.target;
    
    const args = userAction === 'list' 
        ? ['ls', '-la', userTarget] 
        : ['find', userTarget, '-name', '*.txt'];
    
    // ok: javascript-correctly-invoke-execa
    execa(args[0], args.slice(1));
    
    res.send('Action performed safely');
}
// {/fact}

// good_case_15: Using array syntax with string methods
// {fact rule=os-command-injection@v1.0 defects=0}
function good_case_15(req, res) {
    const userInput = req.query.input.trim();
    
    // ok: javascript-correctly-invoke-execa
    execa('grep', [userInput, '/var/log/system.log']);
    
    res.send('Log searched safely');
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});