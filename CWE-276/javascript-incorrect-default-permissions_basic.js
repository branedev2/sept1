const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

// True Positive Examples (Vulnerable Code)

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_1() {
  // Creating a file with full permissions (readable, writable, executable by everyone)
  const filePath = path.join(__dirname, 'config.json');
  const data = JSON.stringify({ apiKey: 'secret-key' });
  
  // ruleid: javascript-incorrect-default-permissions
  fs.writeFileSync(filePath, data, { mode: 0o777 });
  
  console.log('File created with 0777 permissions');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_2() {
  // Creating a log file with read/write permissions for everyone
  const logFile = path.join(os.tmpdir(), 'app.log');
  
  // ruleid: javascript-incorrect-default-permissions
  fs.writeFileSync(logFile, 'Application started', { mode: 0o666 });
  
  console.log('Log file created with 0666 permissions');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_3() {
  // Creating a directory with executable permissions for everyone
  const dirPath = path.join(__dirname, 'uploads');
  
  if (!fs.existsSync(dirPath)) {
    // ruleid: javascript-incorrect-default-permissions
    fs.mkdirSync(dirPath, { mode: 0o777 });
  }
  
  console.log('Directory created with 0777 permissions');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_4() {
  // Using chmod to set insecure permissions on an existing file
  const filePath = path.join(__dirname, 'database.sqlite');
  
  // ruleid: javascript-incorrect-default-permissions
  fs.chmodSync(filePath, 0o777);
  
  console.log('Changed file permissions to 0777');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_5() {
  // Creating a script file with executable permissions for all users
  const scriptPath = path.join(__dirname, 'scripts', 'backup.sh');
  const scriptContent = '#!/bin/bash\necho "Backing up data..."';
  
  if (!fs.existsSync(path.dirname(scriptPath))) {
    fs.mkdirSync(path.dirname(scriptPath), { recursive: true });
  }
  
  // ruleid: javascript-incorrect-default-permissions
  fs.writeFileSync(scriptPath, scriptContent, { mode: 0o755 });
  
  console.log('Script created with 0755 permissions');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_6() {
  // Creating a configuration file with read permissions for all users
  const configPath = path.join(__dirname, 'config', 'secrets.json');
  const configData = JSON.stringify({
    dbPassword: 'super-secret-password',
    apiToken: 'abc123xyz789'
  });
  
  // ruleid: javascript-incorrect-default-permissions
  fs.writeFileSync(configPath, configData, { mode: 0o644 });
  
  console.log('Config file created with 0644 permissions');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_7() {
  // Using promises API to create a file with insecure permissions
  const filePath = path.join(__dirname, 'data.json');
  const data = JSON.stringify({ users: ['admin', 'user1'] });
  
  // ruleid: javascript-incorrect-default-permissions
  fs.promises.writeFile(filePath, data, { mode: 0o666 })
    .then(() => console.log('File created with 0666 permissions'))
    .catch(err => console.error('Error creating file:', err));
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_8() {
  // Creating a temporary file with insecure permissions using a variable
  const tempDir = os.tmpdir();
  const tempFile = path.join(tempDir, `temp-${Date.now()}.txt`);
  const permissions = 0o777; // Insecure permissions
  
  // ruleid: javascript-incorrect-default-permissions
  fs.writeFileSync(tempFile, 'Temporary data', { mode: permissions });
  
  console.log(`Temporary file created at ${tempFile} with permissions ${permissions.toString(8)}`);
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_9() {
  // Opening a file with insecure permissions
  const filePath = path.join(__dirname, 'output.log');
  
  // ruleid: javascript-incorrect-default-permissions
  const fd = fs.openSync(filePath, 'w', 0o666);
  fs.writeSync(fd, 'Log entry');
  fs.closeSync(fd);
  
  console.log('File opened and written with 0666 permissions');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_10() {
  // Creating multiple files with insecure permissions
  const dataDir = path.join(__dirname, 'data');
  
  if (!fs.existsSync(dataDir)) {
    // ruleid: javascript-incorrect-default-permissions
    fs.mkdirSync(dataDir, { mode: 0o777 });
  }
  
  for (let i = 1; i <= 3; i++) {
    const filePath = path.join(dataDir, `file${i}.txt`);
    // ruleid: javascript-incorrect-default-permissions
    fs.writeFileSync(filePath, `Content for file ${i}`, { mode: 0o666 });
  }
  
  console.log('Created multiple files with insecure permissions');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_11() {
  // Using a function to create files with insecure permissions
  function createConfigFile(name, content) {
    const filePath = path.join(__dirname, 'configs', name);
    
    if (!fs.existsSync(path.dirname(filePath))) {
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
    }
    
    // ruleid: javascript-incorrect-default-permissions
    fs.writeFileSync(filePath, content, { mode: 0o644 });
    return filePath;
  }
  
  const dbConfigPath = createConfigFile('database.json', JSON.stringify({ host: 'localhost', password: 'secret' }));
  console.log(`Created config file at ${dbConfigPath}`);
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_12() {
  // Using computed permissions that result in insecure value
  const basePermission = 0o400; // Read for owner
  const writePermission = 0o200; // Write for owner
  const othersPermission = 0o077; // Read, write, execute for group and others
  
  const permissions = basePermission | writePermission | othersPermission; // Results in 0o677
  
  const filePath = path.join(__dirname, 'computed-permissions.txt');
  
  // ruleid: javascript-incorrect-default-permissions
  fs.writeFileSync(filePath, 'Content with computed permissions', { mode: permissions });
  
  console.log(`File created with computed permissions: ${permissions.toString(8)}`);
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_13() {
  // Creating a file with insecure permissions using a conditional
  const filePath = path.join(__dirname, 'conditional-file.txt');
  const isDevEnvironment = process.env.NODE_ENV === 'development';
  
  // ruleid: javascript-incorrect-default-permissions
  const permissions = isDevEnvironment ? 0o777 : 0o666; // Both are insecure
  fs.writeFileSync(filePath, 'Conditional permissions', { mode: permissions });
  
  console.log(`File created with permissions: ${permissions.toString(8)}`);
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_14() {
  // Creating a file with insecure permissions using an object
  const fileOptions = {
    encoding: 'utf8',
    flag: 'w',
    mode: 0o777 // Insecure permissions
  };
  
  const filePath = path.join(__dirname, 'options-object.txt');
  
  // ruleid: javascript-incorrect-default-permissions
  fs.writeFileSync(filePath, 'Content with options object', fileOptions);
  
  console.log('File created with options object containing 0777 permissions');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_15() {
  // Using fs.constants to create insecure permissions
  const filePath = path.join(__dirname, 'constants-permissions.txt');
  
  // Combining constants to create 0o666 permissions
  const permissions = fs.constants.S_IRUSR | fs.constants.S_IWUSR | 
                      fs.constants.S_IRGRP | fs.constants.S_IWGRP |
                      fs.constants.S_IROTH | fs.constants.S_IWOTH;
  
  // ruleid: javascript-incorrect-default-permissions
  fs.writeFileSync(filePath, 'Content with constants-based permissions', { mode: permissions });
  
  console.log('File created with permissions constructed from constants');
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_1() {
  // Creating a file with secure permissions (readable and writable only by owner)
  const filePath = path.join(__dirname, 'secure-config.json');
  const data = JSON.stringify({ apiKey: 'secret-key' });
  
  // ok: javascript-incorrect-default-permissions
  fs.writeFileSync(filePath, data, { mode: 0o600 });
  
  console.log('File created with secure 0600 permissions');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_2() {
  // Creating a log file with secure permissions
  const logFile = path.join(os.tmpdir(), 'secure-app.log');
  
  // ok: javascript-incorrect-default-permissions
  fs.writeFileSync(logFile, 'Application started', { mode: 0o640 });
  
  console.log('Log file created with secure 0640 permissions');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_3() {
  // Creating a directory with secure permissions
  const dirPath = path.join(__dirname, 'secure-uploads');
  
  if (!fs.existsSync(dirPath)) {
    // ok: javascript-incorrect-default-permissions
    fs.mkdirSync(dirPath, { mode: 0o700 });
  }
  
  console.log('Directory created with secure 0700 permissions');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_4() {
  // Using chmod to set secure permissions on an existing file
  const filePath = path.join(__dirname, 'secure-database.sqlite');
  
  // ok: javascript-incorrect-default-permissions
  fs.chmodSync(filePath, 0o600);
  
  console.log('Changed file permissions to secure 0600');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_5() {
  // Creating a script file with secure permissions
  const scriptPath = path.join(__dirname, 'secure-scripts', 'secure-backup.sh');
  const scriptContent = '#!/bin/bash\necho "Backing up data securely..."';
  
  if (!fs.existsSync(path.dirname(scriptPath))) {
    fs.mkdirSync(path.dirname(scriptPath), { recursive: true });
  }
  
  // ok: javascript-incorrect-default-permissions
  fs.writeFileSync(scriptPath, scriptContent, { mode: 0o700 });
  
  console.log('Script created with secure 0700 permissions');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_6() {
  // Creating a configuration file with secure permissions
  const configPath = path.join(__dirname, 'secure-config', 'secure-secrets.json');
  const configData = JSON.stringify({
    dbPassword: 'super-secret-password',
    apiToken: 'abc123xyz789'
  });
  
  // ok: javascript-incorrect-default-permissions
  fs.writeFileSync(configPath, configData, { mode: 0o600 });
  
  console.log('Config file created with secure 0600 permissions');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_7() {
  // Using promises API to create a file with secure permissions
  const filePath = path.join(__dirname, 'secure-data.json');
  const data = JSON.stringify({ users: ['admin', 'user1'] });
  
  // ok: javascript-incorrect-default-permissions
  fs.promises.writeFile(filePath, data, { mode: 0o600 })
    .then(() => console.log('File created with secure 0600 permissions'))
    .catch(err => console.error('Error creating file:', err));
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_8() {
  // Creating a temporary file with secure permissions using a variable
  const tempDir = os.tmpdir();
  const tempFile = path.join(tempDir, `secure-temp-${Date.now()}.txt`);
  const permissions = 0o600; // Secure permissions
  
  // ok: javascript-incorrect-default-permissions
  fs.writeFileSync(tempFile, 'Temporary data', { mode: permissions });
  
  console.log(`Temporary file created at ${tempFile} with secure permissions ${permissions.toString(8)}`);
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_9() {
  // Opening a file with secure permissions
  const filePath = path.join(__dirname, 'secure-output.log');
  
  // ok: javascript-incorrect-default-permissions
  const fd = fs.openSync(filePath, 'w', 0o600);
  fs.writeSync(fd, 'Secure log entry');
  fs.closeSync(fd);
  
  console.log('File opened and written with secure 0600 permissions');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_10() {
  // Creating multiple files with secure permissions
  const dataDir = path.join(__dirname, 'secure-data');
  
  if (!fs.existsSync(dataDir)) {
    // ok: javascript-incorrect-default-permissions
    fs.mkdirSync(dataDir, { mode: 0o700 });
  }
  
  for (let i = 1; i <= 3; i++) {
    const filePath = path.join(dataDir, `secure-file${i}.txt`);
    // ok: javascript-incorrect-default-permissions
    fs.writeFileSync(filePath, `Content for secure file ${i}`, { mode: 0o600 });
  }
  
  console.log('Created multiple files with secure permissions');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_11() {
  // Using a function to create files with secure permissions
  function createSecureConfigFile(name, content) {
    const filePath = path.join(__dirname, 'secure-configs', name);
    
    if (!fs.existsSync(path.dirname(filePath))) {
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
    }
    
    // ok: javascript-incorrect-default-permissions
    fs.writeFileSync(filePath, content, { mode: 0o600 });
    return filePath;
  }
  
  const dbConfigPath = createSecureConfigFile('secure-database.json', JSON.stringify({ host: 'localhost', password: 'secret' }));
  console.log(`Created secure config file at ${dbConfigPath}`);
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_12() {
  // Using computed permissions that result in secure value
  const basePermission = 0o400; // Read for owner
  const writePermission = 0o200; // Write for owner
  
  const permissions = basePermission | writePermission; // Results in 0o600
  
  const filePath = path.join(__dirname, 'secure-computed-permissions.txt');
  
  // ok: javascript-incorrect-default-permissions
  fs.writeFileSync(filePath, 'Content with secure computed permissions', { mode: permissions });
  
  console.log(`File created with secure computed permissions: ${permissions.toString(8)}`);
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_13() {
  // Creating a file with secure permissions based on environment
  const filePath = path.join(__dirname, 'secure-conditional-file.txt');
  const isProductionEnvironment = process.env.NODE_ENV === 'production';
  
  // ok: javascript-incorrect-default-permissions
  const permissions = isProductionEnvironment ? 0o600 : 0o640; // Both are secure
  fs.writeFileSync(filePath, 'Secure conditional permissions', { mode: permissions });
  
  console.log(`File created with secure permissions: ${permissions.toString(8)}`);
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_14() {
  // Creating a file with secure permissions using an object
  const fileOptions = {
    encoding: 'utf8',
    flag: 'w',
    mode: 0o600 // Secure permissions
  };
  
  const filePath = path.join(__dirname, 'secure-options-object.txt');
  
  // ok: javascript-incorrect-default-permissions
  fs.writeFileSync(filePath, 'Content with secure options object', fileOptions);
  
  console.log('File created with options object containing secure 0600 permissions');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_15() {
  // Using fs.constants to create secure permissions
  const filePath = path.join(__dirname, 'secure-constants-permissions.txt');
  
  // Combining constants to create 0o600 permissions (owner read/write only)
  const permissions = fs.constants.S_IRUSR | fs.constants.S_IWUSR;
  
  // ok: javascript-incorrect-default-permissions
  fs.writeFileSync(filePath, 'Content with secure constants-based permissions', { mode: permissions });
  
  console.log('File created with secure permissions constructed from constants');
}
// {/fact}