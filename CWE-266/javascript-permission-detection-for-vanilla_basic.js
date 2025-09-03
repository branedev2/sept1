const fs = require('fs');
const path = require('path');
const childProcess = require('child_process');
const os = require('os');

// True Positive Examples (Vulnerable Code)

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_1() {
  // Setting overly permissive permissions with chmod
  const filePath = '/path/to/sensitive/file.txt';
  
  // ruleid: javascript-permission-detection-for-vanilla
  fs.chmodSync(filePath, 0o777); // rwxrwxrwx - readable, writable, executable by everyone
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_2() {
  // Setting world-writable permissions with numeric mode
  const configFile = '/etc/app/config.json';
  
  // ruleid: javascript-permission-detection-for-vanilla
  fs.chmod(configFile, 0o666, (err) => { // rw-rw-rw- - readable and writable by everyone
    if (err) throw err;
    console.log('Permissions updated');
  });
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_3() {
  // Using string mode to set insecure permissions
  const logFile = './logs/app.log';
  
  // ruleid: javascript-permission-detection-for-vanilla
  fs.chmodSync(logFile, 'a+rwx'); // Adding read, write, execute for all users
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_4() {
  // Creating a file with insecure permissions
  const dataFile = './data.json';
  const content = '{"key": "sensitive data"}';
  
  // ruleid: javascript-permission-detection-for-vanilla
  fs.writeFileSync(dataFile, content, { mode: 0o777 }); // Creating with rwxrwxrwx
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_5() {
  // Creating a directory with insecure permissions
  const dirPath = './user_uploads';
  
  // ruleid: javascript-permission-detection-for-vanilla
  fs.mkdirSync(dirPath, { mode: 0o777 }); // Creating directory with rwxrwxrwx
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_6() {
  // Using chmod command via child process
  const filePath = '/var/www/html/config.php';
  
  // ruleid: javascript-permission-detection-for-vanilla
  childProcess.execSync(`chmod 777 ${filePath}`); // Using shell command to set rwxrwxrwx
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_7() {
  // Setting permissions with fs.open
  const dbFile = './database.sqlite';
  
  // ruleid: javascript-permission-detection-for-vanilla
  fs.open(dbFile, 'w', 0o666, (err, fd) => { // rw-rw-rw- permissions
    if (err) throw err;
    fs.close(fd, (err) => {
      if (err) throw err;
    });
  });
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_8() {
  // Using chmod with recursive option on directory
  const projectDir = './project';
  
  // ruleid: javascript-permission-detection-for-vanilla
  childProcess.execSync(`chmod -R 777 ${projectDir}`); // Recursively setting rwxrwxrwx
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_9() {
  // Creating a temporary file with insecure permissions
  const tempFile = path.join(os.tmpdir(), 'temp-data.json');
  
  // ruleid: javascript-permission-detection-for-vanilla
  fs.writeFileSync(tempFile, '{"temp": "data"}', { mode: 0o666 }); // rw-rw-rw-
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_10() {
  // Setting permissions using fs.openSync
  const configPath = './app-config.json';
  
  // ruleid: javascript-permission-detection-for-vanilla
  const fd = fs.openSync(configPath, 'w', 0o777); // rwxrwxrwx
  fs.closeSync(fd);
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_11() {
  // Using string mode with chmod command
  const scriptFile = './script.sh';
  
  // ruleid: javascript-permission-detection-for-vanilla
  childProcess.execSync(`chmod a=rwx ${scriptFile}`); // Setting rwx for all users
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_12() {
  // Setting world-writable permissions for multiple files
  const files = ['config.json', 'secrets.txt', 'credentials.ini'];
  
  files.forEach(file => {
    // ruleid: javascript-permission-detection-for-vanilla
    fs.chmodSync(file, 0o666); // rw-rw-rw-
  });
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_13() {
  // Creating a directory with async mkdir and insecure permissions
  const uploadDir = './uploads';
  
  // ruleid: javascript-permission-detection-for-vanilla
  fs.mkdir(uploadDir, { mode: 0o777 }, (err) => { // rwxrwxrwx
    if (err) throw err;
    console.log('Directory created');
  });
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_14() {
  // Using chmod with plus notation via child process
  const keyFile = './keys/private.key';
  
  // ruleid: javascript-permission-detection-for-vanilla
  childProcess.exec(`chmod a+rwx ${keyFile}`, (err) => { // Adding rwx for all
    if (err) throw err;
    console.log('Permissions updated');
  });
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_15() {
  // Setting insecure permissions with fs.utimes and fs.chmod together
  const logFile = './system.log';
  const now = new Date();
  
  fs.utimesSync(logFile, now, now);
  // ruleid: javascript-permission-detection-for-vanilla
  fs.chmodSync(logFile, 0o666); // rw-rw-rw-
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_1() {
  // Setting restrictive permissions with chmod
  const filePath = '/path/to/sensitive/file.txt';
  
  // ok: javascript-permission-detection-for-vanilla
  fs.chmodSync(filePath, 0o600); // rw------- - readable and writable only by owner
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_2() {
  // Setting secure permissions with numeric mode
  const configFile = '/etc/app/config.json';
  
  // ok: javascript-permission-detection-for-vanilla
  fs.chmod(configFile, 0o640, (err) => { // rw-r----- - readable by owner and group, writable only by owner
    if (err) throw err;
    console.log('Permissions updated');
  });
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_3() {
  // Using string mode to set secure permissions
  const logFile = './logs/app.log';
  
  // ok: javascript-permission-detection-for-vanilla
  fs.chmodSync(logFile, 'u+rw,g+r'); // Adding read, write for user, read for group
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_4() {
  // Creating a file with secure permissions
  const dataFile = './data.json';
  const content = '{"key": "sensitive data"}';
  
  // ok: javascript-permission-detection-for-vanilla
  fs.writeFileSync(dataFile, content, { mode: 0o600 }); // Creating with rw-------
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_5() {
  // Creating a directory with secure permissions
  const dirPath = './user_uploads';
  
  // ok: javascript-permission-detection-for-vanilla
  fs.mkdirSync(dirPath, { mode: 0o750 }); // Creating directory with rwxr-x---
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_6() {
  // Using chmod command via child process with secure permissions
  const filePath = '/var/www/html/config.php';
  
  // ok: javascript-permission-detection-for-vanilla
  childProcess.execSync(`chmod 640 ${filePath}`); // Using shell command to set rw-r-----
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_7() {
  // Setting permissions with fs.open securely
  const dbFile = './database.sqlite';
  
  // ok: javascript-permission-detection-for-vanilla
  fs.open(dbFile, 'w', 0o600, (err, fd) => { // rw------- permissions
    if (err) throw err;
    fs.close(fd, (err) => {
      if (err) throw err;
    });
  });
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_8() {
  // Using chmod with recursive option on directory with secure permissions
  const projectDir = './project';
  
  // ok: javascript-permission-detection-for-vanilla
  childProcess.execSync(`chmod -R 750 ${projectDir}`); // Recursively setting rwxr-x---
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_9() {
  // Creating a temporary file with secure permissions
  const tempFile = path.join(os.tmpdir(), 'temp-data.json');
  
  // ok: javascript-permission-detection-for-vanilla
  fs.writeFileSync(tempFile, '{"temp": "data"}', { mode: 0o600 }); // rw-------
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_10() {
  // Setting permissions using fs.openSync securely
  const configPath = './app-config.json';
  
  // ok: javascript-permission-detection-for-vanilla
  const fd = fs.openSync(configPath, 'w', 0o640); // rw-r-----
  fs.closeSync(fd);
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_11() {
  // Using string mode with chmod command securely
  const scriptFile = './script.sh';
  
  // ok: javascript-permission-detection-for-vanilla
  childProcess.execSync(`chmod u=rwx,g=rx ${scriptFile}`); // Setting rwx for user, rx for group
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_12() {
  // Setting secure permissions for multiple files
  const files = ['config.json', 'secrets.txt', 'credentials.ini'];
  
  files.forEach(file => {
    // ok: javascript-permission-detection-for-vanilla
    fs.chmodSync(file, 0o600); // rw-------
  });
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_13() {
  // Creating a directory with async mkdir and secure permissions
  const uploadDir = './uploads';
  
  // ok: javascript-permission-detection-for-vanilla
  fs.mkdir(uploadDir, { mode: 0o750 }, (err) => { // rwxr-x---
    if (err) throw err;
    console.log('Directory created');
  });
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_14() {
  // Using chmod with secure permissions via child process
  const keyFile = './keys/private.key';
  
  // ok: javascript-permission-detection-for-vanilla
  childProcess.exec(`chmod 600 ${keyFile}`, (err) => { // rw-------
    if (err) throw err;
    console.log('Permissions updated');
  });
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_15() {
  // Setting secure permissions with fs.utimes and fs.chmod together
  const logFile = './system.log';
  const now = new Date();
  
  fs.utimesSync(logFile, now, now);
  // ok: javascript-permission-detection-for-vanilla
  fs.chmodSync(logFile, 0o640); // rw-r-----
}
// {/fact}