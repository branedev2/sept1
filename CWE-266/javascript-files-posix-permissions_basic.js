const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const childProcess = require('child_process');
const exec = promisify(childProcess.exec);

// TRUE POSITIVES (Vulnerable code examples)

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_1() {
  // Setting overly permissive read/write/execute permissions for everyone
  // ruleid: javascript-files-posix-permissions
  fs.chmodSync('config.json', 0o777);
  console.log('File permissions updated');
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_2() {
  const filePath = '/var/www/html/app/data.txt';
  // Setting world-writable permissions
  // ruleid: javascript-files-posix-permissions
  fs.chmod(filePath, 0o666, (err) => {
    if (err) throw err;
    console.log('File permissions updated');
  });
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_3() {
  // Creating a directory with full permissions for everyone
  // ruleid: javascript-files-posix-permissions
  fs.mkdirSync('uploads', 0o777);
  console.log('Directory created with full permissions');
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_4() {
  const dirPath = './logs';
  // Creating a directory with write permissions for everyone
  // ruleid: javascript-files-posix-permissions
  fs.mkdir(dirPath, { mode: 0o776 }, (err) => {
    if (err) throw err;
    console.log('Directory created with write permissions for everyone');
  });
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_5() {
  // Using octal literal for overly permissive permissions
  const mode = 0o777;
  // ruleid: javascript-files-posix-permissions
  fs.chmodSync('secrets.txt', mode);
  console.log('Updated file permissions');
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_6() {
  // Using decimal representation of permissive permissions
  // ruleid: javascript-files-posix-permissions
  fs.chmod('api_keys.json', 511, (err) => { // 511 is decimal for 0o777
    if (err) throw err;
    console.log('Updated permissions');
  });
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_7() {
  const configFile = path.join(__dirname, 'config.json');
  // Using string representation of permissive permissions
  // ruleid: javascript-files-posix-permissions
  fs.chmodSync(configFile, '777');
  console.log('Updated config file permissions');
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_8() {
  // Using promises version with overly permissive permissions
  const fsPromises = fs.promises;
  // ruleid: javascript-files-posix-permissions
  fsPromises.chmod('database.sqlite', 0o777)
    .then(() => console.log('Permissions updated'))
    .catch(err => console.error('Error:', err));
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_9() {
  // Using variable to store path but still using insecure permissions
  const logFile = '/var/log/app.log';
  // ruleid: javascript-files-posix-permissions
  fs.chmodSync(logFile, 0o666);
  console.log(`Updated permissions for ${logFile}`);
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_10() {
  // Creating a temporary file with insecure permissions
  const tempFile = `/tmp/app-${Date.now()}.tmp`;
  fs.writeFileSync(tempFile, 'Temporary data');
  // ruleid: javascript-files-posix-permissions
  fs.chmodSync(tempFile, 0o777);
  console.log('Created temporary file with full permissions');
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_11() {
  // Using chmod with async/await and insecure permissions
  async function updatePermissions() {
    try {
      // ruleid: javascript-files-posix-permissions
      await fs.promises.chmod('credentials.json', 0o777);
      console.log('Updated permissions');
    } catch (err) {
      console.error('Error:', err);
    }
  }
  updatePermissions();
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_12() {
  // Using child_process to set insecure permissions
  // ruleid: javascript-files-posix-permissions
  childProcess.execSync('chmod 777 sensitive_data.txt');
  console.log('Updated file permissions via command');
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_13() {
  // Using exec with promises to set insecure permissions
  // ruleid: javascript-files-posix-permissions
  exec('chmod -R 777 ./uploads')
    .then(() => console.log('Updated directory permissions'))
    .catch(err => console.error('Error:', err));
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_14() {
  // Setting world-writable permissions on a configuration directory
  // ruleid: javascript-files-posix-permissions
  fs.chmodSync('./config', 0o776);
  console.log('Updated directory permissions');
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_15() {
  // Using a calculated permission value that's still insecure
  const basePermission = 0o700;
  const worldWritable = 0o077;
  // ruleid: javascript-files-posix-permissions
  fs.chmodSync('user_data.json', basePermission | worldWritable); // Results in 0o777
  console.log('Updated file permissions');
}
// {/fact}

// TRUE NEGATIVES (Secure code examples)

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_1() {
  // Setting restrictive permissions (owner read/write only)
  // ok: javascript-files-posix-permissions
  fs.chmodSync('config.json', 0o600);
  console.log('File permissions updated securely');
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_2() {
  const filePath = '/var/www/html/app/data.txt';
  // Setting owner read/write, group read-only permissions
  // ok: javascript-files-posix-permissions
  fs.chmod(filePath, 0o640, (err) => {
    if (err) throw err;
    console.log('File permissions updated securely');
  });
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_3() {
  // Creating a directory with restricted permissions
  // ok: javascript-files-posix-permissions
  fs.mkdirSync('uploads', 0o750);
  console.log('Directory created with secure permissions');
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_4() {
  const dirPath = './logs';
  // Creating a directory with secure permissions
  // ok: javascript-files-posix-permissions
  fs.mkdir(dirPath, { mode: 0o700 }, (err) => {
    if (err) throw err;
    console.log('Directory created with secure permissions');
  });
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_5() {
  // Using octal literal for secure permissions
  const mode = 0o600;
  // ok: javascript-files-posix-permissions
  fs.chmodSync('secrets.txt', mode);
  console.log('Updated file permissions securely');
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_6() {
  // Using decimal representation of secure permissions
  // ok: javascript-files-posix-permissions
  fs.chmod('api_keys.json', 384, (err) => { // 384 is decimal for 0o600
    if (err) throw err;
    console.log('Updated permissions securely');
  });
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_7() {
  const configFile = path.join(__dirname, 'config.json');
  // Using string representation of secure permissions
  // ok: javascript-files-posix-permissions
  fs.chmodSync(configFile, '600');
  console.log('Updated config file permissions securely');
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_8() {
  // Using promises version with secure permissions
  const fsPromises = fs.promises;
  // ok: javascript-files-posix-permissions
  fsPromises.chmod('database.sqlite', 0o640)
    .then(() => console.log('Permissions updated securely'))
    .catch(err => console.error('Error:', err));
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_9() {
  // Using variable to store path with secure permissions
  const logFile = '/var/log/app.log';
  // ok: javascript-files-posix-permissions
  fs.chmodSync(logFile, 0o600);
  console.log(`Updated permissions securely for ${logFile}`);
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_10() {
  // Creating a temporary file with secure permissions
  const tempFile = `/tmp/app-${Date.now()}.tmp`;
  fs.writeFileSync(tempFile, 'Temporary data');
  // ok: javascript-files-posix-permissions
  fs.chmodSync(tempFile, 0o600);
  console.log('Created temporary file with secure permissions');
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_11() {
  // Using chmod with async/await and secure permissions
  async function updatePermissions() {
    try {
      // ok: javascript-files-posix-permissions
      await fs.promises.chmod('credentials.json', 0o640);
      console.log('Updated permissions securely');
    } catch (err) {
      console.error('Error:', err);
    }
  }
  updatePermissions();
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_12() {
  // Using child_process to set secure permissions
  // ok: javascript-files-posix-permissions
  childProcess.execSync('chmod 600 sensitive_data.txt');
  console.log('Updated file permissions securely via command');
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_13() {
  // Using exec with promises to set secure permissions
  // ok: javascript-files-posix-permissions
  exec('chmod -R 750 ./uploads')
    .then(() => console.log('Updated directory permissions securely'))
    .catch(err => console.error('Error:', err));
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_14() {
  // Setting secure permissions on a configuration directory
  // ok: javascript-files-posix-permissions
  fs.chmodSync('./config', 0o750);
  console.log('Updated directory permissions securely');
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_15() {
  // Using a calculated permission value that's secure
  const ownerReadWrite = 0o600;
  const groupRead = 0o040;
  // ok: javascript-files-posix-permissions
  fs.chmodSync('user_data.json', ownerReadWrite | groupRead); // Results in 0o640
  console.log('Updated file permissions securely');
}
// {/fact}