import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as child_process from 'child_process';
import * as http from 'http';
import { promisify } from 'util';

// True Positives (Vulnerable Code)

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_1() {
  // Setting overly permissive file permissions with 0777 (rwxrwxrwx)
  const filePath = path.join(__dirname, 'sensitive_data.txt');
  
  // ruleid: typescript-permission-detection-for-vanilla
  fs.chmodSync(filePath, 0o777);
  
  console.log('File permissions updated to allow everyone read/write/execute access');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_2() {
  // Setting directory permissions to be world-writable
  const dirPath = path.join(__dirname, 'config_directory');
  
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath);
  }
  
  // ruleid: typescript-permission-detection-for-vanilla
  fs.chmodSync(dirPath, 0o777);
  
  console.log('Directory permissions set to allow everyone full access');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_3() {
  // Creating a file with overly permissive permissions
  const logFile = path.join(os.tmpdir(), 'application.log');
  const content = 'This is a log entry with sensitive information';
  
  // ruleid: typescript-permission-detection-for-vanilla
  fs.writeFileSync(logFile, content, { mode: 0o666 }); // rw-rw-rw-
  
  console.log(`Log file created at ${logFile} with world-readable permissions`);
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_4() {
  // Using promises to set insecure permissions
  const configFile = path.join(__dirname, 'database.config');
  const chmod = promisify(fs.chmod);
  
  async function setPermissions() {
    try {
      // ruleid: typescript-permission-detection-for-vanilla
      await chmod(configFile, 0o777);
      console.log('Config file permissions updated to allow everyone access');
    } catch (error) {
      console.error('Error setting permissions:', error);
    }
  }
  
  setPermissions();
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_5() {
  // Setting permissions on multiple files with a loop
  const fileNames = ['passwords.txt', 'keys.json', 'certificates.pem'];
  
  fileNames.forEach(fileName => {
    const filePath = path.join(__dirname, fileName);
    if (fs.existsSync(filePath)) {
      // ruleid: typescript-permission-detection-for-vanilla
      fs.chmodSync(filePath, 0o666); // rw-rw-rw-
      console.log(`Set world-readable permissions on ${fileName}`);
    }
  });
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_6() {
  // Creating a directory with insecure permissions
  const uploadDir = path.join(__dirname, 'uploads');
  
  if (!fs.existsSync(uploadDir)) {
    // ruleid: typescript-permission-detection-for-vanilla
    fs.mkdirSync(uploadDir, { mode: 0o777 });
    console.log('Created upload directory with full permissions for everyone');
  }
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_7() {
  // Using octal literals in string form
  const secretsFile = path.join(__dirname, 'secrets.env');
  
  // ruleid: typescript-permission-detection-for-vanilla
  fs.chmod(secretsFile, '777', (err) => {
    if (err) {
      console.error('Error setting permissions:', err);
    } else {
      console.log('Set insecure permissions on secrets file');
    }
  });
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_8() {
  // Setting permissions based on user input without validation
  const server = http.createServer((req, res) => {
    if (req.url?.startsWith('/set-permissions')) {
      const filePath = path.join(__dirname, 'user_data.json');
      
      // ruleid: typescript-permission-detection-for-vanilla
      fs.chmod(filePath, 0o777, (err) => {
        if (err) {
          res.writeHead(500);
          res.end('Error setting permissions');
        } else {
          res.writeHead(200);
          res.end('Permissions updated successfully');
        }
      });
    }
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_9() {
  // Using numeric permissions directly
  const logDir = path.join(__dirname, 'logs');
  
  if (!fs.existsSync(logDir)) {
    // ruleid: typescript-permission-detection-for-vanilla
    fs.mkdirSync(logDir, 511); // Decimal for 0o777
    console.log('Created log directory with insecure permissions');
  }
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_10() {
  // Setting insecure permissions in a conditional block
  const configFile = path.join(__dirname, 'app.config');
  const isDevMode = process.env.NODE_ENV === 'development';
  
  if (isDevMode) {
    // ruleid: typescript-permission-detection-for-vanilla
    fs.chmodSync(configFile, 0o666);
    console.log('Set development mode permissions (world-readable)');
  } else {
    fs.chmodSync(configFile, 0o600);
    console.log('Set production mode permissions (owner-only)');
  }
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_11() {
  // Using fs.openSync with insecure permissions
  const dataFile = path.join(__dirname, 'data.bin');
  
  try {
    // ruleid: typescript-permission-detection-for-vanilla
    const fd = fs.openSync(dataFile, 'w', 0o777);
    fs.writeSync(fd, 'Sensitive data');
    fs.closeSync(fd);
    console.log('Created file with insecure permissions');
  } catch (error) {
    console.error('Error creating file:', error);
  }
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_12() {
  // Setting permissions in a promise chain
  const keyFile = path.join(__dirname, 'private_key.pem');
  
  Promise.resolve()
    .then(() => {
      // ruleid: typescript-permission-detection-for-vanilla
      return promisify(fs.chmod)(keyFile, 0o777);
    })
    .then(() => {
      console.log('Set insecure permissions on private key file');
    })
    .catch(error => {
      console.error('Error setting permissions:', error);
    });
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_13() {
  // Using template literals to construct paths with insecure permissions
  const username = 'admin';
  const userDir = path.join(__dirname, `users/${username}`);
  
  if (!fs.existsSync(userDir)) {
    // ruleid: typescript-permission-detection-for-vanilla
    fs.mkdirSync(userDir, { recursive: true, mode: 0o777 });
    console.log(`Created user directory for ${username} with insecure permissions`);
  }
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_14() {
  // Setting permissions on a temporary file
  const tempFile = path.join(os.tmpdir(), `temp-${Date.now()}.json`);
  fs.writeFileSync(tempFile, JSON.stringify({ key: 'sensitive_value' }));
  
  // ruleid: typescript-permission-detection-for-vanilla
  fs.chmodSync(tempFile, 0o666);
  console.log('Created temporary file with world-readable permissions');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_15() {
  // Using child_process to set insecure permissions
  const secretsDir = path.join(__dirname, 'secrets');
  
  if (!fs.existsSync(secretsDir)) {
    fs.mkdirSync(secretsDir);
  }
  
  // ruleid: typescript-permission-detection-for-vanilla
  child_process.execSync(`chmod -R 777 ${secretsDir}`);
  console.log('Set recursive insecure permissions on secrets directory');
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_1() {
  // Setting secure file permissions with 0600 (rw-------)
  const filePath = path.join(__dirname, 'sensitive_data.txt');
  
  // ok: typescript-permission-detection-for-vanilla
  fs.chmodSync(filePath, 0o600);
  
  console.log('File permissions updated to allow only owner access');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_2() {
  // Setting directory permissions to be owner-only writable
  const dirPath = path.join(__dirname, 'config_directory');
  
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath);
  }
  
  // ok: typescript-permission-detection-for-vanilla
  fs.chmodSync(dirPath, 0o755); // rwxr-xr-x
  
  console.log('Directory permissions set to allow owner full access, others read/execute only');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_3() {
  // Creating a file with secure permissions
  const logFile = path.join(os.tmpdir(), 'application.log');
  const content = 'This is a log entry with sensitive information';
  
  // ok: typescript-permission-detection-for-vanilla
  fs.writeFileSync(logFile, content, { mode: 0o600 }); // rw-------
  
  console.log(`Log file created at ${logFile} with owner-only permissions`);
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_4() {
  // Using promises to set secure permissions
  const configFile = path.join(__dirname, 'database.config');
  const chmod = promisify(fs.chmod);
  
  async function setPermissions() {
    try {
      // ok: typescript-permission-detection-for-vanilla
      await chmod(configFile, 0o640); // rw-r-----
      console.log('Config file permissions updated to allow owner read/write, group read');
    } catch (error) {
      console.error('Error setting permissions:', error);
    }
  }
  
  setPermissions();
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_5() {
  // Setting permissions on multiple files with a loop
  const fileNames = ['passwords.txt', 'keys.json', 'certificates.pem'];
  
  fileNames.forEach(fileName => {
    const filePath = path.join(__dirname, fileName);
    if (fs.existsSync(filePath)) {
      // ok: typescript-permission-detection-for-vanilla
      fs.chmodSync(filePath, 0o600); // rw-------
      console.log(`Set owner-only permissions on ${fileName}`);
    }
  });
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_6() {
  // Creating a directory with secure permissions
  const uploadDir = path.join(__dirname, 'uploads');
  
  if (!fs.existsSync(uploadDir)) {
    // ok: typescript-permission-detection-for-vanilla
    fs.mkdirSync(uploadDir, { mode: 0o750 }); // rwxr-x---
    console.log('Created upload directory with permissions for owner and group only');
  }
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_7() {
  // Using octal literals in string form with secure permissions
  const secretsFile = path.join(__dirname, 'secrets.env');
  
  // ok: typescript-permission-detection-for-vanilla
  fs.chmod(secretsFile, '600', (err) => {
    if (err) {
      console.error('Error setting permissions:', err);
    } else {
      console.log('Set secure permissions on secrets file');
    }
  });
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_8() {
  // Setting secure permissions based on user input
  const server = http.createServer((req, res) => {
    if (req.url?.startsWith('/set-permissions')) {
      const filePath = path.join(__dirname, 'user_data.json');
      
      // ok: typescript-permission-detection-for-vanilla
      fs.chmod(filePath, 0o640, (err) => {
        if (err) {
          res.writeHead(500);
          res.end('Error setting permissions');
        } else {
          res.writeHead(200);
          res.end('Permissions updated successfully');
        }
      });
    }
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_9() {
  // Using numeric permissions directly with secure values
  const logDir = path.join(__dirname, 'logs');
  
  if (!fs.existsSync(logDir)) {
    // ok: typescript-permission-detection-for-vanilla
    fs.mkdirSync(logDir, 448); // Decimal for 0o700
    console.log('Created log directory with secure permissions');
  }
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_10() {
  // Setting secure permissions in all conditions
  const configFile = path.join(__dirname, 'app.config');
  const isDevMode = process.env.NODE_ENV === 'development';
  
  if (isDevMode) {
    // ok: typescript-permission-detection-for-vanilla
    fs.chmodSync(configFile, 0o640);
    console.log('Set development mode permissions (owner read/write, group read)');
  } else {
    // ok: typescript-permission-detection-for-vanilla
    fs.chmodSync(configFile, 0o600);
    console.log('Set production mode permissions (owner-only)');
  }
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_11() {
  // Using fs.openSync with secure permissions
  const dataFile = path.join(__dirname, 'data.bin');
  
  try {
    // ok: typescript-permission-detection-for-vanilla
    const fd = fs.openSync(dataFile, 'w', 0o600);
    fs.writeSync(fd, 'Sensitive data');
    fs.closeSync(fd);
    console.log('Created file with secure permissions');
  } catch (error) {
    console.error('Error creating file:', error);
  }
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_12() {
  // Setting permissions in a promise chain with secure values
  const keyFile = path.join(__dirname, 'private_key.pem');
  
  Promise.resolve()
    .then(() => {
      // ok: typescript-permission-detection-for-vanilla
      return promisify(fs.chmod)(keyFile, 0o600);
    })
    .then(() => {
      console.log('Set secure permissions on private key file');
    })
    .catch(error => {
      console.error('Error setting permissions:', error);
    });
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_13() {
  // Using template literals to construct paths with secure permissions
  const username = 'admin';
  const userDir = path.join(__dirname, `users/${username}`);
  
  if (!fs.existsSync(userDir)) {
    // ok: typescript-permission-detection-for-vanilla
    fs.mkdirSync(userDir, { recursive: true, mode: 0o750 });
    console.log(`Created user directory for ${username} with secure permissions`);
  }
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_14() {
  // Setting permissions on a temporary file with secure values
  const tempFile = path.join(os.tmpdir(), `temp-${Date.now()}.json`);
  fs.writeFileSync(tempFile, JSON.stringify({ key: 'sensitive_value' }));
  
  // ok: typescript-permission-detection-for-vanilla
  fs.chmodSync(tempFile, 0o600);
  console.log('Created temporary file with owner-only permissions');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_15() {
  // Using child_process to set secure permissions
  const secretsDir = path.join(__dirname, 'secrets');
  
  if (!fs.existsSync(secretsDir)) {
    fs.mkdirSync(secretsDir);
  }
  
  // ok: typescript-permission-detection-for-vanilla
  child_process.execSync(`chmod -R 700 ${secretsDir}`);
  console.log('Set recursive secure permissions on secrets directory');
}
// {/fact}