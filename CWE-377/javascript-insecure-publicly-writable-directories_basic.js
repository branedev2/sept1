const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const multer = require('multer');
const rimraf = require('rimraf');

// True Positives (Vulnerable Code)

// {fact rule=insecure-temp-file@v1.0 defects=1}
function bad_case_1() {
  // Creating a file in /tmp with predictable name
  const tempFile = '/tmp/app-data.json';
  
  // ruleid: javascript-insecure-publicly-writable-directories
  fs.writeFileSync(tempFile, JSON.stringify({ sensitive: 'data' }));
  
  console.log(`Data written to ${tempFile}`);
  return tempFile;
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
function bad_case_2() {
  // Using a predictable directory name in /tmp
  const tempDir = '/tmp/app-uploads';
  
  if (!fs.existsSync(tempDir)) {
    // ruleid: javascript-insecure-publicly-writable-directories
    fs.mkdirSync(tempDir, { mode: 0o777 });
  }
  
  const filePath = path.join(tempDir, 'config.json');
  fs.writeFileSync(filePath, JSON.stringify({ key: 'value' }));
  return filePath;
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
function bad_case_3() {
  // Using /var/tmp with predictable name and world-writable permissions
  const logDir = '/var/tmp/app-logs';
  
  if (!fs.existsSync(logDir)) {
    // ruleid: javascript-insecure-publicly-writable-directories
    fs.mkdirSync(logDir, { recursive: true, mode: 0o777 });
  }
  
  const logFile = path.join(logDir, 'app.log');
  fs.appendFileSync(logFile, `Log entry at ${new Date()}\n`);
  return logFile;
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  // Setting up file upload to a publicly writable directory with predictable name
  const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      // ruleid: javascript-insecure-publicly-writable-directories
      const uploadDir = '/tmp/uploads';
      if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { mode: 0o777 });
      }
      cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
      cb(null, file.originalname);
    }
  });
  
  const upload = multer({ storage: storage });
  
  app.post('/upload', upload.single('file'), (req, res) => {
    res.send('File uploaded successfully');
  });
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
function bad_case_5() {
  // Creating a temp file with predictable name based on user input
  const app = express();
  
  app.get('/generate-report', (req, res) => {
    const reportName = req.query.name || 'default';
    // ruleid: javascript-insecure-publicly-writable-directories
    const reportPath = `/tmp/${reportName}-report.pdf`;
    
    fs.writeFileSync(reportPath, 'Report content');
    res.download(reportPath);
  });
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
function bad_case_6() {
  // Using a fixed path in /dev/shm (shared memory - publicly writable)
  const cacheFile = '/dev/shm/app-cache.json';
  
  // ruleid: javascript-insecure-publicly-writable-directories
  fs.writeFileSync(cacheFile, JSON.stringify({ cache: 'data' }));
  
  const data = JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
  return data;
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
function bad_case_7() {
  // Creating sequential files in /tmp
  let counter = 0;
  
  function createLogFile(data) {
    counter++;
    // ruleid: javascript-insecure-publicly-writable-directories
    const logFile = `/tmp/app-log-${counter}.txt`;
    fs.writeFileSync(logFile, data);
    return logFile;
  }
  
  return createLogFile('Log entry');
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
function bad_case_8() {
  // Using timestamp-based filenames in /tmp (still predictable)
  const timestamp = Date.now();
  // ruleid: javascript-insecure-publicly-writable-directories
  const tempFile = `/tmp/backup-${timestamp}.zip`;
  
  fs.writeFileSync(tempFile, 'backup data');
  console.log(`Backup created at ${tempFile}`);
  return tempFile;
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
function bad_case_9() {
  // Using a fixed path with world-writable permissions
  const app = express();
  
  app.post('/save-config', (req, res) => {
    const config = req.body.config;
    // ruleid: javascript-insecure-publicly-writable-directories
    const configPath = '/tmp/app-config.json';
    
    fs.writeFileSync(configPath, JSON.stringify(config), { mode: 0o666 });
    res.send('Configuration saved');
  });
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
function bad_case_10() {
  // Creating a temp directory with a fixed name and using it for processing
  function processFiles(files) {
    // ruleid: javascript-insecure-publicly-writable-directories
    const processingDir = '/tmp/processing';
    
    if (!fs.existsSync(processingDir)) {
      fs.mkdirSync(processingDir, { mode: 0o777 });
    }
    
    files.forEach((file, index) => {
      fs.copyFileSync(file, path.join(processingDir, `file-${index}.dat`));
    });
    
    // Process files...
    return processingDir;
  }
  
  return processFiles(['file1.txt', 'file2.txt']);
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
function bad_case_11() {
  // Using a predictable path in /run/user which could be writable by others
  const userId = process.getuid();
  // ruleid: javascript-insecure-publicly-writable-directories
  const runtimeDir = `/run/user/${userId}/app-runtime`;
  
  if (!fs.existsSync(runtimeDir)) {
    fs.mkdirSync(runtimeDir, { recursive: true, mode: 0o777 });
  }
  
  const socketPath = path.join(runtimeDir, 'app.sock');
  // Create a socket or other IPC mechanism
  return socketPath;
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
function bad_case_12() {
  // Using a fixed path with username (still predictable)
  const username = os.userInfo().username;
  // ruleid: javascript-insecure-publicly-writable-directories
  const tempFile = `/tmp/${username}-app-data.json`;
  
  fs.writeFileSync(tempFile, JSON.stringify({ user: username }));
  return tempFile;
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
function bad_case_13() {
  // Creating a world-writable directory for file uploads
  const app = express();
  
  app.post('/api/upload', (req, res) => {
    // ruleid: javascript-insecure-publicly-writable-directories
    const uploadDir = '/tmp/user-uploads';
    
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { mode: 0o777 });
    }
    
    // Handle file upload logic
    res.send('Upload endpoint ready');
  });
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
function bad_case_14() {
  // Using a predictable path for temporary database files
  function createTempDatabase() {
    // ruleid: javascript-insecure-publicly-writable-directories
    const dbPath = '/tmp/app-temp.db';
    
    fs.writeFileSync(dbPath, 'SQLite format 3\0');
    return dbPath;
  }
  
  return createTempDatabase();
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=1}
function bad_case_15() {
  // Using a predictable path for extracting archives
  function extractArchive(archivePath) {
    // ruleid: javascript-insecure-publicly-writable-directories
    const extractDir = '/tmp/extracted';
    
    if (fs.existsSync(extractDir)) {
      rimraf.sync(extractDir);
    }
    
    fs.mkdirSync(extractDir, { mode: 0o777 });
    
    // Extract archive to extractDir
    return extractDir;
  }
  
  return extractArchive('archive.zip');
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=insecure-temp-file@v1.0 defects=0}
function good_case_1() {
  // Using os.tmpdir() with random suffix
  const randomSuffix = crypto.randomBytes(16).toString('hex');
  const tempFile = path.join(os.tmpdir(), `app-data-${randomSuffix}.json`);
  
  // ok: javascript-insecure-publicly-writable-directories
  fs.writeFileSync(tempFile, JSON.stringify({ sensitive: 'data' }), { mode: 0o600 });
  
  console.log(`Data written to ${tempFile}`);
  return tempFile;
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
function good_case_2() {
  // Using mkdtemp for secure temporary directory creation
  const prefix = path.join(os.tmpdir(), 'app-uploads-');
  
  // ok: javascript-insecure-publicly-writable-directories
  const tempDir = fs.mkdtempSync(prefix);
  
  const filePath = path.join(tempDir, 'config.json');
  fs.writeFileSync(filePath, JSON.stringify({ key: 'value' }), { mode: 0o600 });
  return filePath;
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
function good_case_3() {
  // Using a secure random directory name with restricted permissions
  const randomDir = crypto.randomBytes(16).toString('hex');
  const logDir = path.join(os.tmpdir(), `app-logs-${randomDir}`);
  
  if (!fs.existsSync(logDir)) {
    // ok: javascript-insecure-publicly-writable-directories
    fs.mkdirSync(logDir, { recursive: true, mode: 0o700 });
  }
  
  const logFile = path.join(logDir, 'app.log');
  fs.appendFileSync(logFile, `Log entry at ${new Date()}\n`, { mode: 0o600 });
  return logFile;
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  // Setting up file upload with secure random directory and restricted permissions
  const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      // ok: javascript-insecure-publicly-writable-directories
      const randomDir = crypto.randomBytes(16).toString('hex');
      const uploadDir = path.join(os.tmpdir(), `uploads-${randomDir}`);
      
      if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { mode: 0o700 });
      }
      
      cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
      const randomName = crypto.randomBytes(16).toString('hex');
      const extension = path.extname(file.originalname);
      cb(null, `${randomName}${extension}`);
    }
  });
  
  const upload = multer({ storage: storage });
  
  app.post('/upload', upload.single('file'), (req, res) => {
    res.send('File uploaded successfully');
  });
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
function good_case_5() {
  // Creating a temp file with random name based on user input
  const app = express();
  
  app.get('/generate-report', (req, res) => {
    const reportName = req.query.name || 'default';
    const safeReportName = reportName.replace(/[^a-zA-Z0-9]/g, '-');
    const randomSuffix = crypto.randomBytes(16).toString('hex');
    
    // ok: javascript-insecure-publicly-writable-directories
    const reportPath = path.join(os.tmpdir(), `${safeReportName}-${randomSuffix}.pdf`);
    
    fs.writeFileSync(reportPath, 'Report content', { mode: 0o600 });
    res.download(reportPath, () => {
      fs.unlinkSync(reportPath); // Clean up after download
    });
  });
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
function good_case_6() {
  // Using a secure random path in temp directory instead of /dev/shm
  const randomId = crypto.randomBytes(16).toString('hex');
  
  // ok: javascript-insecure-publicly-writable-directories
  const cacheFile = path.join(os.tmpdir(), `app-cache-${randomId}.json`);
  
  fs.writeFileSync(cacheFile, JSON.stringify({ cache: 'data' }), { mode: 0o600 });
  
  const data = JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
  fs.unlinkSync(cacheFile); // Clean up
  return data;
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
function good_case_7() {
  // Creating files with random names
  function createLogFile(data) {
    const randomId = crypto.randomBytes(16).toString('hex');
    
    // ok: javascript-insecure-publicly-writable-directories
    const logFile = path.join(os.tmpdir(), `app-log-${randomId}.txt`);
    
    fs.writeFileSync(logFile, data, { mode: 0o600 });
    return logFile;
  }
  
  return createLogFile('Log entry');
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
function good_case_8() {
  // Using timestamp and random data for unique filenames
  const timestamp = Date.now();
  const randomSuffix = crypto.randomBytes(8).toString('hex');
  
  // ok: javascript-insecure-publicly-writable-directories
  const tempFile = path.join(os.tmpdir(), `backup-${timestamp}-${randomSuffix}.zip`);
  
  fs.writeFileSync(tempFile, 'backup data', { mode: 0o600 });
  console.log(`Backup created at ${tempFile}`);
  return tempFile;
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
function good_case_9() {
  // Using a per-user config directory with proper permissions
  const app = express();
  
  app.post('/save-config', (req, res) => {
    const config = req.body.config;
    const userId = req.user.id; // Assuming authentication middleware
    const userConfigDir = path.join(os.homedir(), '.app-config');
    
    if (!fs.existsSync(userConfigDir)) {
      // ok: javascript-insecure-publicly-writable-directories
      fs.mkdirSync(userConfigDir, { mode: 0o700 });
    }
    
    const configPath = path.join(userConfigDir, `${userId}-config.json`);
    fs.writeFileSync(configPath, JSON.stringify(config), { mode: 0o600 });
    res.send('Configuration saved');
  });
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
function good_case_10() {
  // Creating a temp directory with a random name for processing
  function processFiles(files) {
    const randomDir = crypto.randomBytes(16).toString('hex');
    
    // ok: javascript-insecure-publicly-writable-directories
    const processingDir = path.join(os.tmpdir(), `processing-${randomDir}`);
    
    fs.mkdirSync(processingDir, { mode: 0o700 });
    
    files.forEach((file, index) => {
      fs.copyFileSync(file, path.join(processingDir, `file-${index}.dat`));
    });
    
    // Process files...
    
    // Clean up
    rimraf.sync(processingDir);
    return true;
  }
  
  return processFiles(['file1.txt', 'file2.txt']);
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
function good_case_11() {
  // Using a secure runtime directory with proper permissions
  const userId = process.getuid();
  const randomId = crypto.randomBytes(8).toString('hex');
  
  // ok: javascript-insecure-publicly-writable-directories
  const runtimeDir = path.join(os.tmpdir(), `app-runtime-${userId}-${randomId}`);
  
  if (!fs.existsSync(runtimeDir)) {
    fs.mkdirSync(runtimeDir, { recursive: true, mode: 0o700 });
  }
  
  const socketPath = path.join(runtimeDir, 'app.sock');
  // Create a socket or other IPC mechanism
  return socketPath;
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
function good_case_12() {
  // Using a secure path with username and random component
  const username = os.userInfo().username;
  const randomId = crypto.randomBytes(16).toString('hex');
  
  // ok: javascript-insecure-publicly-writable-directories
  const tempFile = path.join(os.tmpdir(), `${username}-${randomId}-app-data.json`);
  
  fs.writeFileSync(tempFile, JSON.stringify({ user: username }), { mode: 0o600 });
  return tempFile;
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
function good_case_13() {
  // Creating a secure directory for file uploads with proper permissions
  const app = express();
  
  app.post('/api/upload', (req, res) => {
    const sessionId = req.session.id; // Assuming session middleware
    const randomDir = crypto.randomBytes(16).toString('hex');
    
    // ok: javascript-insecure-publicly-writable-directories
    const uploadDir = path.join(os.tmpdir(), `user-uploads-${sessionId}-${randomDir}`);
    
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { mode: 0o700 });
    }
    
    // Handle file upload logic
    res.send('Upload endpoint ready');
  });
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
function good_case_14() {
  // Using a secure path for temporary database files
  function createTempDatabase() {
    const randomId = crypto.randomBytes(16).toString('hex');
    
    // ok: javascript-insecure-publicly-writable-directories
    const dbPath = path.join(os.tmpdir(), `app-temp-${randomId}.db`);
    
    fs.writeFileSync(dbPath, 'SQLite format 3\0', { mode: 0o600 });
    return dbPath;
  }
  
  return createTempDatabase();
}
// {/fact}

// {fact rule=insecure-temp-file@v1.0 defects=0}
function good_case_15() {
  // Using a secure path for extracting archives
  function extractArchive(archivePath) {
    const randomDir = crypto.randomBytes(16).toString('hex');
    
    // ok: javascript-insecure-publicly-writable-directories
    const extractDir = path.join(os.tmpdir(), `extracted-${randomDir}`);
    
    fs.mkdirSync(extractDir, { mode: 0o700 });
    
    // Extract archive to extractDir
    
    // Clean up when done
    return extractDir;
  }
  
  return extractArchive('archive.zip');
}
// {/fact}