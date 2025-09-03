import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';

// True Positive Examples (Vulnerable Code)

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_1() {
  const filePath = '/tmp/example.txt';
  
  // Check if file exists using filename
  if (fs.existsSync(filePath)) {
    // ruleid: typescript-file-race-bad
    // Time gap between check and use (race condition possible)
    const data = fs.readFileSync(filePath, 'utf8');
    console.log(data);
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_2() {
  const configPath = './config.json';
  
  try {
    // Check file stats using filename
    const stats = fs.statSync(configPath);
    
    if (stats.isFile() && stats.size < 10000) {
      // ruleid: typescript-file-race-bad
      // Time gap between check and use
      const configData = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      updateConfiguration(configData);
    }
  } catch (error) {
    console.error('Error accessing config:', error);
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_3() {
  const logFile = '/var/log/app.log';
  
  // Check if file is writable using filename
  fs.access(logFile, fs.constants.W_OK, (err) => {
    if (!err) {
      // Time gap between check and use
      setTimeout(() => {
        // ruleid: typescript-file-race-bad
        fs.appendFileSync(logFile, 'Log entry\n');
      }, 100);
    }
  });
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_4() {
  const userDataFile = './user_data.json';
  
  // Check if file exists and then write to it
  fs.stat(userDataFile, (err, stats) => {
    if (err || !stats.isFile()) {
      // Create new file
      const defaultData = { users: [] };
      // ruleid: typescript-file-race-bad
      fs.writeFileSync(userDataFile, JSON.stringify(defaultData));
    } else {
      // Modify existing file
      // ruleid: typescript-file-race-bad
      const userData = JSON.parse(fs.readFileSync(userDataFile, 'utf8'));
      userData.users.push({ id: 123, name: 'New User' });
      fs.writeFileSync(userDataFile, JSON.stringify(userData));
    }
  });
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
async function bad_case_5() {
  const dataFile = '/shared/data.txt';
  const fsPromises = fs.promises;
  
  try {
    // Check file existence using promises
    await fsPromises.access(dataFile, fs.constants.R_OK);
    // Time gap between check and use
    // ruleid: typescript-file-race-bad
    const content = await fsPromises.readFile(dataFile, 'utf8');
    processData(content);
  } catch (error) {
    console.error('Cannot access file:', error);
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_6() {
  const tempFile = '/tmp/temp_data.json';
  
  if (!fs.existsSync(path.dirname(tempFile))) {
    fs.mkdirSync(path.dirname(tempFile), { recursive: true });
  }
  
  // Check if file exists before writing
  if (!fs.existsSync(tempFile)) {
    const initialData = { timestamp: Date.now(), values: [] };
    // ruleid: typescript-file-race-bad
    fs.writeFileSync(tempFile, JSON.stringify(initialData));
  } else {
    // ruleid: typescript-file-race-bad
    const data = JSON.parse(fs.readFileSync(tempFile, 'utf8'));
    data.values.push(Math.random());
    fs.writeFileSync(tempFile, JSON.stringify(data));
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_7() {
  const lockFile = './process.lock';
  
  // Try to create lock file if it doesn't exist
  if (!fs.existsSync(lockFile)) {
    // ruleid: typescript-file-race-bad
    fs.writeFileSync(lockFile, process.pid.toString());
    runCriticalProcess();
    fs.unlinkSync(lockFile);
  } else {
    console.log('Process already running');
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_8() {
  const cacheFile = './cache.json';
  
  try {
    // Check if cache file exists and is recent
    if (fs.existsSync(cacheFile)) {
      const stats = fs.statSync(cacheFile);
      const fileAge = Date.now() - stats.mtimeMs;
      
      if (fileAge < 3600000) { // 1 hour
        // ruleid: typescript-file-race-bad
        const cacheData = JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
        return cacheData;
      }
    }
    
    // Generate new cache
    const newData = generateData();
    // ruleid: typescript-file-race-bad
    fs.writeFileSync(cacheFile, JSON.stringify(newData));
    return newData;
  } catch (error) {
    console.error('Cache error:', error);
    return generateData();
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_9() {
  const filesToProcess = fs.readdirSync('./uploads');
  
  for (const file of filesToProcess) {
    const filePath = `./uploads/${file}`;
    
    // Check if it's a valid file
    if (fs.statSync(filePath).isFile() && path.extname(filePath) === '.csv') {
      // ruleid: typescript-file-race-bad
      const content = fs.readFileSync(filePath, 'utf8');
      processCSV(content);
      fs.unlinkSync(filePath);
    }
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_10() {
  const configFile = './app_config.json';
  
  // Check if config exists, create with defaults if not
  if (!fs.existsSync(configFile)) {
    const defaultConfig = {
      port: 3000,
      logLevel: 'info',
      maxConnections: 100
    };
    // ruleid: typescript-file-race-bad
    fs.writeFileSync(configFile, JSON.stringify(defaultConfig, null, 2));
    return defaultConfig;
  }
  
  // Read existing config
  try {
    // ruleid: typescript-file-race-bad
    const config = JSON.parse(fs.readFileSync(configFile, 'utf8'));
    return config;
  } catch (error) {
    console.error('Error reading config:', error);
    return null;
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_11() {
  const userFile = './user.json';
  
  // Check if user file exists and has correct permissions
  try {
    const stats = fs.statSync(userFile);
    
    if (stats.mode & 0o777 !== 0o600) {
      console.error('User file has incorrect permissions');
      return;
    }
    
    // ruleid: typescript-file-race-bad
    const userData = JSON.parse(fs.readFileSync(userFile, 'utf8'));
    processUserData(userData);
  } catch (error) {
    console.error('Error processing user file:', error);
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_12() {
  const dataDir = './data';
  const outputFile = './data/output.txt';
  
  // Ensure directory exists
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir);
  }
  
  // Check if output file exists
  if (fs.existsSync(outputFile)) {
    // ruleid: typescript-file-race-bad
    fs.unlinkSync(outputFile); // Delete existing file
  }
  
  // Create new file
  // ruleid: typescript-file-race-bad
  fs.writeFileSync(outputFile, 'New data');
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_13() {
  const tempDir = './temp';
  
  // Create temp directory if it doesn't exist
  if (!fs.existsSync(tempDir)) {
    fs.mkdirSync(tempDir);
  }
  
  // Create a unique temporary file
  const tempFile = `${tempDir}/temp_${Date.now()}.txt`;
  
  // Check if file already exists (unlikely but possible)
  if (fs.existsSync(tempFile)) {
    // ruleid: typescript-file-race-bad
    fs.unlinkSync(tempFile);
  }
  
  // Write data to temp file
  // ruleid: typescript-file-race-bad
  fs.writeFileSync(tempFile, 'Temporary data');
  
  // Process the file
  // ruleid: typescript-file-race-bad
  const data = fs.readFileSync(tempFile, 'utf8');
  processData(data);
  
  // Clean up
  // ruleid: typescript-file-race-bad
  fs.unlinkSync(tempFile);
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_14() {
  const logDir = './logs';
  const todayLog = `${logDir}/${new Date().toISOString().split('T')[0]}.log`;
  
  // Ensure log directory exists
  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir);
  }
  
  // Check if today's log exists
  if (!fs.existsSync(todayLog)) {
    // ruleid: typescript-file-race-bad
    fs.writeFileSync(todayLog, '# Log file created\n');
  }
  
  // Append to log
  // ruleid: typescript-file-race-bad
  fs.appendFileSync(todayLog, `[${new Date().toISOString()}] Log entry\n`);
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_15() {
  const backupFile = './backup.tar.gz';
  
  // Check if backup file exists and is older than 7 days
  if (fs.existsSync(backupFile)) {
    const stats = fs.statSync(backupFile);
    const fileAge = Date.now() - stats.mtimeMs;
    const sevenDays = 7 * 24 * 60 * 60 * 1000;
    
    if (fileAge > sevenDays) {
      // ruleid: typescript-file-race-bad
      fs.unlinkSync(backupFile);
      createBackup(backupFile);
    }
  } else {
    createBackup(backupFile);
  }
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_1() {
  const filePath = '/tmp/example.txt';
  
  try {
    // ok: typescript-file-race-bad
    // Open file first, then perform operations on the file descriptor
    const fd = fs.openSync(filePath, 'r');
    try {
      const buffer = Buffer.alloc(1024);
      fs.readSync(fd, buffer, 0, buffer.length, 0);
      console.log(buffer.toString('utf8'));
    } finally {
      fs.closeSync(fd);
    }
  } catch (error) {
    console.error('Error reading file:', error);
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_2() {
  const configPath = './config.json';
  
  try {
    // ok: typescript-file-race-bad
    // Open file descriptor first, then check stats and read
    const fd = fs.openSync(configPath, 'r');
    try {
      const stats = fs.fstatSync(fd);
      
      if (stats.isFile() && stats.size < 10000) {
        const buffer = Buffer.alloc(stats.size);
        fs.readSync(fd, buffer, 0, stats.size, 0);
        const configData = JSON.parse(buffer.toString('utf8'));
        updateConfiguration(configData);
      }
    } finally {
      fs.closeSync(fd);
    }
  } catch (error) {
    console.error('Error accessing config:', error);
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_3() {
  const logFile = '/var/log/app.log';
  
  try {
    // ok: typescript-file-race-bad
    // Open file for appending, which will fail if not writable
    const fd = fs.openSync(logFile, 'a');
    setTimeout(() => {
      try {
        fs.writeSync(fd, 'Log entry\n');
      } finally {
        fs.closeSync(fd);
      }
    }, 100);
  } catch (error) {
    console.error('Cannot write to log file:', error);
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_4() {
  const userDataFile = './user_data.json';
  
  try {
    // ok: typescript-file-race-bad
    // Try to open for reading and writing, create if doesn't exist
    const fd = fs.openSync(userDataFile, 'r+');
    try {
      // Read existing data
      const stats = fs.fstatSync(fd);
      const buffer = Buffer.alloc(stats.size);
      fs.readSync(fd, buffer, 0, stats.size, 0);
      const userData = JSON.parse(buffer.toString('utf8'));
      
      // Modify data
      userData.users.push({ id: 123, name: 'New User' });
      
      // Write back to same file descriptor
      const newData = Buffer.from(JSON.stringify(userData));
      fs.ftruncateSync(fd, 0);
      fs.writeSync(fd, newData, 0, newData.length, 0);
    } finally {
      fs.closeSync(fd);
    }
  } catch (error) {
    if (error.code === 'ENOENT') {
      // File doesn't exist, create it
      const fd = fs.openSync(userDataFile, 'w');
      try {
        const defaultData = { users: [] };
        const buffer = Buffer.from(JSON.stringify(defaultData));
        fs.writeSync(fd, buffer, 0, buffer.length, 0);
      } finally {
        fs.closeSync(fd);
      }
    } else {
      console.error('Error handling user data:', error);
    }
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
async function good_case_5() {
  const dataFile = '/shared/data.txt';
  const fsPromises = fs.promises;
  
  try {
    // ok: typescript-file-race-bad
    // Open file handle first, then perform operations
    const fileHandle = await fsPromises.open(dataFile, 'r');
    try {
      const content = await fileHandle.readFile('utf8');
      processData(content);
    } finally {
      await fileHandle.close();
    }
  } catch (error) {
    console.error('Cannot access file:', error);
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_6() {
  const tempFile = '/tmp/temp_data.json';
  
  if (!fs.existsSync(path.dirname(tempFile))) {
    fs.mkdirSync(path.dirname(tempFile), { recursive: true });
  }
  
  try {
    // ok: typescript-file-race-bad
    // Open with wx flag to ensure atomic creation or fail if exists
    const fd = fs.openSync(tempFile, 'wx');
    try {
      const initialData = { timestamp: Date.now(), values: [] };
      const buffer = Buffer.from(JSON.stringify(initialData));
      fs.writeSync(fd, buffer, 0, buffer.length, 0);
    } finally {
      fs.closeSync(fd);
    }
  } catch (error) {
    if (error.code === 'EEXIST') {
      // File exists, open for reading and writing
      const fd = fs.openSync(tempFile, 'r+');
      try {
        const stats = fs.fstatSync(fd);
        const buffer = Buffer.alloc(stats.size);
        fs.readSync(fd, buffer, 0, stats.size, 0);
        const data = JSON.parse(buffer.toString('utf8'));
        
        // Update data
        data.values.push(Math.random());
        
        // Write back
        const newBuffer = Buffer.from(JSON.stringify(data));
        fs.ftruncateSync(fd, 0);
        fs.writeSync(fd, newBuffer, 0, newBuffer.length, 0);
      } finally {
        fs.closeSync(fd);
      }
    } else {
      console.error('Error handling temp file:', error);
    }
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_7() {
  const lockFile = './process.lock';
  
  try {
    // ok: typescript-file-race-bad
    // Use 'wx' flag for atomic creation - will fail if file exists
    const fd = fs.openSync(lockFile, 'wx');
    try {
      fs.writeSync(fd, process.pid.toString());
      runCriticalProcess();
    } finally {
      fs.closeSync(fd);
      fs.unlinkSync(lockFile);
    }
  } catch (error) {
    if (error.code === 'EEXIST') {
      console.log('Process already running');
    } else {
      console.error('Lock file error:', error);
    }
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_8() {
  const cacheFile = './cache.json';
  
  try {
    // ok: typescript-file-race-bad
    // Try to open existing cache file
    const fd = fs.openSync(cacheFile, 'r');
    try {
      const stats = fs.fstatSync(fd);
      const fileAge = Date.now() - stats.mtimeMs;
      
      if (fileAge < 3600000) { // 1 hour
        const buffer = Buffer.alloc(stats.size);
        fs.readSync(fd, buffer, 0, stats.size, 0);
        const cacheData = JSON.parse(buffer.toString('utf8'));
        fs.closeSync(fd);
        return cacheData;
      }
      fs.closeSync(fd);
    } catch (error) {
      fs.closeSync(fd);
      throw error;
    }
    
    // Cache expired, generate new data and write
    const newData = generateData();
    const writefd = fs.openSync(cacheFile, 'w');
    try {
      const buffer = Buffer.from(JSON.stringify(newData));
      fs.writeSync(writefd, buffer, 0, buffer.length, 0);
    } finally {
      fs.closeSync(writefd);
    }
    return newData;
  } catch (error) {
    if (error.code === 'ENOENT') {
      // Cache doesn't exist, create new one
      const newData = generateData();
      const fd = fs.openSync(cacheFile, 'w');
      try {
        const buffer = Buffer.from(JSON.stringify(newData));
        fs.writeSync(fd, buffer, 0, buffer.length, 0);
      } finally {
        fs.closeSync(fd);
      }
      return newData;
    } else {
      console.error('Cache error:', error);
      return generateData();
    }
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_9() {
  const uploadsDir = './uploads';
  const filesToProcess = fs.readdirSync(uploadsDir);
  
  for (const file of filesToProcess) {
    const filePath = path.join(uploadsDir, file);
    
    try {
      // ok: typescript-file-race-bad
      // Open file first to ensure we have a handle to it
      const fd = fs.openSync(filePath, 'r');
      try {
        const stats = fs.fstatSync(fd);
        
        if (stats.isFile() && path.extname(file) === '.csv') {
          const buffer = Buffer.alloc(stats.size);
          fs.readSync(fd, buffer, 0, stats.size, 0);
          const content = buffer.toString('utf8');
          processCSV(content);
          fs.closeSync(fd);
          fs.unlinkSync(filePath);
        } else {
          fs.closeSync(fd);
        }
      } catch (error) {
        fs.closeSync(fd);
        console.error(`Error processing ${file}:`, error);
      }
    } catch (error) {
      console.error(`Cannot open ${file}:`, error);
    }
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_10() {
  const configFile = './app_config.json';
  
  try {
    // ok: typescript-file-race-bad
    // Try to open existing config file
    const fd = fs.openSync(configFile, 'r');
    try {
      const stats = fs.fstatSync(fd);
      const buffer = Buffer.alloc(stats.size);
      fs.readSync(fd, buffer, 0, stats.size, 0);
      const config = JSON.parse(buffer.toString('utf8'));
      fs.closeSync(fd);
      return config;
    } catch (error) {
      fs.closeSync(fd);
      throw error;
    }
  } catch (error) {
    if (error.code === 'ENOENT') {
      // Config doesn't exist, create with defaults
      const defaultConfig = {
        port: 3000,
        logLevel: 'info',
        maxConnections: 100
      };
      
      const fd = fs.openSync(configFile, 'w');
      try {
        const buffer = Buffer.from(JSON.stringify(defaultConfig, null, 2));
        fs.writeSync(fd, buffer, 0, buffer.length, 0);
      } finally {
        fs.closeSync(fd);
      }
      return defaultConfig;
    } else {
      console.error('Error reading config:', error);
      return null;
    }
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_11() {
  const userFile = './user.json';
  
  try {
    // ok: typescript-file-race-bad
    // Open file first to get a file descriptor
    const fd = fs.openSync(userFile, 'r');
    try {
      const stats = fs.fstatSync(fd);
      
      if (stats.mode & 0o777 !== 0o600) {
        console.error('User file has incorrect permissions');
        fs.closeSync(fd);
        return;
      }
      
      const buffer = Buffer.alloc(stats.size);
      fs.readSync(fd, buffer, 0, stats.size, 0);
      const userData = JSON.parse(buffer.toString('utf8'));
      processUserData(userData);
    } finally {
      fs.closeSync(fd);
    }
  } catch (error) {
    console.error('Error processing user file:', error);
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_12() {
  const dataDir = './data';
  const outputFile = './data/output.txt';
  
  // Ensure directory exists
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir);
  }
  
  // ok: typescript-file-race-bad
  // Open with 'w' flag which truncates existing file or creates new one
  const fd = fs.openSync(outputFile, 'w');
  try {
    fs.writeSync(fd, 'New data');
  } finally {
    fs.closeSync(fd);
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_13() {
  const tempDir = './temp';
  
  // Create temp directory if it doesn't exist
  if (!fs.existsSync(tempDir)) {
    fs.mkdirSync(tempDir);
  }
  
  // Create a unique temporary file
  const tempFile = `${tempDir}/temp_${Date.now()}.txt`;
  
  try {
    // ok: typescript-file-race-bad
    // Use 'wx' flag to ensure atomic creation
    const fd = fs.openSync(tempFile, 'wx');
    try {
      // Write data to temp file
      fs.writeSync(fd, 'Temporary data');
      
      // Need to close and reopen to read (or use different approach)
      fs.closeSync(fd);
      
      // Reopen for reading
      const readFd = fs.openSync(tempFile, 'r');
      try {
        const stats = fs.fstatSync(readFd);
        const buffer = Buffer.alloc(stats.size);
        fs.readSync(readFd, buffer, 0, stats.size, 0);
        processData(buffer.toString('utf8'));
      } finally {
        fs.closeSync(readFd);
      }
    } finally {
      // Clean up
      fs.unlinkSync(tempFile);
    }
  } catch (error) {
    console.error('Error with temporary file:', error);
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_14() {
  const logDir = './logs';
  const todayLog = `${logDir}/${new Date().toISOString().split('T')[0]}.log`;
  
  // Ensure log directory exists
  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir);
  }
  
  // ok: typescript-file-race-bad
  // Open file for appending, creating it if it doesn't exist
  const fd = fs.openSync(todayLog, 'a');
  try {
    // If file was just created, write header
    const stats = fs.fstatSync(fd);
    if (stats.size === 0) {
      fs.writeSync(fd, '# Log file created\n');
    }
    
    // Append log entry
    fs.writeSync(fd, `[${new Date().toISOString()}] Log entry\n`);
  } finally {
    fs.closeSync(fd);
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_15() {
  const backupFile = './backup.tar.gz';
  
  try {
    // ok: typescript-file-race-bad
    // Try to open the file to check if it exists
    const fd = fs.openSync(backupFile, 'r');
    try {
      const stats = fs.fstatSync(fd);
      const fileAge = Date.now() - stats.mtimeMs;
      const sevenDays = 7 * 24 * 60 * 60 * 1000;
      
      if (fileAge > sevenDays) {
        fs.closeSync(fd);
        fs.unlinkSync(backupFile);
        createBackup(backupFile);
      } else {
        fs.closeSync(fd);
      }
    } catch (error) {
      fs.closeSync(fd);
      throw error;
    }
  } catch (error) {
    if (error.code === 'ENOENT') {
      // File doesn't exist
      createBackup(backupFile);
    } else {
      console.error('Error checking backup file:', error);
    }
  }
}
// {/fact}

// Helper functions to make the examples work
function updateConfiguration(config: any) {
  console.log('Updating configuration:', config);
}

function processData(data: string) {
  console.log('Processing data:', data.substring(0, 20) + '...');
}

function processCSV(content: string) {
  console.log('Processing CSV:', content.substring(0, 20) + '...');
}

function processUserData(userData: any) {
  console.log('Processing user data:', userData);
}

function generateData() {
  return { generated: true, timestamp: Date.now() };
}

function createBackup(backupFile: string) {
  console.log(`Creating backup at ${backupFile}`);
  fs.writeFileSync(backupFile, 'Backup data');
}

function runCriticalProcess() {
  console.log('Running critical process');
}