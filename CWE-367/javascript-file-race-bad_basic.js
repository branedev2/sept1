const fs = require('fs');
const fsPromises = fs.promises;
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const app = express();

// True Positive Examples (Vulnerable Code)

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_1() {
  const filePath = '/tmp/user_data.json';
  
  // Check if file exists using filename
  if (fs.existsSync(filePath)) {
    // Time gap between check and use
    setTimeout(() => {
      // ruleid: javascript-file-race-bad
      fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
          console.error('Error reading file:', err);
          return;
        }
        const userData = JSON.parse(data);
        console.log('User data:', userData);
      });
    }, 100);
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_2() {
  const configPath = './config.json';
  
  // Check if file exists
  fs.stat(configPath, (err, stats) => {
    if (!err && stats.isFile()) {
      // Process something else first, creating a time gap
      processOtherData();
      
      // ruleid: javascript-file-race-bad
      fs.writeFile(configPath, JSON.stringify({ updated: true }), (err) => {
        if (err) console.error('Failed to write to file:', err);
      });
    }
  });
  
  function processOtherData() {
    // Some processing that takes time
    for (let i = 0; i < 1000000; i++) {
      Math.random();
    }
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  
  app.post('/save-profile', (req, res) => {
    const username = req.body.username;
    const profilePath = `/var/www/profiles/${username}.json`;
    
    // Check if profile exists
    if (!fs.existsSync(profilePath)) {
      // Create new profile
      const newProfile = {
        username: username,
        createdAt: new Date().toISOString()
      };
      
      // ruleid: javascript-file-race-bad
      fs.writeFileSync(profilePath, JSON.stringify(newProfile));
      res.send('Profile created');
    } else {
      res.status(400).send('Profile already exists');
    }
  });
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_4() {
  const logFilePath = './app.log';
  
  function appendLog(message) {
    // Check if log file exists and is not too large
    fs.stat(logFilePath, (err, stats) => {
      if (err) {
        // File doesn't exist, create it
        // ruleid: javascript-file-race-bad
        fs.writeFileSync(logFilePath, message + '\n');
      } else if (stats.size < 1024 * 1024) {
        // File exists and is small enough, append to it
        // ruleid: javascript-file-race-bad
        fs.appendFileSync(logFilePath, message + '\n');
      } else {
        // File is too large, rotate it
        const timestamp = Date.now();
        fs.renameSync(logFilePath, `${logFilePath}.${timestamp}`);
        // ruleid: javascript-file-race-bad
        fs.writeFileSync(logFilePath, message + '\n');
      }
    });
  }
  
  appendLog('Application started');
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_5() {
  const tempDir = '/tmp/app_temp';
  
  // Check if directory exists
  if (!fs.existsSync(tempDir)) {
    try {
      fs.mkdirSync(tempDir);
    } catch (err) {
      console.error('Failed to create directory:', err);
      return;
    }
  }
  
  // Time gap between check and use
  setTimeout(() => {
    const tempFile = path.join(tempDir, 'temp_' + Date.now() + '.txt');
    // ruleid: javascript-file-race-bad
    fs.writeFileSync(tempFile, 'Temporary data');
    console.log('Temporary file created:', tempFile);
  }, 200);
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_6() {
  app.get('/download/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join('/var/www/downloads', filename);
    
    // Check if file exists and is accessible
    fs.access(filePath, fs.constants.R_OK, (err) => {
      if (err) {
        res.status(404).send('File not found or not accessible');
        return;
      }
      
      // Process request, creating a time gap
      setTimeout(() => {
        // ruleid: javascript-file-race-bad
        fs.readFile(filePath, (err, data) => {
          if (err) {
            res.status(500).send('Error reading file');
            return;
          }
          res.send(data);
        });
      }, 100);
    });
  });
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_7() {
  const userDataFile = './user_preferences.json';
  
  function updateUserPreference(userId, preference) {
    // Check if file exists
    if (fs.existsSync(userDataFile)) {
      // Read current preferences
      const data = fs.readFileSync(userDataFile, 'utf8');
      const preferences = JSON.parse(data);
      
      // Update preference
      preferences[userId] = preference;
      
      // Write back to file - vulnerable to race condition
      // ruleid: javascript-file-race-bad
      fs.writeFileSync(userDataFile, JSON.stringify(preferences));
      return true;
    }
    return false;
  }
  
  updateUserPreference('user123', { theme: 'dark' });
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_8() {
  async function processUserData(userId) {
    const userFile = `/var/data/users/${userId}.json`;
    
    try {
      // Check if file exists
      await fsPromises.access(userFile, fs.constants.F_OK);
      
      // Time gap - other operations might happen here
      await new Promise(resolve => setTimeout(resolve, 100));
      
      // ruleid: javascript-file-race-bad
      const data = await fsPromises.readFile(userFile, 'utf8');
      const userData = JSON.parse(data);
      return userData;
    } catch (err) {
      console.error('Error processing user data:', err);
      return null;
    }
  }
  
  processUserData('user456');
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_9() {
  app.post('/upload', (req, res) => {
    const uploadPath = `/tmp/uploads/${req.body.filename}`;
    
    // Check if file already exists to avoid overwriting
    fs.stat(uploadPath, (err, stats) => {
      if (!err) {
        // File exists
        res.status(400).send('File already exists');
      } else {
        // File doesn't exist, proceed with upload
        // Time gap - file could be created by another request
        setTimeout(() => {
          // ruleid: javascript-file-race-bad
          fs.writeFile(uploadPath, req.body.data, (err) => {
            if (err) {
              res.status(500).send('Upload failed');
            } else {
              res.send('Upload successful');
            }
          });
        }, 50);
      }
    });
  });
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_10() {
  const cacheFile = './data_cache.json';
  
  function getCachedData() {
    // Check if cache exists and is fresh
    if (fs.existsSync(cacheFile)) {
      const stats = fs.statSync(cacheFile);
      const fileAge = Date.now() - stats.mtimeMs;
      
      if (fileAge < 3600000) { // Less than 1 hour old
        // ruleid: javascript-file-race-bad
        const data = fs.readFileSync(cacheFile, 'utf8');
        return JSON.parse(data);
      }
    }
    
    // Cache doesn't exist or is stale
    const newData = fetchFreshData();
    // ruleid: javascript-file-race-bad
    fs.writeFileSync(cacheFile, JSON.stringify(newData));
    return newData;
  }
  
  function fetchFreshData() {
    return { timestamp: Date.now(), data: "Fresh data" };
  }
  
  getCachedData();
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_11() {
  const lockFile = './process.lock';
  
  function acquireLock() {
    // Check if lock exists
    if (!fs.existsSync(lockFile)) {
      // Create lock file
      // ruleid: javascript-file-race-bad
      fs.writeFileSync(lockFile, process.pid.toString());
      return true;
    }
    return false;
  }
  
  function releaseLock() {
    if (fs.existsSync(lockFile)) {
      // ruleid: javascript-file-race-bad
      fs.unlinkSync(lockFile);
    }
  }
  
  if (acquireLock()) {
    console.log('Lock acquired');
    // Do some work
    releaseLock();
  } else {
    console.log('Could not acquire lock');
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_12() {
  app.get('/config', (req, res) => {
    const configFile = './app_config.json';
    
    // Check if config file exists
    fs.access(configFile, fs.constants.R_OK, (err) => {
      if (err) {
        res.status(500).send('Configuration not available');
        return;
      }
      
      // Process authentication
      authenticateRequest(req, (authenticated) => {
        if (!authenticated) {
          res.status(401).send('Unauthorized');
          return;
        }
        
        // ruleid: javascript-file-race-bad
        fs.readFile(configFile, 'utf8', (err, data) => {
          if (err) {
            res.status(500).send('Error reading configuration');
            return;
          }
          res.json(JSON.parse(data));
        });
      });
    });
    
    function authenticateRequest(req, callback) {
      // Simulate authentication delay
      setTimeout(() => callback(true), 100);
    }
  });
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_13() {
  const dataDir = './data';
  
  function ensureDirectoryExists() {
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir);
    }
  }
  
  function saveData(filename, data) {
    ensureDirectoryExists();
    
    // Time gap between directory check and file write
    setTimeout(() => {
      const filePath = path.join(dataDir, filename);
      // ruleid: javascript-file-race-bad
      fs.writeFileSync(filePath, data);
      console.log(`Data saved to ${filePath}`);
    }, 50);
  }
  
  saveData('important.txt', 'Critical information');
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_14() {
  function processConfigFile() {
    const configFile = '/etc/app/config.json';
    
    // Check if config file exists and read permissions
    try {
      fs.accessSync(configFile, fs.constants.R_OK);
      
      // Do some preprocessing
      const preprocessingTime = Date.now();
      while (Date.now() - preprocessingTime < 100) {
        // Simulate work
      }
      
      // ruleid: javascript-file-race-bad
      const configData = fs.readFileSync(configFile, 'utf8');
      return JSON.parse(configData);
    } catch (err) {
      console.error('Error accessing config file:', err);
      return null;
    }
  }
  
  const config = processConfigFile();
  console.log('Loaded configuration:', config);
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=1}
function bad_case_15() {
  app.post('/append-log', (req, res) => {
    const logFile = './application.log';
    const logEntry = `${new Date().toISOString()} - ${req.body.message}\n`;
    
    // Check if log file exists and is writable
    fs.access(logFile, fs.constants.W_OK, (err) => {
      if (err && err.code === 'ENOENT') {
        // File doesn't exist, create it
        fs.writeFile(logFile, logEntry, (err) => {
          if (err) {
            res.status(500).send('Failed to create log file');
          } else {
            res.send('Log entry created');
          }
        });
      } else if (err) {
        res.status(500).send('Cannot write to log file');
      } else {
        // File exists and is writable, append to it
        // Time gap between check and use
        setTimeout(() => {
          // ruleid: javascript-file-race-bad
          fs.appendFile(logFile, logEntry, (err) => {
            if (err) {
              res.status(500).send('Failed to append to log');
            } else {
              res.send('Log entry appended');
            }
          });
        }, 50);
      }
    });
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_1() {
  const filePath = '/tmp/user_data.json';
  
  // Open file first to get a file descriptor
  fs.open(filePath, 'r', (err, fd) => {
    if (err) {
      console.error('Error opening file:', err);
      return;
    }
    
    // Use the file descriptor for subsequent operations
    // ok: javascript-file-race-bad
    fs.readFile(fd, 'utf8', (err, data) => {
      if (err) {
        console.error('Error reading file:', err);
      } else {
        const userData = JSON.parse(data);
        console.log('User data:', userData);
      }
      
      // Close the file descriptor when done
      fs.close(fd, (err) => {
        if (err) console.error('Error closing file:', err);
      });
    });
  });
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_2() {
  const configPath = './config.json';
  
  // Open file with write access to get a file descriptor
  fs.open(configPath, 'w', (err, fd) => {
    if (err) {
      console.error('Error opening file for writing:', err);
      return;
    }
    
    // Process something else first
    processOtherData();
    
    // Use the file descriptor for writing
    const data = JSON.stringify({ updated: true });
    // ok: javascript-file-race-bad
    fs.write(fd, data, (err) => {
      if (err) {
        console.error('Failed to write to file:', err);
      }
      
      // Close the file descriptor when done
      fs.close(fd, (err) => {
        if (err) console.error('Error closing file:', err);
      });
    });
  });
  
  function processOtherData() {
    // Some processing that takes time
    for (let i = 0; i < 1000000; i++) {
      Math.random();
    }
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_3() {
  const app = express();
  
  app.post('/save-profile', (req, res) => {
    const username = req.body.username;
    const profilePath = `/var/www/profiles/${username}.json`;
    
    // Use open with O_EXCL flag to ensure atomic creation
    // ok: javascript-file-race-bad
    fs.open(profilePath, 'wx', (err, fd) => {
      if (err) {
        if (err.code === 'EEXIST') {
          res.status(400).send('Profile already exists');
        } else {
          console.error('Error creating profile:', err);
          res.status(500).send('Server error');
        }
        return;
      }
      
      // Create new profile
      const newProfile = {
        username: username,
        createdAt: new Date().toISOString()
      };
      
      const data = JSON.stringify(newProfile);
      fs.write(fd, data, (err) => {
        if (err) {
          console.error('Error writing profile:', err);
          res.status(500).send('Server error');
        } else {
          res.send('Profile created');
        }
        
        fs.close(fd, (err) => {
          if (err) console.error('Error closing file:', err);
        });
      });
    });
  });
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_4() {
  const logFilePath = './app.log';
  
  function appendLog(message) {
    // Open file with append flag to get a file descriptor
    // ok: javascript-file-race-bad
    fs.open(logFilePath, 'a', (err, fd) => {
      if (err) {
        console.error('Error opening log file:', err);
        return;
      }
      
      // Get file stats using the file descriptor
      fs.fstat(fd, (err, stats) => {
        if (err) {
          console.error('Error getting file stats:', err);
          fs.close(fd, () => {});
          return;
        }
        
        if (stats.size < 1024 * 1024) {
          // File is small enough, append to it
          fs.write(fd, message + '\n', (err) => {
            if (err) console.error('Error writing to log:', err);
            fs.close(fd, () => {});
          });
        } else {
          // File is too large, close it and rotate
          fs.close(fd, () => {
            const timestamp = Date.now();
            fs.rename(logFilePath, `${logFilePath}.${timestamp}`, (err) => {
              if (err) {
                console.error('Error rotating log file:', err);
                return;
              }
              
              // Create a new log file
              fs.writeFile(logFilePath, message + '\n', (err) => {
                if (err) console.error('Error creating new log file:', err);
              });
            });
          });
        }
      });
    });
  }
  
  appendLog('Application started');
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_5() {
  const tempDir = '/tmp/app_temp';
  
  // Create directory if it doesn't exist
  fs.mkdir(tempDir, { recursive: true }, (err) => {
    if (err) {
      console.error('Failed to create directory:', err);
      return;
    }
    
    const tempFile = path.join(tempDir, 'temp_' + Date.now() + '.txt');
    // ok: javascript-file-race-bad
    fs.open(tempFile, 'wx', (err, fd) => {
      if (err) {
        console.error('Error creating temporary file:', err);
        return;
      }
      
      fs.write(fd, 'Temporary data', (err) => {
        if (err) {
          console.error('Error writing to temporary file:', err);
        } else {
          console.log('Temporary file created:', tempFile);
        }
        
        fs.close(fd, (err) => {
          if (err) console.error('Error closing file:', err);
        });
      });
    });
  });
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_6() {
  app.get('/download/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join('/var/www/downloads', filename);
    
    // Open file directly to get a file descriptor
    // ok: javascript-file-race-bad
    fs.open(filePath, 'r', (err, fd) => {
      if (err) {
        if (err.code === 'ENOENT') {
          res.status(404).send('File not found');
        } else {
          console.error('Error opening file:', err);
          res.status(500).send('Server error');
        }
        return;
      }
      
      // Process request using the file descriptor
      fs.fstat(fd, (err, stats) => {
        if (err) {
          console.error('Error getting file stats:', err);
          fs.close(fd, () => {});
          res.status(500).send('Server error');
          return;
        }
        
        // Create a read stream from the file descriptor
        const stream = fs.createReadStream(null, { fd });
        
        // Set appropriate headers
        res.setHeader('Content-Length', stats.size);
        res.setHeader('Content-Type', 'application/octet-stream');
        
        // Pipe the file to the response
        stream.pipe(res);
        
        // Handle errors
        stream.on('error', (err) => {
          console.error('Error streaming file:', err);
          res.end();
        });
        
        // Close the file descriptor when done
        stream.on('end', () => {
          // The fd will be closed automatically by the stream
        });
      });
    });
  });
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_7() {
  const userDataFile = './user_preferences.json';
  
  function updateUserPreference(userId, preference) {
    // ok: javascript-file-race-bad
    fs.open(userDataFile, 'r+', (err, fd) => {
      if (err) {
        if (err.code === 'ENOENT') {
          // File doesn't exist, create it with initial data
          const initialData = {};
          initialData[userId] = preference;
          fs.writeFile(userDataFile, JSON.stringify(initialData), (err) => {
            if (err) console.error('Error creating preferences file:', err);
          });
        } else {
          console.error('Error opening preferences file:', err);
        }
        return;
      }
      
      // Read current preferences using the file descriptor
      fs.readFile(fd, 'utf8', (err, data) => {
        if (err) {
          console.error('Error reading preferences:', err);
          fs.close(fd, () => {});
          return;
        }
        
        try {
          const preferences = JSON.parse(data);
          
          // Update preference
          preferences[userId] = preference;
          
          // Write back to file using the same file descriptor
          const updatedData = JSON.stringify(preferences);
          
          // Truncate the file first
          fs.ftruncate(fd, 0, (err) => {
            if (err) {
              console.error('Error truncating file:', err);
              fs.close(fd, () => {});
              return;
            }
            
            // Write the updated data
            fs.write(fd, updatedData, 0, 'utf8', (err) => {
              if (err) {
                console.error('Error writing preferences:', err);
              }
              
              // Close the file descriptor
              fs.close(fd, (err) => {
                if (err) console.error('Error closing file:', err);
              });
            });
          });
        } catch (err) {
          console.error('Error parsing preferences:', err);
          fs.close(fd, () => {});
        }
      });
    });
  }
  
  updateUserPreference('user123', { theme: 'dark' });
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_8() {
  async function processUserData(userId) {
    const userFile = `/var/data/users/${userId}.json`;
    
    try {
      // Open file to get a file descriptor
      // ok: javascript-file-race-bad
      const fd = await fsPromises.open(userFile, 'r');
      
      try {
        // Read data using the file descriptor
        const data = await fd.readFile('utf8');
        const userData = JSON.parse(data);
        return userData;
      } finally {
        // Always close the file descriptor
        await fd.close();
      }
    } catch (err) {
      console.error('Error processing user data:', err);
      return null;
    }
  }
  
  processUserData('user456');
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_9() {
  app.post('/upload', (req, res) => {
    const uploadPath = `/tmp/uploads/${req.body.filename}`;
    
    // Use O_EXCL flag to ensure atomic file creation
    // ok: javascript-file-race-bad
    fs.open(uploadPath, 'wx', (err, fd) => {
      if (err) {
        if (err.code === 'EEXIST') {
          res.status(400).send('File already exists');
        } else {
          console.error('Error creating file:', err);
          res.status(500).send('Upload failed');
        }
        return;
      }
      
      // Write data using the file descriptor
      fs.write(fd, req.body.data, (err) => {
        if (err) {
          console.error('Error writing file:', err);
          res.status(500).send('Upload failed');
        } else {
          res.send('Upload successful');
        }
        
        // Close the file descriptor
        fs.close(fd, (err) => {
          if (err) console.error('Error closing file:', err);
        });
      });
    });
  });
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_10() {
  const cacheFile = './data_cache.json';
  
  function getCachedData() {
    try {
      // ok: javascript-file-race-bad
      const fd = fs.openSync(cacheFile, 'r');
      
      try {
        // Get file stats using the file descriptor
        const stats = fs.fstatSync(fd);
        const fileAge = Date.now() - stats.mtimeMs;
        
        if (fileAge < 3600000) { // Less than 1 hour old
          // Read data using the file descriptor
          const data = fs.readFileSync(fd, { encoding: 'utf8' });
          return JSON.parse(data);
        } else {
          // Cache is stale, fetch fresh data
          const newData = fetchFreshData();
          
          // Close the current file descriptor
          fs.closeSync(fd);
          
          // Write fresh data to cache file
          fs.writeFileSync(cacheFile, JSON.stringify(newData));
          return newData;
        }
      } finally {
        // Close the file descriptor if it's still open
        try {
          fs.closeSync(fd);
        } catch (e) {
          // Ignore if already closed
        }
      }
    } catch (err) {
      if (err.code === 'ENOENT') {
        // Cache doesn't exist, fetch fresh data
        const newData = fetchFreshData();
        fs.writeFileSync(cacheFile, JSON.stringify(newData));
        return newData;
      } else {
        console.error('Error accessing cache:', err);
        return fetchFreshData(); // Fallback to fresh data
      }
    }
  }
  
  function fetchFreshData() {
    return { timestamp: Date.now(), data: "Fresh data" };
  }
  
  getCachedData();
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_11() {
  const lockFile = './process.lock';
  
  function acquireLock() {
    try {
      // Try to create the lock file with O_EXCL flag for atomic creation
      // ok: javascript-file-race-bad
      const fd = fs.openSync(lockFile, 'wx');
      
      // Write process ID to lock file
      fs.writeSync(fd, process.pid.toString());
      fs.closeSync(fd);
      
      return true;
    } catch (err) {
      if (err.code === 'EEXIST') {
        // Lock file already exists
        return false;
      }
      
      console.error('Error acquiring lock:', err);
      return false;
    }
  }
  
  function releaseLock() {
    try {
      fs.unlinkSync(lockFile);
    } catch (err) {
      console.error('Error releasing lock:', err);
    }
  }
  
  if (acquireLock()) {
    console.log('Lock acquired');
    // Do some work
    releaseLock();
  } else {
    console.log('Could not acquire lock');
  }
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_12() {
  app.get('/config', (req, res) => {
    // Authenticate request first
    authenticateRequest(req, (authenticated) => {
      if (!authenticated) {
        res.status(401).send('Unauthorized');
        return;
      }
      
      const configFile = './app_config.json';
      
      // Open file to get a file descriptor
      // ok: javascript-file-race-bad
      fs.open(configFile, 'r', (err, fd) => {
        if (err) {
          if (err.code === 'ENOENT') {
            res.status(404).send('Configuration not found');
          } else {
            console.error('Error opening configuration:', err);
            res.status(500).send('Server error');
          }
          return;
        }
        
        // Read configuration using the file descriptor
        fs.readFile(fd, 'utf8', (err, data) => {
          if (err) {
            console.error('Error reading configuration:', err);
            res.status(500).send('Error reading configuration');
          } else {
            try {
              const config = JSON.parse(data);
              res.json(config);
            } catch (err) {
              console.error('Error parsing configuration:', err);
              res.status(500).send('Invalid configuration format');
            }
          }
          
          // Close the file descriptor
          fs.close(fd, (err) => {
            if (err) console.error('Error closing file:', err);
          });
        });
      });
    });
    
    function authenticateRequest(req, callback) {
      // Simulate authentication
      setTimeout(() => callback(true), 100);
    }
  });
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_13() {
  const dataDir = './data';
  
  function saveData(filename, data) {
    // Ensure directory exists
    try {
      fs.mkdirSync(dataDir, { recursive: true });
    } catch (err) {
      if (err.code !== 'EEXIST') {
        console.error('Error creating directory:', err);
        return false;
      }
    }
    
    const filePath = path.join(dataDir, filename);
    
    try {
      // Use O_EXCL flag for atomic file creation or O_TRUNC to overwrite
      // ok: javascript-file-race-bad
      const fd = fs.openSync(filePath, 'w');
      
      try {
        fs.writeSync(fd, data);
        console.log(`Data saved to ${filePath}`);
        return true;
      } finally {
        fs.closeSync(fd);
      }
    } catch (err) {
      console.error(`Error saving data to ${filePath}:`, err);
      return false;
    }
  }
  
  saveData('important.txt', 'Critical information');
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_14() {
  function processConfigFile() {
    const configFile = '/etc/app/config.json';
    
    try {
      // Open file to get a file descriptor
      // ok: javascript-file-race-bad
      const fd = fs.openSync(configFile, 'r');
      
      try {
        // Do some preprocessing
        const preprocessingTime = Date.now();
        while (Date.now() - preprocessingTime < 100) {
          // Simulate work
        }
        
        // Read config using the file descriptor
        const configData = fs.readFileSync(fd, 'utf8');
        return JSON.parse(configData);
      } finally {
        // Always close the file descriptor
        fs.closeSync(fd);
      }
    } catch (err) {
      console.error('Error processing config file:', err);
      return null;
    }
  }
  
  const config = processConfigFile();
  console.log('Loaded configuration:', config);
}
// {/fact}

// {fact rule=file-race-bad@v1.0 defects=0}
function good_case_15() {
  app.post('/append-log', (req, res) => {
    const logFile = './application.log';
    const logEntry = `${new Date().toISOString()} - ${req.body.message}\n`;
    
    // Open file with append flag to get a file descriptor
    // ok: javascript-file-race-bad
    fs.open(logFile, 'a', (err, fd) => {
      if (err) {
        console.error('Error opening log file:', err);
        res.status(500).send('Failed to open log file');
        return;
      }
      
      // Write log entry using the file descriptor
      fs.write(fd, logEntry, (err) => {
        if (err) {
          console.error('Error writing to log:', err);
          res.status(500).send('Failed to write log entry');
        } else {
          res.send('Log entry appended');
        }
        
        // Close the file descriptor
        fs.close(fd, (err) => {
          if (err) console.error('Error closing file:', err);
        });
      });
    });
  });
}
// {/fact}