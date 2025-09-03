const fs = require('fs');
const path = require('path');
const AdmZip = require('adm-zip');
const extract = require('extract-zip');
const unzipper = require('unzipper');
const yauzl = require('yauzl');
const JSZip = require('jszip');
const StreamZip = require('node-stream-zip');
const decompress = require('decompress');
const tar = require('tar');
const http = require('http');

// BAD EXAMPLES - Vulnerable to Zip Slip

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_1() {
  const zip = new AdmZip("./user_uploads/archive.zip");
  const entries = zip.getEntries();
  
  entries.forEach(entry => {
    const filePath = path.join('./extracted', entry.entryName);
    // ruleid: javascript-zip-slip
    fs.writeFileSync(filePath, entry.getData());
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_2() {
  extract("./user_uploads/archive.zip", { dir: process.cwd() + '/extracted' }, function (err) {
    if (err) {
      console.error('Extraction failed:', err);
    } else {
      console.log('Extraction complete');
      // The vulnerability is in the extract library usage without path validation
      // ruleid: javascript-zip-slip
    }
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_3() {
  fs.createReadStream('./user_uploads/archive.zip')
    .pipe(unzipper.Parse())
    .on('entry', entry => {
      const fileName = entry.path;
      const type = entry.type;
      const outputPath = path.join('./extracted', fileName);
      
      if (type === 'File') {
        // ruleid: javascript-zip-slip
        entry.pipe(fs.createWriteStream(outputPath));
      } else {
        entry.autodrain();
      }
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_4() {
  yauzl.open('./user_uploads/archive.zip', { lazyEntries: true }, (err, zipfile) => {
    if (err) throw err;
    
    zipfile.on('entry', entry => {
      if (/\/$/.test(entry.fileName)) {
        // Directory entry, skip
        zipfile.readEntry();
      } else {
        zipfile.openReadStream(entry, (err, readStream) => {
          if (err) throw err;
          
          const outputPath = path.join('./extracted', entry.fileName);
          // ruleid: javascript-zip-slip
          readStream.pipe(fs.createWriteStream(outputPath));
          
          readStream.on('end', () => {
            zipfile.readEntry();
          });
        });
      }
    });
    
    zipfile.readEntry();
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_5() {
  const zip = new JSZip();
  
  fs.readFile('./user_uploads/archive.zip', (err, data) => {
    if (err) throw err;
    
    zip.loadAsync(data).then(contents => {
      Object.keys(contents.files).forEach(fileName => {
        const file = contents.files[fileName];
        
        if (!file.dir) {
          const outputPath = path.join('./extracted', fileName);
          file.async('nodebuffer').then(content => {
            // ruleid: javascript-zip-slip
            fs.writeFile(outputPath, content, err => {
              if (err) console.error(`Error extracting ${fileName}:`, err);
            });
          });
        }
      });
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_6() {
  const zip = new StreamZip({
    file: './user_uploads/archive.zip',
    storeEntries: true
  });
  
  zip.on('ready', () => {
    fs.mkdirSync('./extracted', { recursive: true });
    
    for (const entry of Object.values(zip.entries())) {
      if (entry.isDirectory) continue;
      
      const outputPath = path.join('./extracted', entry.name);
      // ruleid: javascript-zip-slip
      zip.extract(entry.name, outputPath, err => {
        if (err) console.error(`Error extracting ${entry.name}:`, err);
      });
    }
    
    zip.close();
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_7() {
  decompress('./user_uploads/archive.zip', './extracted')
    .then(files => {
      // The vulnerability is in the decompress library usage without path validation
      // ruleid: javascript-zip-slip
      console.log('Files decompressed:', files.length);
    })
    .catch(err => {
      console.error('Decompression failed:', err);
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_8() {
  const server = http.createServer((req, res) => {
    if (req.url === '/upload' && req.method === 'POST') {
      let data = [];
      req.on('data', chunk => {
        data.push(chunk);
      });
      
      req.on('end', () => {
        const buffer = Buffer.concat(data);
        fs.writeFileSync('./uploads/archive.zip', buffer);
        
        const zip = new AdmZip('./uploads/archive.zip');
        const entries = zip.getEntries();
        
        entries.forEach(entry => {
          const outputPath = path.join('./extracted', entry.entryName);
          // ruleid: javascript-zip-slip
          fs.writeFileSync(outputPath, entry.getData());
        });
        
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('File extracted successfully');
      });
    }
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_9() {
  function processZipFile(zipFilePath) {
    const zip = new AdmZip(zipFilePath);
    const extractPath = './extracted';
    
    if (!fs.existsSync(extractPath)) {
      fs.mkdirSync(extractPath, { recursive: true });
    }
    
    for (const entry of zip.getEntries()) {
      if (entry.isDirectory) continue;
      
      const entryPath = entry.entryName;
      const outputPath = path.join(extractPath, entryPath);
      
      // Create directory if it doesn't exist
      const dirname = path.dirname(outputPath);
      if (!fs.existsSync(dirname)) {
        fs.mkdirSync(dirname, { recursive: true });
      }
      
      // ruleid: javascript-zip-slip
      fs.writeFileSync(outputPath, entry.getData());
    }
  }
  
  processZipFile('./user_uploads/archive.zip');
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_10() {
  const zipFilePath = './user_uploads/archive.zip';
  const extractPath = './extracted';
  
  yauzl.open(zipFilePath, { lazyEntries: true }, (err, zipfile) => {
    if (err) throw err;
    
    zipfile.on('entry', entry => {
      const fileName = entry.fileName;
      
      // Skip directories
      if (/\/$/.test(fileName)) {
        zipfile.readEntry();
        return;
      }
      
      // Create output directory structure if needed
      const outputPath = path.join(extractPath, fileName);
      const outputDir = path.dirname(outputPath);
      
      fs.mkdirSync(outputDir, { recursive: true });
      
      zipfile.openReadStream(entry, (err, readStream) => {
        if (err) throw err;
        
        // ruleid: javascript-zip-slip
        const writeStream = fs.createWriteStream(outputPath);
        readStream.pipe(writeStream);
        
        writeStream.on('close', () => {
          zipfile.readEntry();
        });
      });
    });
    
    zipfile.readEntry();
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_11() {
  const zip = new JSZip();
  
  fs.readFile('./user_uploads/archive.zip', (err, data) => {
    if (err) throw err;
    
    zip.loadAsync(data).then(contents => {
      const extractionPromises = [];
      
      contents.forEach((relativePath, file) => {
        if (file.dir) return;
        
        const outputPath = path.join('./extracted', relativePath);
        const outputDir = path.dirname(outputPath);
        
        // Create directory if it doesn't exist
        if (!fs.existsSync(outputDir)) {
          fs.mkdirSync(outputDir, { recursive: true });
        }
        
        extractionPromises.push(
          file.async('nodebuffer').then(content => {
            // ruleid: javascript-zip-slip
            return fs.promises.writeFile(outputPath, content);
          })
        );
      });
      
      return Promise.all(extractionPromises);
    }).then(() => {
      console.log('Extraction complete');
    }).catch(err => {
      console.error('Extraction failed:', err);
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_12() {
  const processArchive = async (archivePath) => {
    try {
      const data = await fs.promises.readFile(archivePath);
      const zip = await JSZip.loadAsync(data);
      
      for (const [fileName, file] of Object.entries(zip.files)) {
        if (file.dir) continue;
        
        const content = await file.async('nodebuffer');
        const outputPath = path.join('./extracted', fileName);
        
        // Ensure directory exists
        await fs.promises.mkdir(path.dirname(outputPath), { recursive: true });
        
        // ruleid: javascript-zip-slip
        await fs.promises.writeFile(outputPath, content);
      }
      
      console.log('Archive processed successfully');
    } catch (err) {
      console.error('Error processing archive:', err);
    }
  };
  
  processArchive('./user_uploads/archive.zip');
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_13() {
  // Using tar instead of zip (similar vulnerability)
  tar.x({
    file: './user_uploads/archive.tar',
    cwd: './extracted'
    // ruleid: javascript-zip-slip
    // The vulnerability is in the tar library usage without path validation
  }).then(() => {
    console.log('Extraction complete');
  }).catch(err => {
    console.error('Extraction failed:', err);
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_14() {
  const extractZipWithCallbacks = (zipPath, destPath, callback) => {
    const zip = new AdmZip(zipPath);
    const entries = zip.getEntries();
    let processed = 0;
    
    entries.forEach(entry => {
      if (entry.isDirectory) {
        processed++;
        if (processed === entries.length) {
          callback(null);
        }
        return;
      }
      
      const outputPath = path.join(destPath, entry.entryName);
      const outputDir = path.dirname(outputPath);
      
      fs.mkdir(outputDir, { recursive: true }, err => {
        if (err) return callback(err);
        
        // ruleid: javascript-zip-slip
        fs.writeFile(outputPath, entry.getData(), err => {
          if (err) return callback(err);
          
          processed++;
          if (processed === entries.length) {
            callback(null);
          }
        });
      });
    });
  };
  
  extractZipWithCallbacks('./user_uploads/archive.zip', './extracted', err => {
    if (err) {
      console.error('Extraction failed:', err);
    } else {
      console.log('Extraction complete');
    }
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_15() {
  const processZipEntries = (zipPath, processor) => {
    const zip = new AdmZip(zipPath);
    const entries = zip.getEntries();
    
    entries.forEach(entry => {
      if (!entry.isDirectory) {
        processor(entry);
      }
    });
  };
  
  processZipEntries('./user_uploads/archive.zip', entry => {
    const outputPath = path.join('./extracted', entry.entryName);
    
    // Ensure directory exists
    const outputDir = path.dirname(outputPath);
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
    
    // ruleid: javascript-zip-slip
    fs.writeFileSync(outputPath, entry.getData());
    console.log(`Extracted: ${entry.entryName}`);
  });
}
// {/fact}

// GOOD EXAMPLES - Safe from Zip Slip

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_1() {
  const zip = new AdmZip("./user_uploads/archive.zip");
  const entries = zip.getEntries();
  
  entries.forEach(entry => {
    const entryName = entry.entryName;
    
    // ok: javascript-zip-slip
    // Validate that the entry doesn't contain path traversal
    if (entryName.includes('..') || entryName.startsWith('/') || entryName.startsWith('\\')) {
      console.warn(`Skipping potentially malicious entry: ${entryName}`);
      return;
    }
    
    const filePath = path.join('./extracted', entryName);
    
    // Additional validation to ensure the path is within the target directory
    const targetDir = path.resolve('./extracted');
    const resolvedPath = path.resolve(filePath);
    
    if (!resolvedPath.startsWith(targetDir)) {
      console.warn(`Path traversal attempt detected: ${entryName}`);
      return;
    }
    
    fs.writeFileSync(filePath, entry.getData());
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_2() {
  const extractSafely = (zipPath, targetDir) => {
    const zip = new AdmZip(zipPath);
    const entries = zip.getEntries();
    const targetDirResolved = path.resolve(targetDir);
    
    entries.forEach(entry => {
      if (entry.isDirectory) return;
      
      const sanitizedName = entry.entryName.replace(/^(\.\.[\/\\])+/, '');
      const outputPath = path.join(targetDir, sanitizedName);
      const resolvedPath = path.resolve(outputPath);
      
      // ok: javascript-zip-slip
      // Ensure the final path is still within the target directory
      if (!resolvedPath.startsWith(targetDirResolved)) {
        console.warn(`Blocked path traversal attempt: ${entry.entryName}`);
        return;
      }
      
      // Create directory if it doesn't exist
      const dirname = path.dirname(outputPath);
      if (!fs.existsSync(dirname)) {
        fs.mkdirSync(dirname, { recursive: true });
      }
      
      fs.writeFileSync(outputPath, entry.getData());
    });
  };
  
  extractSafely('./user_uploads/archive.zip', './extracted');
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_3() {
  fs.createReadStream('./user_uploads/archive.zip')
    .pipe(unzipper.Parse())
    .on('entry', entry => {
      const fileName = entry.path;
      const type = entry.type;
      
      // ok: javascript-zip-slip
      // Validate the path to prevent path traversal
      if (fileName.includes('..') || !isWithinDirectory('./extracted', path.join('./extracted', fileName))) {
        console.warn(`Skipping suspicious file: ${fileName}`);
        entry.autodrain();
        return;
      }
      
      const outputPath = path.join('./extracted', fileName);
      
      if (type === 'File') {
        entry.pipe(fs.createWriteStream(outputPath));
      } else {
        entry.autodrain();
      }
    });
  
  // Helper function to check if a path is within a directory
  function isWithinDirectory(directory, file) {
    const relative = path.relative(directory, file);
    return relative && !relative.startsWith('..') && !path.isAbsolute(relative);
  }
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_4() {
  yauzl.open('./user_uploads/archive.zip', { lazyEntries: true }, (err, zipfile) => {
    if (err) throw err;
    
    const targetDir = path.resolve('./extracted');
    
    zipfile.on('entry', entry => {
      if (/\/$/.test(entry.fileName)) {
        // Directory entry, skip
        zipfile.readEntry();
      } else {
        // ok: javascript-zip-slip
        // Validate file path
        if (entry.fileName.includes('..') || entry.fileName.startsWith('/')) {
          console.warn(`Skipping suspicious entry: ${entry.fileName}`);
          zipfile.readEntry();
          return;
        }
        
        const outputPath = path.join('./extracted', entry.fileName);
        const resolvedPath = path.resolve(outputPath);
        
        // Ensure the path is within the target directory
        if (!resolvedPath.startsWith(targetDir)) {
          console.warn(`Path traversal attempt detected: ${entry.fileName}`);
          zipfile.readEntry();
          return;
        }
        
        // Create directory if it doesn't exist
        const dirname = path.dirname(outputPath);
        fs.mkdirSync(dirname, { recursive: true }, { recursive: true });
        
        zipfile.openReadStream(entry, (err, readStream) => {
          if (err) throw err;
          
          readStream.pipe(fs.createWriteStream(outputPath));
          
          readStream.on('end', () => {
            zipfile.readEntry();
          });
        });
      }
    });
    
    zipfile.readEntry();
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_5() {
  const zip = new JSZip();
  
  fs.readFile('./user_uploads/archive.zip', (err, data) => {
    if (err) throw err;
    
    zip.loadAsync(data).then(contents => {
      const targetDir = path.resolve('./extracted');
      
      Object.keys(contents.files).forEach(fileName => {
        const file = contents.files[fileName];
        
        if (!file.dir) {
          // ok: javascript-zip-slip
          // Validate the file name to prevent path traversal
          if (fileName.includes('..') || fileName.startsWith('/') || fileName.startsWith('\\')) {
            console.warn(`Skipping suspicious file: ${fileName}`);
            return;
          }
          
          const outputPath = path.join('./extracted', fileName);
          const resolvedPath = path.resolve(outputPath);
          
          // Ensure the path is within the target directory
          if (!resolvedPath.startsWith(targetDir)) {
            console.warn(`Path traversal attempt detected: ${fileName}`);
            return;
          }
          
          file.async('nodebuffer').then(content => {
            // Create directory if it doesn't exist
            const dirname = path.dirname(outputPath);
            if (!fs.existsSync(dirname)) {
              fs.mkdirSync(dirname, { recursive: true });
            }
            
            fs.writeFile(outputPath, content, err => {
              if (err) console.error(`Error extracting ${fileName}:`, err);
            });
          });
        }
      });
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_6() {
  const zip = new StreamZip({
    file: './user_uploads/archive.zip',
    storeEntries: true
  });
  
  zip.on('ready', () => {
    fs.mkdirSync('./extracted', { recursive: true });
    const targetDir = path.resolve('./extracted');
    
    for (const entry of Object.values(zip.entries())) {
      if (entry.isDirectory) continue;
      
      // ok: javascript-zip-slip
      // Validate entry name
      if (entry.name.includes('..') || entry.name.startsWith('/') || entry.name.startsWith('\\')) {
        console.warn(`Skipping suspicious entry: ${entry.name}`);
        continue;
      }
      
      const outputPath = path.join('./extracted', entry.name);
      const resolvedPath = path.resolve(outputPath);
      
      // Ensure the path is within the target directory
      if (!resolvedPath.startsWith(targetDir)) {
        console.warn(`Path traversal attempt detected: ${entry.name}`);
        continue;
      }
      
      // Create directory if it doesn't exist
      const dirname = path.dirname(outputPath);
      if (!fs.existsSync(dirname)) {
        fs.mkdirSync(dirname, { recursive: true });
      }
      
      zip.extract(entry.name, outputPath, err => {
        if (err) console.error(`Error extracting ${entry.name}:`, err);
      });
    }
    
    zip.close();
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_7() {
  const safeDecompress = async (zipPath, targetDir) => {
    try {
      const files = await decompress(zipPath, null); // Extract without writing to disk
      const targetDirResolved = path.resolve(targetDir);
      
      for (const file of files) {
        // ok: javascript-zip-slip
        // Validate file path
        if (file.path.includes('..') || file.path.startsWith('/') || file.path.startsWith('\\')) {
          console.warn(`Skipping suspicious file: ${file.path}`);
          continue;
        }
        
        const outputPath = path.join(targetDir, file.path);
        const resolvedPath = path.resolve(outputPath);
        
        // Ensure the path is within the target directory
        if (!resolvedPath.startsWith(targetDirResolved)) {
          console.warn(`Path traversal attempt detected: ${file.path}`);
          continue;
        }
        
        // Create directory if it doesn't exist
        const dirname = path.dirname(outputPath);
        if (!fs.existsSync(dirname)) {
          fs.mkdirSync(dirname, { recursive: true });
        }
        
        await fs.promises.writeFile(outputPath, file.data);
      }
      
      console.log('Files decompressed safely');
    } catch (err) {
      console.error('Decompression failed:', err);
    }
  };
  
  safeDecompress('./user_uploads/archive.zip', './extracted');
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_8() {
  const server = http.createServer((req, res) => {
    if (req.url === '/upload' && req.method === 'POST') {
      let data = [];
      req.on('data', chunk => {
        data.push(chunk);
      });
      
      req.on('end', () => {
        const buffer = Buffer.concat(data);
        fs.writeFileSync('./uploads/archive.zip', buffer);
        
        const zip = new AdmZip('./uploads/archive.zip');
        const entries = zip.getEntries();
        const targetDir = path.resolve('./extracted');
        
        entries.forEach(entry => {
          // ok: javascript-zip-slip
          // Validate entry name
          if (entry.entryName.includes('..') || entry.entryName.startsWith('/') || entry.entryName.startsWith('\\')) {
            console.warn(`Skipping suspicious entry: ${entry.entryName}`);
            return;
          }
          
          const outputPath = path.join('./extracted', entry.entryName);
          const resolvedPath = path.resolve(outputPath);
          
          // Ensure the path is within the target directory
          if (!resolvedPath.startsWith(targetDir)) {
            console.warn(`Path traversal attempt detected: ${entry.entryName}`);
            return;
          }
          
          // Create directory if it doesn't exist
          const dirname = path.dirname(outputPath);
          if (!fs.existsSync(dirname)) {
            fs.mkdirSync(dirname, { recursive: true });
          }
          
          fs.writeFileSync(outputPath, entry.getData());
        });
        
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('File extracted safely');
      });
    }
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_9() {
  function isSafePath(entryPath, targetDir) {
    // Remove any leading slashes or drive letters
    const normalizedPath = path.normalize(entryPath).replace(/^(\w:)?[\/\\]+/, '');
    
    // Check for path traversal attempts
    if (normalizedPath.includes('..')) {
      return false;
    }
    
    const fullPath = path.join(targetDir, normalizedPath);
    const resolvedPath = path.resolve(fullPath);
    const resolvedTarget = path.resolve(targetDir);
    
    // Ensure the path is within the target directory
    return resolvedPath.startsWith(resolvedTarget);
  }
  
  function processZipFile(zipFilePath) {
    const zip = new AdmZip(zipFilePath);
    const extractPath = './extracted';
    
    if (!fs.existsSync(extractPath)) {
      fs.mkdirSync(extractPath, { recursive: true });
    }
    
    for (const entry of zip.getEntries()) {
      if (entry.isDirectory) continue;
      
      const entryPath = entry.entryName;
      
      // ok: javascript-zip-slip
      // Validate the path
      if (!isSafePath(entryPath, extractPath)) {
        console.warn(`Skipping potentially malicious entry: ${entryPath}`);
        continue;
      }
      
      const outputPath = path.join(extractPath, entryPath);
      
      // Create directory if it doesn't exist
      const dirname = path.dirname(outputPath);
      if (!fs.existsSync(dirname)) {
        fs.mkdirSync(dirname, { recursive: true });
      }
      
      fs.writeFileSync(outputPath, entry.getData());
    }
  }
  
  processZipFile('./user_uploads/archive.zip');
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_10() {
  const zipFilePath = './user_uploads/archive.zip';
  const extractPath = './extracted';
  
  yauzl.open(zipFilePath, { lazyEntries: true }, (err, zipfile) => {
    if (err) throw err;
    
    const targetDir = path.resolve(extractPath);
    
    zipfile.on('entry', entry => {
      const fileName = entry.fileName;
      
      // Skip directories
      if (/\/$/.test(fileName)) {
        zipfile.readEntry();
        return;
      }
      
      // ok: javascript-zip-slip
      // Validate file path
      if (fileName.includes('..') || fileName.startsWith('/') || fileName.startsWith('\\')) {
        console.warn(`Skipping suspicious file: ${fileName}`);
        zipfile.readEntry();
        return;
      }
      
      const outputPath = path.join(extractPath, fileName);
      const resolvedPath = path.resolve(outputPath);
      
      // Ensure the path is within the target directory
      if (!resolvedPath.startsWith(targetDir)) {
        console.warn(`Path traversal attempt detected: ${fileName}`);
        zipfile.readEntry();
        return;
      }
      
      // Create output directory structure if needed
      const outputDir = path.dirname(outputPath);
      fs.mkdirSync(outputDir, { recursive: true });
      
      zipfile.openReadStream(entry, (err, readStream) => {
        if (err) throw err;
        
        const writeStream = fs.createWriteStream(outputPath);
        readStream.pipe(writeStream);
        
        writeStream.on('close', () => {
          zipfile.readEntry();
        });
      });
    });
    
    zipfile.readEntry();
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_11() {
  const zip = new JSZip();
  
  fs.readFile('./user_uploads/archive.zip', (err, data) => {
    if (err) throw err;
    
    zip.loadAsync(data).then(contents => {
      const extractionPromises = [];
      const targetDir = path.resolve('./extracted');
      
      contents.forEach((relativePath, file) => {
        if (file.dir) return;
        
        // ok: javascript-zip-slip
        // Validate the path
        if (relativePath.includes('..') || relativePath.startsWith('/') || relativePath.startsWith('\\')) {
          console.warn(`Skipping suspicious file: ${relativePath}`);
          return;
        }
        
        const outputPath = path.join('./extracted', relativePath);
        const resolvedPath = path.resolve(outputPath);
        
        // Ensure the path is within the target directory
        if (!resolvedPath.startsWith(targetDir)) {
          console.warn(`Path traversal attempt detected: ${relativePath}`);
          return;
        }
        
        const outputDir = path.dirname(outputPath);
        
        extractionPromises.push(
          fs.promises.mkdir(outputDir, { recursive: true })
            .then(() => file.async('nodebuffer'))
            .then(content => {
              return fs.promises.writeFile(outputPath, content);
            })
        );
      });
      
      return Promise.all(extractionPromises);
    }).then(() => {
      console.log('Extraction complete');
    }).catch(err => {
      console.error('Extraction failed:', err);
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_12() {
  const processArchive = async (archivePath) => {
    try {
      const data = await fs.promises.readFile(archivePath);
      const zip = await JSZip.loadAsync(data);
      const targetDir = path.resolve('./extracted');
      
      for (const [fileName, file] of Object.entries(zip.files)) {
        if (file.dir) continue;
        
        // ok: javascript-zip-slip
        // Validate the file path
        if (fileName.includes('..') || fileName.startsWith('/') || fileName.startsWith('\\')) {
          console.warn(`Skipping suspicious file: ${fileName}`);
          continue;
        }
        
        const outputPath = path.join('./extracted', fileName);
        const resolvedPath = path.resolve(outputPath);
        
        // Ensure the path is within the target directory
        if (!resolvedPath.startsWith(targetDir)) {
          console.warn(`Path traversal attempt detected: ${fileName}`);
          continue;
        }
        
        const content = await file.async('nodebuffer');
        
        // Ensure directory exists
        await fs.promises.mkdir(path.dirname(outputPath), { recursive: true });
        await fs.promises.writeFile(outputPath, content);
      }
      
      console.log('Archive processed successfully');
    } catch (err) {
      console.error('Error processing archive:', err);
    }
  };
  
  processArchive('./user_uploads/archive.zip');
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_13() {
  // Using tar with path validation
  const validatePaths = (pathsToExtract) => {
    const targetDir = path.resolve('./extracted');
    
    return pathsToExtract.filter(entryPath => {
      // ok: javascript-zip-slip
      // Validate the path
      if (entryPath.includes('..') || entryPath.startsWith('/')) {
        console.warn(`Skipping suspicious entry: ${entryPath}`);
        return false;
      }
      
      const outputPath = path.join('./extracted', entryPath);
      const resolvedPath = path.resolve(outputPath);
      
      // Ensure the path is within the target directory
      if (!resolvedPath.startsWith(targetDir)) {
        console.warn(`Path traversal attempt detected: ${entryPath}`);
        return false;
      }
      
      return true;
    });
  };
  
  // First list all entries
  tar.t({
    file: './user_uploads/archive.tar',
    onentry: entry => {
      // Just collecting entry names
    }
  }).then(entries => {
    // Filter out unsafe paths
    const safeEntries = validatePaths(entries);
    
    // Extract only safe entries
    return tar.x({
      file: './user_uploads/archive.tar',
      cwd: './extracted',
      filter: (path, entry) => safeEntries.includes(entry.path)
    });
  }).then(() => {
    console.log('Safe extraction complete');
  }).catch(err => {
    console.error('Extraction failed:', err);
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_14() {
  const extractZipWithCallbacks = (zipPath, destPath, callback) => {
    const zip = new AdmZip(zipPath);
    const entries = zip.getEntries();
    let processed = 0;
    const targetDir = path.resolve(destPath);
    
    entries.forEach(entry => {
      if (entry.isDirectory) {
        processed++;
        if (processed === entries.length) {
          callback(null);
        }
        return;
      }
      
      // ok: javascript-zip-slip
      // Validate entry name
      if (entry.entryName.includes('..') || entry.entryName.startsWith('/') || entry.entryName.startsWith('\\')) {
        console.warn(`Skipping suspicious entry: ${entry.entryName}`);
        processed++;
        if (processed === entries.length) {
          callback(null);
        }
        return;
      }
      
      const outputPath = path.join(destPath, entry.entryName);
      const resolvedPath = path.resolve(outputPath);
      
      // Ensure the path is within the target directory
      if (!resolvedPath.startsWith(targetDir)) {
        console.warn(`Path traversal attempt detected: ${entry.entryName}`);
        processed++;
        if (processed === entries.length) {
          callback(null);
        }
        return;
      }
      
      const outputDir = path.dirname(outputPath);
      
      fs.mkdir(outputDir, { recursive: true }, err => {
        if (err) return callback(err);
        
        fs.writeFile(outputPath, entry.getData(), err => {
          if (err) return callback(err);
          
          processed++;
          if (processed === entries.length) {
            callback(null);
          }
        });
      });
    });
  };
  
  extractZipWithCallbacks('./user_uploads/archive.zip', './extracted', err => {
    if (err) {
      console.error('Extraction failed:', err);
    } else {
      console.log('Extraction complete');
    }
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_15() {
  const isPathSafe = (filePath, targetDir) => {
    const normalizedPath = path.normalize(filePath);
    
    // Check for path traversal attempts
    if (normalizedPath.includes('..') || normalizedPath.startsWith('/') || normalizedPath.startsWith('\\')) {
      return false;
    }
    
    const fullPath = path.join(targetDir, normalizedPath);
    const resolvedPath = path.resolve(fullPath);
    const resolvedTarget = path.resolve(targetDir);
    
    // Ensure the path is within the target directory
    return resolvedPath.startsWith(resolvedTarget);
  };
  
  const processZipEntries = (zipPath, processor) => {
    const zip = new AdmZip(zipPath);
    const entries = zip.getEntries();
    const targetDir = './extracted';
    
    entries.forEach(entry => {
      if (!entry.isDirectory) {
        // ok: javascript-zip-slip
        // Validate the path
        if (!isPathSafe(entry.entryName, targetDir)) {
          console.warn(`Skipping potentially malicious entry: ${entry.entryName}`);
          return;
        }
        
        processor(entry, targetDir);
      }
    });
  };
  
  processZipEntries('./user_uploads/archive.zip', (entry, targetDir) => {
    const outputPath = path.join(targetDir, entry.entryName);
    
    // Ensure directory exists
    const outputDir = path.dirname(outputPath);
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
    
    fs.writeFileSync(outputPath, entry.getData());
    console.log(`Extracted: ${entry.entryName}`);
  });
}
// {/fact}