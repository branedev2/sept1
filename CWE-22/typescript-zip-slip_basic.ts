import * as fs from 'fs';
import * as path from 'path';
import * as unzipper from 'unzipper';
import * as AdmZip from 'adm-zip';
import * as yauzl from 'yauzl';
import * as extract from 'extract-zip';
import * as JSZip from 'jszip';
import * as archiver from 'archiver';
import * as express from 'express';
import * as multer from 'multer';
import * as http from 'http';
import * as https from 'https';

// True Positive Examples (Vulnerable Code)

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_1() {
  const zip = new AdmZip("archive.zip");
  const zipEntries = zip.getEntries();
  
  zipEntries.forEach(entry => {
    const entryPath = path.join("output_dir", entry.entryName);
    // ruleid: typescript-zip-slip
    fs.writeFileSync(entryPath, entry.getData());
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  const upload = multer({ dest: 'uploads/' });
  
  app.post('/upload', upload.single('zipfile'), (req, res) => {
    const zip = new AdmZip(req.file.path);
    const extractDir = './extracted';
    
    zip.getEntries().forEach(entry => {
      const outputPath = path.join(extractDir, entry.entryName);
      // ruleid: typescript-zip-slip
      fs.mkdirSync(path.dirname(outputPath), { recursive: true });
      if (!entry.isDirectory) {
        fs.writeFileSync(outputPath, entry.getData());
      }
    });
    
    res.send('File extracted successfully');
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_3() {
  yauzl.open("example.zip", { lazyEntries: true }, (err, zipfile) => {
    if (err) throw err;
    
    zipfile.on("entry", (entry) => {
      zipfile.openReadStream(entry, (err, readStream) => {
        if (err) throw err;
        
        const outputPath = path.join("output_directory", entry.fileName);
        // ruleid: typescript-zip-slip
        const writeStream = fs.createWriteStream(outputPath);
        readStream.pipe(writeStream);
      });
      
      zipfile.readEntry();
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_4() {
  fs.createReadStream('archive.zip')
    .pipe(unzipper.Parse())
    .on('entry', (entry) => {
      const fileName = entry.path;
      const outputPath = path.join('destination', fileName);
      // ruleid: typescript-zip-slip
      entry.pipe(fs.createWriteStream(outputPath));
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_5() {
  async function extractZip() {
    const jszip = new JSZip();
    const data = await fs.promises.readFile('file.zip');
    const zip = await jszip.loadAsync(data);
    
    for (const [fileName, fileData] of Object.entries(zip.files)) {
      if (!fileData.dir) {
        const content = await fileData.async('nodebuffer');
        const outputPath = path.join('output', fileName);
        // ruleid: typescript-zip-slip
        await fs.promises.mkdir(path.dirname(outputPath), { recursive: true });
        await fs.promises.writeFile(outputPath, content);
      }
    }
  }
  
  extractZip().catch(console.error);
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  
  app.get('/extract', async (req, res) => {
    const zipFilePath = req.query.zipPath as string;
    const extractDir = './extracted_files';
    
    try {
      await extract(zipFilePath, { 
        dir: extractDir,
        // No path sanitization
        // ruleid: typescript-zip-slip
        onEntry: (entry, zipfile) => {
          console.log(`Extracting ${entry.fileName}`);
        }
      });
      res.send('Extraction complete');
    } catch (err) {
      res.status(500).send('Extraction failed');
    }
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_7() {
  const processZipBuffer = async (buffer: Buffer) => {
    const zip = await JSZip.loadAsync(buffer);
    const extractDir = './extracted_content';
    
    for (const [filename, file] of Object.entries(zip.files)) {
      if (!file.dir) {
        const content = await file.async('nodebuffer');
        const targetPath = path.join(extractDir, filename);
        // ruleid: typescript-zip-slip
        fs.mkdirSync(path.dirname(targetPath), { recursive: true });
        fs.writeFileSync(targetPath, content);
      }
    }
  };
  
  https.get('https://example.com/files/archive.zip', (res) => {
    const chunks: Buffer[] = [];
    res.on('data', (chunk) => chunks.push(chunk));
    res.on('end', () => {
      const buffer = Buffer.concat(chunks);
      processZipBuffer(buffer).catch(console.error);
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  const upload = multer({ dest: 'uploads/' });
  
  app.post('/unzip', upload.single('zipfile'), (req, res) => {
    const extractPath = req.body.extractPath || './extracted';
    
    yauzl.open(req.file.path, { lazyEntries: true }, (err, zipfile) => {
      if (err) return res.status(500).send(err.message);
      
      zipfile.on('entry', (entry) => {
        if (/\/$/.test(entry.fileName)) {
          // Directory entry
          zipfile.readEntry();
        } else {
          // File entry
          zipfile.openReadStream(entry, (err, readStream) => {
            if (err) return res.status(500).send(err.message);
            
            const outputPath = path.join(extractPath, entry.fileName);
            // ruleid: typescript-zip-slip
            fs.mkdirSync(path.dirname(outputPath), { recursive: true });
            readStream.pipe(fs.createWriteStream(outputPath));
            readStream.on('end', () => zipfile.readEntry());
          });
        }
      });
      
      zipfile.on('end', () => res.send('Extraction complete'));
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_9() {
  const unzipFile = (zipPath: string, destDir: string) => {
    const zip = new AdmZip(zipPath);
    const entries = zip.getEntries();
    
    entries.forEach(entry => {
      if (entry.isDirectory) return;
      
      const entryPath = entry.entryName;
      const outputPath = path.join(destDir, entryPath);
      // ruleid: typescript-zip-slip
      zip.extractEntryTo(entry, destDir, false, true);
    });
  };
  
  http.createServer((req, res) => {
    if (req.url === '/unzip' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk.toString(); });
      req.on('end', () => {
        const { zipPath } = JSON.parse(body);
        unzipFile(zipPath, './output');
        res.end('Unzipped successfully');
      });
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_10() {
  async function processZipFile(zipFilePath: string) {
    const jszip = new JSZip();
    const data = await fs.promises.readFile(zipFilePath);
    const zip = await jszip.loadAsync(data);
    
    const extractPromises = [];
    
    zip.forEach((relativePath, file) => {
      if (!file.dir) {
        const promise = file.async('nodebuffer').then(content => {
          const outputPath = path.join('output_directory', relativePath);
          // ruleid: typescript-zip-slip
          return fs.promises.mkdir(path.dirname(outputPath), { recursive: true })
            .then(() => fs.promises.writeFile(outputPath, content));
        });
        extractPromises.push(promise);
      }
    });
    
    await Promise.all(extractPromises);
  }
  
  processZipFile('user_uploads/archive.zip').catch(console.error);
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  app.get('/download-and-extract', (req, res) => {
    const fileUrl = req.query.url as string;
    const outputDir = './downloads';
    
    https.get(fileUrl, (response) => {
      const chunks: Buffer[] = [];
      
      response.on('data', (chunk) => chunks.push(chunk));
      
      response.on('end', async () => {
        const zipBuffer = Buffer.concat(chunks);
        const zip = new AdmZip(zipBuffer);
        
        zip.getEntries().forEach((entry) => {
          if (!entry.isDirectory) {
            const filePath = path.join(outputDir, entry.entryName);
            // ruleid: typescript-zip-slip
            fs.mkdirSync(path.dirname(filePath), { recursive: true });
            fs.writeFileSync(filePath, entry.getData());
          }
        });
        
        res.send('Downloaded and extracted successfully');
      });
    }).on('error', (err) => {
      res.status(500).send(`Error: ${err.message}`);
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_12() {
  const extractZipToDirectory = (zipPath: string, targetDir: string) => {
    return new Promise<void>((resolve, reject) => {
      fs.createReadStream(zipPath)
        .pipe(unzipper.Parse())
        .on('entry', (entry) => {
          const entryPath = entry.path;
          const outputPath = path.join(targetDir, entryPath);
          
          if (entry.type === 'Directory') {
            // ruleid: typescript-zip-slip
            fs.mkdirSync(outputPath, { recursive: true });
          } else {
            // ruleid: typescript-zip-slip
            entry.pipe(fs.createWriteStream(outputPath));
          }
        })
        .on('close', resolve)
        .on('error', reject);
    });
  };
  
  const app = express();
  app.post('/extract', multer({ dest: 'uploads/' }).single('zipfile'), (req, res) => {
    extractZipToDirectory(req.file.path, req.body.targetDir || './extracted')
      .then(() => res.send('Extraction complete'))
      .catch(err => res.status(500).send(`Error: ${err.message}`));
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_13() {
  class ZipExtractor {
    private zipPath: string;
    private outputDir: string;
    
    constructor(zipPath: string, outputDir: string) {
      this.zipPath = zipPath;
      this.outputDir = outputDir;
    }
    
    public async extract(): Promise<void> {
      const zip = new AdmZip(this.zipPath);
      const entries = zip.getEntries();
      
      for (const entry of entries) {
        if (entry.isDirectory) continue;
        
        const entryName = entry.entryName;
        const content = entry.getData();
        const targetPath = path.join(this.outputDir, entryName);
        
        // ruleid: typescript-zip-slip
        await fs.promises.mkdir(path.dirname(targetPath), { recursive: true });
        await fs.promises.writeFile(targetPath, content);
      }
    }
  }
  
  const app = express();
  app.post('/extract-zip', multer({ dest: 'uploads/' }).single('zipfile'), async (req, res) => {
    try {
      const extractor = new ZipExtractor(req.file.path, './extracted');
      await extractor.extract();
      res.send('Extraction successful');
    } catch (err) {
      res.status(500).send(`Error: ${err.message}`);
    }
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_14() {
  async function extractZipFromUrl(url: string, outputDir: string): Promise<void> {
    return new Promise((resolve, reject) => {
      https.get(url, (response) => {
        if (response.statusCode !== 200) {
          reject(new Error(`Failed to download: ${response.statusCode}`));
          return;
        }
        
        const chunks: Buffer[] = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', async () => {
          try {
            const buffer = Buffer.concat(chunks);
            const jszip = new JSZip();
            const zip = await jszip.loadAsync(buffer);
            
            for (const [filename, file] of Object.entries(zip.files)) {
              if (file.dir) continue;
              
              const content = await file.async('nodebuffer');
              const targetPath = path.join(outputDir, filename);
              
              // ruleid: typescript-zip-slip
              await fs.promises.mkdir(path.dirname(targetPath), { recursive: true });
              await fs.promises.writeFile(targetPath, content);
            }
            
            resolve();
          } catch (err) {
            reject(err);
          }
        });
      }).on('error', reject);
    });
  }
  
  const app = express();
  app.get('/extract-from-url', async (req, res) => {
    try {
      await extractZipFromUrl(req.query.url as string, './downloads');
      res.send('Extraction complete');
    } catch (err) {
      res.status(500).send(`Error: ${err.message}`);
    }
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=1}
function bad_case_15() {
  function processZipEntries(zipFilePath: string, callback: (fileName: string, content: Buffer) => void): Promise<void> {
    return new Promise((resolve, reject) => {
      yauzl.open(zipFilePath, { lazyEntries: true }, (err, zipfile) => {
        if (err) return reject(err);
        
        zipfile.on('entry', (entry) => {
          if (/\/$/.test(entry.fileName)) {
            // Directory entry
            zipfile.readEntry();
          } else {
            // File entry
            zipfile.openReadStream(entry, (err, stream) => {
              if (err) return reject(err);
              
              const chunks: Buffer[] = [];
              stream.on('data', (chunk) => chunks.push(chunk));
              stream.on('end', () => {
                const content = Buffer.concat(chunks);
                callback(entry.fileName, content);
                zipfile.readEntry();
              });
            });
          }
        });
        
        zipfile.on('end', resolve);
        zipfile.readEntry();
      });
    });
  }
  
  const app = express();
  app.post('/process-zip', multer({ dest: 'uploads/' }).single('zipfile'), async (req, res) => {
    try {
      const outputDir = './processed';
      
      await processZipEntries(req.file.path, (fileName, content) => {
        const outputPath = path.join(outputDir, fileName);
        // ruleid: typescript-zip-slip
        fs.mkdirSync(path.dirname(outputPath), { recursive: true });
        fs.writeFileSync(outputPath, content);
      });
      
      res.send('Processing complete');
    } catch (err) {
      res.status(500).send(`Error: ${err.message}`);
    }
  });
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_1() {
  const zip = new AdmZip("archive.zip");
  const zipEntries = zip.getEntries();
  
  zipEntries.forEach(entry => {
    const entryName = entry.entryName;
    // ok: typescript-zip-slip
    if (entryName.includes('..') || path.isAbsolute(entryName)) {
      console.log(`Skipping potentially malicious entry: ${entryName}`);
      return;
    }
    
    const entryPath = path.join("output_dir", entryName);
    fs.writeFileSync(entryPath, entry.getData());
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_2() {
  const app = express();
  const upload = multer({ dest: 'uploads/' });
  
  app.post('/upload', upload.single('zipfile'), (req, res) => {
    const zip = new AdmZip(req.file.path);
    const extractDir = './extracted';
    
    zip.getEntries().forEach(entry => {
      const entryName = entry.entryName;
      // ok: typescript-zip-slip
      if (entryName.includes('..') || path.isAbsolute(entryName) || !entryName.normalize('NFC') === entryName) {
        console.log(`Skipping potentially malicious entry: ${entryName}`);
        return;
      }
      
      const outputPath = path.join(extractDir, entryName);
      // Ensure the output path is within the target directory
      // ok: typescript-zip-slip
      const normalizedOutputPath = path.normalize(outputPath);
      if (!normalizedOutputPath.startsWith(path.normalize(extractDir))) {
        console.log(`Path traversal attempt detected: ${entryName}`);
        return;
      }
      
      fs.mkdirSync(path.dirname(normalizedOutputPath), { recursive: true });
      if (!entry.isDirectory) {
        fs.writeFileSync(normalizedOutputPath, entry.getData());
      }
    });
    
    res.send('File extracted successfully');
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_3() {
  yauzl.open("example.zip", { lazyEntries: true }, (err, zipfile) => {
    if (err) throw err;
    
    zipfile.on("entry", (entry) => {
      // ok: typescript-zip-slip
      if (entry.fileName.includes('..') || path.isAbsolute(entry.fileName)) {
        console.log(`Skipping potentially malicious entry: ${entry.fileName}`);
        zipfile.readEntry();
        return;
      }
      
      zipfile.openReadStream(entry, (err, readStream) => {
        if (err) throw err;
        
        const outputPath = path.join("output_directory", entry.fileName);
        // ok: typescript-zip-slip
        const normalizedPath = path.normalize(outputPath);
        const normalizedDestDir = path.normalize("output_directory");
        
        if (!normalizedPath.startsWith(normalizedDestDir)) {
          console.log(`Path traversal attempt detected: ${entry.fileName}`);
          zipfile.readEntry();
          return;
        }
        
        const writeStream = fs.createWriteStream(normalizedPath);
        readStream.pipe(writeStream);
      });
      
      zipfile.readEntry();
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_4() {
  // Helper function to validate zip entry paths
  function isValidZipEntry(entryPath: string, destDir: string): boolean {
    // ok: typescript-zip-slip
    if (entryPath.includes('..') || path.isAbsolute(entryPath)) {
      return false;
    }
    
    const normalizedPath = path.normalize(path.join(destDir, entryPath));
    const normalizedDestDir = path.normalize(destDir);
    
    return normalizedPath.startsWith(normalizedDestDir);
  }
  
  fs.createReadStream('archive.zip')
    .pipe(unzipper.Parse())
    .on('entry', (entry) => {
      const fileName = entry.path;
      const destDir = 'destination';
      
      // ok: typescript-zip-slip
      if (!isValidZipEntry(fileName, destDir)) {
        console.log(`Skipping potentially malicious entry: ${fileName}`);
        entry.autodrain();
        return;
      }
      
      const outputPath = path.join(destDir, fileName);
      entry.pipe(fs.createWriteStream(outputPath));
    });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_5() {
  async function extractZip() {
    const jszip = new JSZip();
    const data = await fs.promises.readFile('file.zip');
    const zip = await jszip.loadAsync(data);
    const outputBaseDir = path.resolve('output');
    
    for (const [fileName, fileData] of Object.entries(zip.files)) {
      if (!fileData.dir) {
        // ok: typescript-zip-slip
        if (fileName.includes('..') || path.isAbsolute(fileName)) {
          console.log(`Skipping potentially malicious entry: ${fileName}`);
          continue;
        }
        
        const outputPath = path.join(outputBaseDir, fileName);
        const normalizedOutputPath = path.normalize(outputPath);
        
        // ok: typescript-zip-slip
        if (!normalizedOutputPath.startsWith(outputBaseDir)) {
          console.log(`Path traversal attempt detected: ${fileName}`);
          continue;
        }
        
        const content = await fileData.async('nodebuffer');
        await fs.promises.mkdir(path.dirname(normalizedOutputPath), { recursive: true });
        await fs.promises.writeFile(normalizedOutputPath, content);
      }
    }
  }
  
  extractZip().catch(console.error);
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_6() {
  const app = express();
  
  // Helper function to sanitize zip entry paths
  function sanitizeZipEntry(entryPath: string, baseDir: string): string | null {
    // ok: typescript-zip-slip
    if (entryPath.includes('..') || path.isAbsolute(entryPath)) {
      return null;
    }
    
    const fullPath = path.join(baseDir, entryPath);
    const normalizedPath = path.normalize(fullPath);
    const normalizedBaseDir = path.normalize(baseDir);
    
    if (!normalizedPath.startsWith(normalizedBaseDir)) {
      return null;
    }
    
    return normalizedPath;
  }
  
  app.get('/extract', async (req, res) => {
    const zipFilePath = req.query.zipPath as string;
    const extractDir = path.resolve('./extracted_files');
    
    try {
      await extract(zipFilePath, { 
        dir: extractDir,
        // ok: typescript-zip-slip
        onEntry: (entry, zipfile) => {
          const sanitizedPath = sanitizeZipEntry(entry.fileName, extractDir);
          if (!sanitizedPath) {
            console.log(`Blocked potentially malicious entry: ${entry.fileName}`);
            // Skip this entry
            entry.fileName = '__SKIPPED__';
          }
        }
      });
      res.send('Extraction complete');
    } catch (err) {
      res.status(500).send('Extraction failed');
    }
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_7() {
  // Helper function to validate and normalize paths
  function getSafePath(filePath: string, baseDir: string): string | null {
    // ok: typescript-zip-slip
    if (filePath.includes('..') || path.isAbsolute(filePath)) {
      return null;
    }
    
    const fullPath = path.join(baseDir, filePath);
    const normalizedPath = path.normalize(fullPath);
    
    if (!normalizedPath.startsWith(path.normalize(baseDir))) {
      return null;
    }
    
    return normalizedPath;
  }
  
  const processZipBuffer = async (buffer: Buffer) => {
    const zip = await JSZip.loadAsync(buffer);
    const extractDir = path.resolve('./extracted_content');
    
    for (const [filename, file] of Object.entries(zip.files)) {
      if (!file.dir) {
        // ok: typescript-zip-slip
        const safePath = getSafePath(filename, extractDir);
        if (!safePath) {
          console.log(`Skipping potentially malicious entry: ${filename}`);
          continue;
        }
        
        const content = await file.async('nodebuffer');
        fs.mkdirSync(path.dirname(safePath), { recursive: true });
        fs.writeFileSync(safePath, content);
      }
    }
  };
  
  https.get('https://example.com/files/archive.zip', (res) => {
    const chunks: Buffer[] = [];
    res.on('data', (chunk) => chunks.push(chunk));
    res.on('end', () => {
      const buffer = Buffer.concat(chunks);
      processZipBuffer(buffer).catch(console.error);
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_8() {
  const app = express();
  const upload = multer({ dest: 'uploads/' });
  
  // Path validation utility
  function isPathSafe(entryPath: string, baseDir: string): boolean {
    // ok: typescript-zip-slip
    if (entryPath.includes('..') || path.isAbsolute(entryPath)) {
      return false;
    }
    
    const fullPath = path.join(baseDir, entryPath);
    const normalizedPath = path.normalize(fullPath);
    const normalizedBaseDir = path.normalize(baseDir);
    
    return normalizedPath.startsWith(normalizedBaseDir);
  }
  
  app.post('/unzip', upload.single('zipfile'), (req, res) => {
    const extractPath = path.resolve(req.body.extractPath || './extracted');
    
    yauzl.open(req.file.path, { lazyEntries: true }, (err, zipfile) => {
      if (err) return res.status(500).send(err.message);
      
      zipfile.on('entry', (entry) => {
        if (/\/$/.test(entry.fileName)) {
          // Directory entry
          zipfile.readEntry();
        } else {
          // File entry
          // ok: typescript-zip-slip
          if (!isPathSafe(entry.fileName, extractPath)) {
            console.log(`Blocked malicious zip entry: ${entry.fileName}`);
            zipfile.readEntry();
            return;
          }
          
          zipfile.openReadStream(entry, (err, readStream) => {
            if (err) return res.status(500).send(err.message);
            
            const outputPath = path.join(extractPath, entry.fileName);
            fs.mkdirSync(path.dirname(outputPath), { recursive: true });
            readStream.pipe(fs.createWriteStream(outputPath));
            readStream.on('end', () => zipfile.readEntry());
          });
        }
      });
      
      zipfile.on('end', () => res.send('Extraction complete'));
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_9() {
  const unzipFile = (zipPath: string, destDir: string) => {
    const zip = new AdmZip(zipPath);
    const entries = zip.getEntries();
    const safeDestDir = path.resolve(destDir);
    
    entries.forEach(entry => {
      if (entry.isDirectory) return;
      
      const entryPath = entry.entryName;
      // ok: typescript-zip-slip
      if (entryPath.includes('..') || path.isAbsolute(entryPath)) {
        console.log(`Skipping potentially malicious entry: ${entryPath}`);
        return;
      }
      
      const outputPath = path.join(safeDestDir, entryPath);
      const normalizedOutputPath = path.normalize(outputPath);
      
      // ok: typescript-zip-slip
      if (!normalizedOutputPath.startsWith(safeDestDir)) {
        console.log(`Path traversal attempt detected: ${entryPath}`);
        return;
      }
      
      // Safe to extract
      zip.extractEntryTo(entry, destDir, false, true);
    });
  };
  
  http.createServer((req, res) => {
    if (req.url === '/unzip' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk.toString(); });
      req.on('end', () => {
        const { zipPath } = JSON.parse(body);
        unzipFile(zipPath, './output');
        res.end('Unzipped successfully');
      });
    }
  }).listen(3000);
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_10() {
  // Utility function to validate zip entry paths
  function validateZipEntryPath(entryPath: string, baseDir: string): string | null {
    // ok: typescript-zip-slip
    if (entryPath.includes('..') || path.isAbsolute(entryPath)) {
      return null;
    }
    
    const fullPath = path.join(baseDir, entryPath);
    const normalizedPath = path.normalize(fullPath);
    const normalizedBaseDir = path.normalize(baseDir);
    
    if (!normalizedPath.startsWith(normalizedBaseDir)) {
      return null;
    }
    
    return normalizedPath;
  }
  
  async function processZipFile(zipFilePath: string) {
    const jszip = new JSZip();
    const data = await fs.promises.readFile(zipFilePath);
    const zip = await jszip.loadAsync(data);
    const outputDir = path.resolve('output_directory');
    
    const extractPromises = [];
    
    zip.forEach((relativePath, file) => {
      if (!file.dir) {
        const promise = file.async('nodebuffer').then(content => {
          // ok: typescript-zip-slip
          const safePath = validateZipEntryPath(relativePath, outputDir);
          if (!safePath) {
            console.log(`Skipping potentially malicious entry: ${relativePath}`);
            return Promise.resolve();
          }
          
          return fs.promises.mkdir(path.dirname(safePath), { recursive: true })
            .then(() => fs.promises.writeFile(safePath, content));
        });
        extractPromises.push(promise);
      }
    });
    
    await Promise.all(extractPromises);
  }
  
  processZipFile('user_uploads/archive.zip').catch(console.error);
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  // Helper function to sanitize zip entry paths
  function sanitizeEntryPath(entryPath: string, baseDir: string): string | null {
    // ok: typescript-zip-slip
    if (entryPath.includes('..') || path.isAbsolute(entryPath)) {
      return null;
    }
    
    const fullPath = path.join(baseDir, entryPath);
    const normalizedPath = path.normalize(fullPath);
    const normalizedBaseDir = path.normalize(baseDir);
    
    if (!normalizedPath.startsWith(normalizedBaseDir)) {
      return null;
    }
    
    return normalizedPath;
  }
  
  app.get('/download-and-extract', (req, res) => {
    const fileUrl = req.query.url as string;
    const outputDir = path.resolve('./downloads');
    
    https.get(fileUrl, (response) => {
      const chunks: Buffer[] = [];
      
      response.on('data', (chunk) => chunks.push(chunk));
      
      response.on('end', async () => {
        const zipBuffer = Buffer.concat(chunks);
        const zip = new AdmZip(zipBuffer);
        let extractedCount = 0;
        let skippedCount = 0;
        
        zip.getEntries().forEach((entry) => {
          if (!entry.isDirectory) {
            // ok: typescript-zip-slip
            const safePath = sanitizeEntryPath(entry.entryName, outputDir);
            if (!safePath) {
              console.log(`Skipping potentially malicious entry: ${entry.entryName}`);
              skippedCount++;
              return;
            }
            
            fs.mkdirSync(path.dirname(safePath), { recursive: true });
            fs.writeFileSync(safePath, entry.getData());
            extractedCount++;
          }
        });
        
        res.send(`Downloaded and extracted ${extractedCount} files successfully. Skipped ${skippedCount} potentially malicious entries.`);
      });
    }).on('error', (err) => {
      res.status(500).send(`Error: ${err.message}`);
    });
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_12() {
  // Utility to validate zip entry paths
  function validatePath(entryPath: string, targetDir: string): string | null {
    // ok: typescript-zip-slip
    if (entryPath.includes('..') || path.isAbsolute(entryPath)) {
      return null;
    }
    
    const fullPath = path.join(targetDir, entryPath);
    const normalizedPath = path.normalize(fullPath);
    const normalizedTargetDir = path.normalize(targetDir);
    
    if (!normalizedPath.startsWith(normalizedTargetDir)) {
      return null;
    }
    
    return normalizedPath;
  }
  
  const extractZipToDirectory = (zipPath: string, targetDir: string) => {
    return new Promise<void>((resolve, reject) => {
      const safeTargetDir = path.resolve(targetDir);
      
      fs.createReadStream(zipPath)
        .pipe(unzipper.Parse())
        .on('entry', (entry) => {
          const entryPath = entry.path;
          
          // ok: typescript-zip-slip
          const safePath = validatePath(entryPath, safeTargetDir);
          if (!safePath) {
            console.log(`Skipping potentially malicious entry: ${entryPath}`);
            entry.autodrain();
            return;
          }
          
          if (entry.type === 'Directory') {
            fs.mkdirSync(safePath, { recursive: true });
          } else {
            entry.pipe(fs.createWriteStream(safePath));
          }
        })
        .on('close', resolve)
        .on('error', reject);
    });
  };
  
  const app = express();
  app.post('/extract', multer({ dest: 'uploads/' }).single('zipfile'), (req, res) => {
    extractZipToDirectory(req.file.path, req.body.targetDir || './extracted')
      .then(() => res.send('Extraction complete'))
      .catch(err => res.status(500).send(`Error: ${err.message}`));
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_13() {
  class ZipExtractor {
    private zipPath: string;
    private outputDir: string;
    
    constructor(zipPath: string, outputDir: string) {
      this.zipPath = zipPath;
      this.outputDir = path.resolve(outputDir);
    }
    
    private isPathSafe(entryName: string): boolean {
      // ok: typescript-zip-slip
      if (entryName.includes('..') || path.isAbsolute(entryName)) {
        return false;
      }
      
      const fullPath = path.join(this.outputDir, entryName);
      const normalizedPath = path.normalize(fullPath);
      
      return normalizedPath.startsWith(this.outputDir);
    }
    
    public async extract(): Promise<{ extracted: number, skipped: number }> {
      const zip = new AdmZip(this.zipPath);
      const entries = zip.getEntries();
      let extracted = 0;
      let skipped = 0;
      
      for (const entry of entries) {
        if (entry.isDirectory) continue;
        
        const entryName = entry.entryName;
        
        // ok: typescript-zip-slip
        if (!this.isPathSafe(entryName)) {
          console.log(`Skipping potentially malicious entry: ${entryName}`);
          skipped++;
          continue;
        }
        
        const content = entry.getData();
        const targetPath = path.join(this.outputDir, entryName);
        
        await fs.promises.mkdir(path.dirname(targetPath), { recursive: true });
        await fs.promises.writeFile(targetPath, content);
        extracted++;
      }
      
      return { extracted, skipped };
    }
  }
  
  const app = express();
  app.post('/extract-zip', multer({ dest: 'uploads/' }).single('zipfile'), async (req, res) => {
    try {
      const extractor = new ZipExtractor(req.file.path, './extracted');
      const result = await extractor.extract();
      res.send(`Extraction successful: ${result.extracted} files extracted, ${result.skipped} files skipped`);
    } catch (err) {
      res.status(500).send(`Error: ${err.message}`);
    }
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_14() {
  // Path validation utility
  function validateZipEntryPath(entryPath: string, baseDir: string): string | null {
    // ok: typescript-zip-slip
    if (!entryPath || entryPath.includes('..') || path.isAbsolute(entryPath)) {
      return null;
    }
    
    const fullPath = path.join(baseDir, entryPath);
    const normalizedPath = path.normalize(fullPath);
    const normalizedBaseDir = path.normalize(baseDir);
    
    if (!normalizedPath.startsWith(normalizedBaseDir)) {
      return null;
    }
    
    return normalizedPath;
  }
  
  async function extractZipFromUrl(url: string, outputDir: string): Promise<{ extracted: number, skipped: number }> {
    return new Promise((resolve, reject) => {
      const safeOutputDir = path.resolve(outputDir);
      let extracted = 0;
      let skipped = 0;
      
      https.get(url, (response) => {
        if (response.statusCode !== 200) {
          reject(new Error(`Failed to download: ${response.statusCode}`));
          return;
        }
        
        const chunks: Buffer[] = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', async () => {
          try {
            const buffer = Buffer.concat(chunks);
            const jszip = new JSZip();
            const zip = await jszip.loadAsync(buffer);
            
            for (const [filename, file] of Object.entries(zip.files)) {
              if (file.dir) continue;
              
              // ok: typescript-zip-slip
              const safePath = validateZipEntryPath(filename, safeOutputDir);
              if (!safePath) {
                console.log(`Skipping potentially malicious entry: ${filename}`);
                skipped++;
                continue;
              }
              
              const content = await file.async('nodebuffer');
              await fs.promises.mkdir(path.dirname(safePath), { recursive: true });
              await fs.promises.writeFile(safePath, content);
              extracted++;
            }
            
            resolve({ extracted, skipped });
          } catch (err) {
            reject(err);
          }
        });
      }).on('error', reject);
    });
  }
  
  const app = express();
  app.get('/extract-from-url', async (req, res) => {
    try {
      const result = await extractZipFromUrl(req.query.url as string, './downloads');
      res.send(`Extraction complete: ${result.extracted} files extracted, ${result.skipped} files skipped`);
    } catch (err) {
      res.status(500).send(`Error: ${err.message}`);
    }
  });
}
// {/fact}

// {fact rule=path-traversal@v1.0 defects=0}
function good_case_15() {
  // Path validation utility
  function isValidZipEntryPath(entryPath: string, baseDir: string): boolean {
    // ok: typescript-zip-slip
    if (entryPath.includes('..') || path.isAbsolute(entryPath)) {
      return false;
    }
    
    const fullPath = path.join(baseDir, entryPath);
    const normalizedPath = path.normalize(fullPath);
    const normalizedBaseDir = path.normalize(baseDir);
    
    return normalizedPath.startsWith(normalizedBaseDir);
  }
  
  function processZipEntries(zipFilePath: string, callback: (fileName: string, content: Buffer) => void): Promise<{ processed: number, skipped: number }> {
    return new Promise((resolve, reject) => {
      let processed = 0;
      let skipped = 0;
      
      yauzl.open(zipFilePath, { lazyEntries: true }, (err, zipfile) => {
        if (err) return reject(err);
        
        zipfile.on('entry', (entry) => {
          if (/\/$/.test(entry.fileName)) {
            // Directory entry
            zipfile.readEntry();
          } else {
            // File entry
            zipfile.openReadStream(entry, (err, stream) => {
              if (err) return reject(err);
              
              const chunks: Buffer[] = [];
              stream.on('data', (chunk) => chunks.push(chunk));
              stream.on('end', () => {
                const content = Buffer.concat(chunks);
                
                // ok: typescript-zip-slip
                if (isValidZipEntryPath(entry.fileName, './processed')) {
                  callback(entry.fileName, content);
                  processed++;
                } else {
                  console.log(`Skipping potentially malicious entry: ${entry.fileName}`);
                  skipped++;
                }
                
                zipfile.readEntry();
              });
            });
          }
        });
        
        zipfile.on('end', () => resolve({ processed, skipped }));
        zipfile.readEntry();
      });
    });
  }
  
  const app = express();
  app.post('/process-zip', multer({ dest: 'uploads/' }).single('zipfile'), async (req, res) => {
    try {
      const outputDir = path.resolve('./processed');
      
      const result = await processZipEntries(req.file.path, (fileName, content) => {
        const outputPath = path.join(outputDir, fileName);
        fs.mkdirSync(path.dirname(outputPath), { recursive: true });
        fs.writeFileSync(outputPath, content);
      });
      
      res.send(`Processing complete: ${result.processed} files processed, ${result.skipped} files skipped`);
    } catch (err) {
      res.status(500).send(`Error: ${err.message}`);
    }
  });
}
// {/fact}