// Express.js sendFile Path Traversal Vulnerability Test Cases
const express = require('express');
const path = require('path');
const fs = require('fs');
const app = express();

// True Positive Examples (Vulnerable Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1(req, res) {
  // Direct use of user input in sendFile
  const fileName = req.query.file;
  // ruleid: javascript-express-sendfile-injection
  res.sendFile(fileName);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2(req, res) {
  // Using user input from POST body
  const userFile = req.body.document;
  // ruleid: javascript-express-sendfile-injection
  res.sendFile(userFile);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3(req, res) {
  // Using path concatenation with user input
  const userDir = req.query.directory;
  const filePath = userDir + '/index.html';
  // ruleid: javascript-express-sendfile-injection
  res.sendFile(filePath);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4(req, res) {
  // Using input from request headers
  const requestedFile = req.headers['x-requested-file'];
  // ruleid: javascript-express-sendfile-injection
  res.sendFile(requestedFile);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5(req, res) {
  // Using input from URL parameters
  const fileId = req.params.id;
  const filePath = `/var/www/files/${fileId}`;
  // ruleid: javascript-express-sendfile-injection
  res.sendFile(filePath);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6(req, res) {
  // Using input with template literals
  const fileName = req.query.name;
  // ruleid: javascript-express-sendfile-injection
  res.sendFile(`/var/www/html/${fileName}`);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7(req, res) {
  // Using input from cookies
  const theme = req.cookies.theme;
  const themePath = `/themes/${theme}/style.css`;
  // ruleid: javascript-express-sendfile-injection
  res.sendFile(themePath);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8(req, res) {
  // Using input with string concatenation in multiple steps
  let basePath = '/var/www/';
  let userPath = req.query.path;
  let fullPath = basePath + userPath;
  // ruleid: javascript-express-sendfile-injection
  res.sendFile(fullPath);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9(req, res) {
  // Using input with path.join but still vulnerable
  const userFile = req.query.file;
  const filePath = path.join('public', userFile);
  // ruleid: javascript-express-sendfile-injection
  res.sendFile(filePath);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10(req, res) {
  // Using input with conditional logic
  let filePath;
  if (req.query.admin === 'true') {
    filePath = '/admin/' + req.query.file;
  } else {
    filePath = '/user/' + req.query.file;
  }
  // ruleid: javascript-express-sendfile-injection
  res.sendFile(filePath);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11(req, res) {
  // Using input with array indexing
  const files = req.body.files;
  const index = req.query.index || 0;
  // ruleid: javascript-express-sendfile-injection
  res.sendFile(files[index]);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12(req, res) {
  // Using input with object property access
  const userPrefs = JSON.parse(req.body.preferences);
  // ruleid: javascript-express-sendfile-injection
  res.sendFile(userPrefs.defaultDocument);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13(req, res) {
  // Using input with string manipulation
  const fileName = req.query.file.replace('./', ''); // Insufficient sanitization
  // ruleid: javascript-express-sendfile-injection
  res.sendFile(fileName);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14(req, res) {
  // Using input with ternary operator
  const file = req.query.file ? req.query.file : 'default.html';
  // ruleid: javascript-express-sendfile-injection
  res.sendFile(file);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15(req, res) {
  // Using input with destructuring assignment
  const { document } = req.query;
  // ruleid: javascript-express-sendfile-injection
  res.sendFile(document);
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1(req, res) {
  // Using a fixed file path
  // ok: javascript-express-sendfile-injection
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2(req, res) {
  // Validating file extension and using absolute path
  const fileName = req.query.file;
  if (!/^[a-zA-Z0-9_-]+\.pdf$/.test(fileName)) {
    return res.status(400).send('Invalid filename');
  }
  // ok: javascript-express-sendfile-injection
  res.sendFile(path.join(__dirname, 'pdfs', fileName));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3(req, res) {
  // Using path.resolve with __dirname to ensure files are within a directory
  const fileName = req.query.file;
  const filePath = path.resolve(__dirname, 'public', fileName);
  
  // Ensure the file is within the public directory
  if (!filePath.startsWith(path.resolve(__dirname, 'public'))) {
    return res.status(403).send('Forbidden');
  }
  
  // ok: javascript-express-sendfile-injection
  res.sendFile(filePath);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4(req, res) {
  // Using a whitelist of allowed files
  const allowedFiles = ['report.pdf', 'terms.pdf', 'privacy.pdf'];
  const requestedFile = req.query.file;
  
  if (!allowedFiles.includes(requestedFile)) {
    return res.status(404).send('File not found');
  }
  
  // ok: javascript-express-sendfile-injection
  res.sendFile(path.join(__dirname, 'documents', requestedFile));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5(req, res) {
  // Using options object with root parameter
  const fileName = req.query.file;
  
  if (!/^[a-zA-Z0-9_-]+\.(jpg|png|gif)$/.test(fileName)) {
    return res.status(400).send('Invalid image file');
  }
  
  // ok: javascript-express-sendfile-injection
  res.sendFile(fileName, { root: path.join(__dirname, 'images') });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6(req, res) {
  // Using a mapping object to translate user input to safe file paths
  const fileMap = {
    'profile': 'user-profile.html',
    'settings': 'user-settings.html',
    'dashboard': 'user-dashboard.html'
  };
  
  const page = req.query.page;
  const safeFileName = fileMap[page] || 'default.html';
  
  // ok: javascript-express-sendfile-injection
  res.sendFile(path.join(__dirname, 'templates', safeFileName));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7(req, res) {
  // Using numeric ID to fetch file from a predefined location
  const fileId = parseInt(req.params.id, 10);
  
  if (isNaN(fileId) || fileId < 1 || fileId > 100) {
    return res.status(400).send('Invalid file ID');
  }
  
  const safeFileName = `file-${fileId}.pdf`;
  // ok: javascript-express-sendfile-injection
  res.sendFile(path.join(__dirname, 'documents', safeFileName));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8(req, res) {
  // Using path normalization and validation
  let requestedFile = req.query.file || 'index.html';
  
  // Normalize the path to remove any ../ sequences
  const normalizedPath = path.normalize(requestedFile).replace(/^(\.\.(\/|\\|$))+/, '');
  
  // Ensure file has .html extension
  if (!normalizedPath.endsWith('.html')) {
    return res.status(400).send('Only HTML files are allowed');
  }
  
  // ok: javascript-express-sendfile-injection
  res.sendFile(path.join(__dirname, 'public', normalizedPath));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9(req, res) {
  // Using UUID as filename with fixed extension
  const fileUuid = req.params.uuid;
  
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(fileUuid)) {
    return res.status(400).send('Invalid file identifier');
  }
  
  // ok: javascript-express-sendfile-injection
  res.sendFile(path.join(__dirname, 'uploads', `${fileUuid}.pdf`));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10(req, res) {
  // Using database ID to determine file path
  const productId = parseInt(req.params.id, 10);
  
  if (isNaN(productId)) {
    return res.status(400).send('Invalid product ID');
  }
  
  // In a real app, you'd fetch the actual filename from a database
  // Here we're creating a safe filename based on the ID
  const safeFileName = `product-${productId}.jpg`;
  
  // ok: javascript-express-sendfile-injection
  res.sendFile(path.join(__dirname, 'products', safeFileName));
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11(req, res) {
  // Using a hash function to map user input to files
  const crypto = require('crypto');
  const userRequest = req.query.document;
  
  // Create a hash of the user input
  const hash = crypto.createHash('md5').update(userRequest).digest('hex');
  
  // Check if the file exists (in a real app)
  const filePath = path.join(__dirname, 'cache', `${hash}.pdf`);
  
  if (!fs.existsSync(filePath)) {
    return res.status(404).send('Document not found');
  }
  
  // ok: javascript-express-sendfile-injection
  res.sendFile(filePath);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12(req, res) {
  // Using options object with dotfiles: 'deny' for additional security
  const staticFile = 'index.html'; // Fixed filename
  
  // ok: javascript-express-sendfile-injection
  res.sendFile(path.join(__dirname, 'public', staticFile), {
    dotfiles: 'deny',
    headers: {
      'Content-Type': 'text/html',
      'X-Content-Type-Options': 'nosniff'
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13(req, res) {
  // Using a function to validate file path is within allowed directory
  const requestedFile = req.query.file;
  
  function isPathSafe(filePath, directory) {
    const resolvedPath = path.resolve(filePath);
    const resolvedDirectory = path.resolve(directory);
    return resolvedPath.startsWith(resolvedDirectory);
  }
  
  const fullPath = path.join(__dirname, 'downloads', requestedFile);
  
  if (!isPathSafe(fullPath, path.join(__dirname, 'downloads'))) {
    return res.status(403).send('Access denied');
  }
  
  // ok: javascript-express-sendfile-injection
  res.sendFile(fullPath);
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14(req, res) {
  // Using a configuration object to map user-friendly names to actual files
  const documentMap = {
    'terms': { file: 'terms-of-service-v2.pdf', type: 'application/pdf' },
    'privacy': { file: 'privacy-policy-2023.pdf', type: 'application/pdf' },
    'faq': { file: 'frequently-asked-questions.html', type: 'text/html' }
  };
  
  const docType = req.query.type;
  const docInfo = documentMap[docType];
  
  if (!docInfo) {
    return res.status(404).send('Document not found');
  }
  
  // ok: javascript-express-sendfile-injection
  res.sendFile(path.join(__dirname, 'legal', docInfo.file), {
    headers: { 'Content-Type': docInfo.type }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15(req, res) {
  // Using environment variables to determine base path with fixed subpath
  const env = process.env.NODE_ENV || 'development';
  const basePath = env === 'production' ? '/var/www/app' : __dirname;
  
  // ok: javascript-express-sendfile-injection
  res.sendFile(path.join(basePath, 'static', 'help.pdf'));
}
// {/fact}

// Set up routes
app.get('/bad1', bad_case_1);
app.post('/bad2', bad_case_2);
app.get('/bad3', bad_case_3);
app.get('/bad4', bad_case_4);
app.get('/bad5/:id', bad_case_5);
app.get('/bad6', bad_case_6);
app.get('/bad7', bad_case_7);
app.get('/bad8', bad_case_8);
app.get('/bad9', bad_case_9);
app.get('/bad10', bad_case_10);
app.post('/bad11', bad_case_11);
app.post('/bad12', bad_case_12);
app.get('/bad13', bad_case_13);
app.get('/bad14', bad_case_14);
app.get('/bad15', bad_case_15);

app.get('/good1', good_case_1);
app.get('/good2', good_case_2);
app.get('/good3', good_case_3);
app.get('/good4', good_case_4);
app.get('/good5', good_case_5);
app.get('/good6', good_case_6);
app.get('/good7/:id', good_case_7);
app.get('/good8', good_case_8);
app.get('/good9/:uuid', good_case_9);
app.get('/good10/:id', good_case_10);
app.get('/good11', good_case_11);
app.get('/good12', good_case_12);
app.get('/good13', good_case_13);
app.get('/good14', good_case_14);
app.get('/good15', good_case_15);

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});