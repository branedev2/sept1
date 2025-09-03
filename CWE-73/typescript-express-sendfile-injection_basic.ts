import express from 'express';
import path from 'path';
import { Request, Response } from 'express';
import * as fs from 'fs';
import sanitizeFilename from 'sanitize-filename';
import validator from 'validator';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// True Positive Examples (Vulnerable Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1() {
  app.get('/download', (req: Request, res: Response) => {
    const fileName = req.query.file as string;
    // ruleid: typescript-express-sendfile-injection
    res.sendFile(fileName);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2() {
  app.post('/get-document', (req: Request, res: Response) => {
    const documentPath = req.body.path;
    // ruleid: typescript-express-sendfile-injection
    res.sendFile(documentPath);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3() {
  app.get('/view-file', (req: Request, res: Response) => {
    const userFile = req.params.filename;
    const filePath = path.join('public', userFile);
    // ruleid: typescript-express-sendfile-injection
    res.sendFile(filePath);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4() {
  app.get('/api/files/:type/:name', (req: Request, res: Response) => {
    const { type, name } = req.params;
    const filePath = `./uploads/${type}/${name}`;
    // ruleid: typescript-express-sendfile-injection
    res.sendFile(filePath);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5() {
  app.get('/download-file', (req: Request, res: Response) => {
    let fileName = req.query.name as string;
    if (fileName.endsWith('.pdf')) {
      // ruleid: typescript-express-sendfile-injection
      res.sendFile(`./documents/${fileName}`);
    } else {
      res.status(400).send('Invalid file type');
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6() {
  app.get('/user-profile-pic', (req: Request, res: Response) => {
    const userId = req.query.id as string;
    const profilePic = req.query.pic as string;
    const filePath = `./users/${userId}/images/${profilePic}`;
    // ruleid: typescript-express-sendfile-injection
    res.sendFile(filePath);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7() {
  app.get('/serve-asset', (req: Request, res: Response) => {
    const assetPath = req.headers['x-asset-path'] as string;
    // ruleid: typescript-express-sendfile-injection
    res.sendFile(assetPath);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8() {
  app.get('/download-report', (req: Request, res: Response) => {
    const reportId = req.query.id as string;
    const reportName = req.query.name as string;
    const filePath = reportId + '/' + reportName;
    // ruleid: typescript-express-sendfile-injection
    res.sendFile(filePath, { root: './reports' });
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9() {
  app.get('/template', (req: Request, res: Response) => {
    const template = req.cookies.template;
    // ruleid: typescript-express-sendfile-injection
    res.sendFile(`./templates/${template}`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10() {
  app.get('/download/:category', (req: Request, res: Response) => {
    const category = req.params.category;
    const file = req.query.file as string;
    const filePath = path.join(category, file);
    // ruleid: typescript-express-sendfile-injection
    res.sendFile(filePath, { root: './storage' });
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11() {
  app.post('/get-attachment', (req: Request, res: Response) => {
    const { attachmentId } = req.body;
    let filePath = '';
    
    if (attachmentId.startsWith('invoice-')) {
      filePath = `./invoices/${attachmentId.substring(8)}.pdf`;
    } else {
      filePath = `./attachments/${attachmentId}.pdf`;
    }
    
    // ruleid: typescript-express-sendfile-injection
    res.sendFile(filePath);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12() {
  app.get('/dynamic-content', (req: Request, res: Response) => {
    const contentType = req.query.type as string;
    const contentId = req.query.id as string;
    
    let basePath = '';
    switch (contentType) {
      case 'image':
        basePath = './images';
        break;
      case 'document':
        basePath = './documents';
        break;
      default:
        basePath = './misc';
    }
    
    // ruleid: typescript-express-sendfile-injection
    res.sendFile(`${basePath}/${contentId}`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13() {
  app.get('/legacy-file', (req: Request, res: Response) => {
    const fileId = req.query.id as string;
    const version = req.query.v as string || 'latest';
    
    // ruleid: typescript-express-sendfile-injection
    res.sendFile(`./archive/${fileId}/${version}.dat`);
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14() {
  app.get('/shared-file/:shareId', (req: Request, res: Response) => {
    const shareId = req.params.shareId;
    const filename = req.query.name as string;
    
    // This is still vulnerable despite the conditional check
    if (filename && filename.length > 0) {
      // ruleid: typescript-express-sendfile-injection
      res.sendFile(path.join('./shared', shareId, filename));
    } else {
      res.status(400).send('Missing filename');
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15() {
  app.get('/preview-file', (req: Request, res: Response) => {
    const filePath = req.query.path as string;
    const options = {
      root: './previews',
      dotfiles: 'deny',
      headers: {
        'Content-Type': 'application/pdf'
      }
    };
    
    // ruleid: typescript-express-sendfile-injection
    res.sendFile(filePath, options);
  });
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1() {
  app.get('/download', (req: Request, res: Response) => {
    const fileName = req.query.file as string;
    const safeFileName = sanitizeFilename(fileName);
    // ok: typescript-express-sendfile-injection
    res.sendFile(path.join(__dirname, 'public', safeFileName));
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2() {
  app.post('/get-document', (req: Request, res: Response) => {
    const documentId = req.body.id;
    // Using a whitelist of allowed files
    const allowedDocs = {
      '1': 'document1.pdf',
      '2': 'document2.pdf',
      '3': 'document3.pdf'
    };
    
    if (allowedDocs[documentId]) {
      // ok: typescript-express-sendfile-injection
      res.sendFile(path.join(__dirname, 'documents', allowedDocs[documentId]));
    } else {
      res.status(404).send('Document not found');
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3() {
  app.get('/view-file/:filename', (req: Request, res: Response) => {
    const userFile = req.params.filename;
    const safeFileName = sanitizeFilename(userFile);
    // ok: typescript-express-sendfile-injection
    res.sendFile(path.resolve(__dirname, 'public', safeFileName));
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4() {
  app.get('/api/files/:type/:name', (req: Request, res: Response) => {
    const { type, name } = req.params;
    
    // Validate file type using a whitelist
    const allowedTypes = ['reports', 'images', 'documents'];
    if (!allowedTypes.includes(type)) {
      return res.status(400).send('Invalid file type');
    }
    
    const safeFileName = sanitizeFilename(name);
    // ok: typescript-express-sendfile-injection
    res.sendFile(path.join(__dirname, 'uploads', type, safeFileName));
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5() {
  app.get('/download-file', (req: Request, res: Response) => {
    const fileName = req.query.name as string;
    
    // Validate file extension
    if (!fileName.endsWith('.pdf')) {
      return res.status(400).send('Invalid file type');
    }
    
    const safeFileName = sanitizeFilename(fileName);
    // ok: typescript-express-sendfile-injection
    res.sendFile(path.join(__dirname, 'documents', safeFileName));
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6() {
  app.get('/user-profile-pic', (req: Request, res: Response) => {
    const userId = req.query.id as string;
    const profilePic = req.query.pic as string;
    
    // Validate userId is numeric
    if (!validator.isNumeric(userId)) {
      return res.status(400).send('Invalid user ID');
    }
    
    const safeFileName = sanitizeFilename(profilePic);
    // ok: typescript-express-sendfile-injection
    res.sendFile(path.join(__dirname, 'users', userId, 'images', safeFileName));
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7() {
  app.get('/serve-asset', (req: Request, res: Response) => {
    // Using a fixed path instead of user input
    const assetType = req.query.type as string;
    
    // Whitelist of allowed asset types
    const allowedAssets = {
      'logo': 'logo.png',
      'banner': 'banner.jpg',
      'favicon': 'favicon.ico'
    };
    
    if (allowedAssets[assetType]) {
      // ok: typescript-express-sendfile-injection
      res.sendFile(path.join(__dirname, 'assets', allowedAssets[assetType]));
    } else {
      res.status(404).send('Asset not found');
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8() {
  app.get('/download-report', (req: Request, res: Response) => {
    const reportId = req.query.id as string;
    
    // Validate reportId format (e.g., REP-123)
    if (!reportId.match(/^REP-\d+$/)) {
      return res.status(400).send('Invalid report ID format');
    }
    
    // Map to actual filename
    const reportFilename = `${reportId}.pdf`;
    // ok: typescript-express-sendfile-injection
    res.sendFile(path.join(__dirname, 'reports', reportFilename));
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9() {
  app.get('/template', (req: Request, res: Response) => {
    const template = req.cookies.template;
    
    // Whitelist of allowed templates
    const allowedTemplates = ['basic', 'advanced', 'premium'];
    
    if (allowedTemplates.includes(template)) {
      // ok: typescript-express-sendfile-injection
      res.sendFile(path.join(__dirname, 'templates', `${template}.html`));
    } else {
      res.status(400).send('Invalid template');
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10() {
  app.get('/download/:category', (req: Request, res: Response) => {
    const category = req.params.category;
    const file = req.query.file as string;
    
    // Validate category
    const allowedCategories = ['music', 'videos', 'documents'];
    if (!allowedCategories.includes(category)) {
      return res.status(400).send('Invalid category');
    }
    
    const safeFileName = sanitizeFilename(file);
    // ok: typescript-express-sendfile-injection
    res.sendFile(path.join(__dirname, 'storage', category, safeFileName));
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11() {
  app.post('/get-attachment', (req: Request, res: Response) => {
    const { attachmentId } = req.body;
    
    // Using a database lookup to get the actual filename
    // This is a simplified example - in real code, you'd query a database
    const getAttachmentPath = (id: string): string | null => {
      const attachments = {
        'att1': 'document1.pdf',
        'att2': 'invoice.pdf',
        'att3': 'report.pdf'
      };
      return attachments[id] || null;
    };
    
    const filename = getAttachmentPath(attachmentId);
    if (filename) {
      // ok: typescript-express-sendfile-injection
      res.sendFile(path.join(__dirname, 'attachments', filename));
    } else {
      res.status(404).send('Attachment not found');
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12() {
  app.get('/static-file', (req: Request, res: Response) => {
    // Using only hardcoded paths
    // ok: typescript-express-sendfile-injection
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13() {
  app.get('/download-by-id/:fileId', (req: Request, res: Response) => {
    const fileId = req.params.fileId;
    
    // Validate fileId is a UUID
    if (!validator.isUUID(fileId)) {
      return res.status(400).send('Invalid file ID');
    }
    
    // Map the ID to a file using a function (simulating a database lookup)
    const getFilePathById = (id: string): string => {
      // In a real app, this would query a database
      return path.join(__dirname, 'secure_files', `${id.substring(0, 8)}.pdf`);
    };
    
    // ok: typescript-express-sendfile-injection
    res.sendFile(getFilePathById(fileId));
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14() {
  app.get('/versioned-asset/:version/:asset', (req: Request, res: Response) => {
    const { version, asset } = req.params;
    
    // Validate version format (e.g., v1.2.3)
    if (!version.match(/^v\d+\.\d+\.\d+$/)) {
      return res.status(400).send('Invalid version format');
    }
    
    const safeAssetName = sanitizeFilename(asset);
    // ok: typescript-express-sendfile-injection
    res.sendFile(path.join(__dirname, 'assets', version, safeAssetName));
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15() {
  app.get('/protected-file', (req: Request, res: Response) => {
    // Using a fixed set of files with authentication check
    const fileId = req.query.id as string;
    
    // Simulate authentication check
    const isAuthenticated = req.headers.authorization === 'Bearer valid-token';
    if (!isAuthenticated) {
      return res.status(401).send('Unauthorized');
    }
    
    // Map file IDs to actual paths
    const fileMap: Record<string, string> = {
      'secret1': path.join(__dirname, 'protected', 'confidential.pdf'),
      'secret2': path.join(__dirname, 'protected', 'internal.pdf'),
      'secret3': path.join(__dirname, 'protected', 'classified.pdf')
    };
    
    if (fileMap[fileId]) {
      // ok: typescript-express-sendfile-injection
      res.sendFile(fileMap[fileId]);
    } else {
      res.status(404).send('File not found');
    }
  });
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});