// File: private_file_exposure_test.ts
import express from 'express';
import path from 'path';
import fs from 'fs';
import { Request, Response } from 'express';
import Koa from 'koa';
import serve from 'koa-static';
import serveStatic from 'serve-static';
import http from 'http';
import fastify from 'fastify';
import fastifyStatic from '@fastify/static';

// TRUE POSITIVES - Vulnerable code that should be detected

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  // ruleid: typescript-private-file-exposure
  app.use(express.static('node_modules'));
  
  app.listen(3000, () => {
    console.log('Server running on port 3000');
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  // ruleid: typescript-private-file-exposure
  app.use('/vendor', express.static(path.join(__dirname, 'node_modules')));
  
  app.listen(3000, () => {
    console.log('Server running on port 3000');
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  const nodeModulesPath = path.resolve(__dirname, 'node_modules');
  // ruleid: typescript-private-file-exposure
  app.use('/libs', express.static(nodeModulesPath));
  
  app.listen(3000, () => {
    console.log('Server running on port 3000');
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_4() {
  const app = new Koa();
  // ruleid: typescript-private-file-exposure
  app.use(serve('node_modules'));
  
  app.listen(3000, () => {
    console.log('Koa server running on port 3000');
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_5() {
  const app = new Koa();
  const nodeModulesPath = path.join(process.cwd(), 'node_modules');
  // ruleid: typescript-private-file-exposure
  app.use(serve(nodeModulesPath));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_6() {
  const server = http.createServer((req, res) => {
    // ruleid: typescript-private-file-exposure
    serveStatic('node_modules')(req, res, () => {
      res.statusCode = 404;
      res.end('Not found');
    });
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  const options = { dotfiles: 'allow', etag: false };
  // ruleid: typescript-private-file-exposure
  app.use('/packages', express.static('node_modules', options));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_8() {
  const app = fastify();
  // ruleid: typescript-private-file-exposure
  app.register(fastifyStatic, {
    root: path.join(__dirname, 'node_modules'),
    prefix: '/npm/'
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  const publicPath = 'node_modules';
  // ruleid: typescript-private-file-exposure
  app.use(express.static(publicPath));
  
  app.get('/api', (req: Request, res: Response) => {
    res.json({ message: 'API works' });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  // ruleid: typescript-private-file-exposure
  app.use('/dependencies', express.static(path.join(__dirname, 'node_modules')));
  app.use('/public', express.static(path.join(__dirname, 'public')));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  const env = process.env.NODE_ENV || 'development';
  if (env === 'development') {
    // ruleid: typescript-private-file-exposure
    app.use('/dev-deps', express.static('node_modules'));
  }
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  const config = {
    staticPaths: [
      { route: '/assets', path: 'public' },
      { route: '/vendor', path: 'node_modules' } // This is problematic
    ]
  };
  
  config.staticPaths.forEach(item => {
    if (item.path === 'node_modules') {
      // ruleid: typescript-private-file-exposure
      app.use(item.route, express.static(item.path));
    } else {
      app.use(item.route, express.static(item.path));
    }
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  const nodeModulesDir = 'node_modules';
  const serveNodeModules = () => {
    // ruleid: typescript-private-file-exposure
    app.use('/npm', express.static(nodeModulesDir));
  };
  
  serveNodeModules();
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  const paths = {
    public: 'public',
    nodeModules: 'node_modules',
    dist: 'dist'
  };
  
  // ruleid: typescript-private-file-exposure
  app.use('/modules', express.static(paths.nodeModules));
  app.use('/static', express.static(paths.public));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  const serveOptions = { maxAge: '1d', index: false };
  const nodeModulesPath = path.resolve('node_modules');
  
  // ruleid: typescript-private-file-exposure
  app.use('/external', express.static(nodeModulesPath, serveOptions));
  
  app.listen(3000);
}
// {/fact}

// TRUE NEGATIVES - Secure code that should not be detected

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_1() {
  const app = express();
  // ok: typescript-private-file-exposure
  app.use(express.static('public'));
  
  app.listen(3000, () => {
    console.log('Server running on port 3000');
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_2() {
  const app = express();
  // ok: typescript-private-file-exposure
  app.use('/assets', express.static(path.join(__dirname, 'dist')));
  
  app.listen(3000, () => {
    console.log('Server running on port 3000');
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_3() {
  const app = express();
  // ok: typescript-private-file-exposure
  app.use('/vendor', express.static(path.join(__dirname, 'vendor_libs')));
  
  app.listen(3000, () => {
    console.log('Server running on port 3000');
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_4() {
  const app = new Koa();
  // ok: typescript-private-file-exposure
  app.use(serve('public'));
  
  app.listen(3000, () => {
    console.log('Koa server running on port 3000');
  });
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_5() {
  const app = new Koa();
  const publicPath = path.join(process.cwd(), 'public');
  // ok: typescript-private-file-exposure
  app.use(serve(publicPath));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_6() {
  const server = http.createServer((req, res) => {
    // ok: typescript-private-file-exposure
    serveStatic('public')(req, res, () => {
      res.statusCode = 404;
      res.end('Not found');
    });
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_7() {
  const app = express();
  // Serve specific files from node_modules instead of the whole directory
  // ok: typescript-private-file-exposure
  app.get('/vendor/jquery.min.js', (req, res) => {
    res.sendFile(path.join(__dirname, 'node_modules', 'jquery', 'dist', 'jquery.min.js'));
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_8() {
  const app = fastify();
  // ok: typescript-private-file-exposure
  app.register(fastifyStatic, {
    root: path.join(__dirname, 'public'),
    prefix: '/static/'
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_9() {
  const app = express();
  // Create a whitelist of specific node_modules files to serve
  const allowedFiles = [
    'bootstrap/dist/css/bootstrap.min.css',
    'jquery/dist/jquery.min.js'
  ];
  
  // ok: typescript-private-file-exposure
  app.get('/vendor/:file', (req: Request, res: Response) => {
    const requestedFile = req.params.file;
    const matchedFile = allowedFiles.find(file => file.endsWith(requestedFile));
    
    if (matchedFile) {
      res.sendFile(path.join(__dirname, 'node_modules', matchedFile));
    } else {
      res.status(404).send('Not found');
    }
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_10() {
  const app = express();
  // Copy required files from node_modules to a public directory during build
  // and serve from there instead
  // ok: typescript-private-file-exposure
  app.use('/vendor', express.static(path.join(__dirname, 'public/vendor')));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_11() {
  const app = express();
  // ok: typescript-private-file-exposure
  app.use('/assets', express.static('assets'));
  app.use('/images', express.static('images'));
  app.use('/css', express.static('css'));
  app.use('/js', express.static('js'));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_12() {
  const app = express();
  const config = {
    staticPaths: [
      { route: '/assets', path: 'public' },
      { route: '/images', path: 'images' }
    ]
  };
  
  // ok: typescript-private-file-exposure
  config.staticPaths.forEach(item => {
    app.use(item.route, express.static(item.path));
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_13() {
  const app = express();
  // Create a custom middleware to serve only specific files from node_modules
  // ok: typescript-private-file-exposure
  app.use('/vendor', (req: Request, res: Response, next) => {
    const allowedPaths = [
      '/bootstrap/dist/css/bootstrap.min.css',
      '/jquery/dist/jquery.min.js'
    ];
    
    if (allowedPaths.includes(req.path)) {
      const filePath = path.join(__dirname, 'node_modules', req.path);
      res.sendFile(filePath);
    } else {
      next();
    }
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_14() {
  const app = express();
  // Use a CDN instead of serving from node_modules
  // ok: typescript-private-file-exposure
  app.get('/', (req: Request, res: Response) => {
    res.send(`
      <!DOCTYPE html>
      <html>
        <head>
          <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css">
          <script src="https://cdn.jsdelivr.net/npm/jquery@3.6.3/dist/jquery.min.js"></script>
        </head>
        <body>
          <h1>Hello World</h1>
        </body>
      </html>
    `);
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_15() {
  const app = express();
  // Bundle required node_modules during build process
  // and serve the bundled file
  // ok: typescript-private-file-exposure
  app.use('/js', express.static('dist/js'));
  app.use('/css', express.static('dist/css'));
  
  app.listen(3000);
}
// {/fact}