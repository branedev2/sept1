const express = require('express');
const path = require('path');
const fs = require('fs');
const http = require('http');
const serveStatic = require('serve-static');
const serveIndex = require('serve-index');
const Koa = require('koa');
const koaStatic = require('koa-static');
const fastify = require('fastify');
const staticPlugin = require('fastify-static');
const hapi = require('@hapi/hapi');
const inert = require('@hapi/inert');
const connect = require('connect');

// True Positives (Vulnerable Code)

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  // ruleid: javascript-private-file-exposure
  app.use('/libs', express.static('node_modules'));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  // ruleid: javascript-private-file-exposure
  app.use(express.static(path.join(__dirname, 'node_modules')));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  const nodeModulesPath = 'node_modules';
  // ruleid: javascript-private-file-exposure
  app.use('/vendor', express.static(nodeModulesPath));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  // ruleid: javascript-private-file-exposure
  app.use('/packages', serveStatic('node_modules'));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  // ruleid: javascript-private-file-exposure
  app.use('/browse', serveIndex('node_modules', { 'icons': true }));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_6() {
  const koa = new Koa();
  // ruleid: javascript-private-file-exposure
  koa.use(koaStatic('node_modules'));
  koa.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_7() {
  const koa = new Koa();
  // ruleid: javascript-private-file-exposure
  koa.use(koaStatic(path.join(__dirname, 'node_modules')));
  koa.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_8() {
  const server = fastify();
  // ruleid: javascript-private-file-exposure
  server.register(staticPlugin, {
    root: path.join(__dirname, 'node_modules'),
    prefix: '/dependencies/'
  });
  server.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_9() {
  const init = async () => {
    const server = hapi.server({
      port: 3000,
      host: 'localhost'
    });
    
    await server.register(inert);
    
    // ruleid: javascript-private-file-exposure
    server.route({
      method: 'GET',
      path: '/modules/{param*}',
      handler: {
        directory: {
          path: 'node_modules'
        }
      }
    });
    
    await server.start();
  };
  init();
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_10() {
  const app = connect();
  // ruleid: javascript-private-file-exposure
  app.use('/dependencies', serveStatic('node_modules'));
  http.createServer(app).listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  const publicPath = path.resolve(__dirname, 'public');
  const nodeModulesPath = path.resolve(__dirname, 'node_modules');
  
  app.use('/public', express.static(publicPath));
  // ruleid: javascript-private-file-exposure
  app.use('/modules', express.static(nodeModulesPath));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_12() {
  const http = require('http');
  const finalhandler = require('finalhandler');
  const serveStatic = require('serve-static');
  
  // ruleid: javascript-private-file-exposure
  const serve = serveStatic('node_modules');
  
  const server = http.createServer((req, res) => {
    serve(req, res, finalhandler(req, res));
  });
  
  server.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  const config = {
    staticDirs: ['public', 'assets', 'node_modules']
  };
  
  config.staticDirs.forEach(dir => {
    if (dir === 'node_modules') {
      // ruleid: javascript-private-file-exposure
      app.use(`/${dir}`, express.static(dir));
    } else {
      app.use(`/${dir}`, express.static(dir));
    }
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  const paths = {
    styles: 'public/css',
    scripts: 'public/js',
    vendor: 'node_modules'
  };
  
  // ruleid: javascript-private-file-exposure
  app.use('/vendor', express.static(paths.vendor));
  app.use('/css', express.static(paths.styles));
  app.use('/js', express.static(paths.scripts));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  function setupStaticRoutes() {
    // ruleid: javascript-private-file-exposure
    app.use('/npm-packages', express.static('node_modules'));
  }
  
  setupStaticRoutes();
  app.listen(3000);
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_1() {
  const app = express();
  // ok: javascript-private-file-exposure
  app.use('/libs', express.static('public/libs'));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_2() {
  const app = express();
  // ok: javascript-private-file-exposure
  app.use(express.static(path.join(__dirname, 'public')));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_3() {
  const app = express();
  // ok: javascript-private-file-exposure
  app.use('/vendor', express.static('vendor'));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_4() {
  const app = express();
  // ok: javascript-private-file-exposure
  app.use('/specific-module', express.static('node_modules/specific-module/dist'));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_5() {
  const app = express();
  // ok: javascript-private-file-exposure
  app.use('/bootstrap', express.static('node_modules/bootstrap/dist'));
  app.use('/jquery', express.static('node_modules/jquery/dist'));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_6() {
  const koa = new Koa();
  // ok: javascript-private-file-exposure
  koa.use(koaStatic('public'));
  koa.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_7() {
  const koa = new Koa();
  // ok: javascript-private-file-exposure
  koa.use(koaStatic(path.join(__dirname, 'assets')));
  koa.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_8() {
  const server = fastify();
  // ok: javascript-private-file-exposure
  server.register(staticPlugin, {
    root: path.join(__dirname, 'public'),
    prefix: '/static/'
  });
  server.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_9() {
  const init = async () => {
    const server = hapi.server({
      port: 3000,
      host: 'localhost'
    });
    
    await server.register(inert);
    
    // ok: javascript-private-file-exposure
    server.route({
      method: 'GET',
      path: '/static/{param*}',
      handler: {
        directory: {
          path: 'public'
        }
      }
    });
    
    await server.start();
  };
  init();
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_10() {
  const app = connect();
  // ok: javascript-private-file-exposure
  app.use('/static', serveStatic('public'));
  http.createServer(app).listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  // Create a custom middleware to serve only specific files from node_modules
  const serveSpecificNodeModules = (req, res, next) => {
    const allowedModules = ['jquery', 'bootstrap', 'react'];
    const urlParts = req.url.split('/');
    
    if (urlParts.length >= 2 && allowedModules.includes(urlParts[1])) {
      // ok: javascript-private-file-exposure
      const filePath = path.join(__dirname, 'node_modules', urlParts[1], 'dist');
      express.static(filePath)(req, res, next);
    } else {
      next();
    }
  };
  
  app.use('/vendor', serveSpecificNodeModules);
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_12() {
  const app = express();
  
  // ok: javascript-private-file-exposure
  fs.readdir('node_modules', (err, dirs) => {
    if (err) return;
    
    dirs.forEach(dir => {
      const distPath = path.join('node_modules', dir, 'dist');
      if (fs.existsSync(distPath)) {
        app.use(`/vendor/${dir}`, express.static(distPath));
      }
    });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_13() {
  const app = express();
  
  // Copy necessary files from node_modules to public directory
  const vendorDir = path.join(__dirname, 'public', 'vendor');
  if (!fs.existsSync(vendorDir)) {
    fs.mkdirSync(vendorDir, { recursive: true });
  }
  
  // ok: javascript-private-file-exposure
  app.use('/vendor', express.static(vendorDir));
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  // ok: javascript-private-file-exposure
  app.get('/package-info', (req, res) => {
    const packagePath = path.join(__dirname, 'package.json');
    fs.readFile(packagePath, 'utf8', (err, data) => {
      if (err) {
        return res.status(500).send('Error reading package info');
      }
      
      const packageInfo = JSON.parse(data);
      // Only expose non-sensitive information
      const safeInfo = {
        name: packageInfo.name,
        version: packageInfo.version,
        description: packageInfo.description,
        author: packageInfo.author,
        license: packageInfo.license
      };
      
      res.json(safeInfo);
    });
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=sensitive-information-leak@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  // ok: javascript-private-file-exposure
  app.use('/assets', express.static('public/assets'));
  app.use('/images', express.static('public/images'));
  app.use('/css', express.static('public/css'));
  app.use('/js', express.static('public/js'));
  
  app.listen(3000);
}
// {/fact}