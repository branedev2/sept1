import express from 'express';
import serveStatic from 'serve-static';
import path from 'path';

// True Positive Examples (Vulnerable Code)

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  
  // ruleid: typescript-express-serve-static
  app.use(serveStatic('public', {
    index: ['index.html', 'index.htm']
  }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  const options = {
    dotfiles: 'allow',
    etag: false,
    extensions: ['htm', 'html'],
    index: false,
  };
  
  // ruleid: typescript-express-serve-static
  app.use(serveStatic(path.join(__dirname, 'public'), options));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  const staticOptions = {
    dotfiles: 'allow',
    maxAge: '1d',
    setHeaders: (res: express.Response) => {
      res.set('x-timestamp', Date.now().toString());
    }
  };
  
  // ruleid: typescript-express-serve-static
  app.use('/static', serveStatic('public', staticOptions));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  
  // ruleid: typescript-express-serve-static
  app.use('/assets', serveStatic(path.join(__dirname, 'assets'), { 
    dotfiles: 'allow',
    fallthrough: false
  }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  const config = {
    dotfiles: 'allow',
    immutable: true,
    lastModified: true
  };
  
  // ruleid: typescript-express-serve-static
  app.use('/public', serveStatic('public', config));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  const env = process.env.NODE_ENV || 'development';
  const options = {
    dotfiles: env === 'development' ? 'allow' : 'allow', // Always allow regardless of environment
    etag: true
  };
  
  // ruleid: typescript-express-serve-static
  app.use(serveStatic('public', options));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  
  function createStaticServer(dir: string) {
    // ruleid: typescript-express-serve-static
    return serveStatic(dir, { dotfiles: 'allow' });
  }
  
  app.use('/static', createStaticServer('public'));
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  const staticPaths = ['public', 'assets', 'uploads'];
  
  staticPaths.forEach(dir => {
    // ruleid: typescript-express-serve-static
    app.use(`/${dir}`, serveStatic(dir, { dotfiles: 'allow' }));
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  const dotfilesConfig = 'allow';
  
  // ruleid: typescript-express-serve-static
  app.use(serveStatic('public', { dotfiles: dotfilesConfig }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  const options = { dotfiles: 'allow' as const };
  
  if (process.env.NODE_ENV === 'production') {
    options.maxAge = '1d';
  }
  
  // ruleid: typescript-express-serve-static
  app.use('/static', serveStatic('public', options));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  
  const configureStatic = () => {
    const opts = {
      dotfiles: 'allow',
      etag: true
    };
    
    // ruleid: typescript-express-serve-static
    app.use(serveStatic('public', opts));
  };
  
  configureStatic();
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_12() {
  class StaticServer {
    app: express.Application;
    
    constructor() {
      this.app = express();
      
      // ruleid: typescript-express-serve-static
      this.app.use(serveStatic('public', {
        dotfiles: 'allow',
        index: false
      }));
      
      this.app.listen(3000);
    }
  }
  
  new StaticServer();
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  const allowDotfiles = true;
  
  // ruleid: typescript-express-serve-static
  app.use('/downloads', serveStatic('downloads', {
    dotfiles: allowDotfiles ? 'allow' : 'deny'
  }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  
  const staticMiddleware = serveStatic('public', {
    dotfiles: 'allow',
    redirect: false
  });
  
  // ruleid: typescript-express-serve-static
  app.use(staticMiddleware);
  
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  
  const configureServer = (app: express.Application) => {
    const staticOptions = {
      dotfiles: 'allow',
      extensions: ['html', 'htm']
    };
    
    // ruleid: typescript-express-serve-static
    app.use(serveStatic('public', staticOptions));
  };
  
  configureServer(app);
  app.listen(3000);
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_1() {
  const app = express();
  
  // ok: typescript-express-serve-static
  app.use(serveStatic('public', {
    dotfiles: 'deny',
    index: ['index.html', 'index.htm']
  }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_2() {
  const app = express();
  const options = {
    dotfiles: 'ignore',
    etag: false,
    extensions: ['htm', 'html'],
    index: false,
  };
  
  // ok: typescript-express-serve-static
  app.use(serveStatic(path.join(__dirname, 'public'), options));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_3() {
  const app = express();
  const staticOptions = {
    dotfiles: 'deny',
    maxAge: '1d',
    setHeaders: (res: express.Response) => {
      res.set('x-timestamp', Date.now().toString());
    }
  };
  
  // ok: typescript-express-serve-static
  app.use('/static', serveStatic('public', staticOptions));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_4() {
  const app = express();
  
  // ok: typescript-express-serve-static
  app.use('/assets', serveStatic(path.join(__dirname, 'assets'), { 
    dotfiles: 'ignore',
    fallthrough: false
  }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_5() {
  const app = express();
  const config = {
    dotfiles: 'deny',
    immutable: true,
    lastModified: true
  };
  
  // ok: typescript-express-serve-static
  app.use('/public', serveStatic('public', config));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_6() {
  const app = express();
  const env = process.env.NODE_ENV || 'development';
  const options = {
    dotfiles: 'ignore',
    etag: true
  };
  
  // ok: typescript-express-serve-static
  app.use(serveStatic('public', options));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_7() {
  const app = express();
  
  function createStaticServer(dir: string) {
    // ok: typescript-express-serve-static
    return serveStatic(dir, { dotfiles: 'deny' });
  }
  
  app.use('/static', createStaticServer('public'));
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_8() {
  const app = express();
  const staticPaths = ['public', 'assets', 'uploads'];
  
  staticPaths.forEach(dir => {
    // ok: typescript-express-serve-static
    app.use(`/${dir}`, serveStatic(dir, { dotfiles: 'ignore' }));
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_9() {
  const app = express();
  const dotfilesConfig = 'deny';
  
  // ok: typescript-express-serve-static
  app.use(serveStatic('public', { dotfiles: dotfilesConfig }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_10() {
  const app = express();
  const options = { dotfiles: 'ignore' as const };
  
  if (process.env.NODE_ENV === 'production') {
    options.maxAge = '1d';
  }
  
  // ok: typescript-express-serve-static
  app.use('/static', serveStatic('public', options));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_11() {
  const app = express();
  
  const configureStatic = () => {
    const opts = {
      dotfiles: 'deny',
      etag: true
    };
    
    // ok: typescript-express-serve-static
    app.use(serveStatic('public', opts));
  };
  
  configureStatic();
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_12() {
  class StaticServer {
    app: express.Application;
    
    constructor() {
      this.app = express();
      
      // ok: typescript-express-serve-static
      this.app.use(serveStatic('public', {
        dotfiles: 'ignore',
        index: false
      }));
      
      this.app.listen(3000);
    }
  }
  
  new StaticServer();
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_13() {
  const app = express();
  const allowDotfiles = false;
  
  // ok: typescript-express-serve-static
  app.use('/downloads', serveStatic('downloads', {
    dotfiles: allowDotfiles ? 'allow' : 'deny'
  }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_14() {
  const app = express();
  
  // ok: typescript-express-serve-static
  app.use(express.static('public', {
    dotfiles: 'deny',
    redirect: false
  }));
  
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_15() {
  const app = express();
  
  // Using default options without explicitly setting dotfiles is also secure
  // as the default value for dotfiles is 'ignore'
  // ok: typescript-express-serve-static
  app.use(serveStatic('public'));
  
  app.listen(3000);
}
// {/fact}