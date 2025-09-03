// File: express-serve-static-test-cases.js

const express = require('express');
const serveStatic = require('serve-static');
const path = require('path');

// True Positive Examples (Vulnerable Code)

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_1() {
  const app = express();
  // ruleid: javascript-express-serve-static
  app.use(serveStatic('public'));
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_2() {
  const app = express();
  // ruleid: javascript-express-serve-static
  app.use(serveStatic('public', {
    index: ['index.html', 'index.htm']
  }));
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_3() {
  const app = express();
  const options = {
    setHeaders: function (res, path, stat) {
      res.set('x-timestamp', Date.now());
    }
  };
  // ruleid: javascript-express-serve-static
  app.use(serveStatic('public', options));
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_4() {
  const app = express();
  // ruleid: javascript-express-serve-static
  app.use('/static', serveStatic(path.join(__dirname, 'public')));
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_5() {
  const app = express();
  const options = {
    dotfiles: 'allow', // Explicitly allowing dotfiles - security risk
  };
  // ruleid: javascript-express-serve-static
  app.use(serveStatic('public', options));
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_6() {
  const app = express();
  const staticOptions = {};
  staticOptions.dotfiles = 'allow'; // Explicitly allowing dotfiles - security risk
  // ruleid: javascript-express-serve-static
  app.use('/assets', serveStatic('assets', staticOptions));
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_7() {
  const app = express();
  const env = process.env.NODE_ENV || 'development';
  const options = {
    dotfiles: env === 'development' ? 'allow' : 'allow', // Always allowing dotfiles regardless of environment
  };
  // ruleid: javascript-express-serve-static
  app.use(serveStatic('public', options));
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_8() {
  const app = express();
  function getStaticOptions() {
    return {
      dotfiles: 'allow', // Explicitly allowing dotfiles - security risk
      etag: true
    };
  }
  // ruleid: javascript-express-serve-static
  app.use(serveStatic('public', getStaticOptions()));
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_9() {
  const app = express();
  const config = {
    staticOptions: {
      dotfiles: 'allow', // Explicitly allowing dotfiles - security risk
      maxAge: '1d'
    }
  };
  // ruleid: javascript-express-serve-static
  app.use(serveStatic('public', config.staticOptions));
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_10() {
  const app = express();
  let options = {};
  
  if (process.env.DEBUG) {
    options = {
      dotfiles: 'allow', // Explicitly allowing dotfiles in debug mode - security risk
      etag: false
    };
  } else {
    options = {
      dotfiles: 'allow', // Explicitly allowing dotfiles in production - security risk
      etag: true
    };
  }
  
  // ruleid: javascript-express-serve-static
  app.use(serveStatic('public', options));
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_11() {
  const app = express();
  const options = {
    dotfiles: 'allow', // Explicitly allowing dotfiles - security risk
    fallthrough: false
  };
  
  // ruleid: javascript-express-serve-static
  app.use('/downloads', serveStatic('downloads', options));
  app.use('/uploads', serveStatic('uploads', options));
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_12() {
  const app = express();
  const dotfilesOption = 'allow'; // Explicitly allowing dotfiles - security risk
  
  // ruleid: javascript-express-serve-static
  app.use(serveStatic('public', {
    dotfiles: dotfilesOption,
    etag: true
  }));
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_13() {
  const app = express();
  const options = {};
  
  // Setting options dynamically but still insecure
  if (process.env.NODE_ENV === 'production') {
    options.maxAge = '1d';
  }
  options.dotfiles = 'allow'; // Explicitly allowing dotfiles - security risk
  
  // ruleid: javascript-express-serve-static
  app.use(serveStatic('public', options));
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_14() {
  const app = express();
  const staticDirs = ['public', 'assets', 'uploads'];
  const options = {
    dotfiles: 'allow', // Explicitly allowing dotfiles - security risk
    index: false
  };
  
  // Multiple static directories with the same insecure configuration
  staticDirs.forEach(dir => {
    // ruleid: javascript-express-serve-static
    app.use(`/${dir}`, serveStatic(dir, options));
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=1}
function bad_case_15() {
  const app = express();
  const configureStatic = () => {
    return {
      dotfiles: 'allow', // Explicitly allowing dotfiles - security risk
      extensions: ['html', 'htm']
    };
  };
  
  // ruleid: javascript-express-serve-static
  app.use('/static', serveStatic('static', configureStatic()));
  app.listen(3000);
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_1() {
  const app = express();
  // ok: javascript-express-serve-static
  app.use(serveStatic('public', {
    dotfiles: 'ignore' // Securely ignoring dotfiles
  }));
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_2() {
  const app = express();
  const options = {
    dotfiles: 'deny', // Securely denying dotfiles
    etag: true
  };
  // ok: javascript-express-serve-static
  app.use(serveStatic('public', options));
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_3() {
  const app = express();
  const staticOptions = {};
  staticOptions.dotfiles = 'ignore'; // Securely ignoring dotfiles
  // ok: javascript-express-serve-static
  app.use('/assets', serveStatic('assets', staticOptions));
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_4() {
  const app = express();
  const env = process.env.NODE_ENV || 'development';
  const options = {
    dotfiles: 'deny', // Securely denying dotfiles in all environments
    etag: env === 'production'
  };
  // ok: javascript-express-serve-static
  app.use(serveStatic('public', options));
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_5() {
  const app = express();
  function getStaticOptions() {
    return {
      dotfiles: 'ignore', // Securely ignoring dotfiles
      etag: true
    };
  }
  // ok: javascript-express-serve-static
  app.use(serveStatic('public', getStaticOptions()));
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_6() {
  const app = express();
  const config = {
    staticOptions: {
      dotfiles: 'deny', // Securely denying dotfiles
      maxAge: '1d'
    }
  };
  // ok: javascript-express-serve-static
  app.use(serveStatic('public', config.staticOptions));
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_7() {
  const app = express();
  let options = {};
  
  if (process.env.DEBUG) {
    options = {
      dotfiles: 'ignore', // Securely ignoring dotfiles in debug mode
      etag: false
    };
  } else {
    options = {
      dotfiles: 'deny', // Securely denying dotfiles in production
      etag: true
    };
  }
  
  // ok: javascript-express-serve-static
  app.use(serveStatic('public', options));
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_8() {
  const app = express();
  const options = {
    dotfiles: 'deny', // Securely denying dotfiles
    fallthrough: false
  };
  
  // ok: javascript-express-serve-static
  app.use('/downloads', serveStatic('downloads', options));
  app.use('/uploads', serveStatic('uploads', options));
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_9() {
  const app = express();
  const dotfilesOption = 'ignore'; // Securely ignoring dotfiles
  
  // ok: javascript-express-serve-static
  app.use(serveStatic('public', {
    dotfiles: dotfilesOption,
    etag: true
  }));
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_10() {
  const app = express();
  const options = {};
  
  // Setting options dynamically and securely
  if (process.env.NODE_ENV === 'production') {
    options.maxAge = '1d';
    options.dotfiles = 'deny'; // Securely denying dotfiles in production
  } else {
    options.dotfiles = 'ignore'; // Securely ignoring dotfiles in development
  }
  
  // ok: javascript-express-serve-static
  app.use(serveStatic('public', options));
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_11() {
  const app = express();
  const staticDirs = ['public', 'assets', 'uploads'];
  const options = {
    dotfiles: 'deny', // Securely denying dotfiles
    index: false
  };
  
  // Multiple static directories with the same secure configuration
  staticDirs.forEach(dir => {
    // ok: javascript-express-serve-static
    app.use(`/${dir}`, serveStatic(dir, options));
  });
  
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_12() {
  const app = express();
  const configureStatic = () => {
    return {
      dotfiles: 'ignore', // Securely ignoring dotfiles
      extensions: ['html', 'htm']
    };
  };
  
  // ok: javascript-express-serve-static
  app.use('/static', serveStatic('static', configureStatic()));
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_13() {
  const app = express();
  // Using a more complex configuration but still secure
  const options = {
    dotfiles: 'deny', // Securely denying dotfiles
    etag: true,
    extensions: ['html', 'htm'],
    index: ['index.html', 'index.htm'],
    lastModified: true,
    maxAge: '1d',
    setHeaders: function (res, path, stat) {
      res.set('X-Content-Type-Options', 'nosniff');
    }
  };
  
  // ok: javascript-express-serve-static
  app.use(serveStatic('public', options));
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_14() {
  const app = express();
  const env = process.env.NODE_ENV || 'development';
  
  // Different configuration based on environment but always secure
  if (env === 'development') {
    // ok: javascript-express-serve-static
    app.use(serveStatic('public', {
      dotfiles: 'ignore', // Securely ignoring dotfiles in development
      etag: false,
      lastModified: true
    }));
  } else {
    // ok: javascript-express-serve-static
    app.use(serveStatic('public', {
      dotfiles: 'deny', // Securely denying dotfiles in production
      etag: true,
      lastModified: true,
      maxAge: '1d'
    }));
  }
  
  app.listen(3000);
}
// {/fact}

// {fact rule=file-and-directory-information-exposure@v1.0 defects=0}
function good_case_15() {
  const app = express();
  // Using a middleware factory pattern but still secure
  function createStaticMiddleware(directory) {
    return serveStatic(directory, {
      dotfiles: 'deny', // Securely denying dotfiles
      etag: true,
      maxAge: '1h'
    });
  }
  
  // ok: javascript-express-serve-static
  app.use('/static', createStaticMiddleware('public'));
  app.listen(3000);
}
// {/fact}