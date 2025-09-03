// File: thenify_multiargs_test.js

const thenify = require('thenify');
const fs = require('fs');
const util = require('util');
const childProcess = require('child_process');
const crypto = require('crypto');

// True Positive Examples (Vulnerable Code)

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
  // Using multiArgs: true explicitly
  const readFile = thenify(fs.readFile, {
    // ruleid: javascript-multiargs-code-execution
    multiArgs: true
  });
  
  readFile('config.json', 'utf8')
    .then(args => {
      // Potential unexpected behavior with multiple arguments
      console.log(args);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
  // Using multiArgs as a variable set to true
  const options = {
    // ruleid: javascript-multiargs-code-execution
    multiArgs: true
  };
  
  const exec = thenify(childProcess.exec, options);
  
  exec('ls -la')
    .then(result => {
      console.log(result);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
  // Using multiArgs as 1 (truthy value)
  const stat = thenify(fs.stat, {
    // ruleid: javascript-multiargs-code-execution
    multiArgs: 1
  });
  
  stat('/etc/passwd')
    .then(stats => {
      console.log(stats);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
  // Using multiArgs as string "true" (truthy value)
  const readdir = thenify(fs.readdir, {
    // ruleid: javascript-multiargs-code-execution
    multiArgs: "true"
  });
  
  readdir('/var/log')
    .then(files => {
      console.log(files);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
  // Using multiArgs as an object (truthy value)
  const writeFile = thenify(fs.writeFile, {
    // ruleid: javascript-multiargs-code-execution
    multiArgs: {}
  });
  
  writeFile('output.txt', 'data')
    .then(result => {
      console.log('File written');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
  // Using multiArgs as an array (truthy value)
  const mkdir = thenify(fs.mkdir, {
    // ruleid: javascript-multiargs-code-execution
    multiArgs: []
  });
  
  mkdir('/tmp/newdir')
    .then(result => {
      console.log('Directory created');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
  // Using multiArgs with dynamic value that resolves to true
  const multiArgsValue = process.env.MULTI_ARGS === 'disabled' ? false : true;
  
  const access = thenify(fs.access, {
    // ruleid: javascript-multiargs-code-execution
    multiArgs: multiArgsValue
  });
  
  access('/etc/hosts')
    .then(result => {
      console.log('Access checked');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
  // Using multiArgs with computed property
  const flag = 'multi' + 'Args';
  const options = {};
  // ruleid: javascript-multiargs-code-execution
  options[flag] = true;
  
  const rename = thenify(fs.rename, options);
  
  rename('old.txt', 'new.txt')
    .then(result => {
      console.log('File renamed');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
  // Using multiArgs in a conditional expression
  const debug = true;
  
  const copyFile = thenify(fs.copyFile, {
    // ruleid: javascript-multiargs-code-execution
    multiArgs: debug ? true : false
  });
  
  copyFile('source.txt', 'dest.txt')
    .then(result => {
      console.log('File copied');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
  // Using multiArgs with logical OR that resolves to true
  const userPreference = null;
  
  const unlink = thenify(fs.unlink, {
    // ruleid: javascript-multiargs-code-execution
    multiArgs: userPreference || true
  });
  
  unlink('temp.txt')
    .then(result => {
      console.log('File deleted');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
  // Using multiArgs in an object spread
  const baseOptions = { encoding: 'utf8' };
  const readOptions = {
    ...baseOptions,
    // ruleid: javascript-multiargs-code-execution
    multiArgs: true
  };
  
  const readlink = thenify(fs.readlink, readOptions);
  
  readlink('/var/www/html')
    .then(path => {
      console.log(path);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
  // Using multiArgs with function that returns true
  function getMultiArgsValue() {
    return true;
  }
  
  const chmod = thenify(fs.chmod, {
    // ruleid: javascript-multiargs-code-execution
    multiArgs: getMultiArgsValue()
  });
  
  chmod('script.sh', 0o755)
    .then(result => {
      console.log('Permissions changed');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
  // Using multiArgs with object destructuring and default value
  const { multiArgs = true } = {};
  
  const appendFile = thenify(fs.appendFile, {
    // ruleid: javascript-multiargs-code-execution
    multiArgs
  });
  
  appendFile('log.txt', 'new log entry')
    .then(result => {
      console.log('Log updated');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
  // Using multiArgs with bitwise OR that resolves to truthy
  const flag = 0;
  
  const symlink = thenify(fs.symlink, {
    // ruleid: javascript-multiargs-code-execution
    multiArgs: flag | 1
  });
  
  symlink('target', 'link')
    .then(result => {
      console.log('Symlink created');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
  // Using multiArgs with ternary that evaluates to non-false
  const isDebug = true;
  
  const generateKeyPair = thenify(crypto.generateKeyPair, {
    // ruleid: javascript-multiargs-code-execution
    multiArgs: isDebug ? 'yes' : null
  });
  
  generateKeyPair('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  }).then(keys => {
    console.log(keys);
  });
}
// {/fact}

// True Negative Examples (Safe Code)

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
  // Using multiArgs: false explicitly
  const readFile = thenify(fs.readFile, {
    // ok: javascript-multiargs-code-execution
    multiArgs: false
  });
  
  readFile('config.json', 'utf8')
    .then(data => {
      console.log(data);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
  // Using multiArgs as a variable set to false
  const options = {
    // ok: javascript-multiargs-code-execution
    multiArgs: false
  };
  
  const exec = thenify(childProcess.exec, options);
  
  exec('ls -la')
    .then(result => {
      console.log(result);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
  // Not specifying multiArgs at all (defaults to false)
  // ok: javascript-multiargs-code-execution
  const stat = thenify(fs.stat);
  
  stat('/etc/passwd')
    .then(stats => {
      console.log(stats);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
  // Using empty options object (multiArgs defaults to false)
  // ok: javascript-multiargs-code-execution
  const readdir = thenify(fs.readdir, {});
  
  readdir('/var/log')
    .then(files => {
      console.log(files);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
  // Using other options but not multiArgs
  // ok: javascript-multiargs-code-execution
  const writeFile = thenify(fs.writeFile, {
    encoding: 'utf8'
  });
  
  writeFile('output.txt', 'data')
    .then(result => {
      console.log('File written');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
  // Using multiArgs with dynamic value that resolves to false
  const multiArgsValue = process.env.MULTI_ARGS === 'enabled' ? true : false;
  
  const access = thenify(fs.access, {
    // ok: javascript-multiargs-code-execution
    multiArgs: false
  });
  
  access('/etc/hosts')
    .then(result => {
      console.log('Access checked');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
  // Using util.promisify instead of thenify
  // ok: javascript-multiargs-code-execution
  const mkdir = util.promisify(fs.mkdir);
  
  mkdir('/tmp/newdir')
    .then(result => {
      console.log('Directory created');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
  // Using multiArgs with computed property set to false
  const flag = 'multi' + 'Args';
  const options = {};
  // ok: javascript-multiargs-code-execution
  options[flag] = false;
  
  const rename = thenify(fs.rename, options);
  
  rename('old.txt', 'new.txt')
    .then(result => {
      console.log('File renamed');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
  // Using multiArgs in a conditional expression that resolves to false
  const debug = false;
  
  const copyFile = thenify(fs.copyFile, {
    // ok: javascript-multiargs-code-execution
    multiArgs: debug ? true : false
  });
  
  copyFile('source.txt', 'dest.txt')
    .then(result => {
      console.log('File copied');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
  // Using multiArgs with logical OR that resolves to false
  const userPreference = false;
  
  const unlink = thenify(fs.unlink, {
    // ok: javascript-multiargs-code-execution
    multiArgs: userPreference || false
  });
  
  unlink('temp.txt')
    .then(result => {
      console.log('File deleted');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
  // Using multiArgs in an object spread with false value
  const baseOptions = { encoding: 'utf8' };
  const readOptions = {
    ...baseOptions,
    // ok: javascript-multiargs-code-execution
    multiArgs: false
  };
  
  const readlink = thenify(fs.readlink, readOptions);
  
  readlink('/var/www/html')
    .then(path => {
      console.log(path);
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
  // Using multiArgs with function that returns false
  function getMultiArgsValue() {
    return false;
  }
  
  const chmod = thenify(fs.chmod, {
    // ok: javascript-multiargs-code-execution
    multiArgs: getMultiArgsValue()
  });
  
  chmod('script.sh', 0o755)
    .then(result => {
      console.log('Permissions changed');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
  // Using multiArgs with object destructuring and default value of false
  const { multiArgs = false } = {};
  
  const appendFile = thenify(fs.appendFile, {
    // ok: javascript-multiargs-code-execution
    multiArgs
  });
  
  appendFile('log.txt', 'new log entry')
    .then(result => {
      console.log('Log updated');
    });
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
  // Using async/await pattern instead of thenify
  async function processSymlink() {
    // ok: javascript-multiargs-code-execution
    const fsPromises = require('fs').promises;
    
    try {
      await fsPromises.symlink('target', 'link');
      console.log('Symlink created');
    } catch (error) {
      console.error(error);
    }
  }
  
  processSymlink();
}
// {/fact}

// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_15() {
  // Using Promise constructor directly
  function readFilePromise(path) {
    // ok: javascript-multiargs-code-execution
    return new Promise((resolve, reject) => {
      fs.readFile(path, 'utf8', (err, data) => {
        if (err) reject(err);
        else resolve(data);
      });
    });
  }
  
  readFilePromise('config.json')
    .then(data => {
      console.log(data);
    });
}
// {/fact}