// File: thenify_multiargs_test_cases.ts

import * as thenify from 'thenify';
import * as util from 'util';
import * as fs from 'fs';
import * as http from 'http';
import * as express from 'express';
import { Request, Response } from 'express';

// TRUE POSITIVES (Vulnerable Code)

// Example 1: Basic usage with multiArgs set to true
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_1() {
    const readFile = thenify(fs.readFile, {
        // ruleid: typescript-multiargs-code-execution
        multiArgs: true
    });
    
    readFile('config.json', 'utf8')
        .then(data => {
            console.log('File content:', data);
        })
        .catch(err => {
            console.error('Error reading file:', err);
        });
}
// {/fact}

// Example 2: Using multiArgs with a numeric value (truthy)
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_2() {
    const writeFile = thenify(fs.writeFile, {
        // ruleid: typescript-multiargs-code-execution
        multiArgs: 1
    });
    
    writeFile('output.txt', 'Hello World', 'utf8')
        .then(() => {
            console.log('File written successfully');
        })
        .catch(err => {
            console.error('Error writing file:', err);
        });
}
// {/fact}

// Example 3: Using multiArgs with a string value (truthy)
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_3() {
    const stat = thenify(fs.stat, {
        // ruleid: typescript-multiargs-code-execution
        multiArgs: "yes"
    });
    
    stat('file.txt')
        .then(stats => {
            console.log('File stats:', stats);
        })
        .catch(err => {
            console.error('Error getting file stats:', err);
        });
}
// {/fact}

// Example 4: Using multiArgs with an object (truthy)
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_4() {
    const mkdir = thenify(fs.mkdir, {
        // ruleid: typescript-multiargs-code-execution
        multiArgs: {}
    });
    
    mkdir('./new-directory')
        .then(() => {
            console.log('Directory created');
        })
        .catch(err => {
            console.error('Error creating directory:', err);
        });
}
// {/fact}

// Example 5: Using multiArgs with an array (truthy)
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_5() {
    const readdir = thenify(fs.readdir, {
        // ruleid: typescript-multiargs-code-execution
        multiArgs: []
    });
    
    readdir('./documents')
        .then(files => {
            console.log('Files:', files);
        })
        .catch(err => {
            console.error('Error reading directory:', err);
        });
}
// {/fact}

// Example 6: Using multiArgs with a function (truthy)
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_6() {
    const unlink = thenify(fs.unlink, {
        // ruleid: typescript-multiargs-code-execution
        multiArgs: () => false
    });
    
    unlink('temp.txt')
        .then(() => {
            console.log('File deleted');
        })
        .catch(err => {
            console.error('Error deleting file:', err);
        });
}
// {/fact}

// Example 7: Using multiArgs with a user-provided value from HTTP request
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_7() {
    const app = express();
    
    app.get('/thenify-config', (req: Request, res: Response) => {
        const userMultiArgs = req.query.multiArgs !== undefined;
        
        const readFile = thenify(fs.readFile, {
            // ruleid: typescript-multiargs-code-execution
            multiArgs: userMultiArgs
        });
        
        readFile('data.txt', 'utf8')
            .then(data => {
                res.send(data);
            })
            .catch(err => {
                res.status(500).send('Error reading file');
            });
    });
}
// {/fact}

// Example 8: Using multiArgs with a conditional expression
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_8() {
    const condition = process.env.NODE_ENV === 'development';
    
    const appendFile = thenify(fs.appendFile, {
        // ruleid: typescript-multiargs-code-execution
        multiArgs: condition ? true : null
    });
    
    appendFile('log.txt', 'New log entry\n')
        .then(() => {
            console.log('Log updated');
        })
        .catch(err => {
            console.error('Error updating log:', err);
        });
}
// {/fact}

// Example 9: Using multiArgs with a complex object
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_9() {
    const options = {
        encoding: 'utf8',
        // ruleid: typescript-multiargs-code-execution
        multiArgs: true
    };
    
    const readFile = thenify(fs.readFile, options);
    
    readFile('config.json')
        .then(data => {
            console.log('Config:', data);
        })
        .catch(err => {
            console.error('Error reading config:', err);
        });
}
// {/fact}

// Example 10: Using multiArgs with a variable
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_10() {
    const multiArgsValue = true;
    
    const chmod = thenify(fs.chmod, {
        // ruleid: typescript-multiargs-code-execution
        multiArgs: multiArgsValue
    });
    
    chmod('script.sh', 0o755)
        .then(() => {
            console.log('Permissions updated');
        })
        .catch(err => {
            console.error('Error updating permissions:', err);
        });
}
// {/fact}

// Example 11: Using multiArgs with a computed property
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_11() {
    const config = {
        enableMultiArgs: true
    };
    
    const copyFile = thenify(fs.copyFile, {
        // ruleid: typescript-multiargs-code-execution
        multiArgs: config.enableMultiArgs
    });
    
    copyFile('source.txt', 'destination.txt')
        .then(() => {
            console.log('File copied');
        })
        .catch(err => {
            console.error('Error copying file:', err);
        });
}
// {/fact}

// Example 12: Using multiArgs with a ternary operator
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_12() {
    const debug = true;
    
    const access = thenify(fs.access, {
        // ruleid: typescript-multiargs-code-execution
        multiArgs: debug ? true : false
    });
    
    access('file.txt', fs.constants.F_OK)
        .then(() => {
            console.log('File exists');
        })
        .catch(() => {
            console.log('File does not exist');
        });
}
// {/fact}

// Example 13: Using multiArgs with logical OR
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_13() {
    const defaultValue = null;
    
    const rename = thenify(fs.rename, {
        // ruleid: typescript-multiargs-code-execution
        multiArgs: defaultValue || true
    });
    
    rename('old.txt', 'new.txt')
        .then(() => {
            console.log('File renamed');
        })
        .catch(err => {
            console.error('Error renaming file:', err);
        });
}
// {/fact}

// Example 14: Using multiArgs with logical AND
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_14() {
    const isEnabled = true;
    
    const truncate = thenify(fs.truncate, {
        // ruleid: typescript-multiargs-code-execution
        multiArgs: isEnabled && true
    });
    
    truncate('log.txt', 0)
        .then(() => {
            console.log('File truncated');
        })
        .catch(err => {
            console.error('Error truncating file:', err);
        });
}
// {/fact}

// Example 15: Using multiArgs with a complex expression
// {fact rule=autoescape-disabled@v1.0 defects=1}
function bad_case_15() {
    const config = {
        debug: true,
        options: {
            multiArgs: true
        }
    };
    
    const rmdir = thenify(fs.rmdir, {
        // ruleid: typescript-multiargs-code-execution
        multiArgs: config.debug ? config.options.multiArgs : false
    });
    
    rmdir('./temp')
        .then(() => {
            console.log('Directory removed');
        })
        .catch(err => {
            console.error('Error removing directory:', err);
        });
}
// {/fact}

// TRUE NEGATIVES (Safe Code)

// Example 1: Basic usage with multiArgs set to false
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_1() {
    const readFile = thenify(fs.readFile, {
        // ok: typescript-multiargs-code-execution
        multiArgs: false
    });
    
    readFile('config.json', 'utf8')
        .then(data => {
            console.log('File content:', data);
        })
        .catch(err => {
            console.error('Error reading file:', err);
        });
}
// {/fact}

// Example 2: Using thenify without specifying multiArgs (defaults to false)
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_2() {
    // ok: typescript-multiargs-code-execution
    const writeFile = thenify(fs.writeFile);
    
    writeFile('output.txt', 'Hello World', 'utf8')
        .then(() => {
            console.log('File written successfully');
        })
        .catch(err => {
            console.error('Error writing file:', err);
        });
}
// {/fact}

// Example 3: Using thenify with empty options object
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_3() {
    // ok: typescript-multiargs-code-execution
    const stat = thenify(fs.stat, {});
    
    stat('file.txt')
        .then(stats => {
            console.log('File stats:', stats);
        })
        .catch(err => {
            console.error('Error getting file stats:', err);
        });
}
// {/fact}

// Example 4: Using thenify with other options but multiArgs set to false
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_4() {
    const mkdir = thenify(fs.mkdir, {
        // ok: typescript-multiargs-code-execution
        multiArgs: false,
        thisArg: null
    });
    
    mkdir('./new-directory')
        .then(() => {
            console.log('Directory created');
        })
        .catch(err => {
            console.error('Error creating directory:', err);
        });
}
// {/fact}

// Example 5: Using thenify with a conditional that always evaluates to false
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_5() {
    const condition = false;
    
    const readdir = thenify(fs.readdir, {
        // ok: typescript-multiargs-code-execution
        multiArgs: condition
    });
    
    readdir('./documents')
        .then(files => {
            console.log('Files:', files);
        })
        .catch(err => {
            console.error('Error reading directory:', err);
        });
}
// {/fact}

// Example 6: Using util.promisify instead of thenify
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_6() {
    // ok: typescript-multiargs-code-execution
    const unlink = util.promisify(fs.unlink);
    
    unlink('temp.txt')
        .then(() => {
            console.log('File deleted');
        })
        .catch(err => {
            console.error('Error deleting file:', err);
        });
}
// {/fact}

// Example 7: Using thenify with a variable set to false
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_7() {
    const multiArgsValue = false;
    
    const appendFile = thenify(fs.appendFile, {
        // ok: typescript-multiargs-code-execution
        multiArgs: multiArgsValue
    });
    
    appendFile('log.txt', 'New log entry\n')
        .then(() => {
            console.log('Log updated');
        })
        .catch(err => {
            console.error('Error updating log:', err);
        });
}
// {/fact}

// Example 8: Using thenify with a computed property that evaluates to false
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_8() {
    const config = {
        enableMultiArgs: false
    };
    
    const copyFile = thenify(fs.copyFile, {
        // ok: typescript-multiargs-code-execution
        multiArgs: config.enableMultiArgs
    });
    
    copyFile('source.txt', 'destination.txt')
        .then(() => {
            console.log('File copied');
        })
        .catch(err => {
            console.error('Error copying file:', err);
        });
}
// {/fact}

// Example 9: Using thenify with a ternary that evaluates to false
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_9() {
    const debug = false;
    
    const access = thenify(fs.access, {
        // ok: typescript-multiargs-code-execution
        multiArgs: debug ? true : false
    });
    
    access('file.txt', fs.constants.F_OK)
        .then(() => {
            console.log('File exists');
        })
        .catch(() => {
            console.log('File does not exist');
        });
}
// {/fact}

// Example 10: Using thenify with logical OR that evaluates to false
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_10() {
    const defaultValue = false;
    
    const rename = thenify(fs.rename, {
        // ok: typescript-multiargs-code-execution
        multiArgs: defaultValue || false
    });
    
    rename('old.txt', 'new.txt')
        .then(() => {
            console.log('File renamed');
        })
        .catch(err => {
            console.error('Error renaming file:', err);
        });
}
// {/fact}

// Example 11: Using thenify with logical AND that evaluates to false
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_11() {
    const isEnabled = false;
    
    const truncate = thenify(fs.truncate, {
        // ok: typescript-multiargs-code-execution
        multiArgs: isEnabled && true
    });
    
    truncate('log.txt', 0)
        .then(() => {
            console.log('File truncated');
        })
        .catch(err => {
            console.error('Error truncating file:', err);
        });
}
// {/fact}

// Example 12: Using thenify with a complex expression that evaluates to false
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_12() {
    const config = {
        debug: false,
        options: {
            multiArgs: true
        }
    };
    
    const rmdir = thenify(fs.rmdir, {
        // ok: typescript-multiargs-code-execution
        multiArgs: config.debug ? config.options.multiArgs : false
    });
    
    rmdir('./temp')
        .then(() => {
            console.log('Directory removed');
        })
        .catch(err => {
            console.error('Error removing directory:', err);
        });
}
// {/fact}

// Example 13: Using thenify with a function that returns false
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_13() {
    const getMultiArgsValue = () => false;
    
    const chmod = thenify(fs.chmod, {
        // ok: typescript-multiargs-code-execution
        multiArgs: getMultiArgsValue()
    });
    
    chmod('script.sh', 0o755)
        .then(() => {
            console.log('Permissions updated');
        })
        .catch(err => {
            console.error('Error updating permissions:', err);
        });
}
// {/fact}

// Example 14: Using thenify with an environment variable that is false
// {fact rule=autoescape-disabled@v1.0 defects=0}
function good_case_14() {
    const envValue = process.env.ENABLE_MULTI_ARGS === 'true';
    
    const readFile = thenify(fs.readFile, {
        // ok: typescript-multiargs-code-execution
        multiArgs: envValue && false
    });
    
    readFile('config.json', 'utf8')
        .then(data => {
            console.log('File content:', data);
        })
        .catch(err => {
            console.error('Error reading file:', err);
        });
}
// {/fact}

// Example 15: Using async/await instead of thenify
// {fact rule=autoescape-disabled@v1.0 defects=0}
async function good_case_15() {
    try {
        // ok: typescript-multiargs-code-execution
        const data = await fs.promises.readFile('config.json', 'utf8');
        console.log('File content:', data);
    } catch (err) {
        console.error('Error reading file:', err);
    }
}
// {/fact}