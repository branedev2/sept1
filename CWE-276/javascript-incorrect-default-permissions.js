const fs = require('fs');
const path = require('path');
const fsPromises = require('fs').promises;

// True Positive Examples (Insecure file permissions)

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_1() {
    // Using fs.writeFileSync with 0o777 permissions
    const data = 'This is sensitive data';
    const filePath = path.join(__dirname, 'sensitive_data.txt');
    
    // ruleid: javascript-incorrect-default-permissions
    fs.writeFileSync(filePath, data, { mode: 0o777 });
    console.log('File written with insecure permissions 0o777');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_2() {
    // Using fs.writeFile with 0o666 permissions
    const data = 'This is configuration data';
    const filePath = path.join(__dirname, 'config.json');
    
    // ruleid: javascript-incorrect-default-permissions
    fs.writeFile(filePath, data, { mode: 0o666 }, (err) => {
        if (err) throw err;
        console.log('File written with insecure permissions 0o666');
    });
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_3() {
    // Using fs.chmod with 0o777 permissions
    const filePath = path.join(__dirname, 'existing_file.txt');
    
    // ruleid: javascript-incorrect-default-permissions
    fs.chmod(filePath, 0o777, (err) => {
        if (err) throw err;
        console.log('File permissions changed to 0o777');
    });
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_4() {
    // Using fs.chmodSync with 0o755 permissions
    const filePath = path.join(__dirname, 'script.js');
    
    // ruleid: javascript-incorrect-default-permissions
    fs.chmodSync(filePath, 0o755);
    console.log('File permissions changed to 0o755');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_5() {
    // Using fs.mkdir with 0o777 permissions
    const dirPath = path.join(__dirname, 'new_directory');
    
    // ruleid: javascript-incorrect-default-permissions
    fs.mkdir(dirPath, { mode: 0o777 }, (err) => {
        if (err) throw err;
        console.log('Directory created with insecure permissions 0o777');
    });
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_6() {
    // Using fs.mkdirSync with 0o777 permissions
    const dirPath = path.join(__dirname, 'new_directory_sync');
    
    // ruleid: javascript-incorrect-default-permissions
    fs.mkdirSync(dirPath, { mode: 0o777 });
    console.log('Directory created with insecure permissions 0o777');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
async function bad_case_7() {
    // Using fs.promises.writeFile with 0o666 permissions
    const data = 'This is sensitive data';
    const filePath = path.join(__dirname, 'sensitive_data_async.txt');
    
    try {
        // ruleid: javascript-incorrect-default-permissions
        await fsPromises.writeFile(filePath, data, { mode: 0o666 });
        console.log('File written with insecure permissions 0o666');
    } catch (err) {
        console.error('Error writing file:', err);
    }
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
async function bad_case_8() {
    // Using fs.promises.mkdir with 0o777 permissions
    const dirPath = path.join(__dirname, 'new_directory_async');
    
    try {
        // ruleid: javascript-incorrect-default-permissions
        await fsPromises.mkdir(dirPath, { mode: 0o777 });
        console.log('Directory created with insecure permissions 0o777');
    } catch (err) {
        console.error('Error creating directory:', err);
    }
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_9() {
    // Using fs.open with 0o666 permissions
    const filePath = path.join(__dirname, 'new_file.txt');
    
    // ruleid: javascript-incorrect-default-permissions
    fs.open(filePath, 'w', 0o666, (err, fd) => {
        if (err) throw err;
        fs.close(fd, (err) => {
            if (err) throw err;
            console.log('File opened and created with insecure permissions 0o666');
        });
    });
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_10() {
    // Using fs.openSync with 0o644 permissions
    const filePath = path.join(__dirname, 'new_file_sync.txt');
    
    // ruleid: javascript-incorrect-default-permissions
    const fd = fs.openSync(filePath, 'w', 0o644);
    fs.closeSync(fd);
    console.log('File opened and created with insecure permissions 0o644');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_11() {
    // Using numeric literal for 0o777 permissions
    const filePath = path.join(__dirname, 'numeric_literal.txt');
    
    // ruleid: javascript-incorrect-default-permissions
    fs.writeFileSync(filePath, 'data', { mode: 511 }); // 511 decimal = 0o777 octal
    console.log('File written with insecure permissions 511 (0o777)');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_12() {
    // Using hexadecimal literal for 0o666 permissions
    const filePath = path.join(__dirname, 'hex_literal.txt');
    
    // ruleid: javascript-incorrect-default-permissions
    fs.writeFileSync(filePath, 'data', { mode: 0x1B6 }); // 0x1B6 hex = 0o666 octal
    console.log('File written with insecure permissions 0x1B6 (0o666)');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_13() {
    // Using variable with insecure permissions
    const filePath = path.join(__dirname, 'variable_perms.txt');
    const permissions = 0o777;
    
    // ruleid: javascript-incorrect-default-permissions
    fs.writeFileSync(filePath, 'data', { mode: permissions });
    console.log('File written with insecure permissions from variable');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_14() {
    // Using fs.chmodSync with 0o644 permissions in a conditional
    const filePath = path.join(__dirname, 'conditional_perms.txt');
    const isPublic = true;
    
    if (isPublic) {
        // ruleid: javascript-incorrect-default-permissions
        fs.chmodSync(filePath, 0o644);
        console.log('File permissions changed to 0o644');
    } else {
        fs.chmodSync(filePath, 0o600);
        console.log('File permissions changed to 0o600');
    }
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=1}
function bad_case_15() {
    // Using fs.mkdtempSync with 0o777 permissions
    const tempDirPrefix = path.join(os.tmpdir(), 'app-');
    
    // ruleid: javascript-incorrect-default-permissions
    const tempDir = fs.mkdtempSync(tempDirPrefix, { mode: 0o777 });
    console.log(`Temporary directory created at ${tempDir} with insecure permissions 0o777`);
}
// {/fact}

// True Negative Examples (Secure file permissions)

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_1() {
    // Using fs.writeFileSync with secure 0o600 permissions
    const data = 'This is sensitive data';
    const filePath = path.join(__dirname, 'sensitive_data_secure.txt');
    
    // ok: javascript-incorrect-default-permissions
    fs.writeFileSync(filePath, data, { mode: 0o600 });
    console.log('File written with secure permissions 0o600');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_2() {
    // Using fs.writeFile with secure 0o600 permissions
    const data = 'This is configuration data';
    const filePath = path.join(__dirname, 'config_secure.json');
    
    // ok: javascript-incorrect-default-permissions
    fs.writeFile(filePath, data, { mode: 0o600 }, (err) => {
        if (err) throw err;
        console.log('File written with secure permissions 0o600');
    });
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_3() {
    // Using fs.chmod with secure 0o600 permissions
    const filePath = path.join(__dirname, 'existing_file_secure.txt');
    
    // ok: javascript-incorrect-default-permissions
    fs.chmod(filePath, 0o600, (err) => {
        if (err) throw err;
        console.log('File permissions changed to secure 0o600');
    });
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_4() {
    // Using fs.chmodSync with secure 0o400 permissions (read-only)
    const filePath = path.join(__dirname, 'script_secure.js');
    
    // ok: javascript-incorrect-default-permissions
    fs.chmodSync(filePath, 0o400);
    console.log('File permissions changed to secure 0o400 (read-only)');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_5() {
    // Using fs.mkdir with secure 0o700 permissions
    const dirPath = path.join(__dirname, 'new_directory_secure');
    
    // ok: javascript-incorrect-default-permissions
    fs.mkdir(dirPath, { mode: 0o700 }, (err) => {
        if (err) throw err;
        console.log('Directory created with secure permissions 0o700');
    });
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_6() {
    // Using fs.mkdirSync with secure 0o700 permissions
    const dirPath = path.join(__dirname, 'new_directory_sync_secure');
    
    // ok: javascript-incorrect-default-permissions
    fs.mkdirSync(dirPath, { mode: 0o700 });
    console.log('Directory created with secure permissions 0o700');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
async function good_case_7() {
    // Using fs.promises.writeFile with secure 0o600 permissions
    const data = 'This is sensitive data';
    const filePath = path.join(__dirname, 'sensitive_data_async_secure.txt');
    
    try {
        // ok: javascript-incorrect-default-permissions
        await fsPromises.writeFile(filePath, data, { mode: 0o600 });
        console.log('File written with secure permissions 0o600');
    } catch (err) {
        console.error('Error writing file:', err);
    }
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
async function good_case_8() {
    // Using fs.promises.mkdir with secure 0o700 permissions
    const dirPath = path.join(__dirname, 'new_directory_async_secure');
    
    try {
        // ok: javascript-incorrect-default-permissions
        await fsPromises.mkdir(dirPath, { mode: 0o700 });
        console.log('Directory created with secure permissions 0o700');
    } catch (err) {
        console.error('Error creating directory:', err);
    }
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_9() {
    // Using fs.open with secure 0o600 permissions
    const filePath = path.join(__dirname, 'new_file_secure.txt');
    
    // ok: javascript-incorrect-default-permissions
    fs.open(filePath, 'w', 0o600, (err, fd) => {
        if (err) throw err;
        fs.close(fd, (err) => {
            if (err) throw err;
            console.log('File opened and created with secure permissions 0o600');
        });
    });
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_10() {
    // Using fs.openSync with secure 0o400 permissions (read-only)
    const filePath = path.join(__dirname, 'new_file_sync_secure.txt');
    
    // ok: javascript-incorrect-default-permissions
    const fd = fs.openSync(filePath, 'w', 0o400);
    fs.closeSync(fd);
    console.log('File opened and created with secure permissions 0o400 (read-only)');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_11() {
    // Using numeric literal for secure 0o600 permissions
    const filePath = path.join(__dirname, 'numeric_literal_secure.txt');
    
    // ok: javascript-incorrect-default-permissions
    fs.writeFileSync(filePath, 'data', { mode: 384 }); // 384 decimal = 0o600 octal
    console.log('File written with secure permissions 384 (0o600)');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_12() {
    // Using hexadecimal literal for secure 0o600 permissions
    const filePath = path.join(__dirname, 'hex_literal_secure.txt');
    
    // ok: javascript-incorrect-default-permissions
    fs.writeFileSync(filePath, 'data', { mode: 0x180 }); // 0x180 hex = 0o600 octal
    console.log('File written with secure permissions 0x180 (0o600)');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_13() {
    // Using variable with secure permissions
    const filePath = path.join(__dirname, 'variable_perms_secure.txt');
    const permissions = 0o600;
    
    // ok: javascript-incorrect-default-permissions
    fs.writeFileSync(filePath, 'data', { mode: permissions });
    console.log('File written with secure permissions from variable');
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_14() {
    // Using environment variable to set permissions (secure approach)
    const filePath = path.join(__dirname, 'env_perms.txt');
    // Assuming process.env.FILE_PERMISSIONS is set to a secure value like "0o600"
    const permissionString = process.env.FILE_PERMISSIONS || "0o600";
    const permissions = parseInt(permissionString, 8);
    
    // ok: javascript-incorrect-default-permissions
    fs.writeFileSync(filePath, 'data', { mode: permissions });
    console.log(`File written with permissions from environment: ${permissionString}`);
}
// {/fact}

// {fact rule=insecure-file-permissions@v1.0 defects=0}
function good_case_15() {
    // Using a function to determine appropriate permissions
    const filePath = path.join(__dirname, 'function_perms.txt');
    
    function getSecurePermissions(fileType) {
        switch(fileType) {
            case 'executable':
                return 0o700; // rwx for owner only
            case 'config':
                return 0o400; // read-only for owner
            default:
                return 0o600; // rw for owner only
        }
    }
    
    const fileType = 'config';
    const permissions = getSecurePermissions(fileType);
    
    // ok: javascript-incorrect-default-permissions
    fs.writeFileSync(filePath, 'data', { mode: permissions });
    console.log(`File written with secure permissions for ${fileType}: ${permissions.toString(8)}`);
}
// {/fact}