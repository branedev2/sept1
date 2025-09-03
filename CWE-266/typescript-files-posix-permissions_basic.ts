import * as fs from 'fs';
import * as path from 'path';
import { promises as fsPromises } from 'fs';

// True Positive Examples (Vulnerable Code)

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_1() {
    const filePath = '/path/to/sensitive/file.txt';
    // ruleid: typescript-files-posix-permissions
    fs.chmodSync(filePath, 0o777); // Full permissions for everyone
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_2() {
    const configFile = '/etc/app/config.json';
    // ruleid: typescript-files-posix-permissions
    fs.chmod(configFile, 0o666, (err) => {
        if (err) throw err;
        console.log('File permissions updated');
    });
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_3() {
    const logDirectory = '/var/log/app';
    // ruleid: typescript-files-posix-permissions
    fs.chmodSync(logDirectory, '777'); // String representation of octal
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_4() {
    const secretsFile = '/app/secrets.json';
    
    async function updatePermissions() {
        try {
            // ruleid: typescript-files-posix-permissions
            await fsPromises.chmod(secretsFile, 0o777);
            console.log('Permissions updated');
        } catch (error) {
            console.error('Error updating permissions:', error);
        }
    }
    
    updatePermissions();
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_5() {
    const tempDir = '/tmp/app_data';
    
    if (!fs.existsSync(tempDir)) {
        fs.mkdirSync(tempDir);
        // ruleid: typescript-files-posix-permissions
        fs.chmodSync(tempDir, 0o777); // World-writable directory
    }
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_6() {
    const uploadDir = '/var/www/uploads';
    
    // ruleid: typescript-files-posix-permissions
    fs.mkdirSync(uploadDir, { mode: 0o777 }); // Creating with insecure permissions
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_7() {
    const keyFile = '/etc/ssl/private/server.key';
    
    fs.writeFileSync(keyFile, '-----BEGIN PRIVATE KEY-----\n...');
    // ruleid: typescript-files-posix-permissions
    fs.chmodSync(keyFile, 0o666); // Readable by everyone
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_8() {
    const dbConfigFile = '/app/database.conf';
    const mode = 0o777; // Full permissions stored in variable
    
    // ruleid: typescript-files-posix-permissions
    fs.chmodSync(dbConfigFile, mode);
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_9() {
    const filePath = '/path/to/data.json';
    const permissions = '0777'; // String representation with leading zero
    
    // ruleid: typescript-files-posix-permissions
    fs.chmodSync(filePath, parseInt(permissions, 8));
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_10() {
    const backupDir = '/backup';
    
    try {
        // ruleid: typescript-files-posix-permissions
        fs.mkdirSync(backupDir, { recursive: true, mode: 0o777 });
    } catch (error) {
        console.error('Failed to create backup directory:', error);
    }
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_11() {
    const filePath = '/app/data.txt';
    
    fs.writeFile(filePath, 'sensitive data', (err) => {
        if (err) throw err;
        // ruleid: typescript-files-posix-permissions
        fs.chmod(filePath, 0o777, (err) => {
            if (err) throw err;
            console.log('File created with permissions');
        });
    });
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_12() {
    const configDir = '/etc/app/config';
    const permissionMask = 0o777;
    
    // ruleid: typescript-files-posix-permissions
    fs.mkdirSync(configDir, { mode: permissionMask });
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_13() {
    const tempFile = path.join('/tmp', 'temp_' + Date.now() + '.json');
    
    fs.writeFileSync(tempFile, JSON.stringify({ key: 'value' }));
    // ruleid: typescript-files-posix-permissions
    fs.chmodSync(tempFile, 0o666);
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_14() {
    async function setupEnvironment() {
        const appDir = '/opt/myapp';
        
        try {
            // ruleid: typescript-files-posix-permissions
            await fsPromises.mkdir(appDir, { recursive: true, mode: 0o777 });
            console.log('Application directory created');
        } catch (error) {
            console.error('Failed to create directory:', error);
        }
    }
    
    setupEnvironment();
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=1}
function bad_case_15() {
    const worldWritable = 0o2; // Write permission for others
    const filePath = '/path/to/file.txt';
    
    const currentMode = fs.statSync(filePath).mode;
    // ruleid: typescript-files-posix-permissions
    fs.chmodSync(filePath, currentMode | worldWritable); // Adding world-writable permission
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_1() {
    const filePath = '/path/to/sensitive/file.txt';
    // ok: typescript-files-posix-permissions
    fs.chmodSync(filePath, 0o640); // Owner read/write, group read only
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_2() {
    const configFile = '/etc/app/config.json';
    // ok: typescript-files-posix-permissions
    fs.chmod(configFile, 0o600, (err) => { // Owner read/write only
        if (err) throw err;
        console.log('File permissions updated securely');
    });
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_3() {
    const logDirectory = '/var/log/app';
    // ok: typescript-files-posix-permissions
    fs.chmodSync(logDirectory, '750'); // Owner all, group read/execute
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_4() {
    const secretsFile = '/app/secrets.json';
    
    async function updatePermissions() {
        try {
            // ok: typescript-files-posix-permissions
            await fsPromises.chmod(secretsFile, 0o600); // Owner read/write only
            console.log('Permissions updated securely');
        } catch (error) {
            console.error('Error updating permissions:', error);
        }
    }
    
    updatePermissions();
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_5() {
    const tempDir = '/tmp/app_data';
    
    if (!fs.existsSync(tempDir)) {
        fs.mkdirSync(tempDir);
        // ok: typescript-files-posix-permissions
        fs.chmodSync(tempDir, 0o755); // Owner all, others read/execute
    }
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_6() {
    const uploadDir = '/var/www/uploads';
    
    // ok: typescript-files-posix-permissions
    fs.mkdirSync(uploadDir, { mode: 0o750 }); // Owner all, group read/execute
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_7() {
    const keyFile = '/etc/ssl/private/server.key';
    
    fs.writeFileSync(keyFile, '-----BEGIN PRIVATE KEY-----\n...');
    // ok: typescript-files-posix-permissions
    fs.chmodSync(keyFile, 0o600); // Owner read/write only
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_8() {
    const dbConfigFile = '/app/database.conf';
    const mode = 0o640; // Secure permissions stored in variable
    
    // ok: typescript-files-posix-permissions
    fs.chmodSync(dbConfigFile, mode);
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_9() {
    const filePath = '/path/to/data.json';
    const permissions = '0640'; // String representation with leading zero
    
    // ok: typescript-files-posix-permissions
    fs.chmodSync(filePath, parseInt(permissions, 8));
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_10() {
    const backupDir = '/backup';
    
    try {
        // ok: typescript-files-posix-permissions
        fs.mkdirSync(backupDir, { recursive: true, mode: 0o750 });
    } catch (error) {
        console.error('Failed to create backup directory:', error);
    }
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_11() {
    const filePath = '/app/data.txt';
    
    fs.writeFile(filePath, 'sensitive data', (err) => {
        if (err) throw err;
        // ok: typescript-files-posix-permissions
        fs.chmod(filePath, 0o640, (err) => {
            if (err) throw err;
            console.log('File created with secure permissions');
        });
    });
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_12() {
    const configDir = '/etc/app/config';
    const permissionMask = 0o750;
    
    // ok: typescript-files-posix-permissions
    fs.mkdirSync(configDir, { mode: permissionMask });
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_13() {
    const tempFile = path.join('/tmp', 'temp_' + Date.now() + '.json');
    
    fs.writeFileSync(tempFile, JSON.stringify({ key: 'value' }));
    // ok: typescript-files-posix-permissions
    fs.chmodSync(tempFile, 0o600);
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_14() {
    async function setupEnvironment() {
        const appDir = '/opt/myapp';
        
        try {
            // ok: typescript-files-posix-permissions
            await fsPromises.mkdir(appDir, { recursive: true, mode: 0o750 });
            console.log('Application directory created securely');
        } catch (error) {
            console.error('Failed to create directory:', error);
        }
    }
    
    setupEnvironment();
}
// {/fact}

// {fact rule=loose-file-permissions@v1.0 defects=0}
function good_case_15() {
    const ownerWritable = 0o200; // Write permission for owner only
    const filePath = '/path/to/file.txt';
    
    const currentMode = fs.statSync(filePath).mode;
    // ok: typescript-files-posix-permissions
    fs.chmodSync(filePath, (currentMode & ~0o7) | ownerWritable); // Removing all permissions for others, adding owner write
}
// {/fact}