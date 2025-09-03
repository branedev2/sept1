import * as crypto from 'crypto';
import { promisify } from 'util';

// True Positive Examples (Vulnerable Code)

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_1() {
    const password = 'user-password';
    const salt = crypto.randomBytes(16);
    
    // ruleid: typescript-hash-algo-compliance-check-for-pbkdf2
    crypto.pbkdf2(password, salt, 10000, 64, 'md5', (err, derivedKey) => {
        if (err) throw err;
        console.log(derivedKey.toString('hex'));
    });
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_2() {
    const password = 'user-password';
    const salt = crypto.randomBytes(16);
    
    // ruleid: typescript-hash-algo-compliance-check-for-pbkdf2
    const key = crypto.pbkdf2Sync(password, salt, 10000, 32, 'md5');
    console.log(key.toString('hex'));
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_3() {
    const userInput = 'password123';
    const salt = crypto.randomBytes(16);
    const iterations = 1000;
    const keylen = 64;
    
    // ruleid: typescript-hash-algo-compliance-check-for-pbkdf2
    const digest = 'sha1';
    crypto.pbkdf2(userInput, salt, iterations, keylen, digest, (err, key) => {
        if (err) throw err;
        console.log(key.toString('hex'));
    });
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_4() {
    const password = 'secure-password';
    const salt = 'static-salt';
    const iterations = 5000;
    
    // ruleid: typescript-hash-algo-compliance-check-for-pbkdf2
    const hash = crypto.pbkdf2Sync(password, salt, iterations, 64, 'ripemd160');
    return hash.toString('hex');
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_5() {
    const pbkdf2Async = promisify(crypto.pbkdf2);
    
    async function hashPassword(password: string): Promise<string> {
        const salt = crypto.randomBytes(16);
        // ruleid: typescript-hash-algo-compliance-check-for-pbkdf2
        const derivedKey = await pbkdf2Async(password, salt, 10000, 32, 'md4');
        return derivedKey.toString('hex');
    }
    
    hashPassword('my-password').then(console.log);
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_6() {
    const password = 'user-input';
    const salt = crypto.randomBytes(16);
    const algorithm = 'sha1';
    
    // ruleid: typescript-hash-algo-compliance-check-for-pbkdf2
    crypto.pbkdf2(password, salt, 10000, 64, algorithm, (err, key) => {
        if (err) throw err;
        return key.toString('hex');
    });
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_7() {
    class PasswordService {
        hashPassword(password: string): Promise<string> {
            return new Promise((resolve, reject) => {
                const salt = crypto.randomBytes(16);
                // ruleid: typescript-hash-algo-compliance-check-for-pbkdf2
                crypto.pbkdf2(password, salt, 1000, 64, 'md5', (err, key) => {
                    if (err) reject(err);
                    else resolve(key.toString('hex'));
                });
            });
        }
    }
    
    const service = new PasswordService();
    service.hashPassword('password123').then(console.log);
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_8() {
    function deriveKey(password: string, salt: Buffer): Buffer {
        // ruleid: typescript-hash-algo-compliance-check-for-pbkdf2
        return crypto.pbkdf2Sync(password, salt, 10000, 32, 'rmd160');
    }
    
    const key = deriveKey('secret', crypto.randomBytes(16));
    console.log(key.toString('hex'));
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_9() {
    const getHashAlgorithm = () => {
        return 'md5';
    };
    
    const password = 'user-password';
    const salt = crypto.randomBytes(16);
    
    // ruleid: typescript-hash-algo-compliance-check-for-pbkdf2
    crypto.pbkdf2(password, salt, 10000, 64, getHashAlgorithm(), (err, derivedKey) => {
        if (err) throw err;
        console.log(derivedKey.toString('hex'));
    });
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_10() {
    const config = {
        iterations: 10000,
        keylen: 64,
        digest: 'sha1'
    };
    
    const password = 'user-password';
    const salt = crypto.randomBytes(16);
    
    // ruleid: typescript-hash-algo-compliance-check-for-pbkdf2
    const key = crypto.pbkdf2Sync(password, salt, config.iterations, config.keylen, config.digest);
    console.log(key.toString('hex'));
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_11() {
    interface HashOptions {
        algorithm: string;
        iterations: number;
        keyLength: number;
    }
    
    function hashWithOptions(password: string, options: HashOptions): Buffer {
        const salt = crypto.randomBytes(16);
        // ruleid: typescript-hash-algo-compliance-check-for-pbkdf2
        return crypto.pbkdf2Sync(password, salt, options.iterations, options.keyLength, options.algorithm);
    }
    
    const result = hashWithOptions('password', {
        algorithm: 'md5',
        iterations: 10000,
        keyLength: 32
    });
    console.log(result.toString('hex'));
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_12() {
    const algorithms = ['md5', 'sha1', 'sha256', 'sha512'];
    const password = 'test-password';
    const salt = crypto.randomBytes(16);
    
    for (const algo of algorithms) {
        if (algo === 'md5') {
            // ruleid: typescript-hash-algo-compliance-check-for-pbkdf2
            crypto.pbkdf2(password, salt, 10000, 64, algo, (err, key) => {
                if (err) throw err;
                console.log(`${algo}: ${key.toString('hex')}`);
            });
        }
    }
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_13() {
    const password = 'user-password';
    const salt = crypto.randomBytes(16);
    let algorithm: string;
    
    if (process.env.NODE_ENV === 'production') {
        algorithm = 'sha256';
    } else {
        algorithm = 'md5';
    }
    
    // ruleid: typescript-hash-algo-compliance-check-for-pbkdf2
    const key = crypto.pbkdf2Sync(password, salt, 10000, 64, algorithm);
    return key.toString('hex');
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_14() {
    function createHasher(algorithm: string) {
        return (password: string): Promise<string> => {
            return new Promise((resolve, reject) => {
                const salt = crypto.randomBytes(16);
                // ruleid: typescript-hash-algo-compliance-check-for-pbkdf2
                crypto.pbkdf2(password, salt, 10000, 64, algorithm, (err, key) => {
                    if (err) reject(err);
                    else resolve(key.toString('hex'));
                });
            });
        };
    }
    
    const md5Hasher = createHasher('md5');
    md5Hasher('password123').then(console.log);
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=1}
function bad_case_15() {
    const ALGORITHMS = {
        WEAK: 'sha1',
        MEDIUM: 'sha256',
        STRONG: 'sha512'
    };
    
    const password = 'user-password';
    const salt = crypto.randomBytes(16);
    
    // ruleid: typescript-hash-algo-compliance-check-for-pbkdf2
    const key = crypto.pbkdf2Sync(password, salt, 10000, 64, ALGORITHMS.WEAK);
    console.log(key.toString('hex'));
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_1() {
    const password = 'user-password';
    const salt = crypto.randomBytes(16);
    
    // ok: typescript-hash-algo-compliance-check-for-pbkdf2
    crypto.pbkdf2(password, salt, 10000, 64, 'sha256', (err, derivedKey) => {
        if (err) throw err;
        console.log(derivedKey.toString('hex'));
    });
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_2() {
    const password = 'user-password';
    const salt = crypto.randomBytes(16);
    
    // ok: typescript-hash-algo-compliance-check-for-pbkdf2
    const key = crypto.pbkdf2Sync(password, salt, 10000, 32, 'sha512');
    console.log(key.toString('hex'));
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_3() {
    const userInput = 'password123';
    const salt = crypto.randomBytes(16);
    const iterations = 100000; // Higher iteration count for better security
    const keylen = 64;
    
    // ok: typescript-hash-algo-compliance-check-for-pbkdf2
    const digest = 'sha256';
    crypto.pbkdf2(userInput, salt, iterations, keylen, digest, (err, key) => {
        if (err) throw err;
        console.log(key.toString('hex'));
    });
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_4() {
    const password = 'secure-password';
    const salt = crypto.randomBytes(16); // Dynamic salt
    const iterations = 100000; // Higher iteration count
    
    // ok: typescript-hash-algo-compliance-check-for-pbkdf2
    const hash = crypto.pbkdf2Sync(password, salt, iterations, 64, 'sha512');
    return hash.toString('hex');
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_5() {
    const pbkdf2Async = promisify(crypto.pbkdf2);
    
    async function hashPassword(password: string): Promise<string> {
        const salt = crypto.randomBytes(16);
        // ok: typescript-hash-algo-compliance-check-for-pbkdf2
        const derivedKey = await pbkdf2Async(password, salt, 100000, 32, 'sha256');
        return derivedKey.toString('hex');
    }
    
    hashPassword('my-password').then(console.log);
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_6() {
    const password = 'user-input';
    const salt = crypto.randomBytes(16);
    const algorithm = 'sha512';
    
    // ok: typescript-hash-algo-compliance-check-for-pbkdf2
    crypto.pbkdf2(password, salt, 100000, 64, algorithm, (err, key) => {
        if (err) throw err;
        return key.toString('hex');
    });
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_7() {
    class PasswordService {
        hashPassword(password: string): Promise<string> {
            return new Promise((resolve, reject) => {
                const salt = crypto.randomBytes(16);
                // ok: typescript-hash-algo-compliance-check-for-pbkdf2
                crypto.pbkdf2(password, salt, 100000, 64, 'sha512', (err, key) => {
                    if (err) reject(err);
                    else resolve(key.toString('hex'));
                });
            });
        }
    }
    
    const service = new PasswordService();
    service.hashPassword('password123').then(console.log);
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_8() {
    function deriveKey(password: string, salt: Buffer): Buffer {
        // ok: typescript-hash-algo-compliance-check-for-pbkdf2
        return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha384');
    }
    
    const key = deriveKey('secret', crypto.randomBytes(16));
    console.log(key.toString('hex'));
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_9() {
    const getHashAlgorithm = () => {
        return 'sha256';
    };
    
    const password = 'user-password';
    const salt = crypto.randomBytes(16);
    
    // ok: typescript-hash-algo-compliance-check-for-pbkdf2
    crypto.pbkdf2(password, salt, 100000, 64, getHashAlgorithm(), (err, derivedKey) => {
        if (err) throw err;
        console.log(derivedKey.toString('hex'));
    });
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_10() {
    const config = {
        iterations: 100000,
        keylen: 64,
        digest: 'sha512'
    };
    
    const password = 'user-password';
    const salt = crypto.randomBytes(16);
    
    // ok: typescript-hash-algo-compliance-check-for-pbkdf2
    const key = crypto.pbkdf2Sync(password, salt, config.iterations, config.keylen, config.digest);
    console.log(key.toString('hex'));
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_11() {
    interface HashOptions {
        algorithm: string;
        iterations: number;
        keyLength: number;
    }
    
    function hashWithOptions(password: string, options: HashOptions): Buffer {
        const salt = crypto.randomBytes(16);
        // ok: typescript-hash-algo-compliance-check-for-pbkdf2
        return crypto.pbkdf2Sync(password, salt, options.iterations, options.keyLength, options.algorithm);
    }
    
    const result = hashWithOptions('password', {
        algorithm: 'sha256',
        iterations: 100000,
        keyLength: 32
    });
    console.log(result.toString('hex'));
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_12() {
    const algorithms = ['sha256', 'sha384', 'sha512'];
    const password = 'test-password';
    const salt = crypto.randomBytes(16);
    
    for (const algo of algorithms) {
        // ok: typescript-hash-algo-compliance-check-for-pbkdf2
        crypto.pbkdf2(password, salt, 100000, 64, algo, (err, key) => {
            if (err) throw err;
            console.log(`${algo}: ${key.toString('hex')}`);
        });
    }
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_13() {
    const password = 'user-password';
    const salt = crypto.randomBytes(16);
    let algorithm: string;
    
    if (process.env.NODE_ENV === 'production') {
        algorithm = 'sha512';
    } else {
        algorithm = 'sha256';
    }
    
    // ok: typescript-hash-algo-compliance-check-for-pbkdf2
    const key = crypto.pbkdf2Sync(password, salt, 100000, 64, algorithm);
    return key.toString('hex');
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_14() {
    function createHasher(algorithm: string) {
        return (password: string): Promise<string> => {
            return new Promise((resolve, reject) => {
                const salt = crypto.randomBytes(16);
                // ok: typescript-hash-algo-compliance-check-for-pbkdf2
                crypto.pbkdf2(password, salt, 100000, 64, algorithm, (err, key) => {
                    if (err) reject(err);
                    else resolve(key.toString('hex'));
                });
            });
        };
    }
    
    const sha256Hasher = createHasher('sha256');
    sha256Hasher('password123').then(console.log);
}
// {/fact}

// {fact rule=clear-text-credentials@v1.0 defects=0}
function good_case_15() {
    const ALGORITHMS = {
        MEDIUM: 'sha256',
        STRONG: 'sha512'
    };
    
    const password = 'user-password';
    const salt = crypto.randomBytes(16);
    
    // ok: typescript-hash-algo-compliance-check-for-pbkdf2
    const key = crypto.pbkdf2Sync(password, salt, 100000, 64, ALGORITHMS.STRONG);
    console.log(key.toString('hex'));
}
// {/fact}