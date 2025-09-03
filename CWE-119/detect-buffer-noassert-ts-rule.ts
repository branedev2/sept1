// File: buffer_noassert_test_cases.ts

import * as fs from 'fs';
import * as http from 'http';
import * as crypto from 'crypto';

// True Positive Cases (Vulnerable)

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_1() {
    const buffer = Buffer.alloc(10);
    // ruleid: detect-buffer-noassert-ts-rule
    const value = buffer.readUInt32LE(8, true); // This could read beyond buffer bounds
    console.log(value);
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_2() {
    const buffer = Buffer.from('Hello, world!');
    // ruleid: detect-buffer-noassert-ts-rule
    buffer.writeUInt16BE(0xFFFF, 12, true); // Writing beyond buffer bounds
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_3() {
    const source = Buffer.from([0x01, 0x02, 0x03, 0x04]);
    const target = Buffer.alloc(2);
    
    // ruleid: detect-buffer-noassert-ts-rule
    source.copy(target, 0, 0, 4, true); // Copying more bytes than target can hold
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_4() {
    const buffer = Buffer.from('Testing buffer bounds');
    let offset = 20; // Beyond buffer length
    
    // ruleid: detect-buffer-noassert-ts-rule
    const byte = buffer.readInt8(offset, true);
    console.log(`Byte at offset ${offset}: ${byte}`);
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_5() {
    const server = http.createServer((req, res) => {
        const buffer = Buffer.alloc(4);
        const offset = parseInt(req.url?.split('=')[1] || '0');
        
        // ruleid: detect-buffer-noassert-ts-rule
        buffer.writeFloatBE(3.14, offset, true); // User-controlled offset with noassert
        
        res.end('Data written');
    });
    server.listen(3000);
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_6() {
    function processData(data: Buffer) {
        const smallBuffer = Buffer.alloc(10);
        // ruleid: detect-buffer-noassert-ts-rule
        data.copy(smallBuffer, 0, 0, data.length, true); // Could overflow smallBuffer
        return smallBuffer;
    }
    
    const largeBuffer = Buffer.alloc(100).fill(0xFF);
    const result = processData(largeBuffer);
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_7() {
    const buffer = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05]);
    let i = 0;
    
    while (i < 10) {
        try {
            // ruleid: detect-buffer-noassert-ts-rule
            const value = buffer.readUInt8(i, true); // Will read beyond buffer bounds
            console.log(value);
        } catch (e) {
            // This won't catch errors due to noassert=true
            console.error('Error:', e);
        }
        i++;
    }
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_8() {
    const configureBuffer = (size: number, offset: number) => {
        const buf = Buffer.alloc(size);
        // ruleid: detect-buffer-noassert-ts-rule
        buf.writeInt32LE(0x12345678, offset, true); // offset could be beyond buffer size
        return buf;
    };
    
    const result = configureBuffer(4, 8); // Offset is beyond buffer size
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_9() {
    class BufferHandler {
        private buffer: Buffer;
        
        constructor(size: number) {
            this.buffer = Buffer.alloc(size);
        }
        
        readValue(offset: number): number {
            // ruleid: detect-buffer-noassert-ts-rule
            return this.buffer.readDoubleLE(offset, true); // No bounds checking
        }
    }
    
    const handler = new BufferHandler(4);
    console.log(handler.readValue(10)); // Reading beyond buffer size
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_10() {
    const processRequest = (requestBody: string) => {
        const buffer = Buffer.from(requestBody);
        const positions = [0, 4, 8, 12, 16, 20]; // Some positions may be beyond buffer length
        
        return positions.map(pos => {
            // ruleid: detect-buffer-noassert-ts-rule
            return buffer.readUInt32BE(pos, true); // Some reads may go beyond buffer
        });
    };
    
    processRequest('small');
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_11() {
    const writeConfig = (buffer: Buffer, config: Record<string, number>) => {
        // ruleid: detect-buffer-noassert-ts-rule
        buffer.writeUInt16LE(config.version || 0, config.offset || 0, true);
    };
    
    const buf = Buffer.alloc(2);
    writeConfig(buf, { version: 1, offset: 10 }); // Offset beyond buffer size
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_12() {
    const parseHeader = (buffer: Buffer) => {
        const header = {
            magic: 0,
            version: 0,
            length: 0,
            checksum: 0
        };
        
        // ruleid: detect-buffer-noassert-ts-rule
        header.magic = buffer.readUInt32BE(0, true);
        // ruleid: detect-buffer-noassert-ts-rule
        header.version = buffer.readUInt16BE(4, true);
        // ruleid: detect-buffer-noassert-ts-rule
        header.length = buffer.readUInt32BE(6, true);
        // ruleid: detect-buffer-noassert-ts-rule
        header.checksum = buffer.readUInt32BE(10, true);
        
        return header;
    };
    
    const smallBuffer = Buffer.from([0x01, 0x02]);
    parseHeader(smallBuffer); // Buffer too small for all reads
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_13() {
    const generatePacket = (type: number, payload: Buffer) => {
        const header = Buffer.alloc(4);
        const packet = Buffer.concat([header, payload]);
        
        // ruleid: detect-buffer-noassert-ts-rule
        packet.writeUInt8(type, 0, true);
        // ruleid: detect-buffer-noassert-ts-rule
        packet.writeUInt16BE(payload.length, 1, true);
        // ruleid: detect-buffer-noassert-ts-rule
        packet.writeUInt8(calculateChecksum(payload), 3, true);
        
        return packet;
    };
    
    const calculateChecksum = (data: Buffer): number => {
        return data.reduce((sum, byte) => sum + byte, 0) % 256;
    };
    
    generatePacket(1, Buffer.alloc(100));
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_14() {
    const readFileInChunks = (filePath: string, chunkSize: number) => {
        const fd = fs.openSync(filePath, 'r');
        const buffer = Buffer.alloc(chunkSize);
        let bytesRead = 0;
        let chunks = [];
        
        try {
            while ((bytesRead = fs.readSync(fd, buffer, 0, chunkSize, null)) > 0) {
                const chunk = Buffer.alloc(bytesRead);
                // ruleid: detect-buffer-noassert-ts-rule
                buffer.copy(chunk, 0, 0, bytesRead + 10, true); // Could read beyond buffer bounds
                chunks.push(chunk);
            }
        } finally {
            fs.closeSync(fd);
        }
        
        return Buffer.concat(chunks);
    };
    
    // readFileInChunks('example.txt', 1024);
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_15() {
    const decodeMessage = (encryptedBuffer: Buffer, key: Buffer) => {
        const iv = Buffer.alloc(16);
        // ruleid: detect-buffer-noassert-ts-rule
        encryptedBuffer.copy(iv, 0, 0, 16, true); // May read beyond buffer bounds
        
        const encryptedData = Buffer.alloc(encryptedBuffer.length - 16);
        // ruleid: detect-buffer-noassert-ts-rule
        encryptedBuffer.copy(encryptedData, 0, 16, encryptedBuffer.length, true);
        
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        const decrypted = Buffer.concat([
            decipher.update(encryptedData),
            decipher.final()
        ]);
        
        return decrypted;
    };
    
    // const key = crypto.randomBytes(32);
    // const shortBuffer = Buffer.alloc(10);
    // decodeMessage(shortBuffer, key); // Buffer too small
}
// {/fact}

// True Negative Cases (Safe)

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_1() {
    const buffer = Buffer.alloc(10);
    // ok: detect-buffer-noassert-ts-rule
    const value = buffer.readUInt32LE(8); // No noassert parameter, safe bounds checking
    console.log(value);
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_2() {
    const buffer = Buffer.from('Hello, world!');
    try {
        // ok: detect-buffer-noassert-ts-rule
        buffer.writeUInt16BE(0xFFFF, 12); // Will throw if out of bounds
    } catch (e) {
        console.error('Buffer bounds error:', e);
    }
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_3() {
    const source = Buffer.from([0x01, 0x02, 0x03, 0x04]);
    const target = Buffer.alloc(2);
    
    // ok: detect-buffer-noassert-ts-rule
    const bytesCopied = source.copy(target); // Safe copy with bounds checking
    console.log(`Copied ${bytesCopied} bytes`);
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_4() {
    const buffer = Buffer.from('Testing buffer bounds');
    let offset = 20; // Beyond buffer length
    
    if (offset < buffer.length) {
        // ok: detect-buffer-noassert-ts-rule
        const byte = buffer.readInt8(offset);
        console.log(`Byte at offset ${offset}: ${byte}`);
    } else {
        console.error('Offset out of bounds');
    }
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_5() {
    const server = http.createServer((req, res) => {
        const buffer = Buffer.alloc(4);
        const rawOffset = req.url?.split('=')[1] || '0';
        const offset = parseInt(rawOffset);
        
        if (offset >= 0 && offset <= buffer.length - 4) {
            // ok: detect-buffer-noassert-ts-rule
            buffer.writeFloatBE(3.14, offset); // Safe with bounds checking
            res.end('Data written');
        } else {
            res.statusCode = 400;
            res.end('Invalid offset');
        }
    });
    server.listen(3000);
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_6() {
    function processData(data: Buffer) {
        const smallBuffer = Buffer.alloc(10);
        // ok: detect-buffer-noassert-ts-rule
        data.copy(smallBuffer, 0, 0, Math.min(data.length, smallBuffer.length)); // Safe copy
        return smallBuffer;
    }
    
    const largeBuffer = Buffer.alloc(100).fill(0xFF);
    const result = processData(largeBuffer);
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_7() {
    const buffer = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05]);
    let i = 0;
    
    while (i < 10) {
        if (i < buffer.length) {
            // ok: detect-buffer-noassert-ts-rule
            const value = buffer.readUInt8(i); // Safe bounds checking
            console.log(value);
        } else {
            console.log('End of buffer reached');
            break;
        }
        i++;
    }
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_8() {
    const configureBuffer = (size: number, offset: number) => {
        const buf = Buffer.alloc(size);
        if (offset + 4 <= buf.length) {
            // ok: detect-buffer-noassert-ts-rule
            buf.writeInt32LE(0x12345678, offset); // Safe with bounds checking
        } else {
            throw new Error('Offset would write beyond buffer bounds');
        }
        return buf;
    };
    
    try {
        const result = configureBuffer(4, 0); // Safe offset
    } catch (e) {
        console.error(e);
    }
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_9() {
    class BufferHandler {
        private buffer: Buffer;
        
        constructor(size: number) {
            this.buffer = Buffer.alloc(size);
        }
        
        readValue(offset: number): number | null {
            if (offset + 8 <= this.buffer.length) {
                // ok: detect-buffer-noassert-ts-rule
                return this.buffer.readDoubleLE(offset); // Safe with bounds checking
            }
            return null; // Return null for out of bounds
        }
    }
    
    const handler = new BufferHandler(16);
    console.log(handler.readValue(8)); // Safe read
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_10() {
    const processRequest = (requestBody: string) => {
        const buffer = Buffer.from(requestBody);
        const positions = [0, 4, 8, 12, 16, 20]; // Some positions may be beyond buffer length
        
        return positions
            .filter(pos => pos + 4 <= buffer.length) // Filter valid positions
            .map(pos => {
                // ok: detect-buffer-noassert-ts-rule
                return buffer.readUInt32BE(pos); // Safe with bounds checking
            });
    };
    
    processRequest('small');
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_11() {
    const writeConfig = (buffer: Buffer, config: Record<string, number>) => {
        const offset = config.offset || 0;
        if (offset + 2 <= buffer.length) {
            // ok: detect-buffer-noassert-ts-rule
            buffer.writeUInt16LE(config.version || 0, offset);
            return true;
        }
        return false;
    };
    
    const buf = Buffer.alloc(2);
    const success = writeConfig(buf, { version: 1, offset: 0 }); // Safe offset
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_12() {
    const parseHeader = (buffer: Buffer) => {
        if (buffer.length < 14) {
            throw new Error('Buffer too small to contain header');
        }
        
        const header = {
            magic: 0,
            version: 0,
            length: 0,
            checksum: 0
        };
        
        // ok: detect-buffer-noassert-ts-rule
        header.magic = buffer.readUInt32BE(0);
        // ok: detect-buffer-noassert-ts-rule
        header.version = buffer.readUInt16BE(4);
        // ok: detect-buffer-noassert-ts-rule
        header.length = buffer.readUInt32BE(6);
        // ok: detect-buffer-noassert-ts-rule
        header.checksum = buffer.readUInt32BE(10);
        
        return header;
    };
    
    try {
        const properBuffer = Buffer.alloc(14);
        parseHeader(properBuffer); // Buffer large enough
    } catch (e) {
        console.error(e);
    }
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_13() {
    const generatePacket = (type: number, payload: Buffer) => {
        const header = Buffer.alloc(4);
        
        // ok: detect-buffer-noassert-ts-rule
        header.writeUInt8(type, 0);
        // ok: detect-buffer-noassert-ts-rule
        header.writeUInt16BE(payload.length, 1);
        // ok: detect-buffer-noassert-ts-rule
        header.writeUInt8(calculateChecksum(payload), 3);
        
        return Buffer.concat([header, payload]);
    };
    
    const calculateChecksum = (data: Buffer): number => {
        return data.reduce((sum, byte) => sum + byte, 0) % 256;
    };
    
    generatePacket(1, Buffer.alloc(100));
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_14() {
    const readFileInChunks = (filePath: string, chunkSize: number) => {
        const fd = fs.openSync(filePath, 'r');
        const buffer = Buffer.alloc(chunkSize);
        let bytesRead = 0;
        let chunks = [];
        
        try {
            while ((bytesRead = fs.readSync(fd, buffer, 0, chunkSize, null)) > 0) {
                const chunk = Buffer.alloc(bytesRead);
                // ok: detect-buffer-noassert-ts-rule
                buffer.copy(chunk, 0, 0, bytesRead); // Safe copy with bounds checking
                chunks.push(chunk);
            }
        } finally {
            fs.closeSync(fd);
        }
        
        return Buffer.concat(chunks);
    };
    
    // readFileInChunks('example.txt', 1024);
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_15() {
    const decodeMessage = (encryptedBuffer: Buffer, key: Buffer) => {
        if (encryptedBuffer.length < 16) {
            throw new Error('Encrypted buffer too small');
        }
        
        const iv = Buffer.alloc(16);
        // ok: detect-buffer-noassert-ts-rule
        encryptedBuffer.copy(iv, 0, 0, 16); // Safe with bounds checking
        
        const encryptedData = Buffer.alloc(encryptedBuffer.length - 16);
        // ok: detect-buffer-noassert-ts-rule
        encryptedBuffer.copy(encryptedData, 0, 16, encryptedBuffer.length);
        
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        const decrypted = Buffer.concat([
            decipher.update(encryptedData),
            decipher.final()
        ]);
        
        return decrypted;
    };
    
    // const key = crypto.randomBytes(32);
    // const properBuffer = Buffer.alloc(32);
    // decodeMessage(properBuffer, key); // Buffer large enough
}
// {/fact}