// File: buffer_noassert_test_cases.ts
import * as fs from 'fs';
import * as http from 'http';
import * as crypto from 'crypto';

// True Positive Cases (Vulnerable)

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_1() {
  const buffer = Buffer.alloc(10);
  // ruleid: detect-buffer-noassert-ts-rule
  buffer.readUInt32LE(8, true); // Using noassert=true allows reading beyond buffer bounds
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_2() {
  const buffer = Buffer.from([0x01, 0x02, 0x03, 0x04]);
  // ruleid: detect-buffer-noassert-ts-rule
  buffer.writeUInt32BE(0xdeadbeef, 2, true); // Writing beyond buffer bounds with noassert=true
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_3() {
  const smallBuffer = Buffer.alloc(4);
  const value = 0x12345678;
  // ruleid: detect-buffer-noassert-ts-rule
  smallBuffer.writeInt32LE(value, 2, true); // Writing beyond buffer bounds with noassert=true
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_4() {
  const buffer = Buffer.from('hello world');
  // ruleid: detect-buffer-noassert-ts-rule
  const value = buffer.readDoubleBE(8, true); // Reading beyond buffer bounds with noassert=true
  console.log(value);
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_5() {
  http.createServer((req, res) => {
    const buffer = Buffer.from([0x01, 0x02, 0x03]);
    const offset = parseInt(req.url?.split('=')[1] || '0');
    // ruleid: detect-buffer-noassert-ts-rule
    const value = buffer.readUInt8(offset, true); // Using noassert with user-controlled offset
    res.end(`Value: ${value}`);
  });
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_6() {
  const buffer = Buffer.alloc(8);
  for (let i = 0; i < 10; i++) {
    // ruleid: detect-buffer-noassert-ts-rule
    buffer.writeUInt8(i, i, true); // Loop writes beyond buffer bounds with noassert=true
  }
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_7() {
  const fileData = fs.readFileSync('data.bin');
  // ruleid: detect-buffer-noassert-ts-rule
  const value = fileData.readBigInt64LE(fileData.length - 4, true); // Reading beyond bounds with noassert=true
  return value;
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_8() {
  const buffer = Buffer.from('sensitive data');
  function processAtOffset(offset: number) {
    // ruleid: detect-buffer-noassert-ts-rule
    return buffer.readUInt16LE(offset, true); // Function using noassert=true
  }
  return processAtOffset(20); // Calling with out-of-bounds offset
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_9() {
  const server = http.createServer((req, res) => {
    const data = Buffer.from([0x01, 0x02, 0x03, 0x04]);
    const params = new URLSearchParams(req.url?.split('?')[1]);
    const offset = parseInt(params.get('offset') || '0');
    const value = parseInt(params.get('value') || '0');
    
    // ruleid: detect-buffer-noassert-ts-rule
    data.writeUInt16BE(value, offset, true); // Writing with user-controlled offset and noassert=true
    
    res.end('Data written');
  });
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_10() {
  class DataProcessor {
    private buffer: Buffer;
    
    constructor(size: number) {
      this.buffer = Buffer.alloc(size);
    }
    
    readValue(offset: number): number {
      // ruleid: detect-buffer-noassert-ts-rule
      return this.buffer.readFloatBE(offset, true); // Class method using noassert=true
    }
  }
  
  const processor = new DataProcessor(4);
  return processor.readValue(10); // Using out-of-bounds offset
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_11() {
  const buffer = Buffer.alloc(16);
  let offset = 0;
  
  // Fill buffer with some data
  for (let i = 0; i < 4; i++) {
    buffer.writeUInt32LE(i, i * 4);
  }
  
  // Read values with increasing offset
  while (offset <= 20) {
    // ruleid: detect-buffer-noassert-ts-rule
    const val = buffer.readUInt32LE(offset, true); // Will eventually read beyond bounds with noassert=true
    console.log(val);
    offset += 4;
  }
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_12() {
  const configData = Buffer.from(JSON.stringify({key: "value"}));
  
  function extractConfigValue(key: string, offset: number): number {
    // ruleid: detect-buffer-noassert-ts-rule
    return configData.readUInt8(offset, true); // Using noassert in a configuration extraction function
  }
  
  return extractConfigValue("someKey", 100); // Out-of-bounds access
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_13() {
  const buffer = Buffer.concat([
    Buffer.from([0x01, 0x02]),
    Buffer.from([0x03, 0x04])
  ]);
  
  // ruleid: detect-buffer-noassert-ts-rule
  buffer.writeInt16LE(0x0506, 3, true); // Writing beyond bounds of concatenated buffer with noassert=true
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_14() {
  http.createServer((req, res) => {
    const requestBody: Buffer[] = [];
    
    req.on('data', (chunk) => {
      requestBody.push(chunk);
    });
    
    req.on('end', () => {
      const buffer = Buffer.concat(requestBody);
      const offset = buffer.length - 2; // Potentially dangerous if buffer is too small
      
      // ruleid: detect-buffer-noassert-ts-rule
      const value = buffer.readUInt32LE(offset, true); // Could read beyond bounds with noassert=true
      
      res.end(`Processed: ${value}`);
    });
  });
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=1}
function bad_case_15() {
  const encryptData = (data: string): Buffer => {
    const key = crypto.randomBytes(16);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
    
    const encrypted = Buffer.concat([
      cipher.update(data),
      cipher.final()
    ]);
    
    // ruleid: detect-buffer-noassert-ts-rule
    encrypted.readUInt32BE(encrypted.length - 2, true); // Reading beyond bounds with noassert=true
    
    return encrypted;
  };
  
  return encryptData("sensitive information");
}
// {/fact}

// True Negative Cases (Safe)

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_1() {
  const buffer = Buffer.alloc(10);
  // ok: detect-buffer-noassert-ts-rule
  buffer.readUInt32LE(6); // Safe: No noassert parameter, bounds checking enabled
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_2() {
  const buffer = Buffer.from([0x01, 0x02, 0x03, 0x04]);
  try {
    // ok: detect-buffer-noassert-ts-rule
    buffer.writeUInt32BE(0xdeadbeef, 2); // Safe: No noassert parameter, will throw if out of bounds
  } catch (err) {
    console.error('Buffer bounds error:', err);
  }
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_3() {
  const buffer = Buffer.alloc(8);
  const value = 0x12345678;
  // ok: detect-buffer-noassert-ts-rule
  buffer.writeInt32LE(value, 0); // Safe: Writing within bounds, no noassert parameter
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_4() {
  const buffer = Buffer.from('hello world');
  // ok: detect-buffer-noassert-ts-rule
  const value = buffer.readUInt8(5); // Safe: Reading within bounds, no noassert parameter
  console.log(value);
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_5() {
  http.createServer((req, res) => {
    const buffer = Buffer.from([0x01, 0x02, 0x03]);
    const offset = parseInt(req.url?.split('=')[1] || '0');
    
    // Validate offset before reading
    if (offset >= 0 && offset < buffer.length) {
      // ok: detect-buffer-noassert-ts-rule
      const value = buffer.readUInt8(offset); // Safe: Bounds checked before reading
      res.end(`Value: ${value}`);
    } else {
      res.end('Invalid offset');
    }
  });
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_6() {
  const buffer = Buffer.alloc(8);
  // ok: detect-buffer-noassert-ts-rule
  for (let i = 0; i < buffer.length; i++) {
    buffer.writeUInt8(i, i); // Safe: Loop stays within buffer bounds
  }
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_7() {
  const fileData = fs.readFileSync('data.bin');
  // Ensure we have enough data before reading
  if (fileData.length >= 8) {
    // ok: detect-buffer-noassert-ts-rule
    const value = fileData.readBigInt64LE(0); // Safe: Reading from valid offset
    return value;
  }
  return BigInt(0);
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_8() {
  const buffer = Buffer.from('sensitive data');
  function processAtOffset(offset: number) {
    if (offset >= 0 && offset + 2 <= buffer.length) {
      // ok: detect-buffer-noassert-ts-rule
      return buffer.readUInt16LE(offset); // Safe: Function validates offset before reading
    }
    throw new Error('Invalid offset');
  }
  return processAtOffset(2);
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_9() {
  const server = http.createServer((req, res) => {
    const data = Buffer.from([0x01, 0x02, 0x03, 0x04]);
    const params = new URLSearchParams(req.url?.split('?')[1]);
    const offset = parseInt(params.get('offset') || '0');
    const value = parseInt(params.get('value') || '0');
    
    // Validate offset before writing
    if (offset >= 0 && offset + 2 <= data.length) {
      // ok: detect-buffer-noassert-ts-rule
      data.writeUInt16BE(value, offset); // Safe: Validated offset before writing
      res.end('Data written');
    } else {
      res.end('Invalid offset');
    }
  });
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_10() {
  class DataProcessor {
    private buffer: Buffer;
    
    constructor(size: number) {
      this.buffer = Buffer.alloc(size);
    }
    
    readValue(offset: number): number | null {
      if (offset >= 0 && offset + 4 <= this.buffer.length) {
        // ok: detect-buffer-noassert-ts-rule
        return this.buffer.readFloatBE(offset); // Safe: Class method validates offset
      }
      return null;
    }
  }
  
  const processor = new DataProcessor(8);
  return processor.readValue(4);
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_11() {
  const buffer = Buffer.alloc(16);
  
  // Fill buffer with some data
  for (let i = 0; i < 4; i++) {
    buffer.writeUInt32LE(i, i * 4);
  }
  
  // Read values with bounds checking
  for (let offset = 0; offset <= buffer.length - 4; offset += 4) {
    // ok: detect-buffer-noassert-ts-rule
    const val = buffer.readUInt32LE(offset); // Safe: Loop ensures offset is within bounds
    console.log(val);
  }
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_12() {
  const configData = Buffer.from(JSON.stringify({key: "value"}));
  
  function extractConfigValue(key: string, offset: number): number | null {
    if (offset < 0 || offset >= configData.length) {
      return null;
    }
    // ok: detect-buffer-noassert-ts-rule
    return configData.readUInt8(offset); // Safe: Function validates offset
  }
  
  return extractConfigValue("someKey", 5);
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_13() {
  const buffer = Buffer.concat([
    Buffer.from([0x01, 0x02]),
    Buffer.from([0x03, 0x04])
  ]);
  
  // Check buffer size before writing
  if (buffer.length >= 4) {
    // ok: detect-buffer-noassert-ts-rule
    buffer.writeInt16LE(0x0506, 2); // Safe: Writing within bounds of concatenated buffer
  }
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_14() {
  http.createServer((req, res) => {
    const requestBody: Buffer[] = [];
    
    req.on('data', (chunk) => {
      requestBody.push(chunk);
    });
    
    req.on('end', () => {
      const buffer = Buffer.concat(requestBody);
      
      // Ensure buffer is large enough before reading
      if (buffer.length >= 4) {
        // ok: detect-buffer-noassert-ts-rule
        const value = buffer.readUInt32LE(0); // Safe: Checked buffer size before reading
        res.end(`Processed: ${value}`);
      } else {
        res.end('Insufficient data');
      }
    });
  });
}
// {/fact}

// {fact rule=improper-restriction-of-operations-within-memory-bounds@v1.0 defects=0}
function good_case_15() {
  const encryptData = (data: string): Buffer => {
    const key = crypto.randomBytes(16);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
    
    const encrypted = Buffer.concat([
      cipher.update(data),
      cipher.final()
    ]);
    
    // Read safely from the buffer
    if (encrypted.length >= 4) {
      // ok: detect-buffer-noassert-ts-rule
      encrypted.readUInt32BE(0); // Safe: Reading within bounds
    }
    
    return encrypted;
  };
  
  return encryptData("sensitive information");
}
// {/fact}