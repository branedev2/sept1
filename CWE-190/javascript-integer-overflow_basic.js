// Test cases for javascript-integer-overflow rule
// This file contains examples of vulnerable and safe code patterns related to integer overflow

// True Positives (Vulnerable Code)

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_1() {
  // Performing arithmetic that could lead to integer overflow
  const maxSafeInteger = Number.MAX_SAFE_INTEGER;
  // ruleid: javascript-integer-overflow
  const result = maxSafeInteger + 1; // This will cause precision loss
  console.log(result);
  return result;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_2() {
  // Multiplication that exceeds safe integer bounds
  const largeNumber = 9007199254740990;
  // ruleid: javascript-integer-overflow
  const product = largeNumber * 10; // Will exceed MAX_SAFE_INTEGER
  console.log("Product:", product);
  return product;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_3() {
  // Factorial calculation that will overflow
  function factorial(n) {
    if (n <= 1) return 1;
    // ruleid: javascript-integer-overflow
    return n * factorial(n - 1); // Will overflow for large n
  }
  
  const result = factorial(20); // 20! exceeds MAX_SAFE_INTEGER
  console.log(result);
  return result;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_4() {
  // Processing user input without checking for overflow
  const express = require('express');
  const app = express();
  
  app.get('/calculate', (req, res) => {
    const value = parseInt(req.query.value);
    // ruleid: javascript-integer-overflow
    const result = value * value * value; // Could overflow with large input
    res.send({ result });
  });
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_5() {
  // Exponential calculation leading to overflow
  const base = 2;
  const exponent = 1024;
  
  // ruleid: javascript-integer-overflow
  const result = Math.pow(base, exponent); // Will overflow
  console.log(result);
  return result;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_6() {
  // Bit shifting that causes overflow
  const value = 1;
  // ruleid: javascript-integer-overflow
  const shifted = value << 53; // Shifts beyond safe integer bits
  console.log(shifted);
  return shifted;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_7() {
  // Parsing large numbers from HTTP request
  const http = require('http');
  
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const largeNum = parseInt(url.searchParams.get('num'));
    
    // ruleid: javascript-integer-overflow
    const doubled = largeNum * 2; // Could overflow with large input
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ result: doubled }));
  });
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_8() {
  // Recursive calculation with potential overflow
  function fibonacci(n) {
    if (n <= 1) return n;
    // ruleid: javascript-integer-overflow
    return fibonacci(n - 1) + fibonacci(n - 2); // Will overflow for large n
  }
  
  const result = fibonacci(100); // Will cause overflow
  console.log(result);
  return result;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_9() {
  // Array length calculation that could overflow
  const express = require('express');
  const app = express();
  
  app.post('/create-array', (req, res) => {
    const size = parseInt(req.body.size);
    const multiplier = parseInt(req.body.multiplier);
    
    // ruleid: javascript-integer-overflow
    const totalElements = size * multiplier; // Could overflow
    
    const arr = new Array(totalElements);
    res.send({ arrayCreated: true, length: arr.length });
  });
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_10() {
  // Financial calculation with potential overflow
  const calculateCompoundInterest = (principal, rate, time, compoundingFrequency) => {
    // ruleid: javascript-integer-overflow
    const amount = principal * Math.pow(1 + rate/compoundingFrequency, compoundingFrequency * time);
    return amount;
  };
  
  const result = calculateCompoundInterest(1000000000, 0.05, 100, 365);
  console.log(result);
  return result;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_11() {
  // Hash calculation with large numbers
  const calculateHash = (value) => {
    let hash = 0;
    for (let i = 0; i < 100; i++) {
      // ruleid: javascript-integer-overflow
      hash = ((hash << 5) - hash) + value; // Could overflow with large iterations
    }
    return hash;
  };
  
  const result = calculateHash(Number.MAX_SAFE_INTEGER - 10);
  console.log(result);
  return result;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_12() {
  // Processing large dataset sizes
  const axios = require('axios');
  
  async function processLargeDataset() {
    const response = await axios.get('https://api.example.com/dataset');
    const dataSize = response.data.size;
    
    // ruleid: javascript-integer-overflow
    const processingUnits = dataSize * dataSize * 8; // Could overflow with large datasets
    
    console.log(`Required processing units: ${processingUnits}`);
    return processingUnits;
  }
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_13() {
  // Timer calculation with potential overflow
  const calculateTimeout = (baseDelay, multiplier, iterations) => {
    // ruleid: javascript-integer-overflow
    return baseDelay * Math.pow(multiplier, iterations); // Can overflow with large iterations
  };
  
  const timeout = calculateTimeout(100, 2, 40);
  console.log(timeout);
  setTimeout(() => console.log("Timer expired"), timeout);
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_14() {
  // ID generation with potential overflow
  const generateId = (prefix, timestamp) => {
    // ruleid: javascript-integer-overflow
    const id = prefix + (timestamp * 1000000); // Could overflow with large timestamp
    return id;
  };
  
  const id = generateId(9000000000000000, Date.now());
  console.log(id);
  return id;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_15() {
  // Buffer size calculation with potential overflow
  const fs = require('fs');
  const http = require('http');
  
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const fileSize = parseInt(url.searchParams.get('size'));
    const copies = parseInt(url.searchParams.get('copies'));
    
    // ruleid: javascript-integer-overflow
    const totalSize = fileSize * copies; // Could overflow with large inputs
    
    const buffer = Buffer.alloc(Math.min(totalSize, 1024)); // Limiting for safety, but calculation is still vulnerable
    res.writeHead(200);
    res.end(`Buffer of size ${buffer.length} created`);
  });
}
// {/fact}

// True Negatives (Safe Code)

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_1() {
  // Using BigInt for large integer arithmetic
  const maxSafeInteger = BigInt(Number.MAX_SAFE_INTEGER);
  // ok: javascript-integer-overflow
  const result = maxSafeInteger + 1n; // Using BigInt prevents overflow
  console.log(result.toString());
  return result;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_2() {
  // Safe multiplication with BigInt
  const largeNumber = 9007199254740990n;
  // ok: javascript-integer-overflow
  const product = largeNumber * 10n; // Using BigInt prevents overflow
  console.log("Product:", product.toString());
  return product;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_3() {
  // Safe factorial calculation using BigInt
  function factorial(n) {
    if (n <= 1n) return 1n;
    // ok: javascript-integer-overflow
    return n * factorial(n - 1n); // Using BigInt prevents overflow
  }
  
  const result = factorial(20n); // 20! is handled safely with BigInt
  console.log(result.toString());
  return result;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_4() {
  // Checking input range before calculation
  const express = require('express');
  const app = express();
  
  app.get('/calculate', (req, res) => {
    const value = parseInt(req.query.value);
    
    if (value > 1000) {
      return res.status(400).send({ error: 'Value too large' });
    }
    
    // ok: javascript-integer-overflow
    const result = value * value * value; // Safe because input is limited
    res.send({ result });
  });
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_5() {
  // Using BigInt for exponential calculation
  const base = 2n;
  const exponent = 1024;
  
  let result = 1n;
  for (let i = 0; i < exponent; i++) {
    // ok: javascript-integer-overflow
    result = result * base; // Using BigInt prevents overflow
  }
  
  console.log(result.toString());
  return result;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_6() {
  // Safe bit shifting with BigInt
  const value = 1n;
  // ok: javascript-integer-overflow
  const shifted = value << 53n; // Using BigInt prevents overflow
  console.log(shifted.toString());
  return shifted;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_7() {
  // Parsing large numbers safely from HTTP request
  const http = require('http');
  
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const largeNumStr = url.searchParams.get('num');
    
    try {
      // ok: javascript-integer-overflow
      const largeNum = BigInt(largeNumStr);
      const doubled = largeNum * 2n;
      
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ result: doubled.toString() }));
    } catch (e) {
      res.writeHead(400);
      res.end('Invalid number format');
    }
  });
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_8() {
  // Memoized fibonacci with BigInt to prevent overflow
  const memo = new Map();
  
  function fibonacci(n) {
    if (n <= 1n) return n;
    
    if (memo.has(n.toString())) {
      return memo.get(n.toString());
    }
    
    // ok: javascript-integer-overflow
    const result = fibonacci(n - 1n) + fibonacci(n - 2n); // Using BigInt prevents overflow
    memo.set(n.toString(), result);
    return result;
  }
  
  const result = fibonacci(100n); // Safely calculates large Fibonacci number
  console.log(result.toString());
  return result;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_9() {
  // Safe array length calculation
  const express = require('express');
  const app = express();
  
  app.post('/create-array', (req, res) => {
    const size = parseInt(req.body.size);
    const multiplier = parseInt(req.body.multiplier);
    
    // Check if calculation would exceed safe integer
    if (size > Number.MAX_SAFE_INTEGER / multiplier) {
      return res.status(400).send({ error: 'Requested array size too large' });
    }
    
    // ok: javascript-integer-overflow
    const totalElements = size * multiplier; // Safe because we checked bounds
    
    try {
      const arr = new Array(totalElements);
      res.send({ arrayCreated: true, length: arr.length });
    } catch (e) {
      res.status(500).send({ error: 'Failed to create array' });
    }
  });
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_10() {
  // Financial calculation with BigInt
  const calculateCompoundInterest = (principal, rate, time, compoundingFrequency) => {
    const principalBigInt = BigInt(Math.floor(principal));
    const rateBasis = BigInt(Math.floor(rate * 1000000));
    const timeBigInt = BigInt(time);
    const frequencyBigInt = BigInt(compoundingFrequency);
    
    // Simplified calculation with BigInt (approximation)
    // ok: javascript-integer-overflow
    let amount = principalBigInt;
    for (let i = 0n; i < timeBigInt * frequencyBigInt; i++) {
      amount = amount + (amount * rateBasis) / 1000000n;
    }
    
    return amount;
  };
  
  const result = calculateCompoundInterest(1000000000, 0.05, 100, 365);
  console.log(result.toString());
  return result;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_11() {
  // Safe hash calculation with BigInt
  const calculateHash = (value) => {
    let hash = 0n;
    const bigValue = BigInt(value);
    
    for (let i = 0; i < 100; i++) {
      // ok: javascript-integer-overflow
      hash = ((hash << 5n) - hash) + bigValue; // Using BigInt prevents overflow
    }
    
    return hash;
  };
  
  const result = calculateHash(Number.MAX_SAFE_INTEGER - 10);
  console.log(result.toString());
  return result;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_12() {
  // Safe processing of large dataset sizes
  const axios = require('axios');
  
  async function processLargeDataset() {
    const response = await axios.get('https://api.example.com/dataset');
    const dataSize = response.data.size;
    
    // ok: javascript-integer-overflow
    const processingUnits = BigInt(dataSize) * BigInt(dataSize) * 8n;
    
    console.log(`Required processing units: ${processingUnits.toString()}`);
    return processingUnits;
  }
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_13() {
  // Safe timer calculation
  const calculateTimeout = (baseDelay, multiplier, iterations) => {
    if (iterations > 30) {
      // Limit to avoid overflow
      return Number.MAX_SAFE_INTEGER;
    }
    
    // ok: javascript-integer-overflow
    return baseDelay * Math.pow(multiplier, iterations); // Safe due to input validation
  };
  
  const timeout = calculateTimeout(100, 2, 20);
  console.log(timeout);
  setTimeout(() => console.log("Timer expired"), Math.min(timeout, 2147483647));
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_14() {
  // Safe ID generation using string concatenation
  const generateId = (prefix, timestamp) => {
    // ok: javascript-integer-overflow
    const id = prefix.toString() + "_" + timestamp.toString(); // String concatenation avoids numeric overflow
    return id;
  };
  
  const id = generateId(9000000000000000, Date.now());
  console.log(id);
  return id;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_15() {
  // Safe buffer size calculation with bounds checking
  const fs = require('fs');
  const http = require('http');
  
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const fileSize = parseInt(url.searchParams.get('size'));
    const copies = parseInt(url.searchParams.get('copies'));
    
    // Check if multiplication would overflow
    if (fileSize > Number.MAX_SAFE_INTEGER / copies) {
      return res.status(400).send('Requested size too large');
    }
    
    // ok: javascript-integer-overflow
    const totalSize = fileSize * copies; // Safe because we checked bounds
    
    const buffer = Buffer.alloc(Math.min(totalSize, 1024 * 1024)); // Limiting for practical reasons
    res.writeHead(200);
    res.end(`Buffer of size ${buffer.length} created`);
  });
}
// {/fact}