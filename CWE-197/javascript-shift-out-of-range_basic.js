// This file contains examples of integer overflow vulnerabilities in JavaScript
// related to bit shifting operations that can cause high-order bits to be truncated

// TRUE POSITIVES (vulnerable code examples)

// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_1() {
  // Integer overflow when shifting a 32-bit integer beyond its range
  const userInput = 1;
  // ruleid: javascript-shift-out-of-range
  const result = userInput << 32; // Shifts beyond 32 bits, causing overflow
  console.log("Result:", result);
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_2() {
  // Integer overflow with large shift on user-controlled value
  const req = { query: { shiftAmount: "40" } };
  const shiftAmount = parseInt(req.query.shiftAmount);
  const baseValue = 1;
  
  // ruleid: javascript-shift-out-of-range
  const shiftedValue = baseValue << shiftAmount; // Shifts by 40, beyond 32-bit limit
  console.log(`Shifted value: ${shiftedValue}`);
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_3() {
  // Integer overflow with negative value shift
  const value = -2147483648; // MIN_SAFE_INTEGER
  
  // ruleid: javascript-shift-out-of-range
  const result = value << 31; // Shifting MIN_SAFE_INTEGER by 31 causes overflow
  console.log("Shifted result:", result);
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_4() {
  // Integer overflow with variable shift amount
  let baseNum = 1;
  let shiftBy = 0;
  
  // Loop that causes overflow
  for (let i = 0; i < 40; i++) {
    shiftBy++;
    if (shiftBy >= 32) {
      // ruleid: javascript-shift-out-of-range
      baseNum = baseNum << shiftBy; // Will shift beyond 32 bits
    }
  }
  console.log("Final value:", baseNum);
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_5() {
  // Integer overflow with right shift beyond range
  const largeNum = 0xFFFFFFFF;
  
  // ruleid: javascript-shift-out-of-range
  const result = largeNum >>> 33; // Right shift beyond 32 bits
  console.log("Right shifted result:", result);
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_6() {
  // Integer overflow with calculated shift amount
  const req = { body: { x: "10", y: "30" } };
  const x = parseInt(req.body.x);
  const y = parseInt(req.body.y);
  const shiftAmount = x + y; // 40
  
  // ruleid: javascript-shift-out-of-range
  const result = 1 << shiftAmount; // Shifts by 40, beyond 32-bit limit
  console.log(`Result of 1 << ${shiftAmount} = ${result}`);
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_7() {
  // Integer overflow with multiple shifts
  let value = 1;
  
  // ruleid: javascript-shift-out-of-range
  value = value << 16 << 16 << 8; // Total shift of 40 bits
  console.log("Multiple shifted value:", value);
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_8() {
  // Integer overflow with shift in mathematical expression
  const headers = { 'x-shift-value': '35' };
  const shiftValue = parseInt(headers['x-shift-value']);
  
  // ruleid: javascript-shift-out-of-range
  const calculatedValue = (1 << shiftValue) - 1; // Shift by 35, beyond 32-bit limit
  console.log("Calculated mask:", calculatedValue);
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_9() {
  // Integer overflow with conditional large shift
  const cookies = { shiftParam: '50' };
  const userShift = parseInt(cookies.shiftParam);
  let result = 1;
  
  if (userShift > 10) {
    // ruleid: javascript-shift-out-of-range
    result = result << userShift; // Shifts by 50, way beyond 32-bit limit
  }
  
  console.log("Conditional shift result:", result);
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_10() {
  // Integer overflow with shift in array index calculation
  const req = { params: { power: '33' } };
  const power = parseInt(req.params.power);
  const array = new Array(100).fill(0);
  
  // ruleid: javascript-shift-out-of-range
  const index = (1 << power) % array.length; // Shift by 33, beyond 32-bit limit
  array[index] = 42;
  
  console.log("Array with modified index:", array);
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_11() {
  // Integer overflow with shift in bitwise operations
  const value = 0xFF;
  
  // ruleid: javascript-shift-out-of-range
  const mask = ~(0xFFFFFFFF << 40); // Shift by 40, beyond 32-bit limit
  const result = value & mask;
  
  console.log("Masked value:", result);
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_12() {
  // Integer overflow with dynamic calculation of shift amount
  const data = { size: '15' };
  const size = parseInt(data.size);
  const shiftAmount = size * 3; // 45
  
  // ruleid: javascript-shift-out-of-range
  const value = 1 << shiftAmount; // Shift by 45, beyond 32-bit limit
  console.log(`Shifted by ${shiftAmount}: ${value}`);
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_13() {
  // Integer overflow with shift in object property
  const req = { query: { bits: '34' } };
  const bits = parseInt(req.query.bits);
  
  const obj = {
    // ruleid: javascript-shift-out-of-range
    value: 1 << bits, // Shift by 34, beyond 32-bit limit
    name: "overflow-example"
  };
  
  console.log("Object:", obj);
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_14() {
  // Integer overflow with shift in callback function
  const userValue = { shift: '36' };
  
  [1, 2, 3].forEach(num => {
    const shiftBy = parseInt(userValue.shift);
    // ruleid: javascript-shift-out-of-range
    const result = num << shiftBy; // Shift by 36, beyond 32-bit limit
    console.log(`${num} << ${shiftBy} = ${result}`);
  });
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_15() {
  // Integer overflow with shift in ternary operation
  const config = { maxShift: '38' };
  const maxShift = parseInt(config.maxShift);
  const useMax = true;
  
  // ruleid: javascript-shift-out-of-range
  const value = useMax ? (1 << maxShift) : (1 << 10); // Shift by 38 when useMax is true
  console.log("Ternary shift result:", value);
}
// {/fact}

// TRUE NEGATIVES (safe code examples)

// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_1() {
  // Safe shift within 32-bit range
  const userInput = 1;
  // ok: javascript-shift-out-of-range
  const result = userInput << 31; // Shifts within 32 bits, no overflow
  console.log("Result:", result);
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_2() {
  // Safe shift with bounds checking
  const req = { query: { shiftAmount: "40" } };
  const shiftAmount = parseInt(req.query.shiftAmount);
  const baseValue = 1;
  
  // ok: javascript-shift-out-of-range
  const safeShift = Math.min(shiftAmount, 31); // Limit shift to 31 bits
  const shiftedValue = baseValue << safeShift;
  console.log(`Shifted value: ${shiftedValue}`);
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_3() {
  // Safe shift with modulo to keep within range
  const value = -2147483648; // MIN_SAFE_INTEGER
  
  // ok: javascript-shift-out-of-range
  const result = value << (31 % 32); // Ensures shift is within 32-bit range
  console.log("Shifted result:", result);
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_4() {
  // Safe shift with explicit range check
  let baseNum = 1;
  let shiftBy = 0;
  
  for (let i = 0; i < 40; i++) {
    shiftBy++;
    // ok: javascript-shift-out-of-range
    if (shiftBy < 32) {
      baseNum = baseNum << shiftBy; // Only shifts if within 32-bit range
    }
  }
  console.log("Final value:", baseNum);
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_5() {
  // Safe right shift with modulo
  const largeNum = 0xFFFFFFFF;
  
  // ok: javascript-shift-out-of-range
  const result = largeNum >>> (33 % 32); // Ensures shift is within range
  console.log("Right shifted result:", result);
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_6() {
  // Safe shift with clamped calculated amount
  const req = { body: { x: "10", y: "30" } };
  const x = parseInt(req.body.x);
  const y = parseInt(req.body.y);
  const rawShiftAmount = x + y; // 40
  
  // ok: javascript-shift-out-of-range
  const safeShiftAmount = rawShiftAmount > 31 ? 31 : rawShiftAmount;
  const result = 1 << safeShiftAmount;
  console.log(`Result of 1 << ${safeShiftAmount} = ${result}`);
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_7() {
  // Safe multiple shifts with total within range
  let value = 1;
  
  // ok: javascript-shift-out-of-range
  value = value << 10 << 10 << 10; // Total shift of 30 bits, within range
  console.log("Multiple shifted value:", value);
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_8() {
  // Safe shift in mathematical expression with validation
  const headers = { 'x-shift-value': '35' };
  const rawShiftValue = parseInt(headers['x-shift-value']);
  
  // ok: javascript-shift-out-of-range
  const safeShiftValue = Math.min(rawShiftValue, 31);
  const calculatedValue = (1 << safeShiftValue) - 1;
  console.log("Calculated mask:", calculatedValue);
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_9() {
  // Safe conditional shift with maximum limit
  const cookies = { shiftParam: '50' };
  const userShift = parseInt(cookies.shiftParam);
  let result = 1;
  
  // ok: javascript-shift-out-of-range
  const safeShift = userShift > 31 ? 31 : userShift;
  result = result << safeShift;
  
  console.log("Conditional shift result:", result);
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_10() {
  // Safe shift in array index calculation with bounds
  const req = { params: { power: '33' } };
  const power = parseInt(req.params.power);
  const array = new Array(100).fill(0);
  
  // ok: javascript-shift-out-of-range
  const safePower = power % 32;
  const index = (1 << safePower) % array.length;
  array[index] = 42;
  
  console.log("Array with modified index:", array);
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_11() {
  // Safe shift in bitwise operations with range check
  const value = 0xFF;
  
  // ok: javascript-shift-out-of-range
  const safeBits = 31; // Maximum safe shift for 32-bit integers
  const mask = ~(0xFFFFFFFF << safeBits);
  const result = value & mask;
  
  console.log("Masked value:", result);
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_12() {
  // Safe dynamic calculation of shift amount with validation
  const data = { size: '15' };
  const size = parseInt(data.size);
  const rawShiftAmount = size * 3; // 45
  
  // ok: javascript-shift-out-of-range
  const safeShiftAmount = rawShiftAmount >= 32 ? 31 : rawShiftAmount;
  const value = 1 << safeShiftAmount;
  console.log(`Safely shifted by ${safeShiftAmount}: ${value}`);
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_13() {
  // Safe shift in object property with bounds check
  const req = { query: { bits: '34' } };
  const bits = parseInt(req.query.bits);
  
  const obj = {
    // ok: javascript-shift-out-of-range
    value: 1 << (bits % 32), // Ensures shift is within 32-bit range
    name: "safe-example"
  };
  
  console.log("Object:", obj);
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_14() {
  // Safe shift in callback function with validation
  const userValue = { shift: '36' };
  
  [1, 2, 3].forEach(num => {
    const rawShiftBy = parseInt(userValue.shift);
    // ok: javascript-shift-out-of-range
    const safeShiftBy = Math.min(rawShiftBy, 31);
    const result = num << safeShiftBy;
    console.log(`${num} << ${safeShiftBy} = ${result}`);
  });
}
// {/fact}

// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_15() {
  // Safe shift in ternary operation with maximum limit
  const config = { maxShift: '38' };
  const rawMaxShift = parseInt(config.maxShift);
  const useMax = true;
  
  // ok: javascript-shift-out-of-range
  const safeMaxShift = Math.min(rawMaxShift, 31);
  const value = useMax ? (1 << safeMaxShift) : (1 << 10);
  console.log("Safe ternary shift result:", value);
}
// {/fact}