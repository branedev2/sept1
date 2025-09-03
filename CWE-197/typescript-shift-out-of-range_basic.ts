// True Positives (Vulnerable Code)

// Example 1: Shifting a number beyond the 32-bit range
// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_1() {
    const value = 1;
    // ruleid: typescript-shift-out-of-range
    const result = value << 32; // Shifting by 32 bits is out of range for 32-bit integers
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 2: Shifting by a negative amount
// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_2() {
    const value = 8;
    // ruleid: typescript-shift-out-of-range
    const result = value << -2; // Negative shift amounts are problematic
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 3: Shifting with a variable that could be out of range
// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_3() {
    const userInput = 35; // Could be any value from user input
    const value = 1;
    // ruleid: typescript-shift-out-of-range
    const result = value << userInput; // userInput exceeds 32 bits
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 4: Right shift with excessive bits
// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_4() {
    const value = 0xFFFFFFFF;
    // ruleid: typescript-shift-out-of-range
    const result = value >> 33; // Shifting right by more than 32 bits
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 5: Unsigned right shift with excessive bits
// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_5() {
    const value = -1;
    // ruleid: typescript-shift-out-of-range
    const result = value >>> 32; // Shifting unsigned right by 32 bits
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 6: Shifting with a computed value that exceeds range
// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_6() {
    const shiftAmount = 16 + 16; // Equals 32
    const value = 5;
    // ruleid: typescript-shift-out-of-range
    const result = value << shiftAmount;
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 7: Shifting with a large constant
// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_7() {
    const value = 1;
    // ruleid: typescript-shift-out-of-range
    const result = value << 64; // Far beyond 32-bit range
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 8: Shifting with a variable from math operation that exceeds range
// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_8() {
    const baseShift = 30;
    const value = 3;
    // ruleid: typescript-shift-out-of-range
    const result = value << (baseShift + 3); // 33, which exceeds range
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 9: Shifting with a variable that could be negative
// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_9() {
    const shiftAmount = -5;
    const value = 10;
    // ruleid: typescript-shift-out-of-range
    const result = value << shiftAmount;
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 10: Multiple shifts that result in out of range
// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_10() {
    const value = 1;
    // ruleid: typescript-shift-out-of-range
    const result = (value << 16) << 16; // Total shift of 32 bits
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 11: Shifting in a loop with potential to exceed range
// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_11() {
    let value = 1;
    let result = value;
    
    for (let i = 0; i < 33; i++) {
        // ruleid: typescript-shift-out-of-range
        result = result << 1; // Will shift by 33 bits total
    }
    
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 12: Shifting with a parameter that could be out of range
// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_12() {
    function shiftValue(value: number, shiftAmount: number): number {
        // ruleid: typescript-shift-out-of-range
        return value << shiftAmount; // shiftAmount could be out of range
    }
    
    const result = shiftValue(1, 40);
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 13: Shifting with a computed negative value
// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_13() {
    const baseShift = 5;
    const value = 8;
    // ruleid: typescript-shift-out-of-range
    const result = value << (baseShift - 10); // -5, which is negative
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 14: Shifting with a value from bitwise operations that exceeds range
// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_14() {
    const mask = 0xFF;
    const shiftBase = 0x20; // 32 in hex
    const value = 7;
    // ruleid: typescript-shift-out-of-range
    const result = value << (shiftBase & mask); // Still 32, which is out of range
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 15: Shifting with a value from string conversion that could be out of range
// {fact rule=numeric-truncation-error@v1.0 defects=1}
function bad_case_15() {
    const shiftStr = "40";
    const value = 3;
    // ruleid: typescript-shift-out-of-range
    const result = value << parseInt(shiftStr, 10); // 40 is out of range
    console.log(`Result: ${result}`);
}
// {/fact}

// True Negatives (Safe Code)

// Example 1: Shifting within the valid range
// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_1() {
    const value = 1;
    // ok: typescript-shift-out-of-range
    const result = value << 31; // Maximum valid left shift for 32-bit integers
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 2: Shifting with bounds checking
// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_2() {
    const userInput = 35;
    const value = 1;
    const safeShiftAmount = Math.min(31, Math.max(0, userInput));
    // ok: typescript-shift-out-of-range
    const result = value << safeShiftAmount;
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 3: Shifting with a constant within range
// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_3() {
    const value = 0xFFFFFFFF;
    // ok: typescript-shift-out-of-range
    const result = value >> 16; // Within valid range
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 4: Ensuring shift amount is positive and within range
// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_4() {
    const shiftAmount = -5;
    const value = 10;
    const safeShiftAmount = Math.abs(shiftAmount) % 32;
    // ok: typescript-shift-out-of-range
    const result = value << safeShiftAmount;
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 5: Using modulo to ensure shift amount is within range
// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_5() {
    const shiftAmount = 40;
    const value = 1;
    // ok: typescript-shift-out-of-range
    const result = value << (shiftAmount % 32);
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 6: Checking range before shifting
// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_6() {
    const shiftAmount = 35;
    const value = 7;
    let result: number;
    
    if (shiftAmount >= 0 && shiftAmount < 32) {
        // ok: typescript-shift-out-of-range
        result = value << shiftAmount;
    } else {
        result = 0; // Default value for out-of-range shifts
    }
    
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 7: Using bitwise AND to limit shift amount
// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_7() {
    const shiftAmount = 36;
    const value = 3;
    // ok: typescript-shift-out-of-range
    const result = value << (shiftAmount & 0x1F); // Limits to 0-31
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 8: Multiple shifts that stay within range
// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_8() {
    const value = 1;
    // ok: typescript-shift-out-of-range
    const result = (value << 15) << 15; // Total shift of 30 bits
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 9: Shifting in a loop with range check
// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_9() {
    let value = 1;
    let result = value;
    
    for (let i = 0; i < 40; i++) {
        if (i < 31) {
            // ok: typescript-shift-out-of-range
            result = result << 1; // Will only shift up to 31 bits
        }
    }
    
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 10: Safe function for shifting with range validation
// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_10() {
    function safeShift(value: number, shiftAmount: number): number {
        if (shiftAmount < 0 || shiftAmount >= 32) {
            return 0; // Return a default value for out-of-range shifts
        }
        // ok: typescript-shift-out-of-range
        return value << shiftAmount;
    }
    
    const result = safeShift(1, 25);
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 11: Using a constant within range
// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_11() {
    const value = 0xFF;
    // ok: typescript-shift-out-of-range
    const result = value << 8; // Well within range
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 12: Shifting with computed value that's within range
// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_12() {
    const baseShift = 10;
    const value = 5;
    // ok: typescript-shift-out-of-range
    const result = value << (baseShift + 5); // 15, which is within range
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 13: Using zero as shift amount
// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_13() {
    const value = 42;
    // ok: typescript-shift-out-of-range
    const result = value << 0; // No shift, always safe
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 14: Using right shift within range
// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_14() {
    const value = -1;
    // ok: typescript-shift-out-of-range
    const result = value >>> 31; // Maximum valid unsigned right shift
    console.log(`Result: ${result}`);
}
// {/fact}

// Example 15: Using conditional to select a safe shift amount
// {fact rule=numeric-truncation-error@v1.0 defects=0}
function good_case_15() {
    const userInput = "50";
    const value = 3;
    const parsedShift = parseInt(userInput, 10);
    const shiftAmount = isNaN(parsedShift) || parsedShift < 0 || parsedShift >= 32 ? 1 : parsedShift;
    
    // ok: typescript-shift-out-of-range
    const result = value << shiftAmount;
    console.log(`Result: ${result}`);
}
// {/fact}