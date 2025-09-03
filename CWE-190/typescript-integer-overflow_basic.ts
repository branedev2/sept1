// Integer Overflow Examples - True Positives and True Negatives

// True Positives (Vulnerable Code)

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_1() {
  const maxInt = Number.MAX_SAFE_INTEGER;
  // ruleid: typescript-integer-overflow
  const result = maxInt + 1; // This will cause an integer overflow
  console.log(`Result: ${result}`);
  return result;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_2() {
  const userInput = "9007199254740991"; // MAX_SAFE_INTEGER as string
  const value = parseInt(userInput);
  // ruleid: typescript-integer-overflow
  const doubled = value * 2; // This will cause an integer overflow
  console.log(`Doubled value: ${doubled}`);
  return doubled;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_3() {
  const largeNumber = 9007199254740991; // MAX_SAFE_INTEGER
  // ruleid: typescript-integer-overflow
  const factorial = largeNumber * largeNumber * largeNumber;
  console.log(`Factorial: ${factorial}`);
  return factorial;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_4() {
  let counter = Number.MAX_SAFE_INTEGER;
  // ruleid: typescript-integer-overflow
  counter++; // This will cause an integer overflow
  console.log(`Counter: ${counter}`);
  return counter;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_5() {
  const values = [Number.MAX_SAFE_INTEGER, 1, 2, 3];
  // ruleid: typescript-integer-overflow
  const sum = values.reduce((acc, val) => acc + val, 0);
  console.log(`Sum: ${sum}`);
  return sum;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_6() {
  const base = 2;
  // ruleid: typescript-integer-overflow
  const result = Math.pow(base, 1024); // This will exceed MAX_SAFE_INTEGER
  console.log(`2^1024 = ${result}`);
  return result;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_7() {
  const userValues = ["1000000000000000", "9007199254740991"];
  // ruleid: typescript-integer-overflow
  const multiplied = parseInt(userValues[0]) * parseInt(userValues[1]);
  console.log(`Product: ${multiplied}`);
  return multiplied;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_8() {
  const largeValue = Number.MAX_SAFE_INTEGER;
  let result = 0;
  
  for (let i = 0; i < 10; i++) {
    // ruleid: typescript-integer-overflow
    result += largeValue; // Will eventually overflow
  }
  
  console.log(`Final result: ${result}`);
  return result;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_9() {
  const factorial = (n: number): number => {
    if (n <= 1) return 1;
    // ruleid: typescript-integer-overflow
    return n * factorial(n - 1); // Will overflow for large n
  };
  
  const result = factorial(100); // This will cause overflow
  console.log(`Factorial of 100: ${result}`);
  return result;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_10() {
  const calculateCompoundInterest = (principal: number, rate: number, years: number): number => {
    // ruleid: typescript-integer-overflow
    return principal * Math.pow(1 + rate, years); // Can overflow with large values
  };
  
  const result = calculateCompoundInterest(1000000, 0.05, 1000);
  console.log(`Compound interest: ${result}`);
  return result;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_11() {
  const numbers = [9007199254740990, 9007199254740990];
  // ruleid: typescript-integer-overflow
  const product = numbers[0] * numbers[1];
  console.log(`Product of large numbers: ${product}`);
  return product;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_12() {
  const performOperation = (a: number, b: number): number => {
    // ruleid: typescript-integer-overflow
    return (a * a) + (b * b) + (2 * a * b); // (a + b)^2 can overflow
  };
  
  const result = performOperation(Number.MAX_SAFE_INTEGER / 2, Number.MAX_SAFE_INTEGER / 2);
  console.log(`Operation result: ${result}`);
  return result;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_13() {
  const calculatePermutations = (n: number): number => {
    let result = 1;
    for (let i = 2; i <= n; i++) {
      // ruleid: typescript-integer-overflow
      result *= i; // Will overflow for large n
    }
    return result;
  };
  
  console.log(`Permutations: ${calculatePermutations(30)}`);
  return calculatePermutations(30);
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_14() {
  const shiftOperation = (value: number, positions: number): number => {
    // ruleid: typescript-integer-overflow
    return value << positions; // Left shift can cause overflow
  };
  
  const result = shiftOperation(1, 54);
  console.log(`Shift result: ${result}`);
  return result;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=1}
function bad_case_15() {
  const fibonacciRecursive = (n: number): number => {
    if (n <= 1) return n;
    // ruleid: typescript-integer-overflow
    return fibonacciRecursive(n - 1) + fibonacciRecursive(n - 2); // Will overflow for large n
  };
  
  const result = fibonacciRecursive(100);
  console.log(`Fibonacci(100): ${result}`);
  return result;
}
// {/fact}

// True Negatives (Safe Code)

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_1() {
  const maxInt = Number.MAX_SAFE_INTEGER;
  // ok: typescript-integer-overflow
  const result = BigInt(maxInt) + BigInt(1); // Using BigInt prevents overflow
  console.log(`Result: ${result}`);
  return result;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_2() {
  const userInput = "9007199254740991"; // MAX_SAFE_INTEGER as string
  // ok: typescript-integer-overflow
  const value = BigInt(userInput);
  const doubled = value * BigInt(2); // Using BigInt prevents overflow
  console.log(`Doubled value: ${doubled}`);
  return doubled;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_3() {
  // ok: typescript-integer-overflow
  const largeNumber = BigInt(9007199254740991); // MAX_SAFE_INTEGER as BigInt
  const factorial = largeNumber * largeNumber * largeNumber;
  console.log(`Factorial: ${factorial}`);
  return factorial;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_4() {
  // ok: typescript-integer-overflow
  let counter = BigInt(Number.MAX_SAFE_INTEGER);
  counter++; // Using BigInt prevents overflow
  console.log(`Counter: ${counter}`);
  return counter;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_5() {
  const values = [BigInt(Number.MAX_SAFE_INTEGER), BigInt(1), BigInt(2), BigInt(3)];
  // ok: typescript-integer-overflow
  const sum = values.reduce((acc, val) => acc + val, BigInt(0));
  console.log(`Sum: ${sum}`);
  return sum;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_6() {
  // ok: typescript-integer-overflow
  const calculatePower = (base: bigint, exponent: number): bigint => {
    let result = BigInt(1);
    const bigBase = BigInt(base);
    for (let i = 0; i < exponent; i++) {
      result *= bigBase;
    }
    return result;
  };
  
  const result = calculatePower(2, 1024);
  console.log(`2^1024 = ${result}`);
  return result;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_7() {
  const userValues = ["1000000000000000", "9007199254740991"];
  // ok: typescript-integer-overflow
  const multiplied = BigInt(userValues[0]) * BigInt(userValues[1]);
  console.log(`Product: ${multiplied}`);
  return multiplied;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_8() {
  // ok: typescript-integer-overflow
  const largeValue = BigInt(Number.MAX_SAFE_INTEGER);
  let result = BigInt(0);
  
  for (let i = 0; i < 10; i++) {
    result += largeValue; // Using BigInt prevents overflow
  }
  
  console.log(`Final result: ${result}`);
  return result;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_9() {
  // ok: typescript-integer-overflow
  const factorial = (n: bigint): bigint => {
    if (n <= BigInt(1)) return BigInt(1);
    return n * factorial(n - BigInt(1)); // Using BigInt prevents overflow
  };
  
  const result = factorial(BigInt(100));
  console.log(`Factorial of 100: ${result}`);
  return result;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_10() {
  // ok: typescript-integer-overflow
  const calculateCompoundInterest = (principal: bigint, rate: number, years: number): bigint => {
    // Using BigInt and a more precise calculation to prevent overflow
    const ratePercentage = Math.floor(rate * 10000);
    const rateFactor = BigInt(10000 + ratePercentage);
    const denominator = BigInt(10000);
    
    let result = principal;
    for (let i = 0; i < years; i++) {
      result = (result * rateFactor) / denominator;
    }
    
    return result;
  };
  
  const result = calculateCompoundInterest(BigInt(1000000), 0.05, 1000);
  console.log(`Compound interest: ${result}`);
  return result;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_11() {
  // ok: typescript-integer-overflow
  const numbers = [BigInt(9007199254740990), BigInt(9007199254740990)];
  const product = numbers[0] * numbers[1];
  console.log(`Product of large numbers: ${product}`);
  return product;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_12() {
  // ok: typescript-integer-overflow
  const performOperation = (a: bigint, b: bigint): bigint => {
    return (a * a) + (b * b) + (BigInt(2) * a * b); // Using BigInt prevents overflow
  };
  
  const maxSafeInt = BigInt(Number.MAX_SAFE_INTEGER);
  const result = performOperation(maxSafeInt / BigInt(2), maxSafeInt / BigInt(2));
  console.log(`Operation result: ${result}`);
  return result;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_13() {
  // ok: typescript-integer-overflow
  const calculatePermutations = (n: number): bigint => {
    let result = BigInt(1);
    for (let i = 2; i <= n; i++) {
      result *= BigInt(i); // Using BigInt prevents overflow
    }
    return result;
  };
  
  console.log(`Permutations: ${calculatePermutations(30)}`);
  return calculatePermutations(30);
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_14() {
  // ok: typescript-integer-overflow
  const safeShiftOperation = (value: number, positions: number): bigint => {
    // Using BigInt for large shift operations
    if (positions > 30) {
      return BigInt(value) << BigInt(positions);
    }
    return BigInt(value << positions);
  };
  
  const result = safeShiftOperation(1, 54);
  console.log(`Shift result: ${result}`);
  return result;
}
// {/fact}

// {fact rule=arithmetic-overflow@v1.0 defects=0}
function good_case_15() {
  // Using a safe approach with memoization to calculate Fibonacci
  // ok: typescript-integer-overflow
  const fibonacci = (n: number): bigint => {
    const memo: Map<number, bigint> = new Map();
    
    const fib = (x: number): bigint => {
      if (x <= 1) return BigInt(x);
      
      if (memo.has(x)) return memo.get(x)!;
      
      const result = fib(x - 1) + fib(x - 2);
      memo.set(x, result);
      return result;
    };
    
    return fib(n);
  };
  
  const result = fibonacci(100);
  console.log(`Fibonacci(100): ${result}`);
  return result;
}
// {/fact}