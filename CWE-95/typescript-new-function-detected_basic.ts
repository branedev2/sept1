// Examples for typescript-new-function-detected rule
// This rule detects usage of new Function() which can lead to code injection vulnerabilities

// Import common libraries for examples
import express from 'express';
import * as fs from 'fs';
import axios from 'axios';

// TRUE POSITIVES (Vulnerable code that should be detected)

// Basic usage of new Function
// {fact rule=code-injection@v1.0 defects=1}
function bad_case_1() {
    // ruleid: typescript-new-function-detected
    const dynamicFunc = new Function('a', 'b', 'return a + b');
    return dynamicFunc(5, 3);
}
// {/fact}

// Using new Function with user input from HTTP request
// {fact rule=code-injection@v1.0 defects=1}
function bad_case_2() {
    const app = express();
    
    app.get('/calculate', (req, res) => {
        const operation = req.query.operation as string;
        const a = parseInt(req.query.a as string);
        const b = parseInt(req.query.b as string);
        
        // ruleid: typescript-new-function-detected
        const calculator = new Function('a', 'b', `return a ${operation} b`);
        const result = calculator(a, b);
        
        res.send({ result });
    });
}
// {/fact}

// Using new Function to create a method dynamically
// {fact rule=code-injection@v1.0 defects=1}
function bad_case_3() {
    class Calculator {
        compute(operation: string, a: number, b: number) {
            // ruleid: typescript-new-function-detected
            const method = new Function('a', 'b', `return a ${operation} b`);
            return method(a, b);
        }
    }
    
    const calc = new Calculator();
    return calc.compute('+', 10, 20);
}
// {/fact}

// Using new Function with template literals
// {fact rule=code-injection@v1.0 defects=1}
function bad_case_4() {
    const operation = '+';
    
    // ruleid: typescript-new-function-detected
    const func = new Function('x', 'y', `
        const result = x ${operation} y;
        return result;
    `);
    
    return func(5, 10);
}
// {/fact}

// Using new Function with array of strings
// {fact rule=code-injection@v1.0 defects=1}
function bad_case_5() {
    const paramNames = ['a', 'b', 'c'];
    const functionBody = 'return a + b + c';
    
    // ruleid: typescript-new-function-detected
    const sum = new Function(...paramNames, functionBody);
    
    return sum(1, 2, 3);
}
// {/fact}

// Using new Function to create event handlers
// {fact rule=code-injection@v1.0 defects=1}
function bad_case_6() {
    const buttonId = 'myButton';
    const eventCode = 'console.log("Button clicked!")';
    
    // ruleid: typescript-new-function-detected
    const eventHandler = new Function('event', eventCode);
    
    document.getElementById(buttonId)?.addEventListener('click', eventHandler);
}
// {/fact}

// Using new Function with JSON data
// {fact rule=code-injection@v1.0 defects=1}
function bad_case_7() {
    const jsonData = '{"name":"John","age":30}';
    
    // ruleid: typescript-new-function-detected
    const jsonParser = new Function(`
        const data = ${jsonData};
        return data;
    `);
    
    return jsonParser();
}
// {/fact}

// Using new Function in a React-like component
// {fact rule=code-injection@v1.0 defects=1}
function bad_case_8() {
    interface Props {
        expression: string;
    }
    
    function DynamicComponent(props: Props) {
        // ruleid: typescript-new-function-detected
        const evaluator = new Function('return ' + props.expression);
        const result = evaluator();
        
        return { result };
    }
    
    return DynamicComponent({ expression: '2 + 2' });
}
// {/fact}

// Using new Function with async/await
// {fact rule=code-injection@v1.0 defects=1}
async function bad_case_9() {
    const response = await axios.get('https://api.example.com/code');
    const code = response.data.code;
    
    // ruleid: typescript-new-function-detected
    const dynamicFunc = new Function('data', code);
    
    return dynamicFunc({ value: 42 });
}
// {/fact}

// Using new Function with conditional logic
// {fact rule=code-injection@v1.0 defects=1}
function bad_case_10() {
    const condition = true;
    let dynamicCode = '';
    
    if (condition) {
        dynamicCode = 'return x * 2;';
    } else {
        dynamicCode = 'return x + 10;';
    }
    
    // ruleid: typescript-new-function-detected
    const processor = new Function('x', dynamicCode);
    
    return processor(5);
}
// {/fact}

// Using new Function with file content
// {fact rule=code-injection@v1.0 defects=1}
function bad_case_11() {
    const scriptContent = fs.readFileSync('script.js', 'utf8');
    
    // ruleid: typescript-new-function-detected
    const scriptRunner = new Function(scriptContent);
    
    return scriptRunner();
}
// {/fact}

// Using new Function with multiple statements in body
// {fact rule=code-injection@v1.0 defects=1}
function bad_case_12() {
    // ruleid: typescript-new-function-detected
    const complexFunc = new Function('x', `
        let result = 0;
        for (let i = 0; i < x; i++) {
            result += i;
        }
        return result;
    `);
    
    return complexFunc(5);
}
// {/fact}

// Using new Function with error handling
// {fact rule=code-injection@v1.0 defects=1}
function bad_case_13() {
    try {
        // ruleid: typescript-new-function-detected
        const riskyFunc = new Function('input', `
            if (!input) throw new Error('Invalid input');
            return input.toUpperCase();
        `);
        
        return riskyFunc('test');
    } catch (error) {
        console.error('Function execution failed:', error);
        return null;
    }
}
// {/fact}

// Using new Function with setTimeout
// {fact rule=code-injection@v1.0 defects=1}
function bad_case_14() {
    const delayedCode = 'console.log("Executed after delay");';
    
    // ruleid: typescript-new-function-detected
    const delayedFunc = new Function(delayedCode);
    
    setTimeout(delayedFunc, 1000);
}
// {/fact}

// Using new Function with object methods
// {fact rule=code-injection@v1.0 defects=1}
function bad_case_15() {
    const methods = {
        add: 'return a + b;',
        subtract: 'return a - b;',
        multiply: 'return a * b;'
    };
    
    const operation = 'add';
    
    // ruleid: typescript-new-function-detected
    const calculator = new Function('a', 'b', methods[operation as keyof typeof methods]);
    
    return calculator(10, 5);
}
// {/fact}

// TRUE NEGATIVES (Safe code that should not be detected)

// Using regular function declaration
// {fact rule=code-injection@v1.0 defects=0}
function good_case_1() {
    // ok: typescript-new-function-detected
    function add(a: number, b: number) {
        return a + b;
    }
    
    return add(5, 3);
}
// {/fact}

// Using arrow function
// {fact rule=code-injection@v1.0 defects=0}
function good_case_2() {
    // ok: typescript-new-function-detected
    const multiply = (a: number, b: number) => a * b;
    
    return multiply(4, 5);
}
// {/fact}

// Using function expression
// {fact rule=code-injection@v1.0 defects=0}
function good_case_3() {
    // ok: typescript-new-function-detected
    const divide = function(a: number, b: number) {
        return a / b;
    };
    
    return divide(10, 2);
}
// {/fact}

// Using class methods
// {fact rule=code-injection@v1.0 defects=0}
function good_case_4() {
    class Calculator {
        // ok: typescript-new-function-detected
        add(a: number, b: number): number {
            return a + b;
        }
        
        subtract(a: number, b: number): number {
            return a - b;
        }
    }
    
    const calc = new Calculator();
    return calc.add(10, 5);
}
// {/fact}

// Using a map of functions
// {fact rule=code-injection@v1.0 defects=0}
function good_case_5() {
    // ok: typescript-new-function-detected
    const operations = {
        add: (a: number, b: number) => a + b,
        subtract: (a: number, b: number) => a - b,
        multiply: (a: number, b: number) => a * b
    };
    
    const operation = 'add';
    return operations[operation as keyof typeof operations](5, 3);
}
// {/fact}

// Using Function.prototype methods
// {fact rule=code-injection@v1.0 defects=0}
function good_case_6() {
    // ok: typescript-new-function-detected
    function baseFunction(x: number) {
        return x * 2;
    }
    
    const boundFunction = baseFunction.bind(null, 5);
    return boundFunction();
}
// {/fact}

// Using higher-order functions
// {fact rule=code-injection@v1.0 defects=0}
function good_case_7() {
    // ok: typescript-new-function-detected
    function createMultiplier(factor: number) {
        return function(x: number) {
            return x * factor;
        };
    }
    
    const double = createMultiplier(2);
    return double(10);
}
// {/fact}

// Using callback functions
// {fact rule=code-injection@v1.0 defects=0}
function good_case_8() {
    // ok: typescript-new-function-detected
    function processArray(arr: number[], callback: (item: number) => number) {
        return arr.map(callback);
    }
    
    return processArray([1, 2, 3], (x) => x * x);
}
// {/fact}

// Using async functions
// {fact rule=code-injection@v1.0 defects=0}
function good_case_9() {
    // ok: typescript-new-function-detected
    async function fetchData(url: string) {
        const response = await axios.get(url);
        return response.data;
    }
    
    return fetchData('https://api.example.com/data');
}
// {/fact}

// Using generator functions
// {fact rule=code-injection@v1.0 defects=0}
function good_case_10() {
    // ok: typescript-new-function-detected
    function* numberGenerator() {
        let i = 0;
        while (i < 5) {
            yield i++;
        }
    }
    
    const gen = numberGenerator();
    return Array.from({ length: 5 }, () => gen.next().value);
}
// {/fact}

// Using function with destructuring
// {fact rule=code-injection@v1.0 defects=0}
function good_case_11() {
    // ok: typescript-new-function-detected
    const processUser = ({ name, age }: { name: string, age: number }) => {
        return `${name} is ${age} years old`;
    };
    
    return processUser({ name: 'John', age: 30 });
}
// {/fact}

// Using function with rest parameters
// {fact rule=code-injection@v1.0 defects=0}
function good_case_12() {
    // ok: typescript-new-function-detected
    function sum(...numbers: number[]) {
        return numbers.reduce((total, num) => total + num, 0);
    }
    
    return sum(1, 2, 3, 4, 5);
}
// {/fact}

// Using function with default parameters
// {fact rule=code-injection@v1.0 defects=0}
function good_case_13() {
    // ok: typescript-new-function-detected
    function greet(name: string, greeting = 'Hello') {
        return `${greeting}, ${name}!`;
    }
    
    return greet('World');
}
// {/fact}

// Using function with type guards
// {fact rule=code-injection@v1.0 defects=0}
function good_case_14() {
    // ok: typescript-new-function-detected
    function isString(value: any): value is string {
        return typeof value === 'string';
    }
    
    function processValue(value: string | number) {
        if (isString(value)) {
            return value.toUpperCase();
        }
        return value * 2;
    }
    
    return processValue('test');
}
// {/fact}

// Using function with generic types
// {fact rule=code-injection@v1.0 defects=0}
function good_case_15() {
    // ok: typescript-new-function-detected
    function identity<T>(value: T): T {
        return value;
    }
    
    return identity<string>('hello');
}
// {/fact}

// Export functions to avoid unused variable warnings
export {
    bad_case_1, bad_case_2, bad_case_3, bad_case_4, bad_case_5,
    bad_case_6, bad_case_7, bad_case_8, bad_case_9, bad_case_10,
    bad_case_11, bad_case_12, bad_case_13, bad_case_14, bad_case_15,
    good_case_1, good_case_2, good_case_3, good_case_4, good_case_5,
    good_case_6, good_case_7, good_case_8, good_case_9, good_case_10,
    good_case_11, good_case_12, good_case_13, good_case_14, good_case_15
};