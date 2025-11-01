using System;
using System.Net;
using System.Web;
using System.Collections.Generic;
using System.IO;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;

namespace IntegerOverflowExamples
{
    public class IntegerOverflowCases
    {
// {fact rule=arithmetic-overflow@v1.0 defects=1}
        // True Positive Examples (Vulnerable Code)

        public void bad_case_1(HttpRequest request)
        {
            string input = request.Query["value"];
            int value = int.Parse(input);
            
            // ruleid: integer-overflow-csharp-rule
            int result = value * 100; // No overflow check, could overflow for large values
            
            Console.WriteLine($"Result: {result}");
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=1}
        
        public void bad_case_2(HttpRequest request)
        {
            string input1 = request.Query["value1"];
            string input2 = request.Query["value2"];
            int a = int.Parse(input1);
            int b = int.Parse(input2);
            
            // ruleid: integer-overflow-csharp-rule
            int sum = a + b; // No overflow check on addition
            
            Console.WriteLine($"Sum: {sum}");
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=1}
        
        public void bad_case_3(HttpRequest request)
        {
            string input = request.Form["count"];
            int count = int.Parse(input);
            int bufferSize = 1024;
            
            // ruleid: integer-overflow-csharp-rule
            int totalSize = count * bufferSize; // Could overflow for large count values
            byte[] buffer = new byte[totalSize]; // This could cause problems if totalSize overflows
            
            Console.WriteLine($"Buffer created with size: {totalSize}");
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=1}
        
        public void bad_case_4(HttpRequest request)
        {
            string input = request.Headers["X-Items-Count"];
            int itemCount = int.Parse(input);
            int itemSize = 16;
            
            // ruleid: integer-overflow-csharp-rule
            int memoryNeeded = itemCount * itemSize; // No overflow check
            
            AllocateMemory(memoryNeeded);
        }
// {/fact}
        
        private void AllocateMemory(int size)
        {
            // Memory allocation logic
            Console.WriteLine($"Allocating {size} bytes");
        }
// {fact rule=arithmetic-overflow@v1.0 defects=1}
        
        public void bad_case_5(HttpRequest request)
        {
            string input = request.Query["factor"];
            int factor = int.Parse(input);
            int baseValue = int.MaxValue - 10; // Already close to maximum
            
            // ruleid: integer-overflow-csharp-rule
            int result = baseValue + factor; // Could easily overflow
            
            Console.WriteLine($"Result: {result}");
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=1}
        
        public void bad_case_6(HttpRequest request)
        {
            string widthStr = request.Query["width"];
            string heightStr = request.Query["height"];
            int width = int.Parse(widthStr);
            int height = int.Parse(heightStr);
            
            // ruleid: integer-overflow-csharp-rule
            int area = width * height; // Area calculation could overflow
            
            Console.WriteLine($"Area: {area} square units");
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=1}
        
        public void bad_case_7(HttpRequest request)
        {
            string input = request.Query["seconds"];
            int seconds = int.Parse(input);
            
            // ruleid: integer-overflow-csharp-rule
            int milliseconds = seconds * 1000; // Could overflow for large second values
            
            Console.WriteLine($"Timeout set to: {milliseconds} ms");
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=1}
        
        public void bad_case_8(HttpRequest request)
        {
            string input = request.Form["quantity"];
            int quantity = int.Parse(input);
            int unitPrice = 1000000; // High unit price
            
            // ruleid: integer-overflow-csharp-rule
            int totalPrice = quantity * unitPrice; // Could overflow for large quantities
            
            Console.WriteLine($"Total price: {totalPrice}");
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=1}
        
        public void bad_case_9(HttpRequest request)
        {
            string input = request.Query["iterations"];
            int iterations = int.Parse(input);
            int operationsPerIteration = 1000000;
            
            // ruleid: integer-overflow-csharp-rule
            int totalOperations = iterations * operationsPerIteration; // Could overflow
            
            Console.WriteLine($"Will perform {totalOperations} operations");
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=1}
        
        public void bad_case_10(HttpRequest request)
        {
            string input1 = request.Query["base"];
            string input2 = request.Query["exponent"];
            int baseNum = int.Parse(input1);
            int exponent = int.Parse(input2);
            
            int result = 1;
            for (int i = 0; i < exponent; i++)
            {
                // ruleid: integer-overflow-csharp-rule
                result *= baseNum; // Could overflow for large exponents or base values
            }
            
            Console.WriteLine($"Power result: {result}");
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=1}
        
        public void bad_case_11(HttpRequest request)
        {
            string input = request.Query["value"];
            int value = int.Parse(input);
            
            // ruleid: integer-overflow-csharp-rule
            int squared = value * value; // Squaring can easily cause overflow
            
            Console.WriteLine($"Square: {squared}");
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=1}
        
        public void bad_case_12(HttpRequest request)
        {
            string input = request.Headers["X-Array-Size"];
            int size = int.Parse(input);
            
            // ruleid: integer-overflow-csharp-rule
            int doubledSize = size * 2; // Could overflow
            int[] array = new int[doubledSize];
            
            Console.WriteLine($"Array created with size: {doubledSize}");
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=1}
        
        public void bad_case_13(HttpRequest request)
        {
            string input1 = request.Query["a"];
            string input2 = request.Query["b"];
            string input3 = request.Query["c"];
            
            int a = int.Parse(input1);
            int b = int.Parse(input2);
            int c = int.Parse(input3);
            
            // ruleid: integer-overflow-csharp-rule
            int result = a * b + c; // Multiple operations without overflow checks
            
            Console.WriteLine($"Calculation result: {result}");
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=1}
        
        public void bad_case_14(HttpRequest request)
        {
            string input = request.Query["increment"];
            int increment = int.Parse(input);
            int currentValue = int.MaxValue - 100; // Close to maximum
            
            // ruleid: integer-overflow-csharp-rule
            currentValue += increment; // Could overflow with large increment
            
            Console.WriteLine($"New value: {currentValue}");
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=1}
        
        public void bad_case_15(HttpRequest request)
        {
            string input = request.Query["factor"];
            int factor = int.Parse(input);
            int[] values = { 1000000, 2000000, 3000000 };
            
            for (int i = 0; i < values.Length; i++)
            {
                // ruleid: integer-overflow-csharp-rule
                values[i] *= factor; // Could overflow with large factor
            }
            
            Console.WriteLine($"Updated values: {string.Join(", ", values)}");
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}
        
        // True Negative Examples (Safe Code)
        
        public void good_case_1(HttpRequest request)
        {
            string input = request.Query["value"];
            int value = int.Parse(input);
            
            // ok: integer-overflow-csharp-rule
            long result = (long)value * 100; // Using long to prevent overflow
            
            if (result > int.MaxValue || result < int.MinValue)
            {
                Console.WriteLine("Result would overflow int bounds");
                return;
            }
            
            Console.WriteLine($"Result: {result}");
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}
        
        public void good_case_2(HttpRequest request)
        {
            string input1 = request.Query["value1"];
            string input2 = request.Query["value2"];
            int a = int.Parse(input1);
            int b = int.Parse(input2);
            
            // ok: integer-overflow-csharp-rule
            if (b > 0 && a > int.MaxValue - b)
            {
                Console.WriteLine("Addition would overflow");
                return;
            }
            
            int sum = a + b; // Safe addition with overflow check
            Console.WriteLine($"Sum: {sum}");
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}
        
        public void good_case_3(HttpRequest request)
        {
            string input = request.Form["count"];
            int count = int.Parse(input);
            int bufferSize = 1024;
            
            // ok: integer-overflow-csharp-rule
            if (count > int.MaxValue / bufferSize)
            {
                Console.WriteLine("Buffer size would overflow");
                return;
            }
            
            int totalSize = count * bufferSize; // Safe multiplication with overflow check
            byte[] buffer = new byte[totalSize];
            
            Console.WriteLine($"Buffer created with size: {totalSize}");
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}
        
        public void good_case_4(HttpRequest request)
        {
            string input = request.Headers["X-Items-Count"];
            int itemCount = int.Parse(input);
            int itemSize = 16;
            
            // ok: integer-overflow-csharp-rule
            long memoryNeeded = (long)itemCount * itemSize; // Using long for calculation
            
            if (memoryNeeded > int.MaxValue)
            {
                Console.WriteLine("Memory size would overflow int bounds");
                return;
            }
            
            AllocateMemory((int)memoryNeeded);
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}
        
        public void good_case_5(HttpRequest request)
        {
            string input = request.Query["factor"];
            int factor = int.Parse(input);
            int baseValue = int.MaxValue - 10; // Already close to maximum
            
            // ok: integer-overflow-csharp-rule
            checked
            {
                try
                {
                    int result = baseValue + factor; // Using checked context to throw on overflow
                    Console.WriteLine($"Result: {result}");
                }
                catch (OverflowException)
                {
                    Console.WriteLine("Operation would overflow");
                }
            }
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}
        
        public void good_case_6(HttpRequest request)
        {
            string widthStr = request.Query["width"];
            string heightStr = request.Query["height"];
            int width = int.Parse(widthStr);
            int height = int.Parse(heightStr);
            
            // ok: integer-overflow-csharp-rule
            long area = (long)width * height; // Using long for calculation
            
            if (area > int.MaxValue)
            {
                Console.WriteLine("Area calculation would overflow int bounds");
                return;
            }
            
            Console.WriteLine($"Area: {area} square units");
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}
        
        public void good_case_7(HttpRequest request)
        {
            string input = request.Query["seconds"];
            int seconds = int.Parse(input);
            
            // ok: integer-overflow-csharp-rule
            if (seconds > int.MaxValue / 1000)
            {
                Console.WriteLine("Milliseconds calculation would overflow");
                return;
            }
            
            int milliseconds = seconds * 1000; // Safe multiplication with overflow check
            Console.WriteLine($"Timeout set to: {milliseconds} ms");
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}
        
        public void good_case_8(HttpRequest request)
        {
            string input = request.Form["quantity"];
            int quantity = int.Parse(input);
            int unitPrice = 1000000; // High unit price
            
            // ok: integer-overflow-csharp-rule
            long totalPrice = (long)quantity * unitPrice; // Using long for calculation
            
            if (totalPrice > int.MaxValue)
            {
                Console.WriteLine("Total price would overflow int bounds");
                return;
            }
            
            Console.WriteLine($"Total price: {totalPrice}");
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}
        
        public void good_case_9(HttpRequest request)
        {
            string input = request.Query["iterations"];
            int iterations = int.Parse(input);
            int operationsPerIteration = 1000000;
            
            // ok: integer-overflow-csharp-rule
            try
            {
                int totalOperations = checked(iterations * operationsPerIteration); // Using checked for overflow detection
                Console.WriteLine($"Will perform {totalOperations} operations");
            }
            catch (OverflowException)
            {
                Console.WriteLine("Operation count would overflow");
            }
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}
        
        public void good_case_10(HttpRequest request)
        {
            string input1 = request.Query["base"];
            string input2 = request.Query["exponent"];
            int baseNum = int.Parse(input1);
            int exponent = int.Parse(input2);
            
            // ok: integer-overflow-csharp-rule
            long result = 1;
            for (int i = 0; i < exponent; i++)
            {
                result *= baseNum;
                if (result > int.MaxValue)
                {
                    Console.WriteLine("Power calculation would overflow int bounds");
                    return;
                }
            }
            
            Console.WriteLine($"Power result: {result}");
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}
        
        public void good_case_11(HttpRequest request)
        {
            string input = request.Query["value"];
            int value = int.Parse(input);
            
            // ok: integer-overflow-csharp-rule
            if (value > Math.Sqrt(int.MaxValue) || value < -Math.Sqrt(int.MaxValue))
            {
                Console.WriteLine("Square would overflow int bounds");
                return;
            }
            
            int squared = value * value; // Safe squaring with overflow check
            Console.WriteLine($"Square: {squared}");
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}
        
        public void good_case_12(HttpRequest request)
        {
            string input = request.Headers["X-Array-Size"];
            int size = int.Parse(input);
            
            // ok: integer-overflow-csharp-rule
            if (size > int.MaxValue / 2)
            {
                Console.WriteLine("Doubled size would overflow");
                return;
            }
            
            int doubledSize = size * 2; // Safe multiplication with overflow check
            int[] array = new int[doubledSize];
            
            Console.WriteLine($"Array created with size: {doubledSize}");
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}
        
        public void good_case_13(HttpRequest request)
        {
            string input1 = request.Query["a"];
            string input2 = request.Query["b"];
            string input3 = request.Query["c"];
            
            int a = int.Parse(input1);
            int b = int.Parse(input2);
            int c = int.Parse(input3);
            
            // ok: integer-overflow-csharp-rule
            long temp = (long)a * b; // Using long for intermediate calculation
            if (temp > int.MaxValue || temp < int.MinValue)
            {
                Console.WriteLine("Multiplication would overflow");
                return;
            }
            
            if (temp > int.MaxValue - c || temp < int.MinValue - c)
            {
                Console.WriteLine("Addition would overflow");
                return;
            }
            
            int result = (int)temp + c; // Safe calculation with overflow checks
            Console.WriteLine($"Calculation result: {result}");
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}
        
        public void good_case_14(HttpRequest request)
        {
            string input = request.Query["increment"];
            int increment = int.Parse(input);
            int currentValue = int.MaxValue - 100; // Close to maximum
            
            // ok: integer-overflow-csharp-rule
            if (increment > 0 && currentValue > int.MaxValue - increment)
            {
                Console.WriteLine("Increment would cause overflow");
                return;
            }
            
            currentValue += increment; // Safe addition with overflow check
            Console.WriteLine($"New value: {currentValue}");
        }
// {/fact}
// {fact rule=arithmetic-overflow@v1.0 defects=0}
        
        public void good_case_15(HttpRequest request)
        {
            string input = request.Query["factor"];
            int factor = int.Parse(input);
            int[] values = { 1000000, 2000000, 3000000 };
            
            // ok: integer-overflow-csharp-rule
            for (int i = 0; i < values.Length; i++)
            {
                if (factor != 0 && values[i] > int.MaxValue / Math.Abs(factor))
                {
                    Console.WriteLine($"Multiplication at index {i} would overflow");
                    continue;
                }
                
                values[i] *= factor; // Safe multiplication with overflow check
            }
            
            Console.WriteLine($"Updated values: {string.Join(", ", values)}");
        }
// {/fact}
    }
}