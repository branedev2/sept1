using System;
using System.Collections.Generic;

namespace DoubleEpsilonEqualityTests
{
    public class DoubleEpsilonEqualityExamples
    {
// {fact rule=guru-cfn-lint@v1.0 defects=1}
        // True Positives (Vulnerable/Incorrect Usage)
        
        public void bad_case_1()
        {
            double a = 1.0;
            double b = 1.0 + 0.1;
            
            // ruleid: double-epsilon-equality
            if (Math.Abs(a - b) < Double.Epsilon)
            {
                Console.WriteLine("Values are equal");
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}
        
        public void bad_case_2()
        {
            double result = CalculateValue();
            double expected = 5.5;
            
            // ruleid: double-epsilon-equality
            bool areEqual = Math.Abs(result - expected) <= Double.Epsilon;
            if (areEqual)
            {
                Console.WriteLine("Calculation is correct");
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}
        
        public void bad_case_3()
        {
            double x = 100.0;
            double y = 100.0 + 0.00001;
            
            // ruleid: double-epsilon-equality
            if (Math.Abs(x - y) <= Double.Epsilon)
            {
                Console.WriteLine("x and y are considered equal");
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}
        
        public void bad_case_4()
        {
            List<double> values = new List<double> { 1.1, 2.2, 3.3 };
            double searchValue = 2.2;
            
            foreach (var value in values)
            {
                // ruleid: double-epsilon-equality
                if (Math.Abs(value - searchValue) < Double.Epsilon)
                {
                    Console.WriteLine("Found the value");
                    break;
                }
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}
        
        public void bad_case_5()
        {
            double price1 = 19.99;
            double price2 = 19.99;
            
            // ruleid: double-epsilon-equality
            bool pricesMatch = Math.Abs(price1 - price2) <= Double.Epsilon;
            Console.WriteLine($"Prices match: {pricesMatch}");
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}
        
        public void bad_case_6()
        {
            double[] measurements = { 10.5, 10.51, 10.49 };
            double target = 10.5;
            
            foreach (var measurement in measurements)
            {
                // ruleid: double-epsilon-equality
                if (Math.Abs(measurement - target) < Double.Epsilon)
                {
                    Console.WriteLine("Measurement matches target");
                }
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}
        
        public void bad_case_7()
        {
            double angle1 = Math.PI / 2;
            double angle2 = Math.PI / 2 + 0.0000001;
            
            // ruleid: double-epsilon-equality
            bool anglesEqual = Math.Abs(angle1 - angle2) <= Double.Epsilon;
            if (anglesEqual)
            {
                Console.WriteLine("Angles are equal");
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}
        
        public void bad_case_8()
        {
            double result = ComputeResult();
            
            // ruleid: double-epsilon-equality
            if (Math.Abs(result) < Double.Epsilon)
            {
                Console.WriteLine("Result is effectively zero");
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}
        
        public void bad_case_9()
        {
            double balance = GetAccountBalance();
            
            // ruleid: double-epsilon-equality
            if (Math.Abs(balance - 1000.0) <= Double.Epsilon)
            {
                Console.WriteLine("Balance is exactly $1000");
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}
        
        public void bad_case_10()
        {
            Dictionary<string, double> rates = new Dictionary<string, double>
            {
                { "USD", 1.0 },
                { "EUR", 1.1 },
                { "GBP", 1.3 }
            };
            
            double rate = rates["EUR"];
            double targetRate = 1.1;
            
            // ruleid: double-epsilon-equality
            bool rateMatches = Math.Abs(rate - targetRate) < Double.Epsilon;
            Console.WriteLine($"Rate matches target: {rateMatches}");
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}
        
        public void bad_case_11()
        {
            double width = 10.0;
            double height = 20.0;
            double area = width * height;
            double expectedArea = 200.0;
            
            // ruleid: double-epsilon-equality
            if (Math.Abs(area - expectedArea) <= Double.Epsilon)
            {
                Console.WriteLine("Area calculation is correct");
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}
        
        public void bad_case_12()
        {
            double[] samples = { 0.1, 0.2, 0.3, 0.4 };
            double sum = 0;
            
            foreach (var sample in samples)
            {
                sum += sample;
            }
            
            double average = sum / samples.Length;
            double expectedAverage = 0.25;
            
            // ruleid: double-epsilon-equality
            bool averageIsCorrect = Math.Abs(average - expectedAverage) < Double.Epsilon;
            Console.WriteLine($"Average is correct: {averageIsCorrect}");
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}
        
        public void bad_case_13()
        {
            double temperature = GetTemperature();
            double freezingPoint = 0.0;
            
            // ruleid: double-epsilon-equality
            if (Math.Abs(temperature - freezingPoint) <= Double.Epsilon)
            {
                Console.WriteLine("Temperature is at freezing point");
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}
        
        public void bad_case_14()
        {
            double actualValue = MeasureDistance();
            double expectedValue = 100.0;
            
            // ruleid: double-epsilon-equality
            bool isAccurate = Math.Abs(actualValue - expectedValue) < Double.Epsilon;
            Console.WriteLine($"Measurement is accurate: {isAccurate}");
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}
        
        public void bad_case_15()
        {
            double x1 = 10.0, y1 = 20.0;
            double x2 = 10.0, y2 = 20.0;
            
            // ruleid: double-epsilon-equality
            bool samePoint = Math.Abs(x1 - x2) < Double.Epsilon && Math.Abs(y1 - y2) < Double.Epsilon;
            Console.WriteLine($"Same point: {samePoint}");
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}
        
        // True Negatives (Safe/Correct Usage)
        
        public void good_case_1()
        {
            double a = 1.0;
            double b = 1.0 + 0.1;
            
            // ok: double-epsilon-equality
            const double tolerance = 0.0001;
            if (Math.Abs(a - b) < tolerance)
            {
                Console.WriteLine("Values are equal within tolerance");
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}
        
        public void good_case_2()
        {
            double result = CalculateValue();
            double expected = 5.5;
            
            // ok: double-epsilon-equality
            double relativeTolerance = 1e-10;
            bool areEqual = Math.Abs(result - expected) <= relativeTolerance * Math.Max(Math.Abs(result), Math.Abs(expected));
            if (areEqual)
            {
                Console.WriteLine("Calculation is correct");
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}
        
        public void good_case_3()
        {
            double x = 100.0;
            double y = 100.0 + 0.00001;
            
            // ok: double-epsilon-equality
            double absoluteTolerance = 0.0001;
            if (Math.Abs(x - y) <= absoluteTolerance)
            {
                Console.WriteLine("x and y are considered equal");
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}
        
        public void good_case_4()
        {
            List<double> values = new List<double> { 1.1, 2.2, 3.3 };
            double searchValue = 2.2;
            
            foreach (var value in values)
            {
                // ok: double-epsilon-equality
                if (Math.Abs(value - searchValue) < 0.00001)
                {
                    Console.WriteLine("Found the value");
                    break;
                }
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}
        
        public void good_case_5()
        {
            double price1 = 19.99;
            double price2 = 19.99;
            
            // ok: double-epsilon-equality
            bool pricesMatch = price1 == price2; // Exact comparison is fine for identical values
            Console.WriteLine($"Prices match: {pricesMatch}");
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}
        
        public void good_case_6()
        {
            double[] measurements = { 10.5, 10.51, 10.49 };
            double target = 10.5;
            
            foreach (var measurement in measurements)
            {
                // ok: double-epsilon-equality
                if (Math.Abs(measurement - target) < 0.02)
                {
                    Console.WriteLine("Measurement is within acceptable range");
                }
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}
        
        public void good_case_7()
        {
            double angle1 = Math.PI / 2;
            double angle2 = Math.PI / 2 + 0.0000001;
            
            // ok: double-epsilon-equality
            double tolerance = 0.000001;
            bool anglesEqual = Math.Abs(angle1 - angle2) <= tolerance;
            if (anglesEqual)
            {
                Console.WriteLine("Angles are equal within tolerance");
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}
        
        public void good_case_8()
        {
            double result = ComputeResult();
            
            // ok: double-epsilon-equality
            const double zeroThreshold = 1e-10;
            if (Math.Abs(result) < zeroThreshold)
            {
                Console.WriteLine("Result is effectively zero");
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}
        
        public void good_case_9()
        {
            double balance = GetAccountBalance();
            
            // ok: double-epsilon-equality
            const double tolerance = 0.01; // 1 cent tolerance
            if (Math.Abs(balance - 1000.0) <= tolerance)
            {
                Console.WriteLine("Balance is approximately $1000");
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}
        
        public void good_case_10()
        {
            Dictionary<string, double> rates = new Dictionary<string, double>
            {
                { "USD", 1.0 },
                { "EUR", 1.1 },
                { "GBP", 1.3 }
            };
            
            double rate = rates["EUR"];
            double targetRate = 1.1;
            
            // ok: double-epsilon-equality
            const double tolerance = 0.0001;
            bool rateMatches = Math.Abs(rate - targetRate) < tolerance;
            Console.WriteLine($"Rate matches target: {rateMatches}");
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}
        
        public void good_case_11()
        {
            // Using decimal for financial calculations instead of double
            // ok: double-epsilon-equality
            decimal price1 = 19.99m;
            decimal price2 = 19.99m;
            bool pricesMatch = price1 == price2;
            Console.WriteLine($"Prices match: {pricesMatch}");
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}
        
        public void good_case_12()
        {
            double[] samples = { 0.1, 0.2, 0.3, 0.4 };
            double sum = 0;
            
            foreach (var sample in samples)
            {
                sum += sample;
            }
            
            double average = sum / samples.Length;
            double expectedAverage = 0.25;
            
            // ok: double-epsilon-equality
            double relativeTolerance = 1e-6;
            bool averageIsCorrect = Math.Abs(average - expectedAverage) / Math.Abs(expectedAverage) < relativeTolerance;
            Console.WriteLine($"Average is correct: {averageIsCorrect}");
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}
        
        public void good_case_13()
        {
            double temperature = GetTemperature();
            double freezingPoint = 0.0;
            
            // ok: double-epsilon-equality
            const double tolerance = 0.1; // 0.1 degree tolerance
            if (Math.Abs(temperature - freezingPoint) <= tolerance)
            {
                Console.WriteLine("Temperature is approximately at freezing point");
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}
        
        public void good_case_14()
        {
            double actualValue = MeasureDistance();
            double expectedValue = 100.0;
            
            // ok: double-epsilon-equality
            double percentTolerance = 0.01; // 1% tolerance
            bool isAccurate = Math.Abs(actualValue - expectedValue) / expectedValue < percentTolerance;
            Console.WriteLine($"Measurement is accurate within 1%: {isAccurate}");
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}
        
        public void good_case_15()
        {
            // Using a proper equality comparer for doubles
            // ok: double-epsilon-equality
            bool AreAlmostEqual(double a, double b, double tolerance = 1e-9)
            {
                return Math.Abs(a - b) <= tolerance * Math.Max(1.0, Math.Max(Math.Abs(a), Math.Abs(b)));
            }
            
            double x1 = 10.0, y1 = 20.0;
            double x2 = 10.0, y2 = 20.0;
            
            bool samePoint = AreAlmostEqual(x1, x2) && AreAlmostEqual(y1, y2);
            Console.WriteLine($"Same point: {samePoint}");
        }
// {/fact}
        
        // Helper methods to make the examples compile
        private double CalculateValue() => 5.5;
        private double ComputeResult() => 0.0000001;
        private double GetAccountBalance() => 1000.0;
        private double GetTemperature() => 0.0;
        private double MeasureDistance() => 100.0;
    }
}