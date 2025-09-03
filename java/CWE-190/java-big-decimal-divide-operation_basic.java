import java.math.BigDecimal;
import java.math.RoundingMode;
import java.math.MathContext;

public class BigDecimalDivideOperationTest {

    // True Positives (Vulnerable Code)

// {fact rule=arithmetic-overflow@v1.0 defects=1}
    public void bad_case_1() {
        BigDecimal dividend = new BigDecimal("10");
        BigDecimal divisor = new BigDecimal("3");
        
        // ruleid: java-big-decimal-divide-operation
        BigDecimal result = dividend.divide(divisor); // Can throw ArithmeticException for non-terminating decimal expansions
    }

    public void bad_case_2() {
        BigDecimal price = new BigDecimal("100.00");
        BigDecimal quantity = new BigDecimal("3");
        
        try {
            // ruleid: java-big-decimal-divide-operation
            BigDecimal unitPrice = price.divide(quantity); // No scale or rounding mode specified
            System.out.println("Unit price: " + unitPrice);
        } catch (ArithmeticException e) {
            System.err.println("Division error: " + e.getMessage());
        }
    }

    public void bad_case_3() {
        BigDecimal totalAmount = new BigDecimal("355.99");
        BigDecimal itemCount = new BigDecimal("7");
        
        // ruleid: java-big-decimal-divide-operation
        BigDecimal average = totalAmount.divide(itemCount); // Will throw exception for non-terminating decimal
        System.out.println("Average price: " + average);
    }

    public void bad_case_4() {
        BigDecimal revenue = new BigDecimal("1000000.00");
        BigDecimal expenses = new BigDecimal("333333.33");
        
        // ruleid: java-big-decimal-divide-operation
        BigDecimal profitRatio = revenue.divide(expenses); // No precision control
        System.out.println("Profit ratio: " + profitRatio);
    }

    public void bad_case_5() {
        for (int i = 1; i <= 10; i++) {
            BigDecimal numerator = new BigDecimal(i * 10);
            BigDecimal denominator = new BigDecimal(i * 3);
            
            // ruleid: java-big-decimal-divide-operation
            BigDecimal quotient = numerator.divide(denominator); // Potential ArithmeticException
            System.out.println(numerator + " / " + denominator + " = " + quotient);
        }
    }

    public void bad_case_6() {
        BigDecimal[] values = {
            new BigDecimal("10.5"),
            new BigDecimal("20.7"),
            new BigDecimal("30.9")
        };
        
        BigDecimal sum = BigDecimal.ZERO;
        for (BigDecimal value : values) {
            sum = sum.add(value);
        }
        
        BigDecimal count = new BigDecimal(values.length);
        // ruleid: java-big-decimal-divide-operation
        BigDecimal average = sum.divide(count); // No rounding mode specified
        System.out.println("Average: " + average);
    }

    public void bad_case_7() {
        BigDecimal principal = new BigDecimal("1000.00");
        BigDecimal rate = new BigDecimal("0.05"); // 5% interest rate
        BigDecimal periods = new BigDecimal("12"); // Monthly compounding
        
        // Calculate monthly rate
        // ruleid: java-big-decimal-divide-operation
        BigDecimal monthlyRate = rate.divide(periods); // No rounding mode
        System.out.println("Monthly interest rate: " + monthlyRate);
    }

    public void bad_case_8() {
        BigDecimal totalDistance = new BigDecimal("150.75");
        BigDecimal totalTime = new BigDecimal("2.5");
        
        // ruleid: java-big-decimal-divide-operation
        BigDecimal speed = totalDistance.divide(totalTime); // Missing rounding mode
        System.out.println("Average speed: " + speed + " km/h");
    }

    public void bad_case_9() {
        BigDecimal weight = new BigDecimal("85.5");
        BigDecimal height = new BigDecimal("1.75");
        
        // Calculate BMI: weight / (height * height)
        BigDecimal heightSquared = height.multiply(height);
        // ruleid: java-big-decimal-divide-operation
        BigDecimal bmi = weight.divide(heightSquared); // No precision control
        System.out.println("BMI: " + bmi);
    }

    public void bad_case_10() {
        BigDecimal totalSales = new BigDecimal("567890.25");
        BigDecimal salesTarget = new BigDecimal("600000.00");
        
        // ruleid: java-big-decimal-divide-operation
        BigDecimal achievementRatio = totalSales.divide(salesTarget); // Missing rounding mode
        System.out.println("Sales achievement: " + achievementRatio.multiply(new BigDecimal("100")) + "%");
    }

    public void bad_case_11() {
        BigDecimal dividend = new BigDecimal("1");
        BigDecimal divisor = new BigDecimal("3");
        
        if (dividend.compareTo(BigDecimal.ZERO) > 0) {
            // ruleid: java-big-decimal-divide-operation
            BigDecimal result = dividend.divide(divisor); // Will throw ArithmeticException
            System.out.println("Result: " + result);
        }
    }

    public void bad_case_12() {
        BigDecimal[] prices = {
            new BigDecimal("10.99"),
            new BigDecimal("24.50"),
            new BigDecimal("5.75")
        };
        
        BigDecimal exchangeRate = new BigDecimal("1.18"); // EUR to USD
        
        for (BigDecimal price : prices) {
            // ruleid: java-big-decimal-divide-operation
            BigDecimal convertedPrice = price.divide(exchangeRate); // No rounding mode
            System.out.println("Price in EUR: " + convertedPrice);
        }
    }

    public void bad_case_13() {
        BigDecimal totalCost = new BigDecimal("1250.75");
        BigDecimal itemCount = new BigDecimal("7");
        
        try {
            // ruleid: java-big-decimal-divide-operation
            BigDecimal costPerItem = totalCost.divide(itemCount);
            System.out.println("Cost per item: " + costPerItem);
        } catch (ArithmeticException e) {
            System.err.println("Error calculating cost per item");
        }
    }

    public void bad_case_14() {
        BigDecimal taxAmount = new BigDecimal("120.50");
        BigDecimal totalAmount = new BigDecimal("1000.00");
        
        // Calculate tax rate
        // ruleid: java-big-decimal-divide-operation
        BigDecimal taxRate = taxAmount.divide(totalAmount); // No rounding mode specified
        System.out.println("Tax rate: " + taxRate.multiply(new BigDecimal("100")) + "%");
    }

    public void bad_case_15() {
        BigDecimal netIncome = new BigDecimal("250000.00");
        BigDecimal totalAssets = new BigDecimal("1200000.00");
        
        // Calculate ROA (Return on Assets)
        // ruleid: java-big-decimal-divide-operation
        BigDecimal returnOnAssets = netIncome.divide(totalAssets); // Missing precision control
        System.out.println("Return on Assets: " + returnOnAssets);
    }

    // True Negatives (Safe Code)

    public void good_case_1() {
        BigDecimal dividend = new BigDecimal("10");
        BigDecimal divisor = new BigDecimal("3");
        
        // ok: java-big-decimal-divide-operation
        BigDecimal result = dividend.divide(divisor, 10, RoundingMode.HALF_UP);
        System.out.println("Result: " + result);
    }

    public void good_case_2() {
        BigDecimal price = new BigDecimal("100.00");
        BigDecimal quantity = new BigDecimal("3");
        
        // ok: java-big-decimal-divide-operation
        BigDecimal unitPrice = price.divide(quantity, 2, RoundingMode.HALF_EVEN);
        System.out.println("Unit price: " + unitPrice);
    }

    public void good_case_3() {
        BigDecimal totalAmount = new BigDecimal("355.99");
        BigDecimal itemCount = new BigDecimal("7");
        
        // ok: java-big-decimal-divide-operation
        BigDecimal average = totalAmount.divide(itemCount, new MathContext(10));
        System.out.println("Average price: " + average);
    }

    public void good_case_4() {
        BigDecimal revenue = new BigDecimal("1000000.00");
        BigDecimal expenses = new BigDecimal("333333.33");
        
        // ok: java-big-decimal-divide-operation
        BigDecimal profitRatio = revenue.divide(expenses, 4, RoundingMode.DOWN);
        System.out.println("Profit ratio: " + profitRatio);
    }

    public void good_case_5() {
        for (int i = 1; i <= 10; i++) {
            BigDecimal numerator = new BigDecimal(i * 10);
            BigDecimal denominator = new BigDecimal(i * 3);
            
            // ok: java-big-decimal-divide-operation
            BigDecimal quotient = numerator.divide(denominator, 5, RoundingMode.HALF_UP);
            System.out.println(numerator + " / " + denominator + " = " + quotient);
        }
    }

    public void good_case_6() {
        BigDecimal[] values = {
            new BigDecimal("10.5"),
            new BigDecimal("20.7"),
            new BigDecimal("30.9")
        };
        
        BigDecimal sum = BigDecimal.ZERO;
        for (BigDecimal value : values) {
            sum = sum.add(value);
        }
        
        BigDecimal count = new BigDecimal(values.length);
        // ok: java-big-decimal-divide-operation
        BigDecimal average = sum.divide(count, 2, RoundingMode.HALF_UP);
        System.out.println("Average: " + average);
    }

    public void good_case_7() {
        BigDecimal principal = new BigDecimal("1000.00");
        BigDecimal rate = new BigDecimal("0.05"); // 5% interest rate
        BigDecimal periods = new BigDecimal("12"); // Monthly compounding
        
        // Calculate monthly rate
        // ok: java-big-decimal-divide-operation
        BigDecimal monthlyRate = rate.divide(periods, 10, RoundingMode.HALF_EVEN);
        System.out.println("Monthly interest rate: " + monthlyRate);
    }

    public void good_case_8() {
        BigDecimal totalDistance = new BigDecimal("150.75");
        BigDecimal totalTime = new BigDecimal("2.5");
        
        // ok: java-big-decimal-divide-operation
        BigDecimal speed = totalDistance.divide(totalTime, new MathContext(6));
        System.out.println("Average speed: " + speed + " km/h");
    }

    public void good_case_9() {
        BigDecimal weight = new BigDecimal("85.5");
        BigDecimal height = new BigDecimal("1.75");
        
        // Calculate BMI: weight / (height * height)
        BigDecimal heightSquared = height.multiply(height);
        // ok: java-big-decimal-divide-operation
        BigDecimal bmi = weight.divide(heightSquared, 1, RoundingMode.HALF_UP);
        System.out.println("BMI: " + bmi);
    }

    public void good_case_10() {
        BigDecimal totalSales = new BigDecimal("567890.25");
        BigDecimal salesTarget = new BigDecimal("600000.00");
        
        // ok: java-big-decimal-divide-operation
        BigDecimal achievementRatio = totalSales.divide(salesTarget, 4, RoundingMode.HALF_UP);
        System.out.println("Sales achievement: " + achievementRatio.multiply(new BigDecimal("100")) + "%");
    }

    public void good_case_11() {
        BigDecimal dividend = new BigDecimal("1");
        BigDecimal divisor = new BigDecimal("3");
        
        if (dividend.compareTo(BigDecimal.ZERO) > 0) {
            // ok: java-big-decimal-divide-operation
            BigDecimal result = dividend.divide(divisor, 5, RoundingMode.CEILING);
            System.out.println("Result: " + result);
        }
    }

    public void good_case_12() {
        BigDecimal[] prices = {
            new BigDecimal("10.99"),
            new BigDecimal("24.50"),
            new BigDecimal("5.75")
        };
        
        BigDecimal exchangeRate = new BigDecimal("1.18"); // EUR to USD
        
        for (BigDecimal price : prices) {
            // ok: java-big-decimal-divide-operation
            BigDecimal convertedPrice = price.divide(exchangeRate, 2, RoundingMode.HALF_DOWN);
            System.out.println("Price in EUR: " + convertedPrice);
        }
    }

    public void good_case_13() {
        BigDecimal totalCost = new BigDecimal("1250.75");
        BigDecimal itemCount = new BigDecimal("7");
        
        // ok: java-big-decimal-divide-operation
        BigDecimal costPerItem = totalCost.divide(itemCount, new MathContext(8, RoundingMode.HALF_EVEN));
        System.out.println("Cost per item: " + costPerItem);
    }

    public void good_case_14() {
        BigDecimal taxAmount = new BigDecimal("120.50");
        BigDecimal totalAmount = new BigDecimal("1000.00");
        
        // Calculate tax rate
        // ok: java-big-decimal-divide-operation
        BigDecimal taxRate = taxAmount.divide(totalAmount, 4, RoundingMode.UP);
        System.out.println("Tax rate: " + taxRate.multiply(new BigDecimal("100")) + "%");
    }

    public void good_case_15() {
        BigDecimal netIncome = new BigDecimal("250000.00");
        BigDecimal totalAssets = new BigDecimal("1200000.00");
        
        // Calculate ROA (Return on Assets)
        // ok: java-big-decimal-divide-operation
        BigDecimal returnOnAssets = netIncome.divide(totalAssets, 6, RoundingMode.HALF_UP);
        System.out.println("Return on Assets: " + returnOnAssets);
    }
}
// {/fact}