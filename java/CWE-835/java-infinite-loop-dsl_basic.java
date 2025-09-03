import java.util.*;
import java.io.*;
import java.net.*;
import java.util.concurrent.*;
import java.util.regex.*;
import javax.servlet.http.*;
import javax.servlet.*;

public class InfiniteLoopExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=infinite-loop@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        String input = request.getParameter("count");
        int count = 0;
        try {
            count = Integer.parseInt(input);
        } catch (NumberFormatException e) {
            // Exception silently caught but count remains 0
        }
        
        int i = 0;
        // ruleid: java-infinite-loop-dsl
        while (i < count) {
            System.out.println("Processing item: " + i);
            // No increment of i, causing infinite loop
        }
    }

    public void bad_case_2() {
        List<String> items = new ArrayList<>();
        items.add("item1");
        
        int index = 0;
        // ruleid: java-infinite-loop-dsl
        while (index < items.size()) {
            System.out.println(items.get(index));
            items.add("new_item"); // List size increases, condition never false
        }
    }

    public void bad_case_3(HttpServletRequest request) {
        String input = request.getParameter("data");
        
        // ruleid: java-infinite-loop-dsl
        for (;;) {
            if (input != null && input.equals("stop")) {
                // Condition never evaluated as there's no break
                break;
            }
            System.out.println("Processing...");
        }
    }

    public void bad_case_4() {
        boolean flag = true;
        
        // ruleid: java-infinite-loop-dsl
        while (flag) {
            System.out.println("Running...");
            // flag is never set to false
        }
    }

    public void bad_case_5(HttpServletRequest request) {
        String data = request.getParameter("data");
        int i = 0;
        
        // ruleid: java-infinite-loop-dsl
        do {
            System.out.println("Processing: " + data);
            // No increment or exit condition
        } while (i == 0);
    }

    public void bad_case_6() {
        int counter = 0;
        
        // ruleid: java-infinite-loop-dsl
        while (counter >= 0) {
            System.out.println("Count: " + counter);
            counter++; // Will eventually overflow but practically infinite
        }
    }

    public void bad_case_7(HttpServletRequest request) {
        String input = request.getParameter("iterations");
        int iterations = 10;
        
        try {
            iterations = Integer.parseInt(input);
        } catch (NumberFormatException e) {
            // Exception caught but using default value
        }
        
        // ruleid: java-infinite-loop-dsl
        for (int i = iterations; i > 0;) {
            System.out.println("Iteration: " + i);
            // No decrement of i
        }
    }

    public void bad_case_8() {
        // ruleid: java-infinite-loop-dsl
        while (true) {
            try {
                System.out.println("Processing...");
                // Exception that would break the loop is caught
                if (System.currentTimeMillis() % 100 == 0) {
                    throw new RuntimeException("Error");
                }
            } catch (Exception e) {
                // Exception caught but loop continues
                System.out.println("Error occurred: " + e.getMessage());
            }
        }
    }

    public void bad_case_9(HttpServletRequest request) {
        String input = request.getParameter("value");
        int value = 5;
        
        try {
            value = Integer.parseInt(input);
        } catch (NumberFormatException e) {
            // Using default value
        }
        
        // ruleid: java-infinite-loop-dsl
        for (int i = 0; i != value; i += 2) {
            // If value is odd, i will never equal value
            System.out.println("Current: " + i);
        }
    }

    public void bad_case_10() {
        List<Integer> numbers = new ArrayList<>();
        numbers.add(1);
        numbers.add(2);
        
        Iterator<Integer> iterator = numbers.iterator();
        
        // ruleid: java-infinite-loop-dsl
        while (iterator.hasNext()) {
            Integer num = iterator.next();
            System.out.println(num);
            numbers.add(num + 2); // Modifying collection during iteration
        }
    }

    public void bad_case_11(HttpServletRequest request) {
        String regex = request.getParameter("regex");
        String input = "test input";
        
        if (regex == null || regex.isEmpty()) {
            regex = ".*";
        }
        
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(input);
        
        // ruleid: java-infinite-loop-dsl
        while (matcher.find()) {
            System.out.println("Match found");
            // Catastrophic backtracking possible with certain regex patterns
            // No progress check or limit
        }
    }

    public void bad_case_12() {
        int x = 10;
        int y = 10;
        
        // ruleid: java-infinite-loop-dsl
        while (x == y) {
            System.out.println("x equals y");
            // x and y are never modified
        }
    }

    public void bad_case_13(HttpServletRequest request) {
        String direction = request.getParameter("direction");
        int counter = 0;
        
        // ruleid: java-infinite-loop-dsl
        while (counter < 100) {
            System.out.println("Counter: " + counter);
            
            if ("up".equals(direction)) {
                counter++;
            } else if ("down".equals(direction)) {
                counter--;
            }
            // If direction is neither "up" nor "down", counter never changes
        }
    }

    public void bad_case_14() {
        double target = 1.0;
        double current = 0.0;
        
        // ruleid: java-infinite-loop-dsl
        while (current != target) {
            current += 0.1; // Floating point precision issues
            System.out.println("Current: " + current);
        }
    }

    public void bad_case_15(HttpServletRequest request) {
        String input = request.getParameter("threshold");
        double threshold = 0.5;
        
        try {
            threshold = Double.parseDouble(input);
        } catch (NumberFormatException e) {
            // Using default value
        }
        
        // ruleid: java-infinite-loop-dsl
        for (double d = 0; d < 1.0; d += threshold / 10) {
            if (threshold <= 0) {
                // If threshold is negative or zero, loop never terminates
                System.out.println("Processing: " + d);
            }
        }
    }

    // True Negative Examples (Safe Code)

    public void good_case_1(HttpServletRequest request) {
        String input = request.getParameter("count");
        int count = 0;
        try {
            count = Integer.parseInt(input);
        } catch (NumberFormatException e) {
            // Exception handled, using default value
        }
        
        int i = 0;
        // ok: java-infinite-loop-dsl
        while (i < count) {
            System.out.println("Processing item: " + i);
            i++; // Proper increment ensures termination
        }
    }

    public void good_case_2() {
        List<String> items = new ArrayList<>();
        items.add("item1");
        items.add("item2");
        
        // ok: java-infinite-loop-dsl
        for (String item : items) {
            System.out.println(item);
            // Using for-each loop avoids infinite loop issues
        }
    }

    public void good_case_3(HttpServletRequest request) {
        String input = request.getParameter("data");
        int maxIterations = 1000;
        int count = 0;
        
        // ok: java-infinite-loop-dsl
        while (true) {
            if (input != null && input.equals("stop") || count >= maxIterations) {
                break; // Proper exit condition
            }
            System.out.println("Processing...");
            count++;
        }
    }

    public void good_case_4() {
        boolean flag = true;
        int counter = 0;
        int maxIterations = 100;
        
        // ok: java-infinite-loop-dsl
        while (flag) {
            System.out.println("Running...");
            counter++;
            if (counter >= maxIterations) {
                flag = false; // Proper termination condition
            }
        }
    }

    public void good_case_5(HttpServletRequest request) {
        String data = request.getParameter("data");
        int i = 0;
        int maxIterations = 50;
        
        // ok: java-infinite-loop-dsl
        do {
            System.out.println("Processing: " + data);
            i++;
        } while (i < maxIterations); // Proper termination condition
    }

    public void good_case_6() {
        int limit = Integer.MAX_VALUE - 10; // Avoid overflow
        
        // ok: java-infinite-loop-dsl
        for (int counter = 0; counter < 100; counter++) {
            System.out.println("Count: " + counter);
            // Proper loop with termination condition
        }
    }

    public void good_case_7(HttpServletRequest request) {
        String input = request.getParameter("iterations");
        int iterations = 10;
        
        try {
            iterations = Integer.parseInt(input);
            // Limit to reasonable value
            iterations = Math.min(iterations, 1000);
        } catch (NumberFormatException e) {
            // Using default value
        }
        
        // ok: java-infinite-loop-dsl
        for (int i = iterations; i > 0; i--) {
            System.out.println("Iteration: " + i);
            // Proper decrement ensures termination
        }
    }

    public void good_case_8() {
        int maxAttempts = 100;
        int attempts = 0;
        
        // ok: java-infinite-loop-dsl
        while (true) {
            try {
                System.out.println("Processing...");
                attempts++;
                
                if (attempts >= maxAttempts) {
                    break; // Safety exit condition
                }
                
                if (System.currentTimeMillis() % 100 == 0) {
                    throw new RuntimeException("Error");
                }
            } catch (Exception e) {
                System.out.println("Error occurred: " + e.getMessage());
                // Still counting attempts even with exceptions
            }
        }
    }

    public void good_case_9(HttpServletRequest request) {
        String input = request.getParameter("value");
        int value = 5;
        
        try {
            value = Integer.parseInt(input);
        } catch (NumberFormatException e) {
            // Using default value
        }
        
        // ok: java-infinite-loop-dsl
        for (int i = 0; i < 100 && i != value; i++) {
            // Added upper bound to prevent infinite loop
            System.out.println("Current: " + i);
        }
    }

    public void good_case_10() {
        List<Integer> numbers = new ArrayList<>();
        numbers.add(1);
        numbers.add(2);
        
        // Create a copy to avoid concurrent modification
        List<Integer> copyList = new ArrayList<>(numbers);
        
        // ok: java-infinite-loop-dsl
        for (Integer num : copyList) {
            System.out.println(num);
            numbers.add(num + 2); // Safe because iterating over copy
        }
    }

    public void good_case_11(HttpServletRequest request) {
        String regex = request.getParameter("regex");
        String input = "test input";
        
        if (regex == null || regex.isEmpty()) {
            regex = ".*";
        }
        
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(input);
        
        int matchCount = 0;
        int maxMatches = 1000;
        
        // ok: java-infinite-loop-dsl
        while (matcher.find() && matchCount < maxMatches) {
            System.out.println("Match found");
            matchCount++; // Limit the number of matches
        }
    }

    public void good_case_12() {
        int x = 10;
        int y = 10;
        int iterations = 0;
        int maxIterations = 5;
        
        // ok: java-infinite-loop-dsl
        while (x == y && iterations < maxIterations) {
            System.out.println("x equals y");
            iterations++; // Safety counter
        }
    }

    public void good_case_13(HttpServletRequest request) {
        String direction = request.getParameter("direction");
        int counter = 0;
        int maxIterations = 200;
        int iterations = 0;
        
        // ok: java-infinite-loop-dsl
        while (counter < 100 && iterations < maxIterations) {
            System.out.println("Counter: " + counter);
            iterations++; // Safety counter
            
            if ("up".equals(direction)) {
                counter++;
            } else if ("down".equals(direction)) {
                counter--;
            } else {
                counter++; // Default behavior to ensure progress
            }
        }
    }

    public void good_case_14() {
        double target = 1.0;
        double current = 0.0;
        double epsilon = 0.0001; // Tolerance for floating point comparison
        int iterations = 0;
        int maxIterations = 1000;
        
        // ok: java-infinite-loop-dsl
        while (Math.abs(current - target) > epsilon && iterations < maxIterations) {
            current += 0.1;
            System.out.println("Current: " + current);
            iterations++;
        }
    }

    public void good_case_15(HttpServletRequest request) {
        String input = request.getParameter("threshold");
        double threshold = 0.5;
        
        try {
            threshold = Double.parseDouble(input);
            // Ensure positive value
            threshold = Math.max(0.001, threshold);
        } catch (NumberFormatException e) {
            // Using default value
        }
        
        int maxIterations = 10000;
        int iterations = 0;
        
        // ok: java-infinite-loop-dsl
        for (double d = 0; d < 1.0 && iterations < maxIterations; d += threshold / 10) {
            System.out.println("Processing: " + d);
            iterations++;
        }
    }
}
// {/fact}