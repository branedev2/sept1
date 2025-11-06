import java.io.*;
import java.util.*;
import java.nio.file.*;
import java.sql.*;
import java.net.*;
import javax.servlet.http.*;
import java.util.logging.Logger;
import java.util.logging.Level;

public class ExceptionInLoopExamples {
    private static final Logger logger = Logger.getLogger(ExceptionInLoopExamples.class.getName());

    // True Positive Examples (Bad Cases)

// {fact rule=improper-error-handling@v1.0 defects=1}
    public void bad_case_1() {
        List<String> fileNames = Arrays.asList("file1.txt", "file2.txt", "file3.txt");
        
        for (String fileName : fileNames) {
            try {
                File file = new File(fileName);
                if (!file.exists()) {
                    // ruleid: java-avoid-throwing-exceptions-in-a-loop
                    throw new FileNotFoundException("File not found: " + fileName);
                }
                // Process file
            } catch (Exception e) {
                logger.log(Level.SEVERE, "Error processing file", e);
            }
        }
    }

    public void bad_case_2() {
        int[] numbers = {1, 2, 3, 4, 5};
        
        for (int i = 0; i < numbers.length; i++) {
            if (numbers[i] % 2 == 0) {
                // ruleid: java-avoid-throwing-exceptions-in-a-loop
                throw new IllegalArgumentException("Even number found: " + numbers[i]);
            }
        }
    }

    public void bad_case_3() {
        List<String> urls = Arrays.asList("http://example.com", "http://invalid", "http://test.com");
        
        for (String url : urls) {
            try {
                URL u = new URL(url);
                // Process URL
            } catch (MalformedURLException e) {
                // ruleid: java-avoid-throwing-exceptions-in-a-loop
                throw new RuntimeException("Invalid URL: " + url, e);
            }
        }
    }

    public void bad_case_4() {
        String[] queries = {"SELECT * FROM users", "INSERT INTO logs VALUES(1)", "INVALID SQL"};
        
        for (String query : queries) {
            if (!query.toUpperCase().startsWith("SELECT") && !query.toUpperCase().startsWith("INSERT")) {
                // ruleid: java-avoid-throwing-exceptions-in-a-loop
                throw new SQLException("Invalid SQL query: " + query);
            }
        }
    }

    public void bad_case_5() {
        Map<String, Integer> userAges = new HashMap<>();
        userAges.put("Alice", 25);
        userAges.put("Bob", 30);
        
        for (String user : userAges.keySet()) {
            int age = userAges.get(user);
            if (age < 18) {
                // ruleid: java-avoid-throwing-exceptions-in-a-loop
                throw new IllegalStateException("User " + user + " is underage");
            }
        }
    }

    public void bad_case_6(HttpServletRequest request) {
        String[] paramNames = {"id", "name", "email"};
        
        for (String param : paramNames) {
            String value = request.getParameter(param);
            if (value == null || value.isEmpty()) {
                // ruleid: java-avoid-throwing-exceptions-in-a-loop
                throw new IllegalArgumentException("Missing required parameter: " + param);
            }
        }
    }

    public void bad_case_7() {
        List<Integer> values = Arrays.asList(10, 20, 30, 40, 50);
        
        for (int i = 0; i < 10; i++) {
            try {
                int value = values.get(i);
                System.out.println("Value: " + value);
            } catch (IndexOutOfBoundsException e) {
                // ruleid: java-avoid-throwing-exceptions-in-a-loop
                throw new RuntimeException("Invalid index: " + i, e);
            }
        }
    }

    public void bad_case_8() {
        int[] divisors = {2, 0, 3, 0, 5};
        
        for (int divisor : divisors) {
            if (divisor == 0) {
                // ruleid: java-avoid-throwing-exceptions-in-a-loop
                throw new ArithmeticException("Cannot divide by zero");
            }
            int result = 100 / divisor;
            System.out.println("Result: " + result);
        }
    }

    public void bad_case_9() {
        String[] inputs = {"123", "abc", "456", "def"};
        
        for (String input : inputs) {
            try {
                int value = Integer.parseInt(input);
                System.out.println("Parsed value: " + value);
            } catch (NumberFormatException e) {
                // ruleid: java-avoid-throwing-exceptions-in-a-loop
                throw new IllegalArgumentException("Invalid number format: " + input, e);
            }
        }
    }

    public void bad_case_10() {
        List<String> configFiles = Arrays.asList("config1.xml", "config2.xml", "config3.xml");
        
        for (int i = 0; i < configFiles.size(); i++) {
            String file = configFiles.get(i);
            if (!file.endsWith(".xml")) {
                // ruleid: java-avoid-throwing-exceptions-in-a-loop
                throw new IllegalArgumentException("Not an XML file: " + file);
            }
        }
    }

    public void bad_case_11() {
        while (true) {
            Scanner scanner = new Scanner(System.in);
            String input = scanner.nextLine();
            
            if ("exit".equals(input)) {
                break;
            } else if (input.length() < 3) {
                // ruleid: java-avoid-throwing-exceptions-in-a-loop
                throw new IllegalArgumentException("Input too short");
            }
        }
    }

    public void bad_case_12() {
        String[] commands = {"start", "stop", "restart", "invalid"};
        
        for (String cmd : commands) {
            switch (cmd) {
                case "start":
                case "stop":
                case "restart":
                    System.out.println("Executing command: " + cmd);
                    break;
                default:
                    // ruleid: java-avoid-throwing-exceptions-in-a-loop
                    throw new UnsupportedOperationException("Unsupported command: " + cmd);
            }
        }
    }

    public void bad_case_13() {
        int maxRetries = 5;
        
        for (int attempt = 0; attempt < maxRetries; attempt++) {
            boolean success = Math.random() > 0.8;
            if (!success && attempt == maxRetries - 1) {
                // ruleid: java-avoid-throwing-exceptions-in-a-loop
                throw new RuntimeException("Operation failed after " + maxRetries + " attempts");
            }
        }
    }

    public void bad_case_14() {
        List<Map<String, Object>> records = new ArrayList<>();
        // Assume records is populated with data
        
        for (Map<String, Object> record : records) {
            if (!record.containsKey("id")) {
                // ruleid: java-avoid-throwing-exceptions-in-a-loop
                throw new IllegalStateException("Record missing required 'id' field");
            }
        }
    }

    public void bad_case_15() {
        do {
            int randomValue = new Random().nextInt(10);
            if (randomValue == 0) {
                // ruleid: java-avoid-throwing-exceptions-in-a-loop
                throw new ArithmeticException("Random value cannot be zero");
            }
        } while (Math.random() < 0.5);
    }

    // True Negative Examples (Good Cases)

    public void good_case_1() {
        List<String> fileNames = Arrays.asList("file1.txt", "file2.txt", "file3.txt");
        List<String> missingFiles = new ArrayList<>();
        
        for (String fileName : fileNames) {
            File file = new File(fileName);
            if (!file.exists()) {
                // ok: java-avoid-throwing-exceptions-in-a-loop
                missingFiles.add(fileName);
            }
        }
        
        if (!missingFiles.isEmpty()) {
            throw new FileNotFoundException("Files not found: " + String.join(", ", missingFiles));
        }
    }

    public void good_case_2() {
        int[] numbers = {1, 2, 3, 4, 5};
        List<Integer> evenNumbers = new ArrayList<>();
        
        for (int i = 0; i < numbers.length; i++) {
            if (numbers[i] % 2 == 0) {
                // ok: java-avoid-throwing-exceptions-in-a-loop
                evenNumbers.add(numbers[i]);
            }
        }
        
        if (!evenNumbers.isEmpty()) {
            throw new IllegalArgumentException("Even numbers found: " + evenNumbers);
        }
    }

    public void good_case_3() {
        List<String> urls = Arrays.asList("http://example.com", "http://invalid", "http://test.com");
        List<String> invalidUrls = new ArrayList<>();
        
        for (String url : urls) {
            try {
                // ok: java-avoid-throwing-exceptions-in-a-loop
                URL u = new URL(url);
                // Process URL
            } catch (MalformedURLException e) {
                invalidUrls.add(url);
            }
        }
        
        if (!invalidUrls.isEmpty()) {
            throw new RuntimeException("Invalid URLs: " + String.join(", ", invalidUrls));
        }
    }

    public void good_case_4() {
        String[] queries = {"SELECT * FROM users", "INSERT INTO logs VALUES(1)", "INVALID SQL"};
        List<String> invalidQueries = new ArrayList<>();
        
        for (String query : queries) {
            // ok: java-avoid-throwing-exceptions-in-a-loop
            if (!query.toUpperCase().startsWith("SELECT") && !query.toUpperCase().startsWith("INSERT")) {
                invalidQueries.add(query);
            }
        }
        
        if (!invalidQueries.isEmpty()) {
            throw new SQLException("Invalid SQL queries: " + String.join(", ", invalidQueries));
        }
    }

    public void good_case_5() {
        Map<String, Integer> userAges = new HashMap<>();
        userAges.put("Alice", 25);
        userAges.put("Bob", 30);
        List<String> underage = new ArrayList<>();
        
        for (String user : userAges.keySet()) {
            // ok: java-avoid-throwing-exceptions-in-a-loop
            int age = userAges.get(user);
            if (age < 18) {
                underage.add(user);
            }
        }
        
        if (!underage.isEmpty()) {
            throw new IllegalStateException("Underage users: " + String.join(", ", underage));
        }
    }

    public void good_case_6(HttpServletRequest request) {
        String[] paramNames = {"id", "name", "email"};
        List<String> missingParams = new ArrayList<>();
        
        for (String param : paramNames) {
            // ok: java-avoid-throwing-exceptions-in-a-loop
            String value = request.getParameter(param);
            if (value == null || value.isEmpty()) {
                missingParams.add(param);
            }
        }
        
        if (!missingParams.isEmpty()) {
            throw new IllegalArgumentException("Missing required parameters: " + String.join(", ", missingParams));
        }
    }

    public void good_case_7() {
        List<Integer> values = Arrays.asList(10, 20, 30, 40, 50);
        List<Integer> invalidIndices = new ArrayList<>();
        
        for (int i = 0; i < 10; i++) {
            try {
                // ok: java-avoid-throwing-exceptions-in-a-loop
                int value = values.get(i);
                System.out.println("Value: " + value);
            } catch (IndexOutOfBoundsException e) {
                invalidIndices.add(i);
            }
        }
        
        if (!invalidIndices.isEmpty()) {
            throw new RuntimeException("Invalid indices: " + invalidIndices);
        }
    }

    public void good_case_8() {
        int[] divisors = {2, 0, 3, 0, 5};
        List<Integer> zeroDivisors = new ArrayList<>();
        
        for (int i = 0; i < divisors.length; i++) {
            // ok: java-avoid-throwing-exceptions-in-a-loop
            if (divisors[i] == 0) {
                zeroDivisors.add(i);
                continue;
            }
            int result = 100 / divisors[i];
            System.out.println("Result: " + result);
        }
        
        if (!zeroDivisors.isEmpty()) {
            throw new ArithmeticException("Cannot divide by zero at indices: " + zeroDivisors);
        }
    }

    public void good_case_9() {
        String[] inputs = {"123", "abc", "456", "def"};
        List<String> invalidInputs = new ArrayList<>();
        
        for (String input : inputs) {
            try {
                // ok: java-avoid-throwing-exceptions-in-a-loop
                int value = Integer.parseInt(input);
                System.out.println("Parsed value: " + value);
            } catch (NumberFormatException e) {
                invalidInputs.add(input);
            }
        }
        
        if (!invalidInputs.isEmpty()) {
            throw new IllegalArgumentException("Invalid number formats: " + invalidInputs);
        }
    }

    public void good_case_10() {
        List<String> configFiles = Arrays.asList("config1.xml", "config2.xml", "config3.xml");
        List<String> nonXmlFiles = new ArrayList<>();
        
        for (int i = 0; i < configFiles.size(); i++) {
            // ok: java-avoid-throwing-exceptions-in-a-loop
            String file = configFiles.get(i);
            if (!file.endsWith(".xml")) {
                nonXmlFiles.add(file);
            }
        }
        
        if (!nonXmlFiles.isEmpty()) {
            throw new IllegalArgumentException("Non-XML files: " + String.join(", ", nonXmlFiles));
        }
    }

    public void good_case_11() {
        List<String> invalidInputs = new ArrayList<>();
        
        while (true) {
            Scanner scanner = new Scanner(System.in);
            String input = scanner.nextLine();
            
            if ("exit".equals(input)) {
                break;
            } else if (input.length() < 3) {
                // ok: java-avoid-throwing-exceptions-in-a-loop
                invalidInputs.add(input);
            }
        }
        
        if (!invalidInputs.isEmpty()) {
            throw new IllegalArgumentException("Inputs too short: " + invalidInputs);
        }
    }

    public void good_case_12() {
        String[] commands = {"start", "stop", "restart", "invalid"};
        List<String> invalidCommands = new ArrayList<>();
        
        for (String cmd : commands) {
            // ok: java-avoid-throwing-exceptions-in-a-loop
            switch (cmd) {
                case "start":
                case "stop":
                case "restart":
                    System.out.println("Executing command: " + cmd);
                    break;
                default:
                    invalidCommands.add(cmd);
            }
        }
        
        if (!invalidCommands.isEmpty()) {
            throw new UnsupportedOperationException("Unsupported commands: " + String.join(", ", invalidCommands));
        }
    }

    public void good_case_13() {
        int maxRetries = 5;
        boolean success = false;
        Exception lastException = null;
        
        for (int attempt = 0; attempt < maxRetries; attempt++) {
            try {
                // ok: java-avoid-throwing-exceptions-in-a-loop
                success = Math.random() > 0.8;
                if (success) {
                    break;
                }
            } catch (Exception e) {
                lastException = e;
            }
        }
        
        if (!success) {
            throw new RuntimeException("Operation failed after " + maxRetries + " attempts", lastException);
        }
    }

    public void good_case_14() {
        List<Map<String, Object>> records = new ArrayList<>();
        // Assume records is populated with data
        List<Integer> invalidRecords = new ArrayList<>();
        
        for (int i = 0; i < records.size(); i++) {
            // ok: java-avoid-throwing-exceptions-in-a-loop
            Map<String, Object> record = records.get(i);
            if (!record.containsKey("id")) {
                invalidRecords.add(i);
            }
        }
        
        if (!invalidRecords.isEmpty()) {
            throw new IllegalStateException("Records missing required 'id' field at indices: " + invalidRecords);
        }
    }

    public void good_case_15() {
        List<Integer> zeroValues = new ArrayList<>();
        boolean shouldContinue = true;
        
        do {
            // ok: java-avoid-throwing-exceptions-in-a-loop
            int randomValue = new Random().nextInt(10);
            if (randomValue == 0) {
                zeroValues.add(randomValue);
            }
            shouldContinue = Math.random() < 0.5;
        } while (shouldContinue);
        
        if (!zeroValues.isEmpty()) {
            throw new ArithmeticException("Zero values found: " + zeroValues.size() + " times");
        }
    }
}
// {/fact}