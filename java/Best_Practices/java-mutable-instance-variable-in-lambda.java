import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Function;

public class MutableInstanceVariableInLambdaExamples {

    // BAD CASES - Using mutable instance variables in Lambda functions

    // Case 1: Basic mutable counter in Lambda handler
    public class bad_case_1 implements RequestHandler<Map<String, Object>, String> {
        private int requestCount = 0; // Mutable instance variable
        
        @Override
        public String handleRequest(Map<String, Object> input, Context context) {
            // ruleid: java-mutable-instance-variable-in-lambda
            requestCount++; // Modifying instance variable
            return "Processed request #" + requestCount;
        }
    }

    // Case 2: Mutable list as instance variable
    public class bad_case_2 implements RequestHandler<String, List<String>> {
        private List<String> processingHistory = new ArrayList<>(); // Mutable collection
        
        @Override
        public List<String> handleRequest(String input, Context context) {
            // ruleid: java-mutable-instance-variable-in-lambda
            processingHistory.add(input); // Modifying instance collection
            return processingHistory;
        }
    }

    // Case 3: Mutable map storing user data
    public class bad_case_3 implements RequestHandler<Map<String, String>, String> {
        private Map<String, String> userCache = new HashMap<>(); // Mutable map
        
        @Override
        public String handleRequest(Map<String, String> input, Context context) {
            String userId = input.get("userId");
            // ruleid: java-mutable-instance-variable-in-lambda
            userCache.put(userId, input.get("userData")); // Storing data in instance map
            return "User data stored for: " + userId;
        }
    }

    // Case 4: Mutable StringBuilder for logging
    public class bad_case_4 implements RequestHandler<String, String> {
        private StringBuilder logBuffer = new StringBuilder(); // Mutable StringBuilder
        
        @Override
        public String handleRequest(String input, Context context) {
            // ruleid: java-mutable-instance-variable-in-lambda
            logBuffer.append("[").append(System.currentTimeMillis()).append("] ")
                     .append(input).append("\n"); // Modifying instance StringBuilder
            return "Logged: " + input;
        }
    }

    // Case 5: Mutable atomic counter
    public class bad_case_5 implements RequestHandler<Map<String, Object>, Integer> {
        private AtomicInteger counter = new AtomicInteger(0); // Mutable atomic
        
        @Override
        public Integer handleRequest(Map<String, Object> input, Context context) {
            // ruleid: java-mutable-instance-variable-in-lambda
            return counter.incrementAndGet(); // Modifying atomic counter
        }
    }

    // Case 6: Mutable instance variable in nested lambda
    public class bad_case_6 implements RequestHandler<List<Integer>, Integer> {
        private int sum = 0; // Mutable instance variable
        
        @Override
        public Integer handleRequest(List<Integer> input, Context context) {
            // ruleid: java-mutable-instance-variable-in-lambda
            input.forEach(num -> sum += num); // Modifying instance variable in lambda
            return sum;
        }
    }

    // Case 7: Multiple mutable instance variables
    public class bad_case_7 implements RequestHandler<String, Map<String, Integer>> {
        private int requestCount = 0;
        private Map<String, Integer> wordCounts = new HashMap<>();
        
        @Override
        public Map<String, Integer> handleRequest(String input, Context context) {
            // ruleid: java-mutable-instance-variable-in-lambda
            requestCount++;
            String[] words = input.split("\\s+");
            for (String word : words) {
                wordCounts.put(word, wordCounts.getOrDefault(word, 0) + 1);
            }
            return wordCounts;
        }
    }

    // Case 8: Mutable instance variable with conditional update
    public class bad_case_8 implements RequestHandler<Integer, String> {
        private int maxValue = 0;
        
        @Override
        public String handleRequest(Integer input, Context context) {
            if (input > maxValue) {
                // ruleid: java-mutable-instance-variable-in-lambda
                maxValue = input; // Conditionally updating instance variable
                return "New max: " + maxValue;
            }
            return "Current max: " + maxValue;
        }
    }

    // Case 9: Mutable instance variable in consumer lambda
    public class bad_case_9 implements RequestHandler<List<String>, Integer> {
        private List<String> processedItems = new ArrayList<>();
        
        @Override
        public Integer handleRequest(List<String> input, Context context) {
            Consumer<String> processor = item -> {
                // ruleid: java-mutable-instance-variable-in-lambda
                processedItems.add(item.toUpperCase()); // Modifying instance variable in consumer
            };
            
            input.forEach(processor);
            return processedItems.size();
        }
    }

    // Case 10: Mutable instance variable in function lambda
    public class bad_case_10 implements RequestHandler<List<Integer>, Double> {
        private double total = 0.0;
        
        @Override
        public Double handleRequest(List<Integer> input, Context context) {
            Function<Integer, Double> processor = num -> {
                double value = num * 1.5;
                // ruleid: java-mutable-instance-variable-in-lambda
                total += value; // Modifying instance variable in function
                return value;
            };
            
            input.stream().map(processor).count();
            return total;
        }
    }

    // Case 11: Mutable instance variable with complex processing
    public class bad_case_11 implements RequestHandler<Map<String, Object>, List<String>> {
        private List<String> errorLog = new ArrayList<>();
        
        @Override
        public List<String> handleRequest(Map<String, Object> input, Context context) {
            try {
                processData(input);
            } catch (Exception e) {
                // ruleid: java-mutable-instance-variable-in-lambda
                errorLog.add("Error: " + e.getMessage()); // Modifying instance variable
            }
            return errorLog;
        }
        
        private void processData(Map<String, Object> data) {
            // Processing logic
        }
    }

    // Case 12: Mutable instance variable with thread
    public class bad_case_12 implements RequestHandler<String, String> {
        private StringBuilder buffer = new StringBuilder();
        
        @Override
        public String handleRequest(String input, Context context) {
            Runnable task = () -> {
                // ruleid: java-mutable-instance-variable-in-lambda
                buffer.append(input); // Modifying instance variable in runnable
            };
            
            Thread t = new Thread(task);
            t.start();
            try {
                t.join();
            } catch (InterruptedException e) {
                // Handle exception
            }
            
            return buffer.toString();
        }
    }

    // Case 13: Mutable instance variable with synchronization
    public class bad_case_13 implements RequestHandler<String, Integer> {
        private int counter = 0;
        
        @Override
        public Integer handleRequest(String input, Context context) {
            synchronized(this) {
                // ruleid: java-mutable-instance-variable-in-lambda
                counter += input.length(); // Modifying instance variable with synchronization
            }
            return counter;
        }
    }

    // Case 14: Mutable instance variable with complex lambda
    public class bad_case_14 implements RequestHandler<List<Map<String, Object>>, Map<String, Integer>> {
        private Map<String, Integer> statistics = new HashMap<>();
        
        @Override
        public Map<String, Integer> handleRequest(List<Map<String, Object>> input, Context context) {
            input.stream()
                 .filter(map -> map.containsKey("category"))
                 .forEach(map -> {
                     String category = (String) map.get("category");
                     // ruleid: java-mutable-instance-variable-in-lambda
                     statistics.put(category, statistics.getOrDefault(category, 0) + 1);
                 });
            
            return statistics;
        }
    }

    // Case 15: Mutable instance variable with delayed execution
    public class bad_case_15 implements RequestHandler<String, String> {
        private List<String> queue = new ArrayList<>();
        
        @Override
        public String handleRequest(String input, Context context) {
            Runnable delayedTask = () -> {
                try {
                    Thread.sleep(100);
                    // ruleid: java-mutable-instance-variable-in-lambda
                    queue.add(input); // Delayed modification of instance variable
                } catch (InterruptedException e) {
                    // Handle exception
                }
            };
            
            new Thread(delayedTask).start();
            return "Queued: " + input;
        }
    }

    // GOOD CASES - Using method-local variables instead of mutable instance variables

    // Case 1: Method-local counter
    public class good_case_1 implements RequestHandler<Map<String, Object>, String> {
        @Override
        public String handleRequest(Map<String, Object> input, Context context) {
            // ok: java-mutable-instance-variable-in-lambda
            int requestCount = 0; // Method-local variable
            requestCount++;
            return "Processed request #" + requestCount;
        }
    }

    // Case 2: Method-local list
    public class good_case_2 implements RequestHandler<String, List<String>> {
        @Override
        public List<String> handleRequest(String input, Context context) {
            // ok: java-mutable-instance-variable-in-lambda
            List<String> processingHistory = new ArrayList<>(); // Method-local collection
            processingHistory.add(input);
            return processingHistory;
        }
    }

    // Case 3: Method-local map
    public class good_case_3 implements RequestHandler<Map<String, String>, String> {
        @Override
        public String handleRequest(Map<String, String> input, Context context) {
            String userId = input.get("userId");
            // ok: java-mutable-instance-variable-in-lambda
            Map<String, String> userCache = new HashMap<>(); // Method-local map
            userCache.put(userId, input.get("userData"));
            return "User data stored for: " + userId;
        }
    }

    // Case 4: Method-local StringBuilder
    public class good_case_4 implements RequestHandler<String, String> {
        @Override
        public String handleRequest(String input, Context context) {
            // ok: java-mutable-instance-variable-in-lambda
            StringBuilder logBuffer = new StringBuilder(); // Method-local StringBuilder
            logBuffer.append("[").append(System.currentTimeMillis()).append("] ")
                     .append(input).append("\n");
            return "Logged: " + input;
        }
    }

    // Case 5: Method-local atomic counter
    public class good_case_5 implements RequestHandler<Map<String, Object>, Integer> {
        @Override
        public Integer handleRequest(Map<String, Object> input, Context context) {
            // ok: java-mutable-instance-variable-in-lambda
            AtomicInteger counter = new AtomicInteger(0); // Method-local atomic
            return counter.incrementAndGet();
        }
    }

    // Case 6: Method-local variable with lambda
    public class good_case_6 implements RequestHandler<List<Integer>, Integer> {
        @Override
        public Integer handleRequest(List<Integer> input, Context context) {
            // ok: java-mutable-instance-variable-in-lambda
            final int[] sum = {0}; // Method-local array for mutable access in lambda
            input.forEach(num -> sum[0] += num);
            return sum[0];
        }
    }

    // Case 7: Multiple method-local variables
    public class good_case_7 implements RequestHandler<String, Map<String, Integer>> {
        @Override
        public Map<String, Integer> handleRequest(String input, Context context) {
            // ok: java-mutable-instance-variable-in-lambda
            int requestCount = 0;
            Map<String, Integer> wordCounts = new HashMap<>();
            
            requestCount++;
            String[] words = input.split("\\s+");
            for (String word : words) {
                wordCounts.put(word, wordCounts.getOrDefault(word, 0) + 1);
            }
            return wordCounts;
        }
    }

    // Case 8: Method-local variable with conditional update
    public class good_case_8 implements RequestHandler<Integer, String> {
        @Override
        public String handleRequest(Integer input, Context context) {
            // ok: java-mutable-instance-variable-in-lambda
            int maxValue = 0; // Method-local variable
            
            if (input > maxValue) {
                maxValue = input;
                return "New max: " + maxValue;
            }
            return "Current max: " + maxValue;
        }
    }

    // Case 9: Method-local variable in consumer lambda
    public class good_case_9 implements RequestHandler<List<String>, Integer> {
        @Override
        public Integer handleRequest(List<String> input, Context context) {
            // ok: java-mutable-instance-variable-in-lambda
            List<String> processedItems = new ArrayList<>(); // Method-local list
            
            Consumer<String> processor = item -> {
                processedItems.add(item.toUpperCase());
            };
            
            input.forEach(processor);
            return processedItems.size();
        }
    }

    // Case 10: Method-local variable in function lambda
    public class good_case_10 implements RequestHandler<List<Integer>, Double> {
        @Override
        public Double handleRequest(List<Integer> input, Context context) {
            // ok: java-mutable-instance-variable-in-lambda
            final double[] total = {0.0}; // Method-local array for mutable access
            
            Function<Integer, Double> processor = num -> {
                double value = num * 1.5;
                total[0] += value;
                return value;
            };
            
            input.stream().map(processor).count();
            return total[0];
        }
    }

    // Case 11: Method-local variable with complex processing
    public class good_case_11 implements RequestHandler<Map<String, Object>, List<String>> {
        @Override
        public List<String> handleRequest(Map<String, Object> input, Context context) {
            // ok: java-mutable-instance-variable-in-lambda
            List<String> errorLog = new ArrayList<>(); // Method-local list
            
            try {
                processData(input);
            } catch (Exception e) {
                errorLog.add("Error: " + e.getMessage());
            }
            return errorLog;
        }
        
        private void processData(Map<String, Object> data) {
            // Processing logic
        }
    }

    // Case 12: Method-local variable with thread
    public class good_case_12 implements RequestHandler<String, String> {
        @Override
        public String handleRequest(String input, Context context) {
            // ok: java-mutable-instance-variable-in-lambda
            StringBuilder buffer = new StringBuilder(); // Method-local StringBuilder
            
            Runnable task = () -> {
                buffer.append(input);
            };
            
            Thread t = new Thread(task);
            t.start();
            try {
                t.join();
            } catch (InterruptedException e) {
                // Handle exception
            }
            
            return buffer.toString();
        }
    }

    // Case 13: Method-local variable with synchronization
    public class good_case_13 implements RequestHandler<String, Integer> {
        @Override
        public Integer handleRequest(String input, Context context) {
            // ok: java-mutable-instance-variable-in-lambda
            int counter = 0; // Method-local counter
            
            synchronized(this) {
                counter += input.length();
            }
            return counter;
        }
    }

    // Case 14: Method-local variable with complex lambda
    public class good_case_14 implements RequestHandler<List<Map<String, Object>>, Map<String, Integer>> {
        @Override
        public Map<String, Integer> handleRequest(List<Map<String, Object>> input, Context context) {
            // ok: java-mutable-instance-variable-in-lambda
            Map<String, Integer> statistics = new HashMap<>(); // Method-local map
            
            input.stream()
                 .filter(map -> map.containsKey("category"))
                 .forEach(map -> {
                     String category = (String) map.get("category");
                     statistics.put(category, statistics.getOrDefault(category, 0) + 1);
                 });
            
            return statistics;
        }
    }

    // Case 15: Method-local variable with delayed execution
    public class good_case_15 implements RequestHandler<String, String> {
        @Override
        public String handleRequest(String input, Context context) {
            // ok: java-mutable-instance-variable-in-lambda
            List<String> queue = new ArrayList<>(); // Method-local list
            
            Runnable delayedTask = () -> {
                try {
                    Thread.sleep(100);
                    queue.add(input);
                } catch (InterruptedException e) {
                    // Handle exception
                }
            };
            
            new Thread(delayedTask).start();
            return "Queued: " + input;
        }
    }
}