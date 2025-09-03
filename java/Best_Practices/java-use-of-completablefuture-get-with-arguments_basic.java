import java.util.concurrent.*;
import java.util.function.*;
import java.util.*;
import java.net.http.*;
import java.net.URI;
import java.io.IOException;

public class CompletableFutureUsageExamples {

    // True Positive Examples (Bad Cases)

// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_1() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try {
                Thread.sleep(10000); // Simulating long operation
                return "Result";
            } catch (InterruptedException e) {
                return "Error";
            }
        });
        
        try {
            // ruleid: java-use-of-completablefuture-get-with-arguments
            String result = future.get(); // No timeout specified, can wait indefinitely
            System.out.println("Result: " + result);
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        CompletableFuture<Integer> future = CompletableFuture.supplyAsync(() -> {
            // Simulating a potentially hanging operation
            while (true) {
                // This will never complete
            }
        });
        
        // ruleid: java-use-of-completablefuture-get-with-arguments
        Integer result = future.join(); // This will hang indefinitely
        System.out.println("Result: " + result);
    }

    public void bad_case_3() {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.example.com/data"))
                .build();
                
        CompletableFuture<HttpResponse<String>> responseFuture = 
                client.sendAsync(request, HttpResponse.BodyHandlers.ofString());
        
        try {
            // ruleid: java-use-of-completablefuture-get-with-arguments
            HttpResponse<String> response = responseFuture.get(); // No timeout, could hang if server doesn't respond
            System.out.println(response.body());
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        ExecutorService executor = Executors.newFixedThreadPool(1);
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try {
                // Simulating a database query that might hang
                Thread.sleep(Integer.MAX_VALUE);
                return "Database result";
            } catch (InterruptedException e) {
                return "Error";
            }
        }, executor);
        
        try {
            // ruleid: java-use-of-completablefuture-get-with-arguments
            String result = future.get(); // No timeout, will wait forever if the database query hangs
            System.out.println(result);
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        } finally {
            executor.shutdown();
        }
    }

    public void bad_case_5() {
        CompletableFuture<String> future1 = CompletableFuture.supplyAsync(() -> "First result");
        CompletableFuture<String> future2 = CompletableFuture.supplyAsync(() -> {
            try {
                Thread.sleep(100000); // Long operation
                return "Second result";
            } catch (InterruptedException e) {
                return "Error";
            }
        });
        
        CompletableFuture<Void> combinedFuture = CompletableFuture.allOf(future1, future2);
        
        try {
            // ruleid: java-use-of-completablefuture-get-with-arguments
            combinedFuture.get(); // No timeout, will wait for all futures to complete
            String result1 = future1.join();
            String result2 = future2.join();
            System.out.println(result1 + " " + result2);
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6() {
        CompletableFuture<String> future = new CompletableFuture<>();
        // This future is never completed
        
        try {
            // ruleid: java-use-of-completablefuture-get-with-arguments
            String result = future.get(); // Will wait forever
            System.out.println(result);
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try {
                Thread.sleep(5000);
                return "Result";
            } catch (InterruptedException e) {
                return "Error";
            }
        });
        
        // In a loop, which could cause multiple indefinite waits
        for (int i = 0; i < 5; i++) {
            CompletableFuture<String> newFuture = future.thenApply(s -> s + " " + i);
            // ruleid: java-use-of-completablefuture-get-with-arguments
            String result = newFuture.join(); // No timeout
            System.out.println(result);
        }
    }

    public void bad_case_8() {
        List<CompletableFuture<String>> futures = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            final int index = i;
            futures.add(CompletableFuture.supplyAsync(() -> {
                if (index == 5) {
                    // This one will hang
                    try {
                        Thread.sleep(Integer.MAX_VALUE);
                    } catch (InterruptedException e) {
                        // Ignored
                    }
                }
                return "Result " + index;
            }));
        }
        
        for (CompletableFuture<String> future : futures) {
            try {
                // ruleid: java-use-of-completablefuture-get-with-arguments
                String result = future.get(); // One of these will hang indefinitely
                System.out.println(result);
            } catch (InterruptedException | ExecutionException e) {
                e.printStackTrace();
            }
        }
    }

    public void bad_case_9() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            // Simulating a network call that might hang
            try {
                Socket socket = new Socket("example.com", 80);
                // ... socket operations that might hang
                return "Network result";
            } catch (Exception e) {
                return "Error";
            }
        });
        
        // ruleid: java-use-of-completablefuture-get-with-arguments
        String result = future.join(); // No timeout for potentially hanging network operation
        System.out.println(result);
    }

    public void bad_case_10() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            // Simulate a long-running computation
            BigInteger result = BigInteger.ONE;
            for (int i = 0; i < 1000000; i++) {
                result = result.multiply(BigInteger.valueOf(i + 1));
            }
            return result.toString();
        });
        
        try {
            // ruleid: java-use-of-completablefuture-get-with-arguments
            String result = future.get(); // No timeout for long computation
            System.out.println("Result length: " + result.length());
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        // Using CompletableFuture with a custom executor
        ExecutorService executor = Executors.newSingleThreadExecutor();
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            // Simulate a deadlock scenario
            synchronized(this) {
                try {
                    this.wait(); // This will never be notified
                } catch (InterruptedException e) {
                    // Ignored
                }
            }
            return "This will never be reached";
        }, executor);
        
        try {
            // ruleid: java-use-of-completablefuture-get-with-arguments
            String result = future.get(); // Will wait forever due to deadlock
            System.out.println(result);
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        } finally {
            executor.shutdown();
        }
    }

    public void bad_case_12() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            // Simulate a resource-intensive operation
            try {
                Process process = Runtime.getRuntime().exec("some-long-running-command");
                process.waitFor(); // This might take a very long time
                return "Process completed";
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        });
        
        // ruleid: java-use-of-completablefuture-get-with-arguments
        String result = future.join(); // No timeout for external process
        System.out.println(result);
    }

    public void bad_case_13() {
        // Chain of futures with potential for hanging
        CompletableFuture<String> future1 = CompletableFuture.supplyAsync(() -> "Step 1");
        CompletableFuture<String> future2 = future1.thenApplyAsync(s -> {
            try {
                Thread.sleep(10000); // Long delay
                return s + " -> Step 2";
            } catch (InterruptedException e) {
                return "Error";
            }
        });
        CompletableFuture<String> future3 = future2.thenApplyAsync(s -> {
            while (true) {
                // This will never complete
            }
        });
        
        try {
            // ruleid: java-use-of-completablefuture-get-with-arguments
            String result = future3.get(); // Will hang indefinitely
            System.out.println(result);
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        // Using CompletableFuture in a recursive scenario
        CompletableFuture<Integer> future = calculateFactorial(20);
        
        // ruleid: java-use-of-completablefuture-get-with-arguments
        Integer result = future.join(); // No timeout for recursive operation
        System.out.println("Factorial result: " + result);
    }
    
    private CompletableFuture<Integer> calculateFactorial(int n) {
        if (n <= 1) {
            return CompletableFuture.completedFuture(1);
        }
        return calculateFactorial(n - 1).thenApply(prev -> n * prev);
    }

    public void bad_case_15() {
        // Using CompletableFuture with a condition that might never be satisfied
        CompletableFuture<String> future = new CompletableFuture<>();
        
        // In another thread (simulated here)
        new Thread(() -> {
            // Wait for a condition that might never be true
            while (System.currentTimeMillis() % 1000000 == 0) {
                // This condition is extremely unlikely to be true
                future.complete("Condition met");
            }
        }).start();
        
        try {
            // ruleid: java-use-of-completablefuture-get-with-arguments
            String result = future.get(); // Will likely wait indefinitely
            System.out.println(result);
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Good Cases)

    public void good_case_1() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try {
                Thread.sleep(10000); // Simulating long operation
                return "Result";
            } catch (InterruptedException e) {
                return "Error";
            }
        });
        
        try {
            // ok: java-use-of-completablefuture-get-with-arguments
            String result = future.get(5, TimeUnit.SECONDS); // Timeout specified
            System.out.println("Result: " + result);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            System.out.println("Operation timed out or failed: " + e.getMessage());
        }
    }

    public void good_case_2() {
        CompletableFuture<Integer> future = CompletableFuture.supplyAsync(() -> {
            // Simulating a potentially hanging operation
            try {
                Thread.sleep(2000);
                return 42;
            } catch (InterruptedException e) {
                return -1;
            }
        });
        
        try {
            // ok: java-use-of-completablefuture-get-with-arguments
            Integer result = future.get(3, TimeUnit.SECONDS); // Timeout specified
            System.out.println("Result: " + result);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            System.out.println("Operation timed out or failed: " + e.getMessage());
        }
    }

    public void good_case_3() {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.example.com/data"))
                .build();
                
        CompletableFuture<HttpResponse<String>> responseFuture = 
                client.sendAsync(request, HttpResponse.BodyHandlers.ofString());
        
        try {
            // ok: java-use-of-completablefuture-get-with-arguments
            HttpResponse<String> response = responseFuture.get(10, TimeUnit.SECONDS); // Timeout for network operation
            System.out.println(response.body());
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            System.out.println("API request timed out or failed: " + e.getMessage());
        }
    }

    public void good_case_4() {
        ExecutorService executor = Executors.newFixedThreadPool(1);
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try {
                // Simulating a database query
                Thread.sleep(2000);
                return "Database result";
            } catch (InterruptedException e) {
                return "Error";
            }
        }, executor);
        
        try {
            // ok: java-use-of-completablefuture-get-with-arguments
            String result = future.get(5, TimeUnit.SECONDS); // Timeout for database operation
            System.out.println(result);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            System.out.println("Database query timed out or failed: " + e.getMessage());
        } finally {
            executor.shutdown();
        }
    }

    public void good_case_5() {
        CompletableFuture<String> future1 = CompletableFuture.supplyAsync(() -> "First result");
        CompletableFuture<String> future2 = CompletableFuture.supplyAsync(() -> {
            try {
                Thread.sleep(3000); // Long operation
                return "Second result";
            } catch (InterruptedException e) {
                return "Error";
            }
        });
        
        CompletableFuture<Void> combinedFuture = CompletableFuture.allOf(future1, future2);
        
        try {
            // ok: java-use-of-completablefuture-get-with-arguments
            combinedFuture.get(5, TimeUnit.SECONDS); // Timeout for combined operations
            String result1 = future1.getNow("Default if not done"); // Safe alternative to join()
            String result2 = future2.getNow("Default if not done"); // Safe alternative to join()
            System.out.println(result1 + " " + result2);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            System.out.println("Combined operation timed out or failed: " + e.getMessage());
        }
    }

    public void good_case_6() {
        CompletableFuture<String> future = new CompletableFuture<>();
        // This future might never be completed
        
        // Start a thread to complete the future after some time
        new Thread(() -> {
            try {
                Thread.sleep(2000);
                future.complete("Completed by thread");
            } catch (InterruptedException e) {
                future.completeExceptionally(e);
            }
        }).start();
        
        try {
            // ok: java-use-of-completablefuture-get-with-arguments
            String result = future.get(3, TimeUnit.SECONDS); // Timeout specified
            System.out.println(result);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            System.out.println("Operation timed out or failed: " + e.getMessage());
        }
    }

    public void good_case_7() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try {
                Thread.sleep(1000);
                return "Result";
            } catch (InterruptedException e) {
                return "Error";
            }
        });
        
        // In a loop, with timeout for each iteration
        for (int i = 0; i < 5; i++) {
            CompletableFuture<String> newFuture = future.thenApply(s -> s + " " + i);
            try {
                // ok: java-use-of-completablefuture-get-with-arguments
                String result = newFuture.get(2, TimeUnit.SECONDS); // Timeout specified
                System.out.println(result);
            } catch (InterruptedException | ExecutionException | TimeoutException e) {
                System.out.println("Operation " + i + " timed out or failed: " + e.getMessage());
            }
        }
    }

    public void good_case_8() {
        List<CompletableFuture<String>> futures = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            final int index = i;
            futures.add(CompletableFuture.supplyAsync(() -> {
                try {
                    Thread.sleep(index * 100); // Varying delays
                    return "Result " + index;
                } catch (InterruptedException e) {
                    return "Error";
                }
            }));
        }
        
        for (CompletableFuture<String> future : futures) {
            try {
                // ok: java-use-of-completablefuture-get-with-arguments
                String result = future.get(1, TimeUnit.SECONDS); // Timeout for each future
                System.out.println(result);
            } catch (InterruptedException | ExecutionException | TimeoutException e) {
                System.out.println("Operation timed out or failed: " + e.getMessage());
            }
        }
    }

    public void good_case_9() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            // Simulating a network call
            try {
                Thread.sleep(2000);
                return "Network result";
            } catch (InterruptedException e) {
                return "Error";
            }
        });
        
        // Using orTimeout to automatically timeout the future
        CompletableFuture<String> timeoutFuture = future.orTimeout(3, TimeUnit.SECONDS);
        
        try {
            // ok: java-use-of-completablefuture-get-with-arguments
            String result = timeoutFuture.get(); // Safe because we've already set a timeout
            System.out.println(result);
        } catch (InterruptedException | ExecutionException e) {
            System.out.println("Operation failed: " + e.getMessage());
        }
    }

    public void good_case_10() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            // Simulate a long-running computation
            try {
                Thread.sleep(4000);
                return "Computation result";
            } catch (InterruptedException e) {
                return "Error";
            }
        });
        
        // Using completeOnTimeout to provide a default value if the operation times out
        CompletableFuture<String> timeoutFuture = future.completeOnTimeout(
            "Default result due to timeout", 2, TimeUnit.SECONDS);
        
        try {
            // ok: java-use-of-completablefuture-get-with-arguments
            String result = timeoutFuture.get(); // Safe because we've handled timeout
            System.out.println(result);
        } catch (InterruptedException | ExecutionException e) {
            System.out.println("Operation failed: " + e.getMessage());
        }
    }

    public void good_case_11() {
        // Using CompletableFuture with a custom executor and timeout
        ExecutorService executor = Executors.newSingleThreadExecutor();
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try {
                Thread.sleep(3000);
                return "Task completed";
            } catch (InterruptedException e) {
                return "Error";
            }
        }, executor);
        
        try {
            // ok: java-use-of-completablefuture-get-with-arguments
            String result = future.get(2, TimeUnit.SECONDS); // Timeout specified
            System.out.println(result);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            System.out.println("Task timed out or failed: " + e.getMessage());
        } finally {
            executor.shutdown();
        }
    }

    public void good_case_12() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            // Simulate an external process
            try {
                Process process = Runtime.getRuntime().exec("echo hello");
                process.waitFor(2, TimeUnit.SECONDS); // Process-level timeout
                return "Process completed";
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        });
        
        try {
            // ok: java-use-of-completablefuture-get-with-arguments
            String result = future.get(5, TimeUnit.SECONDS); // Additional timeout for the future
            System.out.println(result);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            System.out.println("Process execution timed out or failed: " + e.getMessage());
        }
    }

    public void good_case_13() {
        // Chain of futures with timeout
        CompletableFuture<String> future1 = CompletableFuture.supplyAsync(() -> "Step 1");
        CompletableFuture<String> future2 = future1.thenApplyAsync(s -> {
            try {
                Thread.sleep(1000);
                return s + " -> Step 2";
            } catch (InterruptedException e) {
                return "Error";
            }
        });
        CompletableFuture<String> future3 = future2.thenApplyAsync(s -> {
            try {
                Thread.sleep(1000);
                return s + " -> Step 3";
            } catch (InterruptedException e) {
                return "Error";
            }
        });
        
        try {
            // ok: java-use-of-completablefuture-get-with-arguments
            String result = future3.get(5, TimeUnit.SECONDS); // Timeout for the entire chain
            System.out.println(result);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            System.out.println("Chain execution timed out or failed: " + e.getMessage());
        }
    }

    public void good_case_14() {
        // Using CompletableFuture in a recursive scenario with timeout
        CompletableFuture<Integer> future = calculateFactorialWithTimeout(20);
        
        try {
            // ok: java-use-of-completablefuture-get-with-arguments
            Integer result = future.get(2, TimeUnit.SECONDS); // Additional timeout
            System.out.println("Factorial result: " + result);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            System.out.println("Factorial calculation timed out or failed: " + e.getMessage());
        }
    }
    
    private CompletableFuture<Integer> calculateFactorialWithTimeout(int n) {
        CompletableFuture<Integer> result;
        if (n <= 1) {
            result = CompletableFuture.completedFuture(1);
        } else {
            result = calculateFactorialWithTimeout(n - 1)
                    .thenApply(prev -> n * prev)
                    .orTimeout(1, TimeUnit.SECONDS); // Timeout for each recursive step
        }
        return result;
    }

    public void good_case_15() {
        // Using CompletableFuture with a condition that might never be satisfied, but with timeout
        CompletableFuture<String> future = new CompletableFuture<>();
        
        // In another thread (simulated here)
        new Thread(() -> {
            // Wait for a condition that might never be true
            while (System.currentTimeMillis() % 1000000 == 0) {
                // This condition is extremely unlikely to be true
                future.complete("Condition met");
            }
        }).start();
        
        try {
            // ok: java-use-of-completablefuture-get-with-arguments
            String result = future.get(1, TimeUnit.SECONDS); // Timeout specified
            System.out.println(result);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            System.out.println("Waiting for condition timed out: " + e.getMessage());
            // Handle the timeout appropriately
            future.complete("Default value after timeout");
        }
    }

    // Helper class for bad_case_9
    static class Socket {
        public Socket(String host, int port) throws IOException {
            // Simulated socket constructor
        }
    }
}
// {/fact}