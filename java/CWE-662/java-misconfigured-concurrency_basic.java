import java.util.concurrent.*;
import java.util.function.Supplier;
import java.util.List;
import java.util.ArrayList;
import java.util.Random;

public class ConcurrencyMisconfigurationExamples {

    // True positive examples (vulnerable code)

// {fact rule=misconfigured-concurrency@v1.0 defects=1}
    public String bad_case_1() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try {
                Thread.sleep(5000); // Simulating long-running task
                return "Result from long operation";
            } catch (InterruptedException e) {
                return "Error";
            }
        });
        
        try {
            // ruleid: java-misconfigured-concurrency
            return future.get(); // No timeout specified, could block indefinitely
        } catch (InterruptedException | ExecutionException e) {
            return "Error occurred: " + e.getMessage();
        }
    }

    public Integer bad_case_2() {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<Integer> future = executor.submit(() -> {
            // Simulating a computation that might hang
            if (new Random().nextBoolean()) {
                while (true) {
                    // Infinite loop
                }
            }
            return 42;
        });
        
        try {
            // ruleid: java-misconfigured-concurrency
            return future.get(); // No timeout, thread might be blocked forever
        } catch (InterruptedException | ExecutionException e) {
            return -1;
        } finally {
            executor.shutdown();
        }
    }

    public String bad_case_3() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            // Simulating a network call that might hang
            try {
                Thread.sleep(10000);
                return "Network response";
            } catch (Exception e) {
                return "Network error";
            }
        });
        
        CompletableFuture<String> future2 = future.thenApply(result -> result + " processed");
        
        try {
            // ruleid: java-misconfigured-concurrency
            return future2.get(); // No timeout on dependent future
        } catch (InterruptedException | ExecutionException e) {
            return "Error in processing: " + e.getMessage();
        }
    }

    public List<String> bad_case_4() {
        List<CompletableFuture<String>> futures = new ArrayList<>();
        
        for (int i = 0; i < 5; i++) {
            final int index = i;
            futures.add(CompletableFuture.supplyAsync(() -> {
                try {
                    Thread.sleep(1000 * index);
                    return "Result " + index;
                } catch (InterruptedException e) {
                    return "Error " + index;
                }
            }));
        }
        
        List<String> results = new ArrayList<>();
        for (CompletableFuture<String> future : futures) {
            try {
                // ruleid: java-misconfigured-concurrency
                results.add(future.get()); // No timeout in a loop, could cause cascading delays
            } catch (InterruptedException | ExecutionException e) {
                results.add("Error: " + e.getMessage());
            }
        }
        
        return results;
    }

    public Object bad_case_5() {
        ExecutorService executor = Executors.newFixedThreadPool(2);
        Future<Object> future = executor.submit(() -> {
            // Simulating an external service call
            Thread.sleep(3000);
            return new Object();
        });
        
        try {
            // ruleid: java-misconfigured-concurrency
            return future.get(); // No timeout for external service call
        } catch (InterruptedException | ExecutionException e) {
            return null;
        } finally {
            executor.shutdown();
        }
    }

    public String bad_case_6() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try {
                // Simulating database query
                Thread.sleep(2000);
                return "Database result";
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return "Query interrupted";
            }
        });
        
        try {
            // ruleid: java-misconfigured-concurrency
            String result = future.get(); // No timeout for database operation
            return "Processed: " + result;
        } catch (InterruptedException | ExecutionException e) {
            return "Database error: " + e.getMessage();
        }
    }

    public int bad_case_7() {
        CompletableFuture<Integer> future1 = CompletableFuture.supplyAsync(() -> 10);
        CompletableFuture<Integer> future2 = CompletableFuture.supplyAsync(() -> {
            try {
                Thread.sleep(10000); // Simulating slow operation
                return 20;
            } catch (InterruptedException e) {
                return 0;
            }
        });
        
        try {
            // ruleid: java-misconfigured-concurrency
            int result1 = future1.get(); // This might be fast
            // ruleid: java-misconfigured-concurrency
            int result2 = future2.get(); // But this could block
            return result1 + result2;
        } catch (InterruptedException | ExecutionException e) {
            return -1;
        }
    }

    public String bad_case_8() {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        // In another thread (simulated here), we might complete the future
        if (new Random().nextBoolean()) {
            future.complete("Completed");
        }
        
        try {
            // ruleid: java-misconfigured-concurrency
            return future.get(); // No timeout, might never complete
        } catch (InterruptedException | ExecutionException e) {
            return "Error: " + e.getMessage();
        }
    }

    public Double bad_case_9() {
        ExecutorService executor = Executors.newCachedThreadPool();
        Future<Double> future = executor.submit(() -> {
            // Complex calculation
            double result = 0;
            for (int i = 0; i < 10_000_000; i++) {
                result += Math.sin(i);
            }
            return result;
        });
        
        try {
            // ruleid: java-misconfigured-concurrency
            return future.get(); // No timeout for CPU-intensive task
        } catch (InterruptedException | ExecutionException e) {
            return Double.NaN;
        } finally {
            executor.shutdown();
        }
    }

    public String bad_case_10() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            // Simulating file I/O operation
            try {
                Thread.sleep(5000);
                return "File content";
            } catch (InterruptedException e) {
                return "I/O error";
            }
        });
        
        try {
            // ruleid: java-misconfigured-concurrency
            return future.join(); // join() is similar to get() but wraps checked exceptions
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    public Object bad_case_11() {
        CompletableFuture<Object> future = CompletableFuture.supplyAsync(() -> {
            // Simulating a task that depends on external conditions
            try {
                while (!externalConditionMet()) {
                    Thread.sleep(100);
                }
                return new Object();
            } catch (Exception e) {
                return null;
            }
        });
        
        try {
            // ruleid: java-misconfigured-concurrency
            return future.get(); // No timeout, might wait indefinitely for external condition
        } catch (InterruptedException | ExecutionException e) {
            return null;
        }
    }

    public String bad_case_12() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            return performLongRunningTask();
        });
        
        CompletableFuture<String> combinedFuture = future.thenCombine(
            CompletableFuture.supplyAsync(() -> " additional data"),
            (s1, s2) -> s1 + s2
        );
        
        try {
            // ruleid: java-misconfigured-concurrency
            return combinedFuture.get(); // No timeout on combined future
        } catch (InterruptedException | ExecutionException e) {
            return "Error combining results: " + e.getMessage();
        }
    }

    public int bad_case_13() {
        CompletableFuture<Integer> future = CompletableFuture.supplyAsync(() -> {
            try {
                Thread.sleep(3000);
                return 42;
            } catch (InterruptedException e) {
                return 0;
            }
        });
        
        // Using exceptionally without timeout
        CompletableFuture<Integer> safeFuture = future.exceptionally(ex -> -1);
        
        try {
            // ruleid: java-misconfigured-concurrency
            return safeFuture.get(); // Still no timeout despite error handling
        } catch (InterruptedException | ExecutionException e) {
            return -2;
        }
    }

    public String bad_case_14() {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Callable<String> task = () -> {
            // Simulating a task that might deadlock
            synchronized (this) {
                Thread.sleep(1000);
                // In a real scenario, this might try to acquire another lock
                // that's held by the main thread, causing deadlock
            }
            return "Task completed";
        };
        
        Future<String> future = executor.submit(task);
        
        try {
            // ruleid: java-misconfigured-concurrency
            return future.get(); // No timeout, potential deadlock situation
        } catch (InterruptedException | ExecutionException e) {
            return "Task failed: " + e.getMessage();
        } finally {
            executor.shutdown();
        }
    }

    public Object bad_case_15() {
        CompletableFuture<Object> future = CompletableFuture.supplyAsync(() -> {
            try {
                // Simulating a task that might be affected by GC pauses
                byte[] memory = new byte[100_000_000]; // Allocate large memory
                System.gc(); // Hint for garbage collection
                Thread.sleep(2000);
                return memory.length;
            } catch (Exception e) {
                return -1;
            }
        });
        
        try {
            // ruleid: java-misconfigured-concurrency
            return future.get(); // No timeout, might be delayed by GC
        } catch (InterruptedException | ExecutionException e) {
            return "Error: " + e.getMessage();
        }
    }

    // True negative examples (safe code)

    public String good_case_1() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try {
                Thread.sleep(5000); // Simulating long-running task
                return "Result from long operation";
            } catch (InterruptedException e) {
                return "Error";
            }
        });
        
        try {
            // ok: java-misconfigured-concurrency
            return future.get(10, TimeUnit.SECONDS); // Timeout specified
        } catch (InterruptedException | ExecutionException e) {
            return "Error occurred: " + e.getMessage();
        } catch (TimeoutException e) {
            return "Operation timed out";
        }
    }

    public Integer good_case_2() {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<Integer> future = executor.submit(() -> {
            // Simulating a computation that might hang
            if (new Random().nextBoolean()) {
                while (true) {
                    // Infinite loop
                }
            }
            return 42;
        });
        
        try {
            // ok: java-misconfigured-concurrency
            return future.get(5, TimeUnit.SECONDS); // Timeout of 5 seconds
        } catch (InterruptedException | ExecutionException e) {
            return -1;
        } catch (TimeoutException e) {
            return -2; // Special value for timeout
        } finally {
            executor.shutdown();
        }
    }

    public String good_case_3() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            // Simulating a network call that might hang
            try {
                Thread.sleep(10000);
                return "Network response";
            } catch (Exception e) {
                return "Network error";
            }
        });
        
        CompletableFuture<String> future2 = future.thenApply(result -> result + " processed");
        
        try {
            // ok: java-misconfigured-concurrency
            return future2.get(15, TimeUnit.SECONDS); // Timeout on dependent future
        } catch (InterruptedException | ExecutionException e) {
            return "Error in processing: " + e.getMessage();
        } catch (TimeoutException e) {
            return "Processing timed out";
        }
    }

    public List<String> good_case_4() {
        List<CompletableFuture<String>> futures = new ArrayList<>();
        
        for (int i = 0; i < 5; i++) {
            final int index = i;
            futures.add(CompletableFuture.supplyAsync(() -> {
                try {
                    Thread.sleep(1000 * index);
                    return "Result " + index;
                } catch (InterruptedException e) {
                    return "Error " + index;
                }
            }));
        }
        
        List<String> results = new ArrayList<>();
        for (CompletableFuture<String> future : futures) {
            try {
                // ok: java-misconfigured-concurrency
                results.add(future.get(2, TimeUnit.SECONDS)); // Timeout in a loop
            } catch (InterruptedException | ExecutionException e) {
                results.add("Error: " + e.getMessage());
            } catch (TimeoutException e) {
                results.add("Timeout occurred");
            }
        }
        
        return results;
    }

    public Object good_case_5() {
        ExecutorService executor = Executors.newFixedThreadPool(2);
        Future<Object> future = executor.submit(() -> {
            // Simulating an external service call
            Thread.sleep(3000);
            return new Object();
        });
        
        try {
            // ok: java-misconfigured-concurrency
            return future.get(5, TimeUnit.SECONDS); // Timeout for external service call
        } catch (InterruptedException | ExecutionException e) {
            return null;
        } catch (TimeoutException e) {
            return "Service call timed out";
        } finally {
            executor.shutdown();
        }
    }

    public String good_case_6() {
        // Alternative approach: using orTimeout
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try {
                // Simulating database query
                Thread.sleep(2000);
                return "Database result";
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return "Query interrupted";
            }
        });
        
        // ok: java-misconfigured-concurrency
        CompletableFuture<String> timeoutFuture = future.orTimeout(3, TimeUnit.SECONDS);
        
        try {
            String result = timeoutFuture.get(); // Safe because we've set timeout via orTimeout
            return "Processed: " + result;
        } catch (InterruptedException | ExecutionException e) {
            return "Database error: " + e.getMessage();
        }
    }

    public int good_case_7() {
        CompletableFuture<Integer> future1 = CompletableFuture.supplyAsync(() -> 10);
        CompletableFuture<Integer> future2 = CompletableFuture.supplyAsync(() -> {
            try {
                Thread.sleep(10000); // Simulating slow operation
                return 20;
            } catch (InterruptedException e) {
                return 0;
            }
        });
        
        try {
            // ok: java-misconfigured-concurrency
            int result1 = future1.get(1, TimeUnit.SECONDS);
            // ok: java-misconfigured-concurrency
            int result2 = future2.get(2, TimeUnit.SECONDS);
            return result1 + result2;
        } catch (InterruptedException | ExecutionException e) {
            return -1;
        } catch (TimeoutException e) {
            return -2;
        }
    }

    public String good_case_8() {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        // In another thread (simulated here), we might complete the future
        if (new Random().nextBoolean()) {
            future.complete("Completed");
        }
        
        try {
            // ok: java-misconfigured-concurrency
            return future.get(1, TimeUnit.SECONDS); // Timeout of 1 second
        } catch (InterruptedException | ExecutionException e) {
            return "Error: " + e.getMessage();
        } catch (TimeoutException e) {
            future.cancel(true); // Cancel the future if it times out
            return "Future timed out and was cancelled";
        }
    }

    public Double good_case_9() {
        ExecutorService executor = Executors.newCachedThreadPool();
        Future<Double> future = executor.submit(() -> {
            // Complex calculation
            double result = 0;
            for (int i = 0; i < 10_000_000; i++) {
                result += Math.sin(i);
            }
            return result;
        });
        
        try {
            // ok: java-misconfigured-concurrency
            return future.get(30, TimeUnit.SECONDS); // Timeout for CPU-intensive task
        } catch (InterruptedException | ExecutionException e) {
            return Double.NaN;
        } catch (TimeoutException e) {
            return Double.NEGATIVE_INFINITY; // Special value for timeout
        } finally {
            executor.shutdown();
        }
    }

    public String good_case_10() {
        // Using completeOnTimeout
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            // Simulating file I/O operation
            try {
                Thread.sleep(5000);
                return "File content";
            } catch (InterruptedException e) {
                return "I/O error";
            }
        });
        
        // ok: java-misconfigured-concurrency
        CompletableFuture<String> timeoutFuture = future.completeOnTimeout("Timeout occurred", 3, TimeUnit.SECONDS);
        
        try {
            return timeoutFuture.join(); // Safe because we've set timeout via completeOnTimeout
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    public Object good_case_11() {
        CompletableFuture<Object> future = CompletableFuture.supplyAsync(() -> {
            // Simulating a task that depends on external conditions
            try {
                while (!externalConditionMet()) {
                    Thread.sleep(100);
                }
                return new Object();
            } catch (Exception e) {
                return null;
            }
        });
        
        try {
            // ok: java-misconfigured-concurrency
            return future.get(10, TimeUnit.SECONDS); // Timeout for waiting on external condition
        } catch (InterruptedException | ExecutionException e) {
            return null;
        } catch (TimeoutException e) {
            return "Timed out waiting for condition";
        }
    }

    public String good_case_12() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            return performLongRunningTask();
        });
        
        CompletableFuture<String> combinedFuture = future.thenCombine(
            CompletableFuture.supplyAsync(() -> " additional data"),
            (s1, s2) -> s1 + s2
        );
        
        try {
            // ok: java-misconfigured-concurrency
            return combinedFuture.get(7, TimeUnit.SECONDS); // Timeout on combined future
        } catch (InterruptedException | ExecutionException e) {
            return "Error combining results: " + e.getMessage();
        } catch (TimeoutException e) {
            return "Combination timed out";
        }
    }

    public int good_case_13() {
        CompletableFuture<Integer> future = CompletableFuture.supplyAsync(() -> {
            try {
                Thread.sleep(3000);
                return 42;
            } catch (InterruptedException e) {
                return 0;
            }
        });
        
        // Using exceptionally with timeout
        CompletableFuture<Integer> safeFuture = future.exceptionally(ex -> -1);
        
        try {
            // ok: java-misconfigured-concurrency
            return safeFuture.get(4, TimeUnit.SECONDS); // Timeout despite error handling
        } catch (InterruptedException | ExecutionException e) {
            return -2;
        } catch (TimeoutException e) {
            return -3;
        }
    }

    public String good_case_14() {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Callable<String> task = () -> {
            // Simulating a task that might deadlock
            synchronized (this) {
                Thread.sleep(1000);
                // In a real scenario, this might try to acquire another lock
                // that's held by the main thread, causing deadlock
            }
            return "Task completed";
        };
        
        Future<String> future = executor.submit(task);
        
        try {
            // ok: java-misconfigured-concurrency
            return future.get(2, TimeUnit.SECONDS); // Timeout to prevent deadlock
        } catch (InterruptedException | ExecutionException e) {
            return "Task failed: " + e.getMessage();
        } catch (TimeoutException e) {
            return "Task deadlocked or took too long";
        } finally {
            executor.shutdown();
        }
    }

    public Object good_case_15() {
        // Using a non-blocking approach with thenAccept
        CompletableFuture<Object> future = CompletableFuture.supplyAsync(() -> {
            try {
                // Simulating a task that might be affected by GC pauses
                byte[] memory = new byte[100_000_000]; // Allocate large memory
                System.gc(); // Hint for garbage collection
                Thread.sleep(2000);
                return memory.length;
            } catch (Exception e) {
                return -1;
            }
        });
        
        // ok: java-misconfigured-concurrency
        CompletableFuture<Void> handledFuture = future.thenAccept(result -> {
            System.out.println("Result: " + result);
        });
        
        // Set a timeout for the entire operation
        handledFuture.orTimeout(5, TimeUnit.SECONDS);
        
        // Return something immediately without blocking
        return "Processing started";
    }
    
    // Helper methods
    private boolean externalConditionMet() {
        return new Random().nextInt(100) > 95; // 5% chance of being true
    }
    
    private String performLongRunningTask() {
        try {
            Thread.sleep(3000);
            return "Task result";
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "Task interrupted";
        }
    }
}
// {/fact}