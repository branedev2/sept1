import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.util.function.Supplier;

public class CompletableFutureExamples {

    // True positive examples (vulnerable/insecure code)
    
// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_1() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try {
                // Simulating a long-running operation
                Thread.sleep(10000);
                return "Result";
            } catch (InterruptedException e) {
                return "Error";
            }
        });
        
        try {
            // ruleid: java-use-of-completablefuture-get-with-arguments
            String result = future.get(); // No timeout specified, could block indefinitely
            System.out.println("Result: " + result);
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_2() {
        CompletableFuture<Integer> future = CompletableFuture.supplyAsync(() -> {
            // Simulating a potentially hanging operation
            while (true) {
                // This might never complete
                if (Math.random() < 0.00001) {
                    return 42;
                }
            }
        });
        
        // ruleid: java-use-of-completablefuture-get-with-arguments
        Integer result = future.join(); // Using join() which can block indefinitely
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
            HttpResponse<String> response = responseFuture.get(); // No timeout for API call
            System.out.println("Response: " + response.body());
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_4() {
        CompletableFuture<String> future1 = CompletableFuture.supplyAsync(() -> "Hello");
        CompletableFuture<String> future2 = CompletableFuture.supplyAsync(() -> {
            try {
                Thread.sleep(5000); // Simulating delay
                return "World";
            } catch (InterruptedException e) {
                return "Error";
            }
        });
        
        CompletableFuture<Void> combinedFuture = CompletableFuture.allOf(future1, future2);
        
        try {
            // ruleid: java-use-of-completablefuture-get-with-arguments
            combinedFuture.get(); // Waiting for all futures without timeout
            String result1 = future1.join();
            String result2 = future2.join();
            System.out.println(result1 + " " + result2);
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_5() {
        CompletableFuture<Double> priceFuture = CompletableFuture.supplyAsync(() -> {
            // Simulating a price calculation that might take time
            try {
                Thread.sleep(3000);
                return 99.99;
            } catch (InterruptedException e) {
                return 0.0;
            }
        });
        
        // ruleid: java-use-of-completablefuture-get-with-arguments
        Double price = priceFuture.join(); // Using join() which can block indefinitely
        System.out.println("Price: $" + price);
    }
    
    public void bad_case_6() {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        // This future might never be completed
        if (Math.random() < 0.5) {
            future.complete("Done");
        }
        
        try {
            // ruleid: java-use-of-completablefuture-get-with-arguments
            String result = future.get(); // May wait forever if future is not completed
            System.out.println("Result: " + result);
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_7() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try {
                // Simulating a database query
                Thread.sleep(2000);
                return "Database result";
            } catch (InterruptedException e) {
                return "Error";
            }
        });
        
        CompletableFuture<String> transformedFuture = future.thenApply(result -> result.toUpperCase());
        
        // ruleid: java-use-of-completablefuture-get-with-arguments
        String finalResult = transformedFuture.join(); // Using join() which can block indefinitely
        System.out.println("Final result: " + finalResult);
    }
    
    public void bad_case_8() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            // Simulating an operation that might deadlock
            synchronized (this) {
                try {
                    this.wait(); // This might cause a deadlock
                    return "Result";
                } catch (InterruptedException e) {
                    return "Error";
                }
            }
        });
        
        try {
            // ruleid: java-use-of-completablefuture-get-with-arguments
            String result = future.get(); // Will wait indefinitely due to deadlock
            System.out.println(result);
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_9() {
        CompletableFuture<String> future1 = CompletableFuture.supplyAsync(() -> "Result 1");
        CompletableFuture<String> future2 = CompletableFuture.supplyAsync(() -> "Result 2");
        
        CompletableFuture<String> combinedFuture = future1.thenCombine(future2, (r1, r2) -> r1 + " + " + r2);
        
        // ruleid: java-use-of-completablefuture-get-with-arguments
        String result = combinedFuture.join(); // Using join() which can block indefinitely
        System.out.println("Combined result: " + result);
    }
    
    public void bad_case_10() {
        CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
            try {
                // Simulating a long-running task with no result
                Thread.sleep(10000);
            } catch (InterruptedException e) {
                // Ignore
            }
        });
        
        try {
            // ruleid: java-use-of-completablefuture-get-with-arguments
            future.get(); // No timeout specified, could block indefinitely
            System.out.println("Task completed");
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_11() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            if (System.currentTimeMillis() % 2 == 0) {
                // Simulating an operation that might take very long
                while (true) {
                    // Do some work
                    if (Math.random() < 0.00001) {
                        break;
                    }
                }
            }
            return "Result";
        });
        
        try {
            // ruleid: java-use-of-completablefuture-get-with-arguments
            String result = future.get(); // No timeout, might wait forever
            System.out.println("Result: " + result);
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_12() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try {
                // Simulating a network call
                Thread.sleep(5000);
                return "Network response";
            } catch (InterruptedException e) {
                return "Error";
            }
        });
        
        // In a loop, which makes the blocking even more problematic
        for (int i = 0; i < 10; i++) {
            // ruleid: java-use-of-completablefuture-get-with-arguments
            String result = future.join(); // Using join() which can block indefinitely
            System.out.println("Result " + i + ": " + result);
        }
    }
    
    public void bad_case_13() {
        CompletableFuture<Integer> future = CompletableFuture.supplyAsync(() -> {
            try {
                // Simulating a calculation
                Thread.sleep(3000);
                return 42;
            } catch (InterruptedException e) {
                return 0;
            }
        });
        
        // Using exceptionally to handle errors, but still using join without timeout
        CompletableFuture<Integer> safeFuture = future.exceptionally(ex -> -1);
        
        // ruleid: java-use-of-completablefuture-get-with-arguments
        Integer result = safeFuture.join(); // Using join() which can block indefinitely
        System.out.println("Result: " + result);
    }
    
    public void bad_case_14() {
        Supplier<String> supplier = () -> {
            try {
                // Simulating a slow operation
                Thread.sleep(8000);
                return "Result";
            } catch (InterruptedException e) {
                return "Error";
            }
        };
        
        CompletableFuture<String> future = CompletableFuture.supplyAsync(supplier);
        
        try {
            // ruleid: java-use-of-completablefuture-get-with-arguments
            String result = future.get(); // No timeout specified, could block indefinitely
            System.out.println("Result: " + result);
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_15() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try {
                // Simulating an external service call
                Thread.sleep(4000);
                return "Service response";
            } catch (InterruptedException e) {
                return "Error";
            }
        });
        
        // Using thenAccept but still blocking with join
        CompletableFuture<Void> processedFuture = future.thenAccept(System.out::println);
        
        // ruleid: java-use-of-completablefuture-get-with-arguments
        processedFuture.join(); // Using join() which can block indefinitely
        System.out.println("Processing complete");
    }
    
    // True negative examples (safe/secure code)
    
    public void good_case_1() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try {
                // Simulating a long-running operation
                Thread.sleep(10000);
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
            while (true) {
                // This might never complete
                if (Math.random() < 0.00001) {
                    return 42;
                }
            }
        });
        
        try {
            // ok: java-use-of-completablefuture-get-with-arguments
            Integer result = future.get(2, TimeUnit.SECONDS); // Timeout specified
            System.out.println("Result: " + result);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            System.out.println("Operation timed out: " + e.getMessage());
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
            HttpResponse<String> response = responseFuture.get(10, TimeUnit.SECONDS); // Timeout for API call
            System.out.println("Response: " + response.body());
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            System.out.println("API call timed out or failed: " + e.getMessage());
        }
    }
    
    public void good_case_4() {
        CompletableFuture<String> future1 = CompletableFuture.supplyAsync(() -> "Hello");
        CompletableFuture<String> future2 = CompletableFuture.supplyAsync(() -> {
            try {
                Thread.sleep(5000); // Simulating delay
                return "World";
            } catch (InterruptedException e) {
                return "Error";
            }
        });
        
        CompletableFuture<Void> combinedFuture = CompletableFuture.allOf(future1, future2);
        
        try {
            // ok: java-use-of-completablefuture-get-with-arguments
            combinedFuture.get(6, TimeUnit.SECONDS); // Waiting for all futures with timeout
            String result1 = future1.getNow("Fallback1"); // Non-blocking get
            String result2 = future2.getNow("Fallback2"); // Non-blocking get
            System.out.println(result1 + " " + result2);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            System.out.println("Operation timed out: " + e.getMessage());
        }
    }
    
    public void good_case_5() {
        CompletableFuture<Double> priceFuture = CompletableFuture.supplyAsync(() -> {
            // Simulating a price calculation that might take time
            try {
                Thread.sleep(3000);
                return 99.99;
            } catch (InterruptedException e) {
                return 0.0;
            }
        });
        
        try {
            // ok: java-use-of-completablefuture-get-with-arguments
            Double price = priceFuture.get(4, TimeUnit.SECONDS); // Timeout specified
            System.out.println("Price: $" + price);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            System.out.println("Price calculation timed out: " + e.getMessage());
        }
    }
    
    public void good_case_6() {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        // This future might never be completed
        if (Math.random() < 0.5) {
            future.complete("Done");
        }
        
        try {
            // ok: java-use-of-completablefuture-get-with-arguments
            String result = future.get(1, TimeUnit.SECONDS); // Timeout specified
            System.out.println("Result: " + result);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            System.out.println("Operation timed out or failed: " + e.getMessage());
        }
    }
    
    public void good_case_7() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try {
                // Simulating a database query
                Thread.sleep(2000);
                return "Database result";
            } catch (InterruptedException e) {
                return "Error";
            }
        });
        
        CompletableFuture<String> transformedFuture = future.thenApply(result -> result.toUpperCase());
        
        try {
            // ok: java-use-of-completablefuture-get-with-arguments
            String finalResult = transformedFuture.get(3, TimeUnit.SECONDS); // Timeout specified
            System.out.println("Final result: " + finalResult);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            System.out.println("Database query timed out: " + e.getMessage());
        }
    }
    
    public void good_case_8() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            // Simulating an operation that might deadlock
            synchronized (this) {
                try {
                    this.wait(); // This might cause a deadlock
                    return "Result";
                } catch (InterruptedException e) {
                    return "Error";
                }
            }
        });
        
        try {
            // ok: java-use-of-completablefuture-get-with-arguments
            String result = future.get(500, TimeUnit.MILLISECONDS); // Short timeout to detect deadlock
            System.out.println(result);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            System.out.println("Detected potential deadlock: " + e.getMessage());
        }
    }
    
    public void good_case_9() {
        CompletableFuture<String> future1 = CompletableFuture.supplyAsync(() -> "Result 1");
        CompletableFuture<String> future2 = CompletableFuture.supplyAsync(() -> "Result 2");
        
        CompletableFuture<String> combinedFuture = future1.thenCombine(future2, (r1, r2) -> r1 + " + " + r2);
        
        try {
            // ok: java-use-of-completablefuture-get-with-arguments
            String result = combinedFuture.get(2, TimeUnit.SECONDS); // Timeout specified
            System.out.println("Combined result: " + result);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            System.out.println("Combining results timed out: " + e.getMessage());
        }
    }
    
    public void good_case_10() {
        CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
            try {
                // Simulating a long-running task with no result
                Thread.sleep(10000);
            } catch (InterruptedException e) {
                // Ignore
            }
        });
        
        try {
            // ok: java-use-of-completablefuture-get-with-arguments
            future.get(5, TimeUnit.SECONDS); // Timeout specified
            System.out.println("Task completed");
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            System.out.println("Task timed out: " + e.getMessage());
        }
    }
    
    public void good_case_11() {
        // Using non-blocking approach with callbacks instead of get/join
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try {
                Thread.sleep(2000);
                return "Async result";
            } catch (InterruptedException e) {
                return "Error";
            }
        });
        
        // ok: java-use-of-completablefuture-get-with-arguments
        future.thenAccept(result -> System.out.println("Result: " + result));
        
        // Continue with other work without blocking
        System.out.println("Processing continues without waiting...");
    }
    
    public void good_case_12() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try {
                // Simulating a network call
                Thread.sleep(5000);
                return "Network response";
            } catch (InterruptedException e) {
                return "Error";
            }
        });
        
        // In a loop, using timeout for each get call
        for (int i = 0; i < 10; i++) {
            try {
                // ok: java-use-of-completablefuture-get-with-arguments
                String result = future.get(1, TimeUnit.SECONDS); // Timeout specified
                System.out.println("Result " + i + ": " + result);
            } catch (InterruptedException | ExecutionException | TimeoutException e) {
                System.out.println("Operation " + i + " timed out: " + e.getMessage());
            }
        }
    }
    
    public void good_case_13() {
        // Using orTimeout to automatically timeout the CompletableFuture
        CompletableFuture<Integer> future = CompletableFuture.supplyAsync(() -> {
            try {
                Thread.sleep(3000);
                return 42;
            } catch (InterruptedException e) {
                return 0;
            }
        // ok: java-use-of-completablefuture-get-with-arguments
        }).orTimeout(2, TimeUnit.SECONDS); // Built-in timeout
        
        try {
            Integer result = future.join(); // Safe to join since we have orTimeout
            System.out.println("Result: " + result);
        } catch (Exception e) {
            System.out.println("Operation timed out: " + e.getMessage());
        }
    }
    
    public void good_case_14() {
        Supplier<String> supplier = () -> {
            try {
                // Simulating a slow operation
                Thread.sleep(8000);
                return "Result";
            } catch (InterruptedException e) {
                return "Error";
            }
        };
        
        CompletableFuture<String> future = CompletableFuture.supplyAsync(supplier);
        
        // Using completeOnTimeout to provide a default value after timeout
        // ok: java-use-of-completablefuture-get-with-arguments
        CompletableFuture<String> timeoutHandledFuture = future.completeOnTimeout("Default after timeout", 3, TimeUnit.SECONDS);
        
        try {
            String result = timeoutHandledFuture.join(); // Safe to join since we have completeOnTimeout
            System.out.println("Result: " + result);
        } catch (Exception e) {
            System.out.println("Unexpected error: " + e.getMessage());
        }
    }
    
    public void good_case_15() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try {
                // Simulating an external service call
                Thread.sleep(4000);
                return "Service response";
            } catch (InterruptedException e) {
                return "Error";
            }
        });
        
        // Using getNow for non-blocking access with a default value
        // ok: java-use-of-completablefuture-get-with-arguments
        String result = future.getNow("Default value if not complete");
        System.out.println("Immediate result (may be default): " + result);
        
        // Continue with other work without blocking
        System.out.println("Processing continues...");
    }
}
// {/fact}