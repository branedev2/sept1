import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ForkJoinPool;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Optional;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import io.reactivex.Observable;
import io.reactivex.schedulers.Schedulers as RxSchedulers;

public class BlockingServiceCallsExamples {

    // True Positive Examples (Vulnerable Code)
    
// {fact rule=misconfigured-concurrency@v1.0 defects=1}
    public void bad_case_1() {
        CompletableFuture.runAsync(() -> {
            try {
                // ruleid: java-detect-blocking-service-calls
                Thread.sleep(5000); // Blocking call in CompletableFuture
                System.out.println("Operation completed");
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        });
    }
    
    public void bad_case_2() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try {
                URL url = new URL("https://api.example.com/data");
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod("GET");
                
                // ruleid: java-detect-blocking-service-calls
                int responseCode = connection.getResponseCode(); // Blocking I/O in CompletableFuture
                
                return "Response code: " + responseCode;
            } catch (IOException e) {
                return "Error: " + e.getMessage();
            }
        });
    }
    
    public void bad_case_3() {
        Mono.fromCallable(() -> {
            try {
                // ruleid: java-detect-blocking-service-calls
                return Files.readAllLines(Paths.get("/path/to/large/file.txt")); // Blocking file I/O in reactive stream
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }).subscribe(lines -> System.out.println("Read " + lines.size() + " lines"));
    }
    
    public void bad_case_4() {
        Observable.fromCallable(() -> {
            try {
                Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/db", "user", "password");
                Statement stmt = conn.createStatement();
                // ruleid: java-detect-blocking-service-calls
                ResultSet rs = stmt.executeQuery("SELECT * FROM large_table"); // Blocking JDBC call in RxJava
                
                List<String> results = new ArrayList<>();
                while (rs.next()) {
                    results.add(rs.getString("column_name"));
                }
                return results;
            } catch (SQLException e) {
                throw new RuntimeException(e);
            }
        }).subscribe(results -> System.out.println("Found " + results.size() + " records"));
    }
    
    public void bad_case_5() {
        CompletableFuture<Integer> future = CompletableFuture.supplyAsync(() -> {
            try {
                // ruleid: java-detect-blocking-service-calls
                Future<Integer> blockingFuture = Executors.newSingleThreadExecutor().submit(() -> 42);
                return blockingFuture.get(); // Blocking get() call inside CompletableFuture
            } catch (InterruptedException | ExecutionException e) {
                return -1;
            }
        });
    }
    
    public void bad_case_6() {
        Mono.just("data")
            .flatMap(data -> {
                // ruleid: java-detect-blocking-service-calls
                CountDownLatch latch = new CountDownLatch(1);
                try {
                    latch.await(5, TimeUnit.SECONDS); // Blocking latch in reactive stream
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                return Mono.just("Processed: " + data);
            })
            .subscribe(System.out::println);
    }
    
    public void bad_case_7() {
        CompletableFuture.supplyAsync(() -> {
            // ruleid: java-detect-blocking-service-calls
            try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/db", "user", "password")) {
                // Blocking JDBC connection in CompletableFuture
                Statement stmt = conn.createStatement();
                stmt.execute("UPDATE users SET status = 'active'");
                return "Database updated";
            } catch (SQLException e) {
                return "Error: " + e.getMessage();
            }
        });
    }
    
    public void bad_case_8() {
        Mono.fromCallable(() -> {
            Process process;
            try {
                process = Runtime.getRuntime().exec("ls -la");
                // ruleid: java-detect-blocking-service-calls
                int exitCode = process.waitFor(); // Blocking process wait in reactive context
                return "Process completed with exit code: " + exitCode;
            } catch (IOException | InterruptedException e) {
                return "Error: " + e.getMessage();
            }
        }).subscribe(System.out::println);
    }
    
    public void bad_case_9() {
        CompletableFuture.runAsync(() -> {
            // ruleid: java-detect-blocking-service-calls
            Object lock = new Object();
            synchronized (lock) {
                try {
                    lock.wait(3000); // Blocking wait in CompletableFuture
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });
    }
    
    public void bad_case_10() {
        ForkJoinPool.commonPool().submit(() -> {
            // ruleid: java-detect-blocking-service-calls
            try {
                URL url = new URL("https://api.example.com/data");
                String response = new String(url.openStream().readAllBytes()); // Blocking I/O in ForkJoinPool
                System.out.println("Response length: " + response.length());
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
    }
    
    public void bad_case_11() {
        Observable.just(1, 2, 3, 4, 5)
            .map(i -> {
                // ruleid: java-detect-blocking-service-calls
                try {
                    Thread.sleep(100); // Blocking sleep in RxJava stream
                    return i * 2;
                } catch (InterruptedException e) {
                    return -1;
                }
            })
            .subscribe(System.out::println);
    }
    
    public void bad_case_12() {
        CompletableFuture.supplyAsync(() -> {
            AtomicInteger result = new AtomicInteger(0);
            CountDownLatch latch = new CountDownLatch(5);
            
            for (int i = 0; i < 5; i++) {
                new Thread(() -> {
                    result.incrementAndGet();
                    latch.countDown();
                }).start();
            }
            
            try {
                // ruleid: java-detect-blocking-service-calls
                latch.await(); // Blocking latch in CompletableFuture
                return result.get();
            } catch (InterruptedException e) {
                return -1;
            }
        });
    }
    
    public void bad_case_13() {
        Mono.fromCallable(() -> {
            // ruleid: java-detect-blocking-service-calls
            List<String> result = IntStream.range(0, 1000)
                .parallel()
                .mapToObj(i -> {
                    try {
                        Thread.sleep(1); // Blocking call in parallel stream used in reactive context
                        return "Item " + i;
                    } catch (InterruptedException e) {
                        return "Error";
                    }
                })
                .collect(Collectors.toList());
            return result;
        }).subscribe(list -> System.out.println("Processed " + list.size() + " items"));
    }
    
    public void bad_case_14() {
        CompletableFuture<Optional<String>> future = CompletableFuture.supplyAsync(() -> {
            try {
                // ruleid: java-detect-blocking-service-calls
                return Optional.of(Files.readString(Paths.get("/etc/hosts"))); // Blocking file read in CompletableFuture
            } catch (IOException e) {
                return Optional.empty();
            }
        });
    }
    
    public void bad_case_15() {
        Mono.just("data")
            .flatMap(data -> {
                try {
                    // ruleid: java-detect-blocking-service-calls
                    HttpURLConnection connection = (HttpURLConnection) new URL("https://api.example.com/submit").openConnection();
                    connection.setRequestMethod("POST");
                    connection.setDoOutput(true);
                    connection.getOutputStream().write(data.getBytes()); // Blocking I/O in reactive stream
                    int responseCode = connection.getResponseCode();
                    return Mono.just("Response code: " + responseCode);
                } catch (IOException e) {
                    return Mono.error(e);
                }
            })
            .subscribe(System.out::println);
    }
    
    // True Negative Examples (Safe Code)
    
    public void good_case_1() {
        // ok: java-detect-blocking-service-calls
        CompletableFuture.runAsync(() -> {
            System.out.println("Non-blocking operation in CompletableFuture");
        });
    }
    
    public void good_case_2() {
        // ok: java-detect-blocking-service-calls
        CompletableFuture<String> future = CompletableFuture
            .supplyAsync(() -> "Step 1")
            .thenApplyAsync(result -> result + " -> Step 2")
            .thenApplyAsync(result -> result + " -> Step 3");
    }
    
    public void good_case_3() {
        // ok: java-detect-blocking-service-calls
        Mono.fromCallable(() -> "Initial data")
            .subscribeOn(Schedulers.boundedElastic()) // Use dedicated scheduler for potentially blocking calls
            .flatMap(data -> {
                try {
                    return Mono.just(Files.readAllLines(Paths.get("/path/to/file.txt")));
                } catch (IOException e) {
                    return Mono.error(e);
                }
            })
            .subscribe(lines -> System.out.println("Read " + lines.size() + " lines"));
    }
    
    public void good_case_4() {
        // ok: java-detect-blocking-service-calls
        Observable.fromCallable(() -> "data")
            .observeOn(RxSchedulers.io()) // Use IO scheduler for blocking operations
            .flatMap(data -> {
                try {
                    Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/db", "user", "password");
                    Statement stmt = conn.createStatement();
                    ResultSet rs = stmt.executeQuery("SELECT * FROM users");
                    
                    List<String> results = new ArrayList<>();
                    while (rs.next()) {
                        results.add(rs.getString("username"));
                    }
                    return Observable.just(results);
                } catch (SQLException e) {
                    return Observable.error(e);
                }
            })
            .subscribe(results -> System.out.println("Found " + results.size() + " users"));
    }
    
    public void good_case_5() {
        ExecutorService executor = Executors.newFixedThreadPool(4);
        
        // ok: java-detect-blocking-service-calls
        CompletableFuture<Integer> future = CompletableFuture.supplyAsync(() -> {
            return 42; // Non-blocking operation
        }).thenApplyAsync(result -> {
            return result * 2; // Another non-blocking operation
        }, executor);
    }
    
    public void good_case_6() {
        // ok: java-detect-blocking-service-calls
        Mono.just("data")
            .flatMap(data -> {
                return Mono.delay(java.time.Duration.ofSeconds(5)) // Non-blocking delay
                    .map(ignored -> "Processed after delay: " + data);
            })
            .subscribe(System.out::println);
    }
    
    public void good_case_7() {
        // ok: java-detect-blocking-service-calls
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            return "Initial data";
        }).thenComposeAsync(data -> {
            return CompletableFuture.supplyAsync(() -> {
                return "Processed: " + data;
            });
        });
    }
    
    public void good_case_8() {
        // ok: java-detect-blocking-service-calls
        Mono.fromCallable(() -> "command")
            .flatMap(cmd -> {
                Process process;
                try {
                    process = Runtime.getRuntime().exec(cmd);
                    return Mono.fromCallable(() -> process.waitFor())
                        .subscribeOn(Schedulers.boundedElastic()); // Offload blocking call to appropriate scheduler
                } catch (IOException e) {
                    return Mono.error(e);
                }
            })
            .subscribe(exitCode -> System.out.println("Process completed with exit code: " + exitCode));
    }
    
    public void good_case_9() {
        // ok: java-detect-blocking-service-calls
        CompletableFuture<String> future1 = CompletableFuture.supplyAsync(() -> "Result 1");
        CompletableFuture<String> future2 = CompletableFuture.supplyAsync(() -> "Result 2");
        
        CompletableFuture<String> combined = future1.thenCombine(future2, (r1, r2) -> r1 + " and " + r2);
    }
    
    public void good_case_10() {
        // ok: java-detect-blocking-service-calls
        ForkJoinPool.commonPool().submit(() -> {
            CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
                try {
                    URL url = new URL("https://api.example.com/data");
                    return new String(url.openStream().readAllBytes());
                } catch (IOException e) {
                    return "Error: " + e.getMessage();
                }
            });
            
            // Non-blocking handling of the future
            future.thenAccept(response -> System.out.println("Response length: " + response.length()));
        });
    }
    
    public void good_case_11() {
        // ok: java-detect-blocking-service-calls
        Observable.just(1, 2, 3, 4, 5)
            .observeOn(RxSchedulers.computation())
            .map(i -> i * 2)
            .subscribe(System.out::println);
    }
    
    public void good_case_12() {
        // ok: java-detect-blocking-service-calls
        CompletableFuture.supplyAsync(() -> {
            AtomicInteger result = new AtomicInteger(0);
            
            List<CompletableFuture<Void>> futures = new ArrayList<>();
            for (int i = 0; i < 5; i++) {
                futures.add(CompletableFuture.runAsync(() -> result.incrementAndGet()));
            }
            
            // Non-blocking composition of futures
            CompletableFuture<Void> allDone = CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]));
            return allDone.thenApply(v -> result.get());
        });
    }
    
    public void good_case_13() {
        // ok: java-detect-blocking-service-calls
        Mono.fromCallable(() -> IntStream.range(0, 1000).boxed().collect(Collectors.toList()))
            .flatMapIterable(list -> list)
            .parallel()
            .runOn(Schedulers.parallel())
            .map(i -> "Item " + i)
            .sequential()
            .collectList()
            .subscribe(list -> System.out.println("Processed " + list.size() + " items"));
    }
    
    public void good_case_14() {
        // ok: java-detect-blocking-service-calls
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            return "Non-blocking operation";
        }).thenApplyAsync(result -> {
            try {
                return Files.readString(Paths.get("/etc/hosts"));
            } catch (IOException e) {
                return "Error: " + e.getMessage();
            }
        }, Executors.newSingleThreadExecutor()); // Offload blocking I/O to dedicated executor
    }
    
    public void good_case_15() {
        // ok: java-detect-blocking-service-calls
        Mono.just("data")
            .flatMap(data -> {
                return Mono.fromCallable(() -> {
                    HttpURLConnection connection = (HttpURLConnection) new URL("https://api.example.com/submit").openConnection();
                    connection.setRequestMethod("POST");
                    connection.setDoOutput(true);
                    connection.getOutputStream().write(data.getBytes());
                    return connection.getResponseCode();
                }).subscribeOn(Schedulers.boundedElastic()) // Offload blocking I/O to appropriate scheduler
                .map(responseCode -> "Response code: " + responseCode);
            })
            .subscribe(System.out::println);
    }
}
// {/fact}