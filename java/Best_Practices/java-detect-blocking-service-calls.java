import java.util.concurrent.*;
import java.util.List;
import java.util.ArrayList;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.sql.*;
import java.util.stream.*;
import java.util.function.*;
import java.util.concurrent.atomic.*;
import java.time.Duration;
import javax.sql.DataSource;
import java.util.Properties;
import java.util.concurrent.locks.*;
import java.util.Random;
import java.nio.channels.*;
import java.util.concurrent.Flow.*;
import java.util.concurrent.CompletableFuture;
import org.reactivestreams.*;

public class BlockingServiceCallsExamples {

    // True Positives (Vulnerable Code)

// {fact rule=guru-cfn-lint@v1.0 defects=1}
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
        ExecutorService executor = Executors.newFixedThreadPool(10);
        executor.submit(() -> {
            try {
                // ruleid: java-detect-blocking-service-calls
                URL url = new URL("https://api.example.com/data");
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod("GET");
                
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(connection.getInputStream()));
                String line;
                StringBuilder response = new StringBuilder();
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();
                
                System.out.println(response.toString());
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

    public void bad_case_3() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try {
                // ruleid: java-detect-blocking-service-calls
                Connection conn = DriverManager.getConnection(
                    "jdbc:mysql://localhost:3306/mydb", "user", "password");
                Statement stmt = conn.createStatement();
                ResultSet rs = stmt.executeQuery("SELECT * FROM users");
                
                StringBuilder result = new StringBuilder();
                while (rs.next()) {
                    result.append(rs.getString("name")).append("\n");
                }
                
                rs.close();
                stmt.close();
                conn.close();
                
                return result.toString();
            } catch (SQLException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public void bad_case_4() {
        Executor executor = Executors.newSingleThreadExecutor();
        executor.execute(() -> {
            try {
                // ruleid: java-detect-blocking-service-calls
                File file = new File("large_file.txt");
                BufferedReader reader = new BufferedReader(new FileReader(file));
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                }
                reader.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
    }

    public void bad_case_5() {
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        scheduler.scheduleAtFixedRate(() -> {
            // ruleid: java-detect-blocking-service-calls
            try {
                Socket socket = new Socket("example.com", 80);
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));
                
                out.println("GET / HTTP/1.1");
                out.println("Host: example.com");
                out.println("Connection: close");
                out.println();
                
                String response;
                while ((response = in.readLine()) != null) {
                    System.out.println(response);
                }
                
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }, 0, 60, TimeUnit.SECONDS);
    }

    public void bad_case_6() {
        CompletableFuture.supplyAsync(() -> {
            try {
                // ruleid: java-detect-blocking-service-calls
                Process process = Runtime.getRuntime().exec("ping -c 4 google.com");
                process.waitFor(); // Blocking call
                
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                String line;
                StringBuilder output = new StringBuilder();
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                
                return output.toString();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    public void bad_case_7() {
        ExecutorService executor = Executors.newCachedThreadPool();
        executor.submit(() -> {
            // ruleid: java-detect-blocking-service-calls
            Lock lock = new ReentrantLock();
            lock.lock();
            try {
                // Simulate some work that takes time
                Thread.sleep(3000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            } finally {
                lock.unlock();
            }
        });
    }

    public void bad_case_8() {
        CompletableFuture<List<String>> future = CompletableFuture.supplyAsync(() -> {
            try {
                // ruleid: java-detect-blocking-service-calls
                List<String> results = new ArrayList<>();
                Files.lines(Paths.get("huge_log_file.txt"))
                    .filter(line -> line.contains("ERROR"))
                    .forEach(results::add);
                return results;
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public void bad_case_9() {
        Runnable task = () -> {
            CountDownLatch latch = new CountDownLatch(1);
            new Thread(() -> {
                try {
                    Thread.sleep(5000);
                    latch.countDown();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }).start();
            
            try {
                // ruleid: java-detect-blocking-service-calls
                latch.await(); // Blocking call
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        };
        
        CompletableFuture.runAsync(task);
    }

    public void bad_case_10() {
        CompletableFuture<byte[]> future = CompletableFuture.supplyAsync(() -> {
            try {
                // ruleid: java-detect-blocking-service-calls
                URL url = new URL("https://example.com/large-file.zip");
                URLConnection connection = url.openConnection();
                InputStream in = connection.getInputStream();
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
                in.close();
                return out.toByteArray();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public void bad_case_11() {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        executor.execute(() -> {
            // ruleid: java-detect-blocking-service-calls
            try {
                ServerSocket serverSocket = new ServerSocket(8080);
                Socket clientSocket = serverSocket.accept(); // Blocking call
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
                out.println("Hello from server!");
                clientSocket.close();
                serverSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
    }

    public void bad_case_12() {
        CompletableFuture<Integer> future = CompletableFuture.supplyAsync(() -> {
            // ruleid: java-detect-blocking-service-calls
            Semaphore semaphore = new Semaphore(1);
            try {
                semaphore.acquire(); // Blocking call
                int result = performExpensiveCalculation();
                semaphore.release();
                return result;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException(e);
            }
        });
    }
    
    private int performExpensiveCalculation() {
        // Simulate expensive calculation
        return 42;
    }

    public void bad_case_13() {
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            // ruleid: java-detect-blocking-service-calls
            try {
                DatagramSocket socket = new DatagramSocket();
                byte[] buffer = new byte[1024];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet); // Blocking call
                String received = new String(packet.getData(), 0, packet.getLength());
                socket.close();
                return received;
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public void bad_case_14() {
        CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
            // ruleid: java-detect-blocking-service-calls
            try {
                RandomAccessFile file = new RandomAccessFile("data.bin", "rw");
                FileChannel channel = file.getChannel();
                FileLock lock = channel.lock(); // Blocking call
                
                // Perform file operations
                ByteBuffer buffer = ByteBuffer.allocate(1024);
                buffer.put("Hello, World!".getBytes());
                buffer.flip();
                channel.write(buffer);
                
                lock.release();
                channel.close();
                file.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public void bad_case_15() {
        CompletableFuture<Double> future = CompletableFuture.supplyAsync(() -> {
            // ruleid: java-detect-blocking-service-calls
            try {
                // Simulate a blocking third-party API call
                return callBlockingExternalService();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }
    
    private double callBlockingExternalService() throws Exception {
        // Simulate a blocking external service call
        Thread.sleep(3000);
        return new Random().nextDouble();
    }

    // True Negatives (Safe Code)

    public void good_case_1() {
        // ok: java-detect-blocking-service-calls
        CompletableFuture.runAsync(() -> {
            System.out.println("Non-blocking operation in CompletableFuture");
        });
    }

    public void good_case_2() {
        ExecutorService executor = Executors.newFixedThreadPool(10);
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try {
                URL url = new URL("https://api.example.com/data");
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod("GET");
                
                // ok: java-detect-blocking-service-calls
                // Offload the blocking I/O to a dedicated executor
                return CompletableFuture.supplyAsync(() -> {
                    try {
                        BufferedReader reader = new BufferedReader(
                            new InputStreamReader(connection.getInputStream()));
                        String line;
                        StringBuilder response = new StringBuilder();
                        while ((line = reader.readLine()) != null) {
                            response.append(line);
                        }
                        reader.close();
                        return response.toString();
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }, Executors.newCachedThreadPool()).join();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }, executor);
    }

    public void good_case_3() {
        // ok: java-detect-blocking-service-calls
        // Using a dedicated thread pool for blocking database operations
        ExecutorService blockingTasksPool = Executors.newFixedThreadPool(20);
        
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            // Non-blocking part of the task
            String query = "SELECT * FROM users";
            
            // Delegate the blocking operation to a dedicated thread pool
            return CompletableFuture.supplyAsync(() -> {
                try {
                    Connection conn = DriverManager.getConnection(
                        "jdbc:mysql://localhost:3306/mydb", "user", "password");
                    Statement stmt = conn.createStatement();
                    ResultSet rs = stmt.executeQuery(query);
                    
                    StringBuilder result = new StringBuilder();
                    while (rs.next()) {
                        result.append(rs.getString("name")).append("\n");
                    }
                    
                    rs.close();
                    stmt.close();
                    conn.close();
                    
                    return result.toString();
                } catch (SQLException e) {
                    throw new RuntimeException(e);
                }
            }, blockingTasksPool).join();
        });
    }

    public void good_case_4() {
        Executor asyncExecutor = Executors.newSingleThreadExecutor();
        // ok: java-detect-blocking-service-calls
        // Using a separate thread pool for file operations
        ExecutorService fileIOExecutor = Executors.newFixedThreadPool(5);
        
        CompletableFuture<List<String>> future = CompletableFuture.supplyAsync(() -> {
            // Delegate the blocking file I/O to a dedicated executor
            return CompletableFuture.supplyAsync(() -> {
                try {
                    List<String> lines = new ArrayList<>();
                    File file = new File("large_file.txt");
                    BufferedReader reader = new BufferedReader(new FileReader(file));
                    String line;
                    while ((line = reader.readLine()) != null) {
                        lines.add(line);
                    }
                    reader.close();
                    return lines;
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }, fileIOExecutor).join();
        }, asyncExecutor);
    }

    public void good_case_5() {
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        // ok: java-detect-blocking-service-calls
        // Using a dedicated executor for network operations
        ExecutorService networkExecutor = Executors.newCachedThreadPool();
        
        scheduler.scheduleAtFixedRate(() -> {
            // Delegate the blocking network operation to a dedicated executor
            CompletableFuture.runAsync(() -> {
                try {
                    Socket socket = new Socket("example.com", 80);
                    PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                    BufferedReader in = new BufferedReader(
                        new InputStreamReader(socket.getInputStream()));
                    
                    out.println("GET / HTTP/1.1");
                    out.println("Host: example.com");
                    out.println("Connection: close");
                    out.println();
                    
                    String response;
                    while ((response = in.readLine()) != null) {
                        System.out.println(response);
                    }
                    
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }, networkExecutor);
        }, 0, 60, TimeUnit.SECONDS);
    }

    public void good_case_6() {
        // ok: java-detect-blocking-service-calls
        // Using a dedicated executor for process execution
        ExecutorService processExecutor = Executors.newFixedThreadPool(2);
        
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            // Delegate the blocking process execution to a dedicated executor
            return CompletableFuture.supplyAsync(() -> {
                try {
                    Process process = Runtime.getRuntime().exec("ping -c 4 google.com");
                    process.waitFor();
                    
                    BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream()));
                    String line;
                    StringBuilder output = new StringBuilder();
                    while ((line = reader.readLine()) != null) {
                        output.append(line).append("\n");
                    }
                    
                    return output.toString();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }, processExecutor).join();
        });
    }

    public void good_case_7() {
        ExecutorService executor = Executors.newCachedThreadPool();
        // ok: java-detect-blocking-service-calls
        // Using a non-blocking approach with CompletableFuture
        CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
            // Non-blocking operations
            System.out.println("Preparing task");
        }, executor).thenRunAsync(() -> {
            // Offload potentially blocking operations to a separate thread pool
            Lock lock = new ReentrantLock();
            lock.lock();
            try {
                // Simulate some work
                System.out.println("Working with locked resource");
            } finally {
                lock.unlock();
            }
        }, Executors.newFixedThreadPool(4));
    }

    public void good_case_8() {
        // ok: java-detect-blocking-service-calls
        // Using a non-blocking approach with parallel streams
        CompletableFuture<List<String>> future = CompletableFuture.supplyAsync(() -> {
            try {
                // Use parallel stream for better performance with large files
                return Files.lines(Paths.get("huge_log_file.txt"))
                    .parallel()
                    .filter(line -> line.contains("ERROR"))
                    .collect(Collectors.toList());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }, Executors.newWorkStealingPool()); // Using work stealing pool for parallel tasks
    }

    public void good_case_9() {
        // ok: java-detect-blocking-service-calls
        // Using a non-blocking approach with CompletableFuture composition
        CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
            System.out.println("Starting task");
        }).thenRunAsync(() -> {
            // Simulate some work
            System.out.println("Processing");
        }).thenRunAsync(() -> {
            System.out.println("Task completed");
        });
    }

    public void good_case_10() {
        // ok: java-detect-blocking-service-calls
        // Using a dedicated executor for downloading large files
        ExecutorService downloadExecutor = Executors.newFixedThreadPool(3);
        
        CompletableFuture<byte[]> future = CompletableFuture.supplyAsync(() -> {
            // Prepare for download
            String url = "https://example.com/large-file.zip";
            
            // Delegate the blocking download to a dedicated executor
            return CompletableFuture.supplyAsync(() -> {
                try {
                    URL fileUrl = new URL(url);
                    URLConnection connection = fileUrl.openConnection();
                    InputStream in = connection.getInputStream();
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = in.read(buffer)) != -1) {
                        out.write(buffer, 0, bytesRead);
                    }
                    in.close();
                    return out.toByteArray();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }, downloadExecutor).join();
        });
    }

    public void good_case_11() {
        // ok: java-detect-blocking-service-calls
        // Using a dedicated thread for server socket operations
        ExecutorService serverExecutor = Executors.newSingleThreadExecutor();
        
        CompletableFuture.runAsync(() -> {
            // Start the server in a dedicated thread
            serverExecutor.execute(() -> {
                try {
                    ServerSocket serverSocket = new ServerSocket(8080);
                    while (!Thread.currentThread().isInterrupted()) {
                        Socket clientSocket = serverSocket.accept();
                        // Handle each client in a separate thread
                        new Thread(() -> {
                            try {
                                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
                                out.println("Hello from server!");
                                clientSocket.close();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }).start();
                    }
                    serverSocket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });
            
            // Continue with non-blocking operations
            System.out.println("Server started in background");
        });
    }

    public void good_case_12() {
        // ok: java-detect-blocking-service-calls
        // Using a non-blocking approach with tryAcquire
        CompletableFuture<Integer> future = CompletableFuture.supplyAsync(() -> {
            Semaphore semaphore = new Semaphore(1);
            // Non-blocking attempt to acquire the semaphore
            if (semaphore.tryAcquire()) {
                try {
                    int result = performFastCalculation();
                    return result;
                } finally {
                    semaphore.release();
                }
            } else {
                // Handle the case when semaphore is not available
                return -1;
            }
        });
    }
    
    private int performFastCalculation() {
        // Fast calculation that doesn't block
        return 42;
    }

    public void good_case_13() {
        // ok: java-detect-blocking-service-calls
        // Using non-blocking NIO for socket operations
        CompletableFuture<String> future = CompletableFuture.supplyAsync(() -> {
            try {
                // Use NIO for non-blocking socket operations
                DatagramChannel channel = DatagramChannel.open();
                channel.configureBlocking(false);
                channel.socket().bind(new InetSocketAddress(8090));
                
                ByteBuffer buffer = ByteBuffer.allocate(1024);
                String result = "No data received";
                
                // Non-blocking receive attempt
                SocketAddress address = channel.receive(buffer);
                if (address != null) {
                    buffer.flip();
                    byte[] bytes = new byte[buffer.remaining()];
                    buffer.get(bytes);
                    result = new String(bytes);
                }
                
                channel.close();
                return result;
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public void good_case_14() {
        // ok: java-detect-blocking-service-calls
        // Using non-blocking file operations with NIO
        CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
            try {
                // Use NIO for non-blocking file operations
                FileChannel channel = FileChannel.open(
                    Paths.get("data.bin"), 
                    StandardOpenOption.CREATE, 
                    StandardOpenOption.WRITE
                );
                
                // Try to get a non-blocking lock
                FileLock lock = channel.tryLock();
                if (lock != null) {
                    try {
                        ByteBuffer buffer = ByteBuffer.allocate(1024);
                        buffer.put("Hello, World!".getBytes());
                        buffer.flip();
                        channel.write(buffer);
                    } finally {
                        lock.release();
                    }
                } else {
                    System.out.println("Could not acquire lock, file is in use");
                }
                
                channel.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    public void good_case_15() {
        // ok: java-detect-blocking-service-calls
        // Using a dedicated executor for external service calls
        ExecutorService externalServiceExecutor = Executors.newFixedThreadPool(10);
        
        CompletableFuture<Double> future = CompletableFuture.supplyAsync(() -> {
            // Delegate the blocking external service call to a dedicated executor
            return CompletableFuture.supplyAsync(() -> {
                try {
                    // Simulate a blocking third-party API call
                    Thread.sleep(3000);
                    return new Random().nextDouble();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }, externalServiceExecutor).join();
        });
    }
}
// {/fact}