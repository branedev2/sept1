import java.util.concurrent.*;
import java.io.*;
import java.util.*;
import java.net.*;
import java.nio.file.*;

public class ExecutorServiceShutdownTest {

    // True Positive Examples (Vulnerable Code)

// {fact rule=resource-leak@v1.0 defects=1}
    public void bad_case_1() {
        ExecutorService executor = Executors.newFixedThreadPool(5);
        try {
            // Some operations that might throw exceptions
            File file = new File("nonexistent.txt");
            FileInputStream fis = new FileInputStream(file);
            
            // ruleid: java-improper-shutdown-of-executor-service
            executor.shutdown();
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            // Missing executor shutdown in catch block
        }
    }

    public void bad_case_2() {
        ExecutorService executor = Executors.newCachedThreadPool();
        
        try {
            // Operations that might throw exceptions
            URL url = new URL("https://example.com");
            URLConnection conn = url.openConnection();
            conn.connect();
            
            // ruleid: java-improper-shutdown-of-executor-service
            executor.shutdown();
        } catch (IOException e) {
            e.printStackTrace();
            // No executor shutdown in exception handler
        }
    }

    public void bad_case_3() {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        
        // Operations that might throw exceptions
        Map<String, Object> map = new HashMap<>();
        try {
            Object value = map.get("nonexistentKey");
            int result = (Integer) value; // Potential NullPointerException or ClassCastException
            
            // ruleid: java-improper-shutdown-of-executor-service
            executor.shutdown();
        } catch (ClassCastException e) {
            System.err.println("Cast error: " + e.getMessage());
            // Missing executor shutdown
        }
    }

    public void bad_case_4() {
        ExecutorService executor = Executors.newWorkStealingPool();
        
        try {
            String str = null;
            int length = str.length(); // Will throw NullPointerException
            
            // ruleid: java-improper-shutdown-of-executor-service
            executor.shutdown();
        } catch (NullPointerException e) {
            System.err.println("Null error: " + e.getMessage());
            // Missing executor shutdown in exception handler
        }
    }

    public void bad_case_5() {
        ExecutorService executor = Executors.newFixedThreadPool(10);
        
        try {
            // Operations that might throw exceptions
            String[] array = new String[2];
            String item = array[5]; // Will throw ArrayIndexOutOfBoundsException
            
            // ruleid: java-improper-shutdown-of-executor-service
            executor.shutdown();
        } catch (Exception e) {
            throw new RuntimeException("Error occurred", e);
            // No executor shutdown before re-throwing
        }
    }

    public void bad_case_6() {
        ExecutorService executor = Executors.newCachedThreadPool();
        
        try {
            // Operations with potential exceptions
            Path path = Paths.get("/nonexistent/directory/file.txt");
            List<String> lines = Files.readAllLines(path); // May throw IOException
            
            // ruleid: java-improper-shutdown-of-executor-service
            executor.shutdownNow();
        } catch (IOException e) {
            System.err.println("IO error: " + e.getMessage());
            // Missing executor shutdown
        }
    }

    public void bad_case_7() {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        
        try {
            // Operations that might throw exceptions
            String numberStr = "abc";
            int number = Integer.parseInt(numberStr); // Will throw NumberFormatException
            
            // ruleid: java-improper-shutdown-of-executor-service
            executor.shutdown();
        } catch (NumberFormatException e) {
            System.err.println("Parse error: " + e.getMessage());
            // No executor shutdown in catch block
        }
    }

    public void bad_case_8() {
        ExecutorService executor = Executors.newFixedThreadPool(3);
        
        try {
            // Multiple operations that might throw exceptions
            Socket socket = new Socket("nonexistent.host", 8080); // May throw UnknownHostException
            InputStream is = socket.getInputStream();
            
            // ruleid: java-improper-shutdown-of-executor-service
            executor.shutdown();
        } catch (UnknownHostException e) {
            System.err.println("Host not found: " + e.getMessage());
            // Missing executor shutdown
        } catch (IOException e) {
            System.err.println("IO error: " + e.getMessage());
            // Missing executor shutdown
        }
    }

    public void bad_case_9() {
        ExecutorService executor = Executors.newWorkStealingPool(4);
        
        try {
            // Operations with checked exceptions
            Class<?> clazz = Class.forName("nonexistent.Class"); // May throw ClassNotFoundException
            
            // ruleid: java-improper-shutdown-of-executor-service
            executor.shutdown();
        } catch (ClassNotFoundException e) {
            System.err.println("Class not found: " + e.getMessage());
            // No executor shutdown in exception handler
        }
    }

    public void bad_case_10() {
        ExecutorService executor = Executors.newFixedThreadPool(2);
        
        try {
            // Operations with potential exceptions
            Thread.sleep(1000); // May throw InterruptedException
            
            // ruleid: java-improper-shutdown-of-executor-service
            executor.shutdown();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("Thread interrupted");
            // Missing executor shutdown
        }
    }

    public void bad_case_11() {
        ExecutorService executor = Executors.newCachedThreadPool();
        
        try {
            // Complex operations with multiple potential exceptions
            Properties props = new Properties();
            props.load(new FileInputStream("config.properties")); // May throw IOException
            
            // ruleid: java-improper-shutdown-of-executor-service
            executor.shutdown();
        } catch (IOException e) {
            System.err.println("Failed to load properties: " + e.getMessage());
            // No executor shutdown in catch block
        }
    }

    public void bad_case_12() {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        
        try {
            // Operations with potential exceptions
            ServerSocket serverSocket = new ServerSocket(8080); // May throw IOException
            Socket clientSocket = serverSocket.accept();
            
            // ruleid: java-improper-shutdown-of-executor-service
            executor.shutdown();
        } catch (IOException e) {
            System.err.println("Server error: " + e.getMessage());
            // Missing executor shutdown
        }
    }

    public void bad_case_13() {
        ScheduledExecutorService executor = Executors.newScheduledThreadPool(5);
        
        try {
            // Operations with potential exceptions
            URL url = new URL("https://example.com/api");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            int responseCode = conn.getResponseCode(); // May throw IOException
            
            // ruleid: java-improper-shutdown-of-executor-service
            executor.shutdown();
        } catch (IOException e) {
            System.err.println("HTTP error: " + e.getMessage());
            // No executor shutdown in exception handler
        }
    }

    public void bad_case_14() {
        ExecutorService executor = Executors.newFixedThreadPool(4);
        
        try {
            // Operations with potential exceptions
            String json = "{invalid json}";
            // Assume this is a JSON parsing operation that might throw an exception
            if (json.contains("invalid")) {
                throw new IllegalArgumentException("Invalid JSON format");
            }
            
            // ruleid: java-improper-shutdown-of-executor-service
            executor.shutdown();
        } catch (IllegalArgumentException e) {
            System.err.println("JSON parsing error: " + e.getMessage());
            // Missing executor shutdown
        }
    }

    public void bad_case_15() {
        ExecutorService executor = Executors.newCachedThreadPool();
        
        try {
            // Operations with potential exceptions
            List<String> list = new ArrayList<>();
            list.add("item");
            String item = list.get(5); // Will throw IndexOutOfBoundsException
            
            // ruleid: java-improper-shutdown-of-executor-service
            executor.shutdown();
        } catch (IndexOutOfBoundsException e) {
            System.err.println("Index error: " + e.getMessage());
            // No executor shutdown in catch block
        }
    }

    // True Negative Examples (Safe Code)

    public void good_case_1() {
        ExecutorService executor = Executors.newFixedThreadPool(5);
        try {
            // Some operations that might throw exceptions
            File file = new File("nonexistent.txt");
            FileInputStream fis = new FileInputStream(file);
            
            // ok: java-improper-shutdown-of-executor-service
            executor.shutdown();
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            // Properly shutting down in catch block
            // ok: java-improper-shutdown-of-executor-service
            executor.shutdown();
        }
    }

    public void good_case_2() {
        ExecutorService executor = Executors.newCachedThreadPool();
        
        try {
            // Operations that might throw exceptions
            URL url = new URL("https://example.com");
            URLConnection conn = url.openConnection();
            conn.connect();
            
            // ok: java-improper-shutdown-of-executor-service
            executor.shutdown();
        } catch (IOException e) {
            e.printStackTrace();
            // Properly shutting down in exception handler
            // ok: java-improper-shutdown-of-executor-service
            executor.shutdown();
        }
    }

    public void good_case_3() {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        
        try {
            // Operations that might throw exceptions
            Map<String, Object> map = new HashMap<>();
            Object value = map.get("nonexistentKey");
            int result = (Integer) value; // Potential NullPointerException or ClassCastException
            
            executor.shutdown();
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        } finally {
            // Properly shutting down in finally block
            // ok: java-improper-shutdown-of-executor-service
            if (!executor.isShutdown()) {
                executor.shutdown();
            }
        }
    }

    public void good_case_4() {
        ExecutorService executor = Executors.newWorkStealingPool();
        
        try {
            String str = null;
            int length = str.length(); // Will throw NullPointerException
            
            executor.shutdown();
        } catch (NullPointerException e) {
            System.err.println("Null error: " + e.getMessage());
        } finally {
            // Using shutdownNow in finally block
            // ok: java-improper-shutdown-of-executor-service
            executor.shutdownNow();
        }
    }

    public void good_case_5() {
        ExecutorService executor = Executors.newFixedThreadPool(10);
        
        try {
            // Operations that might throw exceptions
            String[] array = new String[2];
            String item = array[5]; // Will throw ArrayIndexOutOfBoundsException
            
            executor.shutdown();
        } catch (Exception e) {
            // Properly shutting down before re-throwing
            // ok: java-improper-shutdown-of-executor-service
            executor.shutdownNow();
            throw new RuntimeException("Error occurred", e);
        }
    }

    public void good_case_6() {
        ExecutorService executor = null;
        try {
            executor = Executors.newCachedThreadPool();
            
            // Operations with potential exceptions
            Path path = Paths.get("/nonexistent/directory/file.txt");
            List<String> lines = Files.readAllLines(path); // May throw IOException
            
            executor.shutdownNow();
        } catch (IOException e) {
            System.err.println("IO error: " + e.getMessage());
        } finally {
            // Null check before shutdown in finally block
            // ok: java-improper-shutdown-of-executor-service
            if (executor != null && !executor.isShutdown()) {
                executor.shutdownNow();
            }
        }
    }

    public void good_case_7() {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        boolean shutdownSuccessful = false;
        
        try {
            // Operations that might throw exceptions
            String numberStr = "abc";
            int number = Integer.parseInt(numberStr); // Will throw NumberFormatException
            
            executor.shutdown();
            shutdownSuccessful = true;
        } catch (NumberFormatException e) {
            System.err.println("Parse error: " + e.getMessage());
        } finally {
            // Using a flag to track shutdown status
            // ok: java-improper-shutdown-of-executor-service
            if (!shutdownSuccessful) {
                executor.shutdown();
            }
        }
    }

    public void good_case_8() {
        ExecutorService executor = Executors.newFixedThreadPool(3);
        
        try {
            // Multiple operations that might throw exceptions
            Socket socket = new Socket("nonexistent.host", 8080); // May throw UnknownHostException
            InputStream is = socket.getInputStream();
            
            executor.shutdown();
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            // Properly shutting down in generic catch
            // ok: java-improper-shutdown-of-executor-service
            executor.shutdown();
        }
    }

    public void good_case_9() {
        ExecutorService executor = Executors.newWorkStealingPool(4);
        
        try {
            // Operations with checked exceptions
            Class<?> clazz = Class.forName("nonexistent.Class"); // May throw ClassNotFoundException
            
            executor.shutdown();
        } catch (ClassNotFoundException e) {
            System.err.println("Class not found: " + e.getMessage());
            // Using awaitTermination after shutdown
            // ok: java-improper-shutdown-of-executor-service
            executor.shutdown();
            try {
                executor.awaitTermination(5, TimeUnit.SECONDS);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
        }
    }

    public void good_case_10() {
        ExecutorService executor = Executors.newFixedThreadPool(2);
        
        try {
            // Operations with potential exceptions
            Thread.sleep(1000); // May throw InterruptedException
            
            executor.shutdown();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("Thread interrupted");
            // Properly handling shutdown with interrupted status
            // ok: java-improper-shutdown-of-executor-service
            executor.shutdownNow();
        }
    }

    public void good_case_11() {
        ExecutorService executor = Executors.newCachedThreadPool();
        
        try (FileInputStream fis = new FileInputStream("config.properties")) {
            // Using try-with-resources for the file operation
            Properties props = new Properties();
            props.load(fis);
            
            // ok: java-improper-shutdown-of-executor-service
            executor.shutdown();
        } catch (IOException e) {
            System.err.println("Failed to load properties: " + e.getMessage());
            // Properly shutting down in catch block
            // ok: java-improper-shutdown-of-executor-service
            executor.shutdown();
        }
    }

    public void good_case_12() {
        ExecutorService executor = Executors.newSingleThreadExecutor();
        ServerSocket serverSocket = null;
        
        try {
            // Operations with potential exceptions
            serverSocket = new ServerSocket(8080); // May throw IOException
            Socket clientSocket = serverSocket.accept();
            
            executor.shutdown();
        } catch (IOException e) {
            System.err.println("Server error: " + e.getMessage());
            // Properly shutting down in catch block
            // ok: java-improper-shutdown-of-executor-service
            executor.shutdown();
        } finally {
            // Closing resources in finally block
            if (serverSocket != null && !serverSocket.isClosed()) {
                try {
                    serverSocket.close();
                } catch (IOException e) {
                    // Ignore
                }
            }
        }
    }

    public void good_case_13() {
        ScheduledExecutorService executor = Executors.newScheduledThreadPool(5);
        
        try {
            // Operations with potential exceptions
            URL url = new URL("https://example.com/api");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            int responseCode = conn.getResponseCode(); // May throw IOException
            
            executor.shutdown();
        } catch (IOException e) {
            System.err.println("HTTP error: " + e.getMessage());
        } finally {
            // Using shutdownNow and awaitTermination in finally block
            // ok: java-improper-shutdown-of-executor-service
            if (!executor.isShutdown()) {
                executor.shutdownNow();
                try {
                    executor.awaitTermination(10, TimeUnit.SECONDS);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    public void good_case_14() {
        ExecutorService executor = Executors.newFixedThreadPool(4);
        
        try {
            // Operations with potential exceptions
            String json = "{invalid json}";
            // Assume this is a JSON parsing operation that might throw an exception
            if (json.contains("invalid")) {
                throw new IllegalArgumentException("Invalid JSON format");
            }
            
            // ok: java-improper-shutdown-of-executor-service
            executor.shutdown();
        } catch (IllegalArgumentException e) {
            System.err.println("JSON parsing error: " + e.getMessage());
            // Properly shutting down with timeout
            // ok: java-improper-shutdown-of-executor-service
            executor.shutdown();
            try {
                if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException ie) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }

    public void good_case_15() {
        // Using try-with-resources with a custom AutoCloseable wrapper
        try (ExecutorServiceWrapper executor = new ExecutorServiceWrapper(Executors.newCachedThreadPool())) {
            // Operations with potential exceptions
            List<String> list = new ArrayList<>();
            list.add("item");
            String item = list.get(5); // Will throw IndexOutOfBoundsException
            
            // No need for explicit shutdown due to try-with-resources
        } catch (IndexOutOfBoundsException e) {
            System.err.println("Index error: " + e.getMessage());
            // AutoCloseable will handle shutdown
        }
    }
    
    // Helper class for good_case_15
    private static class ExecutorServiceWrapper implements AutoCloseable {
        private final ExecutorService executorService;
        
        public ExecutorServiceWrapper(ExecutorService executorService) {
            this.executorService = executorService;
        }
        
        @Override
        public void close() {
            // ok: java-improper-shutdown-of-executor-service
            if (executorService != null && !executorService.isShutdown()) {
                executorService.shutdown();
            }
        }
        
        public ExecutorService getExecutorService() {
            return executorService;
        }
    }
}
// {/fact}