import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

public class ThreadLocalExamples {
    private static final Logger logger = Logger.getLogger(ThreadLocalExamples.class.getName());

    // True Positive Examples (Bad Cases)

    // Example 1: Basic non-static ThreadLocal
    class BadCase1 {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<String> userContext = new ThreadLocal<>();
        
        public void processRequest(HttpServletRequest request) {
            String userId = request.getParameter("userId");
            userContext.set(userId);
            // Process with user context
            userContext.remove();
        }
    }

    // Example 2: Non-static ThreadLocal with initial value
    class BadCase2 {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<Integer> requestCounter = ThreadLocal.withInitial(() -> 0);
        
        public void countRequests() {
            Integer count = requestCounter.get();
            requestCounter.set(count + 1);
            logger.info("Request count: " + count);
        }
    }

    // Example 3: Multiple non-static ThreadLocals in a class
    class BadCase3 {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<String> sessionId = new ThreadLocal<>();
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<Map<String, Object>> sessionAttributes = new ThreadLocal<>();
        
        public void storeSessionData(String id, Map<String, Object> attributes) {
            sessionId.set(id);
            sessionAttributes.set(attributes);
        }
    }

    // Example 4: Non-static ThreadLocal in a service class
    class BadCase4 {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<Connection> connectionHolder = new ThreadLocal<>();
        
        public Connection getConnection() throws SQLException {
            Connection conn = connectionHolder.get();
            if (conn == null) {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
                connectionHolder.set(conn);
            }
            return conn;
        }
    }

    // Example 5: Non-static ThreadLocal in a utility class
    class BadCase5 {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<Boolean> transactionActive = ThreadLocal.withInitial(() -> false);
        
        public void beginTransaction() {
            transactionActive.set(true);
        }
        
        public void endTransaction() {
            transactionActive.set(false);
        }
    }

    // Example 6: Non-static ThreadLocal with complex object
    class BadCase6 {
        class UserProfile {
            String name;
            String role;
        }
        
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<UserProfile> userProfileContext = new ThreadLocal<>();
        
        public void setUserProfile(String name, String role) {
            UserProfile profile = new UserProfile();
            profile.name = name;
            profile.role = role;
            userProfileContext.set(profile);
        }
    }

    // Example 7: Non-static ThreadLocal in a controller
    class BadCase7 {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<HttpServletRequest> requestContext = new ThreadLocal<>();
        
        public void handleRequest(HttpServletRequest request, HttpServletResponse response) {
            requestContext.set(request);
            // Process request
            requestContext.remove();
        }
    }

    // Example 8: Non-static ThreadLocal with inheritance
    class BadCase8 extends Thread {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<Long> startTime = ThreadLocal.withInitial(System::currentTimeMillis);
        
        @Override
        public void run() {
            logger.info("Thread started at: " + startTime.get());
            // Do work
            logger.info("Thread execution time: " + (System.currentTimeMillis() - startTime.get()));
        }
    }

    // Example 9: Non-static ThreadLocal in an inner class
    class BadCase9 {
        public void processInBackground() {
            class BackgroundProcessor {
                // ruleid: java-non-static-threadlocal
                private ThreadLocal<Integer> progress = ThreadLocal.withInitial(() -> 0);
                
                public void updateProgress(int value) {
                    progress.set(value);
                    logger.info("Progress: " + progress.get() + "%");
                }
            }
            
            BackgroundProcessor processor = new BackgroundProcessor();
            processor.updateProgress(50);
        }
    }

    // Example 10: Non-static ThreadLocal with executor service
    class BadCase10 {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<String> workerName = new ThreadLocal<>();
        
        public void executeTask() {
            ExecutorService executor = Executors.newFixedThreadPool(5);
            for (int i = 0; i < 10; i++) {
                final int taskId = i;
                executor.submit(() -> {
                    workerName.set("Worker-" + taskId);
                    logger.info("Task executed by: " + workerName.get());
                    workerName.remove();
                });
            }
            executor.shutdown();
        }
    }

    // Example 11: Non-static ThreadLocal in a singleton
    class BadCase11 {
        private static final BadCase11 INSTANCE = new BadCase11();
        
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<Long> requestTimestamp = new ThreadLocal<>();
        
        private BadCase11() {}
        
        public static BadCase11 getInstance() {
            return INSTANCE;
        }
        
        public void logRequestTime() {
            requestTimestamp.set(System.currentTimeMillis());
        }
    }

    // Example 12: Non-static ThreadLocal with supplier
    class BadCase12 {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<String> currentUser = ThreadLocal.withInitial(() -> "guest");
        
        public void authenticateUser(String username) {
            currentUser.set(username);
        }
        
        public String getCurrentUser() {
            return currentUser.get();
        }
    }

    // Example 13: Non-static ThreadLocal in an abstract class
    abstract class BadCase13 {
        // ruleid: java-non-static-threadlocal
        protected ThreadLocal<Map<String, String>> contextData = ThreadLocal.withInitial(HashMap::new);
        
        public void addContextData(String key, String value) {
            contextData.get().put(key, value);
        }
        
        public abstract void processWithContext();
    }

    // Example 14: Non-static ThreadLocal with try-finally
    class BadCase14 {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<Boolean> inTransaction = ThreadLocal.withInitial(() -> false);
        
        public void executeInTransaction(Runnable task) {
            try {
                inTransaction.set(true);
                task.run();
            } finally {
                inTransaction.remove();
            }
        }
    }

    // Example 15: Non-static ThreadLocal in a generic class
    class BadCase15<T> {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<T> contextValue = new ThreadLocal<>();
        
        public void setContext(T value) {
            contextValue.set(value);
        }
        
        public T getContext() {
            return contextValue.get();
        }
    }

    // True Negative Examples (Good Cases)

    // Example 1: Static ThreadLocal basic usage
    class GoodCase1 {
        // ok: java-non-static-threadlocal
        private static ThreadLocal<String> userContext = new ThreadLocal<>();
        
        public void processRequest(HttpServletRequest request) {
            String userId = request.getParameter("userId");
            userContext.set(userId);
            // Process with user context
            userContext.remove();
        }
    }

    // Example 2: Static ThreadLocal with initial value
    class GoodCase2 {
        // ok: java-non-static-threadlocal
        private static ThreadLocal<Integer> requestCounter = ThreadLocal.withInitial(() -> 0);
        
        public void countRequests() {
            Integer count = requestCounter.get();
            requestCounter.set(count + 1);
            logger.info("Request count: " + count);
        }
    }

    // Example 3: Multiple static ThreadLocals in a class
    class GoodCase3 {
        // ok: java-non-static-threadlocal
        private static ThreadLocal<String> sessionId = new ThreadLocal<>();
        // ok: java-non-static-threadlocal
        private static ThreadLocal<Map<String, Object>> sessionAttributes = new ThreadLocal<>();
        
        public void storeSessionData(String id, Map<String, Object> attributes) {
            sessionId.set(id);
            sessionAttributes.set(attributes);
        }
    }

    // Example 4: Static ThreadLocal in a service class
    class GoodCase4 {
        // ok: java-non-static-threadlocal
        private static ThreadLocal<Connection> connectionHolder = new ThreadLocal<>();
        
        public Connection getConnection() throws SQLException {
            Connection conn = connectionHolder.get();
            if (conn == null) {
                conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");
                connectionHolder.set(conn);
            }
            return conn;
        }
    }

    // Example 5: Static ThreadLocal in a utility class
    class GoodCase5 {
        // ok: java-non-static-threadlocal
        private static ThreadLocal<Boolean> transactionActive = ThreadLocal.withInitial(() -> false);
        
        public void beginTransaction() {
            transactionActive.set(true);
        }
        
        public void endTransaction() {
            transactionActive.set(false);
        }
    }

    // Example 6: Static ThreadLocal with complex object
    class GoodCase6 {
        class UserProfile {
            String name;
            String role;
        }
        
        // ok: java-non-static-threadlocal
        private static ThreadLocal<UserProfile> userProfileContext = new ThreadLocal<>();
        
        public void setUserProfile(String name, String role) {
            UserProfile profile = new UserProfile();
            profile.name = name;
            profile.role = role;
            userProfileContext.set(profile);
        }
    }

    // Example 7: Static ThreadLocal in a controller
    class GoodCase7 {
        // ok: java-non-static-threadlocal
        private static ThreadLocal<HttpServletRequest> requestContext = new ThreadLocal<>();
        
        public void handleRequest(HttpServletRequest request, HttpServletResponse response) {
            requestContext.set(request);
            // Process request
            requestContext.remove();
        }
    }

    // Example 8: Static ThreadLocal with inheritance
    class GoodCase8 extends Thread {
        // ok: java-non-static-threadlocal
        private static ThreadLocal<Long> startTime = ThreadLocal.withInitial(System::currentTimeMillis);
        
        @Override
        public void run() {
            logger.info("Thread started at: " + startTime.get());
            // Do work
            logger.info("Thread execution time: " + (System.currentTimeMillis() - startTime.get()));
        }
    }

    // Example 9: Static ThreadLocal in an inner class
    class GoodCase9 {
        public void processInBackground() {
            class BackgroundProcessor {
                // ok: java-non-static-threadlocal
                private static ThreadLocal<Integer> progress = ThreadLocal.withInitial(() -> 0);
                
                public void updateProgress(int value) {
                    progress.set(value);
                    logger.info("Progress: " + progress.get() + "%");
                }
            }
            
            BackgroundProcessor processor = new BackgroundProcessor();
            processor.updateProgress(50);
        }
    }

    // Example 10: Static ThreadLocal with executor service
    class GoodCase10 {
        // ok: java-non-static-threadlocal
        private static ThreadLocal<String> workerName = new ThreadLocal<>();
        
        public void executeTask() {
            ExecutorService executor = Executors.newFixedThreadPool(5);
            for (int i = 0; i < 10; i++) {
                final int taskId = i;
                executor.submit(() -> {
                    workerName.set("Worker-" + taskId);
                    logger.info("Task executed by: " + workerName.get());
                    workerName.remove();
                });
            }
            executor.shutdown();
        }
    }

    // Example 11: Static ThreadLocal in a singleton
    class GoodCase11 {
        private static final GoodCase11 INSTANCE = new GoodCase11();
        
        // ok: java-non-static-threadlocal
        private static ThreadLocal<Long> requestTimestamp = new ThreadLocal<>();
        
        private GoodCase11() {}
        
        public static GoodCase11 getInstance() {
            return INSTANCE;
        }
        
        public void logRequestTime() {
            requestTimestamp.set(System.currentTimeMillis());
        }
    }

    // Example 12: Static ThreadLocal with supplier
    class GoodCase12 {
        // ok: java-non-static-threadlocal
        private static ThreadLocal<String> currentUser = ThreadLocal.withInitial(() -> "guest");
        
        public void authenticateUser(String username) {
            currentUser.set(username);
        }
        
        public String getCurrentUser() {
            return currentUser.get();
        }
    }

    // Example 13: Static ThreadLocal in an abstract class
    abstract class GoodCase13 {
        // ok: java-non-static-threadlocal
        protected static ThreadLocal<Map<String, String>> contextData = ThreadLocal.withInitial(HashMap::new);
        
        public void addContextData(String key, String value) {
            contextData.get().put(key, value);
        }
        
        public abstract void processWithContext();
    }

    // Example 14: Static ThreadLocal with try-finally
    class GoodCase14 {
        // ok: java-non-static-threadlocal
        private static ThreadLocal<Boolean> inTransaction = ThreadLocal.withInitial(() -> false);
        
        public void executeInTransaction(Runnable task) {
            try {
                inTransaction.set(true);
                task.run();
            } finally {
                inTransaction.remove();
            }
        }
    }

    // Example 15: Static ThreadLocal in a generic class
    class GoodCase15<T> {
        // ok: java-non-static-threadlocal
        private static ThreadLocal<Object> contextValue = new ThreadLocal<>();
        
        @SuppressWarnings("unchecked")
        public void setContext(T value) {
            contextValue.set(value);
        }
        
        @SuppressWarnings("unchecked")
        public T getContext() {
            return (T) contextValue.get();
        }
    }
}