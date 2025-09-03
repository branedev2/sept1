import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

public class ThreadLocalExamples {

    // True Positives (vulnerable code - non-static ThreadLocal)

    static class BadCase1 {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<String> userContext = ThreadLocal.withInitial(() -> "default");
        
        public void processUserRequest(String userId) {
            userContext.set(userId);
            try {
                // Process the request with the user context
                System.out.println("Processing request for: " + userContext.get());
            } finally {
                userContext.remove();
            }
        }
    }

    static class BadCase2 {
        // ruleid: java-non-static-threadlocal
        private final ThreadLocal<Integer> requestCounter = ThreadLocal.withInitial(() -> 0);
        
        public void incrementCounter() {
            requestCounter.set(requestCounter.get() + 1);
            System.out.println("Request count: " + requestCounter.get());
        }
    }

    static class BadCase3 {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<StringBuilder> logBuffer = new ThreadLocal<StringBuilder>() {
            @Override
            protected StringBuilder initialValue() {
                return new StringBuilder();
            }
        };
        
        public void appendLog(String message) {
            logBuffer.get().append(message).append("\n");
        }
        
        public String getLog() {
            return logBuffer.get().toString();
        }
    }

    static class BadCase4 {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<Boolean> transactionActive = ThreadLocal.withInitial(() -> false);
        
        public void beginTransaction() {
            if (transactionActive.get()) {
                throw new IllegalStateException("Transaction already active");
            }
            transactionActive.set(true);
            System.out.println("Transaction started");
        }
        
        public void endTransaction() {
            if (!transactionActive.get()) {
                throw new IllegalStateException("No active transaction");
            }
            transactionActive.set(false);
            System.out.println("Transaction ended");
        }
    }

    static class BadCase5<T> {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<T> contextValue = new ThreadLocal<>();
        
        public void setValue(T value) {
            contextValue.set(value);
        }
        
        public T getValue() {
            return contextValue.get();
        }
    }

    static class BadCase6 {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<Long> startTime = ThreadLocal.withInitial(System::currentTimeMillis);
        
        public void logExecutionTime(String operation) {
            long elapsed = System.currentTimeMillis() - startTime.get();
            System.out.println(operation + " took " + elapsed + "ms");
            startTime.set(System.currentTimeMillis());
        }
    }

    static class BadCase7 {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<java.text.SimpleDateFormat> dateFormatter = 
            ThreadLocal.withInitial(() -> new java.text.SimpleDateFormat("yyyy-MM-dd"));
        
        public String formatDate(java.util.Date date) {
            return dateFormatter.get().format(date);
        }
    }

    static class BadCase8 {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<java.util.Random> randomGenerator = 
            ThreadLocal.withInitial(() -> new java.util.Random());
        
        public int getRandomNumber(int bound) {
            return randomGenerator.get().nextInt(bound);
        }
    }

    static class BadCase9 {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<java.util.Locale> userLocale = 
            ThreadLocal.withInitial(() -> java.util.Locale.getDefault());
        
        public void setUserLocale(java.util.Locale locale) {
            userLocale.set(locale);
        }
        
        public String getLocalizedMessage(String key) {
            // Simulated localization
            return "Message for " + key + " in " + userLocale.get().getDisplayName();
        }
    }

    static class BadCase10 {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<java.util.HashMap<String, Object>> sessionAttributes = 
            ThreadLocal.withInitial(java.util.HashMap::new);
        
        public void setAttribute(String name, Object value) {
            sessionAttributes.get().put(name, value);
        }
        
        public Object getAttribute(String name) {
            return sessionAttributes.get().get(name);
        }
    }

    static class BadCase11 {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<java.sql.Connection> dbConnection = new ThreadLocal<>();
        
        public void openConnection(String url, String username, String password) throws Exception {
            java.sql.Connection conn = java.sql.DriverManager.getConnection(url, username, password);
            dbConnection.set(conn);
        }
        
        public java.sql.Connection getConnection() {
            return dbConnection.get();
        }
        
        public void closeConnection() throws Exception {
            if (dbConnection.get() != null) {
                dbConnection.get().close();
                dbConnection.remove();
            }
        }
    }

    static class BadCase12 {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<Integer> recursionDepth = ThreadLocal.withInitial(() -> 0);
        
        public void recursiveOperation(int maxDepth) {
            int currentDepth = recursionDepth.get();
            recursionDepth.set(currentDepth + 1);
            
            try {
                if (currentDepth < maxDepth) {
                    System.out.println("Recursion depth: " + recursionDepth.get());
                    recursiveOperation(maxDepth);
                }
            } finally {
                recursionDepth.set(currentDepth);
            }
        }
    }

    static class BadCase13 {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<StringBuilder> queryBuilder = 
            ThreadLocal.withInitial(StringBuilder::new);
        
        public void appendToQuery(String clause) {
            if (queryBuilder.get().length() > 0) {
                queryBuilder.get().append(" AND ");
            }
            queryBuilder.get().append(clause);
        }
        
        public String getQuery() {
            String query = queryBuilder.get().toString();
            queryBuilder.get().setLength(0); // Clear for next use
            return query;
        }
    }

    static class BadCase14 {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<java.util.Stack<String>> callStack = 
            ThreadLocal.withInitial(java.util.Stack::new);
        
        public void enterMethod(String methodName) {
            callStack.get().push(methodName);
            System.out.println("Entering: " + methodName);
        }
        
        public void exitMethod() {
            String methodName = callStack.get().pop();
            System.out.println("Exiting: " + methodName);
        }
    }

    static class BadCase15 {
        // ruleid: java-non-static-threadlocal
        private ThreadLocal<java.io.ByteArrayOutputStream> buffer = 
            ThreadLocal.withInitial(java.io.ByteArrayOutputStream::new);
        
        public void writeData(byte[] data) {
            try {
                buffer.get().write(data);
            } catch (java.io.IOException e) {
                throw new RuntimeException(e);
            }
        }
        
        public byte[] getData() {
            byte[] result = buffer.get().toByteArray();
            buffer.get().reset();
            return result;
        }
    }

    // True Negatives (safe code - static ThreadLocal)

    static class GoodCase1 {
        // ok: java-non-static-threadlocal
        private static final ThreadLocal<String> userContext = ThreadLocal.withInitial(() -> "default");
        
        public void processUserRequest(String userId) {
            userContext.set(userId);
            try {
                // Process the request with the user context
                System.out.println("Processing request for: " + userContext.get());
            } finally {
                userContext.remove();
            }
        }
    }

    static class GoodCase2 {
        // ok: java-non-static-threadlocal
        private static final ThreadLocal<Integer> requestCounter = ThreadLocal.withInitial(() -> 0);
        
        public void incrementCounter() {
            requestCounter.set(requestCounter.get() + 1);
            System.out.println("Request count: " + requestCounter.get());
        }
    }

    static class GoodCase3 {
        // ok: java-non-static-threadlocal
        private static final ThreadLocal<StringBuilder> logBuffer = new ThreadLocal<StringBuilder>() {
            @Override
            protected StringBuilder initialValue() {
                return new StringBuilder();
            }
        };
        
        public void appendLog(String message) {
            logBuffer.get().append(message).append("\n");
        }
        
        public String getLog() {
            return logBuffer.get().toString();
        }
    }

    static class GoodCase4 {
        // ok: java-non-static-threadlocal
        private static final ThreadLocal<Boolean> transactionActive = ThreadLocal.withInitial(() -> false);
        
        public void beginTransaction() {
            if (transactionActive.get()) {
                throw new IllegalStateException("Transaction already active");
            }
            transactionActive.set(true);
            System.out.println("Transaction started");
        }
        
        public void endTransaction() {
            if (!transactionActive.get()) {
                throw new IllegalStateException("No active transaction");
            }
            transactionActive.set(false);
            System.out.println("Transaction ended");
        }
    }

    static class GoodCase5<T> {
        // ok: java-non-static-threadlocal
        private static final ThreadLocal<Object> contextValue = new ThreadLocal<>();
        
        @SuppressWarnings("unchecked")
        public void setValue(T value) {
            contextValue.set(value);
        }
        
        @SuppressWarnings("unchecked")
        public T getValue() {
            return (T) contextValue.get();
        }
    }

    static class GoodCase6 {
        // ok: java-non-static-threadlocal
        private static final ThreadLocal<Long> startTime = ThreadLocal.withInitial(System::currentTimeMillis);
        
        public void logExecutionTime(String operation) {
            long elapsed = System.currentTimeMillis() - startTime.get();
            System.out.println(operation + " took " + elapsed + "ms");
            startTime.set(System.currentTimeMillis());
        }
    }

    static class GoodCase7 {
        // ok: java-non-static-threadlocal
        private static final ThreadLocal<java.text.SimpleDateFormat> dateFormatter = 
            ThreadLocal.withInitial(() -> new java.text.SimpleDateFormat("yyyy-MM-dd"));
        
        public String formatDate(java.util.Date date) {
            return dateFormatter.get().format(date);
        }
    }

    static class GoodCase8 {
        // ok: java-non-static-threadlocal
        private static final ThreadLocal<java.util.Random> randomGenerator = 
            ThreadLocal.withInitial(() -> new java.util.Random());
        
        public int getRandomNumber(int bound) {
            return randomGenerator.get().nextInt(bound);
        }
    }

    static class GoodCase9 {
        // ok: java-non-static-threadlocal
        private static final ThreadLocal<java.util.Locale> userLocale = 
            ThreadLocal.withInitial(() -> java.util.Locale.getDefault());
        
        public void setUserLocale(java.util.Locale locale) {
            userLocale.set(locale);
        }
        
        public String getLocalizedMessage(String key) {
            // Simulated localization
            return "Message for " + key + " in " + userLocale.get().getDisplayName();
        }
    }

    static class GoodCase10 {
        // ok: java-non-static-threadlocal
        private static final ThreadLocal<java.util.HashMap<String, Object>> sessionAttributes = 
            ThreadLocal.withInitial(java.util.HashMap::new);
        
        public void setAttribute(String name, Object value) {
            sessionAttributes.get().put(name, value);
        }
        
        public Object getAttribute(String name) {
            return sessionAttributes.get().get(name);
        }
    }

    static class GoodCase11 {
        // ok: java-non-static-threadlocal
        private static final ThreadLocal<java.sql.Connection> dbConnection = new ThreadLocal<>();
        
        public void openConnection(String url, String username, String password) throws Exception {
            java.sql.Connection conn = java.sql.DriverManager.getConnection(url, username, password);
            dbConnection.set(conn);
        }
        
        public java.sql.Connection getConnection() {
            return dbConnection.get();
        }
        
        public void closeConnection() throws Exception {
            if (dbConnection.get() != null) {
                dbConnection.get().close();
                dbConnection.remove();
            }
        }
    }

    static class GoodCase12 {
        // ok: java-non-static-threadlocal
        private static final ThreadLocal<Integer> recursionDepth = ThreadLocal.withInitial(() -> 0);
        
        public void recursiveOperation(int maxDepth) {
            int currentDepth = recursionDepth.get();
            recursionDepth.set(currentDepth + 1);
            
            try {
                if (currentDepth < maxDepth) {
                    System.out.println("Recursion depth: " + recursionDepth.get());
                    recursiveOperation(maxDepth);
                }
            } finally {
                recursionDepth.set(currentDepth);
            }
        }
    }

    static class GoodCase13 {
        // Using a different approach - not using ThreadLocal at all
        // ok: java-non-static-threadlocal
        public String buildQuery(String... clauses) {
            StringBuilder queryBuilder = new StringBuilder();
            
            for (int i = 0; i < clauses.length; i++) {
                if (i > 0) {
                    queryBuilder.append(" AND ");
                }
                queryBuilder.append(clauses[i]);
            }
            
            return queryBuilder.toString();
        }
    }

    static class GoodCase14 {
        // ok: java-non-static-threadlocal
        private static final ThreadLocal<java.util.Stack<String>> callStack = 
            ThreadLocal.withInitial(java.util.Stack::new);
        
        public void enterMethod(String methodName) {
            callStack.get().push(methodName);
            System.out.println("Entering: " + methodName);
        }
        
        public void exitMethod() {
            String methodName = callStack.get().pop();
            System.out.println("Exiting: " + methodName);
        }
    }

    static class GoodCase15 {
        // ok: java-non-static-threadlocal
        private static final ThreadLocal<java.io.ByteArrayOutputStream> buffer = 
            ThreadLocal.withInitial(java.io.ByteArrayOutputStream::new);
        
        public void writeData(byte[] data) {
            try {
                buffer.get().write(data);
            } catch (java.io.IOException e) {
                throw new RuntimeException(e);
            }
        }
        
        public byte[] getData() {
            byte[] result = buffer.get().toByteArray();
            buffer.get().reset();
            return result;
        }
    }

    public static void main(String[] args) {
        // Example usage
        ExecutorService executor = Executors.newFixedThreadPool(5);
        
        // This will create memory leaks with BadCase classes
        for (int i = 0; i < 1000; i++) {
            executor.submit(() -> {
                BadCase1 badInstance = new BadCase1();
                badInstance.processUserRequest("user-" + Thread.currentThread().getId());
                
                GoodCase1 goodInstance = new GoodCase1();
                goodInstance.processUserRequest("user-" + Thread.currentThread().getId());
            });
        }
        
        try {
            executor.shutdown();
            executor.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}