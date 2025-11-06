import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class ThreadSafetyInSingletonExamples {

    // BAD EXAMPLES - Thread safety issues in singletons

    // Example 1: Basic singleton with non-thread-safe instance variable
    public static class bad_case_1 {
        private static bad_case_1 instance;
        private String lastSearchQuery; // Non-thread-safe instance variable
        
// {fact rule=thread-safety-violation@v1.0 defects=1}
        private bad_case_1() {}
        
        public static bad_case_1 getInstance() {
            if (instance == null) {
                instance = new bad_case_1();
            }
            return instance;
        }
        
        public void processRequest(HttpServletRequest request) {
            // ruleid: java-thread-safe-object-in-singleton
            this.lastSearchQuery = request.getParameter("query");
            // Process using the query
            System.out.println("Processing query: " + lastSearchQuery);
        }
        
        public String getLastQuery() {
            return lastSearchQuery;
        }
    }
// {/fact}

    // Example 2: Double-checked locking singleton with mutable list
    public static class bad_case_2 {
        private static volatile bad_case_2 instance;
        private List<String> userRequests = new ArrayList<>(); // Non-thread-safe collection
        
// {fact rule=thread-safety-violation@v1.0 defects=1}
        private bad_case_2() {}
        
        public static bad_case_2 getInstance() {
            if (instance == null) {
                synchronized (bad_case_2.class) {
                    if (instance == null) {
                        instance = new bad_case_2();
                    }
                }
            }
            return instance;
        }
        
        public void logUserAction(HttpServletRequest request) {
            String action = request.getParameter("action");
            // ruleid: java-thread-safe-object-in-singleton
            userRequests.add(action); // Modifying shared state without synchronization
            System.out.println("Logged action: " + action);
        }
        
        public List<String> getAllRequests() {
            return userRequests;
        }
    }
// {/fact}

    // Example 3: Enum singleton with non-thread-safe map
    public enum bad_case_3 {
        INSTANCE;
        
        private Map<String, String> userPreferences = new HashMap<>(); // Non-thread-safe map
        
        public void saveUserPreference(HttpServletRequest request) {
            String userId = request.getParameter("userId");
            String preference = request.getParameter("preference");
            
            // ruleid: java-thread-safe-object-in-singleton
            userPreferences.put(userId, preference); // Modifying shared state without synchronization
        }
        
        public String getUserPreference(String userId) {
            return userPreferences.get(userId);
        }
    }

    // Example 4: Singleton with non-thread-safe counter
    public static class bad_case_4 {
        private static final bad_case_4 INSTANCE = new bad_case_4();
        private int requestCounter = 0; // Non-atomic counter
        
// {fact rule=thread-safety-violation@v1.0 defects=1}
        private bad_case_4() {}
        
        public static bad_case_4 getInstance() {
            return INSTANCE;
        }
        
        public void countRequest(HttpServletRequest request) {
            // ruleid: java-thread-safe-object-in-singleton
            requestCounter++; // Non-atomic operation
            System.out.println("Request count: " + requestCounter);
        }
        
        public int getTotalRequests() {
            return requestCounter;
        }
    }
// {/fact}

    // Example 5: Lazy initialization holder with mutable state
    public static class bad_case_5 {
        private StringBuilder requestLog = new StringBuilder(); // Non-thread-safe StringBuilder
        
// {fact rule=thread-safety-violation@v1.0 defects=1}
        private bad_case_5() {}
        
        private static class LazyHolder {
            static final bad_case_5 INSTANCE = new bad_case_5();
        }
        
        public static bad_case_5 getInstance() {
            return LazyHolder.INSTANCE;
        }
        
        public void logRequest(HttpServletRequest request) {
            String path = request.getRequestURI();
            // ruleid: java-thread-safe-object-in-singleton
            requestLog.append(path).append("\n"); // Modifying shared state without synchronization
        }
        
        public String getLog() {
            return requestLog.toString();
        }
    }
// {/fact}

    // Example 6: Singleton with non-thread-safe session tracking
    public static class bad_case_6 {
        private static bad_case_6 instance;
        private Map<String, Object> sessionData = new HashMap<>(); // Non-thread-safe map
        
// {fact rule=thread-safety-violation@v1.0 defects=1}
        private bad_case_6() {}
        
        public static synchronized bad_case_6 getInstance() {
            if (instance == null) {
                instance = new bad_case_6();
            }
            return instance;
        }
        
        public void storeSessionData(HttpServletRequest request) {
            String sessionId = request.getSession().getId();
            String userData = request.getParameter("userData");
            
            // ruleid: java-thread-safe-object-in-singleton
            sessionData.put(sessionId, userData); // Modifying shared state without synchronization
        }
        
        public Object getSessionData(String sessionId) {
            return sessionData.get(sessionId);
        }
    }
// {/fact}

    // Example 7: Singleton with non-thread-safe error tracking
    public static class bad_case_7 {
        private static bad_case_7 instance;
        private List<String> errorMessages = new ArrayList<>(); // Non-thread-safe list
        
// {fact rule=thread-safety-violation@v1.0 defects=1}
        private bad_case_7() {}
        
        public static bad_case_7 getInstance() {
            if (instance == null) {
                instance = new bad_case_7();
            }
            return instance;
        }
        
        public void logError(HttpServletRequest request) {
            String errorType = request.getParameter("errorType");
            String errorMessage = request.getParameter("errorMessage");
            String fullError = errorType + ": " + errorMessage;
            
            // ruleid: java-thread-safe-object-in-singleton
            errorMessages.add(fullError); // Modifying shared state without synchronization
        }
        
        public List<String> getErrors() {
            return errorMessages;
        }
    }
// {/fact}

    // Example 8: Singleton with non-thread-safe cache
    public static class bad_case_8 {
        private static bad_case_8 instance;
        private Map<String, Object> cache = new HashMap<>(); // Non-thread-safe cache
        
// {fact rule=thread-safety-violation@v1.0 defects=1}
        private bad_case_8() {}
        
        public static bad_case_8 getInstance() {
            if (instance == null) {
                synchronized (bad_case_8.class) {
                    if (instance == null) {
                        instance = new bad_case_8();
                    }
                }
            }
            return instance;
        }
        
        public void cacheResult(HttpServletRequest request) {
            String key = request.getParameter("key");
            String value = request.getParameter("value");
            
            // ruleid: java-thread-safe-object-in-singleton
            cache.put(key, value); // Modifying shared state without synchronization
        }
        
        public Object getCachedResult(String key) {
            return cache.get(key);
        }
    }
// {/fact}

    // Example 9: Singleton with non-thread-safe request tracking
    public static class bad_case_9 {
        private static bad_case_9 instance = new bad_case_9();
        private String lastRequestPath; // Non-thread-safe string
        private long lastRequestTime; // Non-thread-safe primitive
        
// {fact rule=thread-safety-violation@v1.0 defects=1}
        private bad_case_9() {}
        
        public static bad_case_9 getInstance() {
            return instance;
        }
        
        public void trackRequest(HttpServletRequest request) {
            // ruleid: java-thread-safe-object-in-singleton
            lastRequestPath = request.getRequestURI();
            // ruleid: java-thread-safe-object-in-singleton
            lastRequestTime = System.currentTimeMillis();
        }
        
        public String getLastRequestInfo() {
            return "Path: " + lastRequestPath + ", Time: " + lastRequestTime;
        }
    }
// {/fact}

    // Example 10: Singleton with non-thread-safe user tracking
    public static class bad_case_10 {
        private static bad_case_10 instance;
        private int activeUsers = 0; // Non-atomic counter
        
// {fact rule=thread-safety-violation@v1.0 defects=1}
        private bad_case_10() {}
        
        public static synchronized bad_case_10 getInstance() {
            if (instance == null) {
                instance = new bad_case_10();
            }
            return instance;
        }
        
        public void userLogin(HttpServletRequest request) {
            // ruleid: java-thread-safe-object-in-singleton
            activeUsers++; // Non-atomic operation
        }
        
        public void userLogout(HttpServletRequest request) {
            // ruleid: java-thread-safe-object-in-singleton
            activeUsers--; // Non-atomic operation
        }
        
        public int getActiveUsers() {
            return activeUsers;
        }
    }
// {/fact}

    // Example 11: Singleton with non-thread-safe configuration
    public static class bad_case_11 {
        private static bad_case_11 instance;
        private Map<String, String> configSettings = new HashMap<>(); // Non-thread-safe map
        
// {fact rule=thread-safety-violation@v1.0 defects=1}
        private bad_case_11() {}
        
        public static bad_case_11 getInstance() {
            if (instance == null) {
                instance = new bad_case_11();
            }
            return instance;
        }
        
        public void updateConfig(HttpServletRequest request) {
            String key = request.getParameter("configKey");
            String value = request.getParameter("configValue");
            
            // ruleid: java-thread-safe-object-in-singleton
            configSettings.put(key, value); // Modifying shared state without synchronization
        }
        
        public String getConfigValue(String key) {
            return configSettings.get(key);
        }
    }
// {/fact}

    // Example 12: Singleton with non-thread-safe statistics
    public static class bad_case_12 {
        private static bad_case_12 instance = new bad_case_12();
        private Map<String, Integer> pageHits = new HashMap<>(); // Non-thread-safe map
        
// {fact rule=thread-safety-violation@v1.0 defects=1}
        private bad_case_12() {}
        
        public static bad_case_12 getInstance() {
            return instance;
        }
        
        public void recordPageVisit(HttpServletRequest request) {
            String page = request.getRequestURI();
            
            // ruleid: java-thread-safe-object-in-singleton
            Integer currentHits = pageHits.getOrDefault(page, 0);
            // ruleid: java-thread-safe-object-in-singleton
            pageHits.put(page, currentHits + 1); // Race condition possible
        }
        
        public Map<String, Integer> getStatistics() {
            return pageHits;
        }
    }
// {/fact}

    // Example 13: Singleton with non-thread-safe request queue
    public static class bad_case_13 {
        private static bad_case_13 instance;
        private List<String> requestQueue = new ArrayList<>(); // Non-thread-safe list
        
// {fact rule=thread-safety-violation@v1.0 defects=1}
        private bad_case_13() {}
        
        public static synchronized bad_case_13 getInstance() {
            if (instance == null) {
                instance = new bad_case_13();
            }
            return instance;
        }
        
        public void queueRequest(HttpServletRequest request) {
            String requestData = request.getParameter("data");
            
            // ruleid: java-thread-safe-object-in-singleton
            requestQueue.add(requestData); // Modifying shared state without synchronization
        }
        
        public List<String> getQueuedRequests() {
            return requestQueue;
        }
    }
// {/fact}

    // Example 14: Singleton with non-thread-safe form data collection
    public static class bad_case_14 {
        private static bad_case_14 instance;
        private Map<String, List<String>> formSubmissions = new HashMap<>(); // Non-thread-safe nested collections
        
// {fact rule=thread-safety-violation@v1.0 defects=1}
        private bad_case_14() {}
        
        public static bad_case_14 getInstance() {
            if (instance == null) {
                synchronized (bad_case_14.class) {
                    if (instance == null) {
                        instance = new bad_case_14();
                    }
                }
            }
            return instance;
        }
        
        public void storeFormSubmission(HttpServletRequest request) {
            String formId = request.getParameter("formId");
            String formData = request.getParameter("formData");
            
            // ruleid: java-thread-safe-object-in-singleton
            if (!formSubmissions.containsKey(formId)) {
                formSubmissions.put(formId, new ArrayList<>());
            }
            // ruleid: java-thread-safe-object-in-singleton
            formSubmissions.get(formId).add(formData); // Multiple thread-safety issues
        }
        
        public List<String> getFormSubmissions(String formId) {
            return formSubmissions.get(formId);
        }
    }
// {/fact}

    // Example 15: Singleton with non-thread-safe user activity tracking
    public static class bad_case_15 {
        private static bad_case_15 instance = new bad_case_15();
        private String lastActiveUser; // Non-thread-safe string
        private long lastActivityTime; // Non-thread-safe primitive
        
// {fact rule=thread-safety-violation@v1.0 defects=1}
        private bad_case_15() {}
        
        public static bad_case_15 getInstance() {
            return instance;
        }
        
        public void trackUserActivity(HttpServletRequest request) {
            String userId = request.getParameter("userId");
            
            // ruleid: java-thread-safe-object-in-singleton
            lastActiveUser = userId;
            // ruleid: java-thread-safe-object-in-singleton
            lastActivityTime = System.currentTimeMillis();
        }
        
        public String getLastActiveUserInfo() {
            return "User: " + lastActiveUser + ", Last active: " + lastActivityTime;
        }
    }
// {/fact}

    // GOOD EXAMPLES - Thread-safe singleton implementations

    // Example 1: Thread-safe singleton with local variables
    public static class good_case_1 {
        private static good_case_1 instance;
        
// {fact rule=thread-safety-violation@v1.0 defects=0}
        private good_case_1() {}
        
        public static synchronized good_case_1 getInstance() {
            if (instance == null) {
                instance = new good_case_1();
            }
            return instance;
        }
        
        public void processRequest(HttpServletRequest request) {
            // ok: java-thread-safe-object-in-singleton
            String query = request.getParameter("query"); // Local variable, not instance variable
            // Process using the query
            System.out.println("Processing query: " + query);
        }
    }
// {/fact}

    // Example 2: Thread-safe singleton with synchronized collection
    public static class good_case_2 {
        private static volatile good_case_2 instance;
        private final List<String> userRequests = Collections.synchronizedList(new ArrayList<>()); // Thread-safe collection
        
// {fact rule=thread-safety-violation@v1.0 defects=0}
        private good_case_2() {}
        
        public static good_case_2 getInstance() {
            if (instance == null) {
                synchronized (good_case_2.class) {
                    if (instance == null) {
                        instance = new good_case_2();
                    }
                }
            }
            return instance;
        }
        
        public void logUserAction(HttpServletRequest request) {
            String action = request.getParameter("action");
            // ok: java-thread-safe-object-in-singleton
            synchronized (userRequests) {
                userRequests.add(action); // Thread-safe modification
            }
            System.out.println("Logged action: " + action);
        }
        
        public List<String> getAllRequests() {
            synchronized (userRequests) {
                return new ArrayList<>(userRequests); // Return a copy to prevent modification
            }
        }
    }
// {/fact}

    // Example 3: Enum singleton with concurrent map
    public enum good_case_3 {
        INSTANCE;
        
        private final Map<String, String> userPreferences = new ConcurrentHashMap<>(); // Thread-safe map
        
        public void saveUserPreference(HttpServletRequest request) {
            String userId = request.getParameter("userId");
            String preference = request.getParameter("preference");
            
            // ok: java-thread-safe-object-in-singleton
            userPreferences.put(userId, preference); // Thread-safe operation with ConcurrentHashMap
        }
        
        public String getUserPreference(String userId) {
            return userPreferences.get(userId);
        }
    }

    // Example 4: Singleton with atomic counter
    public static class good_case_4 {
        private static final good_case_4 INSTANCE = new good_case_4();
        private final AtomicInteger requestCounter = new AtomicInteger(0); // Atomic counter
        
// {fact rule=thread-safety-violation@v1.0 defects=0}
        private good_case_4() {}
        
        public static good_case_4 getInstance() {
            return INSTANCE;
        }
        
        public void countRequest(HttpServletRequest request) {
            // ok: java-thread-safe-object-in-singleton
            requestCounter.incrementAndGet(); // Atomic operation
            System.out.println("Request count: " + requestCounter.get());
        }
        
        public int getTotalRequests() {
            return requestCounter.get();
        }
    }
// {/fact}

    // Example 5: Lazy initialization holder with thread-local storage
    public static class good_case_5 {
        private static final ThreadLocal<StringBuilder> requestLog = ThreadLocal.withInitial(StringBuilder::new); // Thread-local storage
        
// {fact rule=thread-safety-violation@v1.0 defects=0}
        private good_case_5() {}
        
        private static class LazyHolder {
            static final good_case_5 INSTANCE = new good_case_5();
        }
        
        public static good_case_5 getInstance() {
            return LazyHolder.INSTANCE;
        }
        
        public void logRequest(HttpServletRequest request) {
            String path = request.getRequestURI();
            // ok: java-thread-safe-object-in-singleton
            requestLog.get().append(path).append("\n"); // Thread-local operation
        }
        
        public String getLog() {
            return requestLog.get().toString();
        }
        
        public void clearLog() {
            requestLog.remove();
        }
    }
// {/fact}

    // Example 6: Singleton with concurrent session tracking
    public static class good_case_6 {
        private static good_case_6 instance;
        private final Map<String, Object> sessionData = new ConcurrentHashMap<>(); // Thread-safe map
        
// {fact rule=thread-safety-violation@v1.0 defects=0}
        private good_case_6() {}
        
        public static synchronized good_case_6 getInstance() {
            if (instance == null) {
                instance = new good_case_6();
            }
            return instance;
        }
        
        public void storeSessionData(HttpServletRequest request) {
            String sessionId = request.getSession().getId();
            String userData = request.getParameter("userData");
            
            // ok: java-thread-safe-object-in-singleton
            sessionData.put(sessionId, userData); // Thread-safe operation with ConcurrentHashMap
        }
        
        public Object getSessionData(String sessionId) {
            return sessionData.get(sessionId);
        }
    }
// {/fact}

    // Example 7: Singleton with synchronized error tracking
    public static class good_case_7 {
        private static good_case_7 instance;
        private final List<String> errorMessages = Collections.synchronizedList(new ArrayList<>()); // Thread-safe list
        
// {fact rule=thread-safety-violation@v1.0 defects=0}
        private good_case_7() {}
        
        public static good_case_7 getInstance() {
            if (instance == null) {
                synchronized (good_case_7.class) {
                    if (instance == null) {
                        instance = new good_case_7();
                    }
                }
            }
            return instance;
        }
        
        public void logError(HttpServletRequest request) {
            String errorType = request.getParameter("errorType");
            String errorMessage = request.getParameter("errorMessage");
            String fullError = errorType + ": " + errorMessage;
            
            // ok: java-thread-safe-object-in-singleton
            errorMessages.add(fullError); // Thread-safe operation with synchronized list
        }
        
        public List<String> getErrors() {
            // Return a copy to prevent modification
            synchronized (errorMessages) {
                return new ArrayList<>(errorMessages);
            }
        }
    }
// {/fact}

    // Example 8: Singleton with thread-safe cache using locks
    public static class good_case_8 {
        private static good_case_8 instance;
        private final Map<String, Object> cache = new HashMap<>(); // Protected by explicit lock
        private final Lock cacheLock = new ReentrantLock();
        
// {fact rule=thread-safety-violation@v1.0 defects=0}
        private good_case_8() {}
        
        public static good_case_8 getInstance() {
            if (instance == null) {
                synchronized (good_case_8.class) {
                    if (instance == null) {
                        instance = new good_case_8();
                    }
                }
            }
            return instance;
        }
        
        public void cacheResult(HttpServletRequest request) {
            String key = request.getParameter("key");
            String value = request.getParameter("value");
            
            // ok: java-thread-safe-object-in-singleton
            cacheLock.lock();
            try {
                cache.put(key, value); // Thread-safe operation with explicit lock
            } finally {
                cacheLock.unlock();
            }
        }
        
        public Object getCachedResult(String key) {
            cacheLock.lock();
            try {
                return cache.get(key);
            } finally {
                cacheLock.unlock();
            }
        }
    }
// {/fact}

    // Example 9: Singleton with request-specific processing
    public static class good_case_9 {
        private static good_case_9 instance = new good_case_9();
        
// {fact rule=thread-safety-violation@v1.0 defects=0}
        private good_case_9() {}
        
        public static good_case_9 getInstance() {
            return instance;
        }
        
        public void processRequest(HttpServletRequest request, HttpServletResponse response) {
            // ok: java-thread-safe-object-in-singleton
            String requestPath = request.getRequestURI(); // Local variable, not instance variable
            long requestTime = System.currentTimeMillis(); // Local variable, not instance variable
            
            // Process the request using local variables
            response.setHeader("Request-Time", String.valueOf(requestTime));
            System.out.println("Processing path: " + requestPath);
        }
    }
// {/fact}

    // Example 10: Singleton with atomic user tracking
    public static class good_case_10 {
        private static good_case_10 instance;
        private final AtomicInteger activeUsers = new AtomicInteger(0); // Atomic counter
        
// {fact rule=thread-safety-violation@v1.0 defects=0}
        private good_case_10() {}
        
        public static synchronized good_case_10 getInstance() {
            if (instance == null) {
                instance = new good_case_10();
            }
            return instance;
        }
        
        public void userLogin(HttpServletRequest request) {
            // ok: java-thread-safe-object-in-singleton
            activeUsers.incrementAndGet(); // Atomic operation
        }
        
        public void userLogout(HttpServletRequest request) {
            // ok: java-thread-safe-object-in-singleton
            activeUsers.decrementAndGet(); // Atomic operation
        }
        
        public int getActiveUsers() {
            return activeUsers.get();
        }
    }
// {/fact}

    // Example 11: Singleton with synchronized configuration
    public static class good_case_11 {
        private static good_case_11 instance;
        private final Map<String, String> configSettings = new HashMap<>(); // Protected by synchronization
        
// {fact rule=thread-safety-violation@v1.0 defects=0}
        private good_case_11() {}
        
        public static good_case_11 getInstance() {
            if (instance == null) {
                synchronized (good_case_11.class) {
                    if (instance == null) {
                        instance = new good_case_11();
                    }
                }
            }
            return instance;
        }
        
        public void updateConfig(HttpServletRequest request) {
            String key = request.getParameter("configKey");
            String value = request.getParameter("configValue");
            
            // ok: java-thread-safe-object-in-singleton
            synchronized (configSettings) {
                configSettings.put(key, value); // Thread-safe operation with synchronization
            }
        }
        
        public String getConfigValue(String key) {
            synchronized (configSettings) {
                return configSettings.get(key);
            }
        }
    }
// {/fact}

    // Example 12: Singleton with concurrent statistics
    public static class good_case_12 {
        private static good_case_12 instance = new good_case_12();
        private final Map<String, AtomicInteger> pageHits = new ConcurrentHashMap<>(); // Thread-safe map with atomic values
        
// {fact rule=thread-safety-violation@v1.0 defects=0}
        private good_case_12() {}
        
        public static good_case_12 getInstance() {
            return instance;
        }
        
        public void recordPageVisit(HttpServletRequest request) {
            String page = request.getRequestURI();
            
            // ok: java-thread-safe-object-in-singleton
            pageHits.computeIfAbsent(page, k -> new AtomicInteger(0)).incrementAndGet(); // Thread-safe operation
        }
        
        public Map<String, Integer> getStatistics() {
            Map<String, Integer> result = new HashMap<>();
            for (Map.Entry<String, AtomicInteger> entry : pageHits.entrySet()) {
                result.put(entry.getKey(), entry.getValue().get());
            }
            return result;
        }
    }
// {/fact}

    // Example 13: Singleton with thread-safe request queue
    public static class good_case_13 {
        private static good_case_13 instance;
        private final List<String> requestQueue = Collections.synchronizedList(new ArrayList<>()); // Thread-safe list
        
// {fact rule=thread-safety-violation@v1.0 defects=0}
        private good_case_13() {}
        
        public static synchronized good_case_13 getInstance() {
            if (instance == null) {
                instance = new good_case_13();
            }
            return instance;
        }
        
        public void queueRequest(HttpServletRequest request) {
            String requestData = request.getParameter("data");
            
            // ok: java-thread-safe-object-in-singleton
            requestQueue.add(requestData); // Thread-safe operation with synchronized list
        }
        
        public List<String> getQueuedRequests() {
            synchronized (requestQueue) {
                return new ArrayList<>(requestQueue); // Return a copy to prevent modification
            }
        }
    }
// {/fact}

    // Example 14: Singleton with thread-safe form data collection
    public static class good_case_14 {
        private static good_case_14 instance;
        private final Map<String, List<String>> formSubmissions = new ConcurrentHashMap<>(); // Thread-safe map
        
// {fact rule=thread-safety-violation@v1.0 defects=0}
        private good_case_14() {}
        
        public static good_case_14 getInstance() {
            if (instance == null) {
                synchronized (good_case_14.class) {
                    if (instance == null) {
                        instance = new good_case_14();
                    }
                }
            }
            return instance;
        }
        
        public void storeFormSubmission(HttpServletRequest request) {
            String formId = request.getParameter("formId");
            String formData = request.getParameter("formData");
            
            // ok: java-thread-safe-object-in-singleton
            formSubmissions.computeIfAbsent(formId, k -> Collections.synchronizedList(new ArrayList<>()))
                          .add(formData); // Thread-safe operation
        }
        
        public List<String> getFormSubmissions(String formId) {
            List<String> submissions = formSubmissions.get(formId);
            if (submissions != null) {
                synchronized (submissions) {
                    return new ArrayList<>(submissions); // Return a copy to prevent modification
                }
            }
            return new ArrayList<>();
        }
    }
// {/fact}

    // Example 15: Singleton with request-specific processing and no shared state
    public static class good_case_15 {
        private static good_case_15 instance = new good_case_15();
        
// {fact rule=thread-safety-violation@v1.0 defects=0}
        private good_case_15() {}
        
        public static good_case_15 getInstance() {
            return instance;
        }
        
        public String processUserActivity(HttpServletRequest request) {
            // ok: java-thread-safe-object-in-singleton
            String userId = request.getParameter("userId"); // Local variable, not instance variable
            long activityTime = System.currentTimeMillis(); // Local variable, not instance variable
            
            // Process the data using local variables
            return "User: " + userId + ", Activity time: " + activityTime;
        }
    }
// {/fact}
}