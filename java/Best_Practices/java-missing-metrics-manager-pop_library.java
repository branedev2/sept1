import com.example.metrics.MetricsManager;
import com.example.metrics.MetricsContext;
import com.example.metrics.MetricsScope;
import com.example.metrics.MetricsTracker;
import com.example.metrics.MetricsCollector;
import com.example.metrics.PerformanceMetrics;
import com.example.metrics.ApplicationMetrics;
import com.example.metrics.DatabaseMetrics;
import com.example.metrics.NetworkMetrics;
import com.example.metrics.CacheMetrics;
import com.example.metrics.ThreadMetrics;
import com.example.metrics.CPUMetrics;
import com.example.metrics.MemoryMetrics;
import com.example.metrics.IOMetrics;
import com.example.metrics.APIMetrics;
import com.example.metrics.RequestMetrics;
import com.example.metrics.ResponseMetrics;
import com.example.metrics.TransactionMetrics;
import com.example.metrics.UserMetrics;
import com.example.metrics.SessionMetrics;
import com.example.metrics.SecurityMetrics;
import com.example.metrics.ErrorMetrics;
import com.example.metrics.LoggingMetrics;
import com.example.metrics.EventMetrics;
import com.example.metrics.QueueMetrics;
import com.example.metrics.BatchMetrics;
import com.example.metrics.StreamMetrics;
import com.example.metrics.ClusterMetrics;
import com.example.metrics.NodeMetrics;
import com.example.metrics.ServiceMetrics;

// Security Issue: Missing pop() call after MetricsManager.get() which can lead to resource leaks and inaccurate metrics

// True Positive Examples (Vulnerable/Insecure Code)
public void bad_case_1() {
    // Basic case - no pop() call after get()
    // ruleid: java-missing-metrics-manager-pop
    MetricsManager.get().startRequest("api/users");
    try {
        // Process request
        System.out.println("Processing request");
    } catch (Exception e) {
        // Handle exception
    }
    // Missing pop() call
}

public void bad_case_2() {
    // Using metrics in a web application context
    // ruleid: java-missing-metrics-manager-pop
    MetricsContext context = MetricsManager.get();
    context.recordEvent("user_login");
    context.incrementCounter("login_attempts");
    
    // Process login
    System.out.println("Processing login");
    
    // Missing pop() call before method exit
}

public void bad_case_3() {
    // Using metrics in a conditional branch
    boolean isSuccessful = true;
    
    // ruleid: java-missing-metrics-manager-pop
    MetricsScope scope = MetricsManager.get();
    scope.startTimer("operation");
    
    if (isSuccessful) {
        scope.incrementCounter("success");
        return; // Early return without pop()
    } else {
        scope.incrementCounter("failure");
        // No pop() call in this branch either
    }
}

public void bad_case_4() {
    // Using metrics in a loop
    for (int i = 0; i < 5; i++) {
        // ruleid: java-missing-metrics-manager-pop
        MetricsTracker tracker = MetricsManager.get();
        tracker.trackOperation("iteration_" + i);
        
        // Process iteration
        System.out.println("Processing iteration " + i);
        
        // Missing pop() call in each iteration
    }
}

public void bad_case_5() {
    // Using metrics with exception handling
    try {
        // ruleid: java-missing-metrics-manager-pop
        MetricsCollector collector = MetricsManager.get();
        collector.startCollection("data_processing");
        
        // Process data
        System.out.println("Processing data");
        
        throw new RuntimeException("Simulated error");
    } catch (Exception e) {
        System.err.println("Error: " + e.getMessage());
        // Missing pop() call in exception handler
    }
}

public void bad_case_6() {
    // Using performance metrics
    // ruleid: java-missing-metrics-manager-pop
    PerformanceMetrics metrics = MetricsManager.get();
    metrics.startMeasurement("algorithm_execution");
    
    // Execute algorithm
    System.out.println("Executing algorithm");
    
    metrics.endMeasurement("algorithm_execution");
    // Missing pop() call
}

public void bad_case_7() {
    // Using application metrics with nested operations
    // ruleid: java-missing-metrics-manager-pop
    ApplicationMetrics appMetrics = MetricsManager.get();
    appMetrics.recordApplicationStart();
    
    try {
        // Initialize components
        System.out.println("Initializing components");
        
        // Nested operations
        for (int i = 0; i < 3; i++) {
            appMetrics.recordComponentInitialization("component_" + i);
        }
        
        appMetrics.recordApplicationReady();
    } catch (Exception e) {
        appMetrics.recordApplicationError(e);
    }
    // Missing pop() call
}

public void bad_case_8() {
    // Using database metrics
    // ruleid: java-missing-metrics-manager-pop
    DatabaseMetrics dbMetrics = MetricsManager.get();
    dbMetrics.startQuery("SELECT * FROM users");
    
    // Execute query
    System.out.println("Executing database query");
    
    dbMetrics.endQuery("SELECT * FROM users", 100);
    // Missing pop() call
}

public void bad_case_9() {
    // Using network metrics
    // ruleid: java-missing-metrics-manager-pop
    NetworkMetrics netMetrics = MetricsManager.get();
    netMetrics.recordNetworkRequest("api.example.com");
    
    // Make network request
    System.out.println("Making network request");
    
    netMetrics.recordNetworkResponse("api.example.com", 200);
    // Missing pop() call
}

public void bad_case_10() {
    // Using cache metrics
    // ruleid: java-missing-metrics-manager-pop
    CacheMetrics cacheMetrics = MetricsManager.get();
    cacheMetrics.recordCacheAccess("user_data");
    
    // Access cache
    System.out.println("Accessing cache");
    
    cacheMetrics.recordCacheHit("user_data");
    // Missing pop() call
}

public void bad_case_11() {
    // Using thread metrics
    // ruleid: java-missing-metrics-manager-pop
    ThreadMetrics threadMetrics = MetricsManager.get();
    threadMetrics.recordThreadStart("worker-1");
    
    // Execute thread
    System.out.println("Executing thread");
    
    threadMetrics.recordThreadEnd("worker-1");
    // Missing pop() call
}

public void bad_case_12() {
    // Using CPU metrics
    // ruleid: java-missing-metrics-manager-pop
    CPUMetrics cpuMetrics = MetricsManager.get();
    cpuMetrics.startCPUIntensiveTask("data_processing");
    
    // Process data
    System.out.println("Processing data");
    
    cpuMetrics.endCPUIntensiveTask("data_processing");
    // Missing pop() call
}

public void bad_case_13() {
    // Using memory metrics
    // ruleid: java-missing-metrics-manager-pop
    MemoryMetrics memoryMetrics = MetricsManager.get();
    memoryMetrics.recordMemoryAllocation("large_buffer");
    
    // Allocate memory
    System.out.println("Allocating memory");
    
    memoryMetrics.recordMemoryDeallocation("large_buffer");
    // Missing pop() call
}

public void bad_case_14() {
    // Using I/O metrics
    // ruleid: java-missing-metrics-manager-pop
    IOMetrics ioMetrics = MetricsManager.get();
    ioMetrics.startFileOperation("config.json");
    
    // Perform file operation
    System.out.println("Performing file operation");
    
    ioMetrics.endFileOperation("config.json");
    // Missing pop() call
}

public void bad_case_15() {
    // Using API metrics
    // ruleid: java-missing-metrics-manager-pop
    APIMetrics apiMetrics = MetricsManager.get();
    apiMetrics.recordAPICall("/api/v1/users");
    
    // Make API call
    System.out.println("Making API call");
    
    apiMetrics.recordAPIResponse("/api/v1/users", 200);
    // Missing pop() call
}

// True Negative Examples (Safe/Secure Code)
public void good_case_1() {
    // Basic case - proper pop() call after get()
    // ok: java-missing-metrics-manager-pop
    MetricsManager.get().startRequest("api/users");
    try {
        // Process request
        System.out.println("Processing request");
    } catch (Exception e) {
        // Handle exception
    } finally {
        MetricsManager.pop();
    }
}

public void good_case_2() {
    // Using metrics in a web application context with proper cleanup
    // ok: java-missing-metrics-manager-pop
    MetricsContext context = MetricsManager.get();
    try {
        context.recordEvent("user_login");
        context.incrementCounter("login_attempts");
        
        // Process login
        System.out.println("Processing login");
    } finally {
        MetricsManager.pop();
    }
}

public void good_case_3() {
    // Using metrics in a conditional branch with proper cleanup
    boolean isSuccessful = true;
    
    // ok: java-missing-metrics-manager-pop
    MetricsScope scope = MetricsManager.get();
    try {
        scope.startTimer("operation");
        
        if (isSuccessful) {
            scope.incrementCounter("success");
        } else {
            scope.incrementCounter("failure");
        }
    } finally {
        MetricsManager.pop();
    }
}

public void good_case_4() {
    // Using metrics in a loop with proper cleanup
    for (int i = 0; i < 5; i++) {
        // ok: java-missing-metrics-manager-pop
        MetricsTracker tracker = MetricsManager.get();
        try {
            tracker.trackOperation("iteration_" + i);
            
            // Process iteration
            System.out.println("Processing iteration " + i);
        } finally {
            MetricsManager.pop();
        }
    }
}

public void good_case_5() {
    // Using metrics with exception handling and proper cleanup
    try {
        // ok: java-missing-metrics-manager-pop
        MetricsCollector collector = MetricsManager.get();
        try {
            collector.startCollection("data_processing");
            
            // Process data
            System.out.println("Processing data");
            
            throw new RuntimeException("Simulated error");
        } finally {
            MetricsManager.pop();
        }
    } catch (Exception e) {
        System.err.println("Error: " + e.getMessage());
    }
}

public void good_case_6() {
    // Using performance metrics with proper cleanup
    // ok: java-missing-metrics-manager-pop
    PerformanceMetrics metrics = MetricsManager.get();
    try {
        metrics.startMeasurement("algorithm_execution");
        
        // Execute algorithm
        System.out.println("Executing algorithm");
        
        metrics.endMeasurement("algorithm_execution");
    } finally {
        MetricsManager.pop();
    }
}

public void good_case_7() {
    // Using application metrics with nested operations and proper cleanup
    // ok: java-missing-metrics-manager-pop
    ApplicationMetrics appMetrics = MetricsManager.get();
    try {
        appMetrics.recordApplicationStart();
        
        try {
            // Initialize components
            System.out.println("Initializing components");
            
            // Nested operations
            for (int i = 0; i < 3; i++) {
                appMetrics.recordComponentInitialization("component_" + i);
            }
            
            appMetrics.recordApplicationReady();
        } catch (Exception e) {
            appMetrics.recordApplicationError(e);
        }
    } finally {
        MetricsManager.pop();
    }
}

public void good_case_8() {
    // Using database metrics with proper cleanup
    // ok: java-missing-metrics-manager-pop
    DatabaseMetrics dbMetrics = MetricsManager.get();
    try {
        dbMetrics.startQuery("SELECT * FROM users");
        
        // Execute query
        System.out.println("Executing database query");
        
        dbMetrics.endQuery("SELECT * FROM users", 100);
    } finally {
        MetricsManager.pop();
    }
}

public void good_case_9() {
    // Using network metrics with proper cleanup
    // ok: java-missing-metrics-manager-pop
    NetworkMetrics netMetrics = MetricsManager.get();
    try {
        netMetrics.recordNetworkRequest("api.example.com");
        
        // Make network request
        System.out.println("Making network request");
        
        netMetrics.recordNetworkResponse("api.example.com", 200);
    } finally {
        MetricsManager.pop();
    }
}

public void good_case_10() {
    // Using cache metrics with proper cleanup
    // ok: java-missing-metrics-manager-pop
    CacheMetrics cacheMetrics = MetricsManager.get();
    try {
        cacheMetrics.recordCacheAccess("user_data");
        
        // Access cache
        System.out.println("Accessing cache");
        
        cacheMetrics.recordCacheHit("user_data");
    } finally {
        MetricsManager.pop();
    }
}

public void good_case_11() {
    // Using thread metrics with proper cleanup
    // ok: java-missing-metrics-manager-pop
    ThreadMetrics threadMetrics = MetricsManager.get();
    try {
        threadMetrics.recordThreadStart("worker-1");
        
        // Execute thread
        System.out.println("Executing thread");
        
        threadMetrics.recordThreadEnd("worker-1");
    } finally {
        MetricsManager.pop();
    }
}

public void good_case_12() {
    // Using CPU metrics with proper cleanup
    // ok: java-missing-metrics-manager-pop
    CPUMetrics cpuMetrics = MetricsManager.get();
    try {
        cpuMetrics.startCPUIntensiveTask("data_processing");
        
        // Process data
        System.out.println("Processing data");
        
        cpuMetrics.endCPUIntensiveTask("data_processing");
    } finally {
        MetricsManager.pop();
    }
}

public void good_case_13() {
    // Using memory metrics with proper cleanup
    // ok: java-missing-metrics-manager-pop
    MemoryMetrics memoryMetrics = MetricsManager.get();
    try {
        memoryMetrics.recordMemoryAllocation("large_buffer");
        
        // Allocate memory
        System.out.println("Allocating memory");
        
        memoryMetrics.recordMemoryDeallocation("large_buffer");
    } finally {
        MetricsManager.pop();
    }
}

public void good_case_14() {
    // Using I/O metrics with proper cleanup
    // ok: java-missing-metrics-manager-pop
    IOMetrics ioMetrics = MetricsManager.get();
    try {
        ioMetrics.startFileOperation("config.json");
        
        // Perform file operation
        System.out.println("Performing file operation");
        
        ioMetrics.endFileOperation("config.json");
    } finally {
        MetricsManager.pop();
    }
}

public void good_case_15() {
    // Using API metrics with proper cleanup
    // ok: java-missing-metrics-manager-pop
    APIMetrics apiMetrics = MetricsManager.get();
    try {
        apiMetrics.recordAPICall("/api/v1/users");
        
        // Make API call
        System.out.println("Making API call");
        
        apiMetrics.recordAPIResponse("/api/v1/users", 200);
    } finally {
        MetricsManager.pop();
    }
}