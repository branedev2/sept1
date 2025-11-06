import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.io.IOException;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;

// Mock MetricsManager class for examples
class MetricsManager {
    private static final MetricsManager INSTANCE = new MetricsManager();
    private final Map<String, Metrics> metricsMap = new HashMap<>();
    
    private MetricsManager() {}
    
    public static MetricsManager getInstance() {
        return INSTANCE;
    }
    
    public static Metrics get() {
        return getInstance().getMetrics();
    }
    
    private Metrics getMetrics() {
        String name = Thread.currentThread().getName();
        if (!metricsMap.containsKey(name)) {
            metricsMap.put(name, new Metrics(name));
        }
        return metricsMap.get(name);
    }
    
    public static void pop() {
        getInstance().popMetrics();
    }
    
    private void popMetrics() {
        String name = Thread.currentThread().getName();
        metricsMap.remove(name);
    }
}

class Metrics {
    private final String name;
    private long startTime;
    
    public Metrics(String name) {
        this.name = name;
        this.startTime = System.nanoTime();
    }
    
    public void recordLatency() {
        long latency = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime);
        System.out.println("Latency for " + name + ": " + latency + "ms");
    }
    
    public void incrementCounter(String counterName) {
        System.out.println("Incrementing counter: " + counterName);
    }
}

// True Positive Examples (Vulnerable Code)

@WebServlet("/metrics-test-bad1")
public class BadMetricsUsageServlet1 extends HttpServlet {
    private static final Logger logger = Logger.getLogger(BadMetricsUsageServlet1.class.getName());
    
// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // ruleid: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        String username = request.getParameter("username");
        logger.info("Processing request for user: " + username);
        
        metrics.incrementCounter("user_request");
        metrics.recordLatency();
        
        // Missing MetricsManager.pop() call
        response.getWriter().println("Request processed");
    }
}
// {/fact}

class BadMetricsUsageExample2 {
// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_2() {
        try {
            // ruleid: java-missing-metrics-manager-pop
            Metrics metrics = MetricsManager.get();
            
            // Do some work
            metrics.incrementCounter("process_started");
            
            // Simulate processing
            Thread.sleep(100);
            
            metrics.recordLatency();
            // Missing MetricsManager.pop() call
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
// {/fact}

class BadMetricsUsageExample3 {
// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_3(String operation) {
        // ruleid: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        if (operation.equals("read")) {
            metrics.incrementCounter("read_operation");
        } else if (operation.equals("write")) {
            metrics.incrementCounter("write_operation");
        } else {
            metrics.incrementCounter("unknown_operation");
        }
        
        // Missing MetricsManager.pop() call
    }
}
// {/fact}

class BadMetricsUsageExample4 {
// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_4() {
        // ruleid: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        for (int i = 0; i < 5; i++) {
            metrics.incrementCounter("iteration_" + i);
            // Simulate work
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        
        metrics.recordLatency();
        // Missing MetricsManager.pop() call
    }
}
// {/fact}

class BadMetricsUsageExample5 {
// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_5(boolean condition) {
        // ruleid: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        try {
            if (condition) {
                metrics.incrementCounter("condition_true");
                // Some processing
            } else {
                metrics.incrementCounter("condition_false");
                // Other processing
                throw new RuntimeException("Test exception");
            }
        } catch (Exception e) {
            metrics.incrementCounter("error_occurred");
        }
        
        // Missing MetricsManager.pop() call
    }
}
// {/fact}

class BadMetricsUsageExample6 {
// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_6() {
        // ruleid: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        Runnable task = () -> {
            metrics.incrementCounter("async_task");
            metrics.recordLatency();
            // Missing MetricsManager.pop() in lambda
        };
        
        new Thread(task).start();
    }
}
// {/fact}

class BadMetricsUsageExample7 {
// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_7(Map<String, String> data) {
        // ruleid: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        data.forEach((key, value) -> {
            metrics.incrementCounter("process_entry");
            // Process each entry
        });
        
        metrics.recordLatency();
        // Missing MetricsManager.pop() call
    }
}
// {/fact}

class BadMetricsUsageExample8 {
// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_8() {
        // ruleid: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        switch (getOperationType()) {
            case "CREATE":
                metrics.incrementCounter("create_operation");
                break;
            case "READ":
                metrics.incrementCounter("read_operation");
                break;
            case "UPDATE":
                metrics.incrementCounter("update_operation");
                break;
            case "DELETE":
                metrics.incrementCounter("delete_operation");
                break;
            default:
                metrics.incrementCounter("unknown_operation");
        }
        
        // Missing MetricsManager.pop() call
    }
    
    private String getOperationType() {
        return "READ"; // Just for example
    }
}
// {/fact}

class BadMetricsUsageExample9 {
// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_9() {
        // ruleid: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        try {
            // Simulate some I/O operation
            metrics.incrementCounter("io_operation_start");
            // I/O operation
            metrics.incrementCounter("io_operation_complete");
        } finally {
            metrics.recordLatency();
            // Missing MetricsManager.pop() call even in finally block
        }
    }
}
// {/fact}

class BadMetricsUsageExample10 {
// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_10(int iterations) {
        // ruleid: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        int i = 0;
        while (i < iterations) {
            metrics.incrementCounter("iteration");
            i++;
            
            if (i == iterations / 2) {
                metrics.incrementCounter("halfway_point");
            }
        }
        
        metrics.recordLatency();
        // Missing MetricsManager.pop() call
    }
}
// {/fact}

class BadMetricsUsageExample11 {
// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_11(String[] items) {
        // ruleid: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        for (String item : items) {
            if (item == null || item.isEmpty()) {
                metrics.incrementCounter("empty_item");
                continue;
            }
            
            metrics.incrementCounter("process_item");
            // Process item
        }
        
        // Missing MetricsManager.pop() call
    }
}
// {/fact}

class BadMetricsUsageExample12 {
// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_12() {
        // ruleid: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        try {
            metrics.incrementCounter("operation_start");
            // Do work
            metrics.incrementCounter("operation_complete");
            return; // Early return without pop()
        } catch (Exception e) {
            metrics.incrementCounter("operation_error");
            // Missing MetricsManager.pop() call
        }
    }
}
// {/fact}

class BadMetricsUsageExample13 {
// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_13(boolean shouldProcess) {
        // ruleid: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        if (!shouldProcess) {
            metrics.incrementCounter("skipped_processing");
            return; // Early return without pop()
        }
        
        metrics.incrementCounter("processing");
        // Process
        metrics.recordLatency();
        // Missing MetricsManager.pop() call
    }
}
// {/fact}

class BadMetricsUsageExample14 {
// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_14() {
        // ruleid: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        metrics.incrementCounter("nested_operation_start");
        
        // Nested operation that also uses metrics
        nestedOperation();
        
        metrics.incrementCounter("nested_operation_end");
        metrics.recordLatency();
        // Missing MetricsManager.pop() call
    }
    
    private void nestedOperation() {
        // Some operation
    }
}
// {/fact}

class BadMetricsUsageExample15 {
// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_15(HttpServletRequest request) {
        // ruleid: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        String action = request.getParameter("action");
        if (action != null) {
            metrics.incrementCounter("action_" + action);
            // Process action
        } else {
            metrics.incrementCounter("no_action");
        }
        
        metrics.recordLatency();
        // Missing MetricsManager.pop() call
    }
}
// {/fact}

// True Negative Examples (Safe Code)

@WebServlet("/metrics-test-good1")
public class GoodMetricsUsageServlet1 extends HttpServlet {
    private static final Logger logger = Logger.getLogger(GoodMetricsUsageServlet1.class.getName());
    
// {fact rule=guru-cfn-lint@v1.0 defects=0}
    public void good_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // ok: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        try {
            String username = request.getParameter("username");
            logger.info("Processing request for user: " + username);
            
            metrics.incrementCounter("user_request");
            metrics.recordLatency();
            
            response.getWriter().println("Request processed");
        } finally {
            MetricsManager.pop(); // Properly releasing metrics
        }
    }
}
// {/fact}

class GoodMetricsUsageExample2 {
// {fact rule=guru-cfn-lint@v1.0 defects=0}
    public void good_case_2() {
        // ok: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        try {
            // Do some work
            metrics.incrementCounter("process_started");
            
            // Simulate processing
            Thread.sleep(100);
            
            metrics.recordLatency();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            MetricsManager.pop(); // Properly releasing metrics
        }
    }
}
// {/fact}

class GoodMetricsUsageExample3 {
// {fact rule=guru-cfn-lint@v1.0 defects=0}
    public void good_case_3(String operation) {
        // ok: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        try {
            if (operation.equals("read")) {
                metrics.incrementCounter("read_operation");
            } else if (operation.equals("write")) {
                metrics.incrementCounter("write_operation");
            } else {
                metrics.incrementCounter("unknown_operation");
            }
        } finally {
            MetricsManager.pop(); // Properly releasing metrics
        }
    }
}
// {/fact}

class GoodMetricsUsageExample4 {
// {fact rule=guru-cfn-lint@v1.0 defects=0}
    public void good_case_4() {
        // ok: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        try {
            for (int i = 0; i < 5; i++) {
                metrics.incrementCounter("iteration_" + i);
                // Simulate work
                try {
                    Thread.sleep(10);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            
            metrics.recordLatency();
        } finally {
            MetricsManager.pop(); // Properly releasing metrics
        }
    }
}
// {/fact}

class GoodMetricsUsageExample5 {
// {fact rule=guru-cfn-lint@v1.0 defects=0}
    public void good_case_5(boolean condition) {
        // ok: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        try {
            try {
                if (condition) {
                    metrics.incrementCounter("condition_true");
                    // Some processing
                } else {
                    metrics.incrementCounter("condition_false");
                    // Other processing
                    throw new RuntimeException("Test exception");
                }
            } catch (Exception e) {
                metrics.incrementCounter("error_occurred");
            }
        } finally {
            MetricsManager.pop(); // Properly releasing metrics
        }
    }
}
// {/fact}

class GoodMetricsUsageExample6 {
// {fact rule=guru-cfn-lint@v1.0 defects=0}
    public void good_case_6() {
        Runnable task = () -> {
            // ok: java-missing-metrics-manager-pop
            Metrics metrics = MetricsManager.get();
            try {
                metrics.incrementCounter("async_task");
                metrics.recordLatency();
            } finally {
                MetricsManager.pop(); // Properly releasing metrics in lambda
            }
        };
        
        new Thread(task).start();
    }
}
// {/fact}

class GoodMetricsUsageExample7 {
// {fact rule=guru-cfn-lint@v1.0 defects=0}
    public void good_case_7(Map<String, String> data) {
        // ok: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        try {
            data.forEach((key, value) -> {
                metrics.incrementCounter("process_entry");
                // Process each entry
            });
            
            metrics.recordLatency();
        } finally {
            MetricsManager.pop(); // Properly releasing metrics
        }
    }
}
// {/fact}

class GoodMetricsUsageExample8 {
// {fact rule=guru-cfn-lint@v1.0 defects=0}
    public void good_case_8() {
        // ok: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        try {
            switch (getOperationType()) {
                case "CREATE":
                    metrics.incrementCounter("create_operation");
                    break;
                case "READ":
                    metrics.incrementCounter("read_operation");
                    break;
                case "UPDATE":
                    metrics.incrementCounter("update_operation");
                    break;
                case "DELETE":
                    metrics.incrementCounter("delete_operation");
                    break;
                default:
                    metrics.incrementCounter("unknown_operation");
            }
        } finally {
            MetricsManager.pop(); // Properly releasing metrics
        }
    }
    
    private String getOperationType() {
        return "READ"; // Just for example
    }
}
// {/fact}

class GoodMetricsUsageExample9 {
// {fact rule=guru-cfn-lint@v1.0 defects=0}
    public void good_case_9() {
        // ok: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        try {
            // Simulate some I/O operation
            metrics.incrementCounter("io_operation_start");
            // I/O operation
            metrics.incrementCounter("io_operation_complete");
        } finally {
            metrics.recordLatency();
            MetricsManager.pop(); // Properly releasing metrics in finally block
        }
    }
}
// {/fact}

class GoodMetricsUsageExample10 {
// {fact rule=guru-cfn-lint@v1.0 defects=0}
    public void good_case_10(int iterations) {
        // ok: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        try {
            int i = 0;
            while (i < iterations) {
                metrics.incrementCounter("iteration");
                i++;
                
                if (i == iterations / 2) {
                    metrics.incrementCounter("halfway_point");
                }
            }
            
            metrics.recordLatency();
        } finally {
            MetricsManager.pop(); // Properly releasing metrics
        }
    }
}
// {/fact}

class GoodMetricsUsageExample11 {
// {fact rule=guru-cfn-lint@v1.0 defects=0}
    public void good_case_11(String[] items) {
        // ok: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        try {
            for (String item : items) {
                if (item == null || item.isEmpty()) {
                    metrics.incrementCounter("empty_item");
                    continue;
                }
                
                metrics.incrementCounter("process_item");
                // Process item
            }
        } finally {
            MetricsManager.pop(); // Properly releasing metrics
        }
    }
}
// {/fact}

class GoodMetricsUsageExample12 {
// {fact rule=guru-cfn-lint@v1.0 defects=0}
    public void good_case_12() {
        // ok: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        try {
            metrics.incrementCounter("operation_start");
            // Do work
            metrics.incrementCounter("operation_complete");
            return; // Early return with pop() in finally
        } catch (Exception e) {
            metrics.incrementCounter("operation_error");
        } finally {
            MetricsManager.pop(); // Properly releasing metrics even with early return
        }
    }
}
// {/fact}

class GoodMetricsUsageExample13 {
// {fact rule=guru-cfn-lint@v1.0 defects=0}
    public void good_case_13(boolean shouldProcess) {
        // ok: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        try {
            if (!shouldProcess) {
                metrics.incrementCounter("skipped_processing");
                return; // Early return with pop() in finally
            }
            
            metrics.incrementCounter("processing");
            // Process
            metrics.recordLatency();
        } finally {
            MetricsManager.pop(); // Properly releasing metrics
        }
    }
}
// {/fact}

class GoodMetricsUsageExample14 {
// {fact rule=guru-cfn-lint@v1.0 defects=0}
    public void good_case_14() {
        // ok: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        try {
            metrics.incrementCounter("nested_operation_start");
            
            // Nested operation that also uses metrics
            nestedOperation();
            
            metrics.incrementCounter("nested_operation_end");
            metrics.recordLatency();
        } finally {
            MetricsManager.pop(); // Properly releasing metrics
        }
    }
    
    private void nestedOperation() {
        // Some operation
    }
}
// {/fact}

class GoodMetricsUsageExample15 {
// {fact rule=guru-cfn-lint@v1.0 defects=0}
    public void good_case_15(HttpServletRequest request) {
        // ok: java-missing-metrics-manager-pop
        Metrics metrics = MetricsManager.get();
        
        try {
            String action = request.getParameter("action");
            if (action != null) {
                metrics.incrementCounter("action_" + action);
                // Process action
            } else {
                metrics.incrementCounter("no_action");
            }
            
            metrics.recordLatency();
        } finally {
            MetricsManager.pop(); // Properly releasing metrics
        }
    }
}
// {/fact}