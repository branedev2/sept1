import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;

// Mock MetricsManager class for testing purposes
class MetricsManager {
    private static final Logger logger = Logger.getLogger(MetricsManager.class.getName());
    private static final MetricsManager instance = new MetricsManager();
    
    private MetricsManager() {}
    
    public static MetricsManager get() {
        logger.info("MetricsManager.get() called");
        return instance;
    }
    
    public void pop() {
        logger.info("MetricsManager.pop() called");
    }
    
    public void recordMetric(String name, long value) {
        logger.info("Recording metric: " + name + " = " + value);
    }
    
    public void startTimer(String name) {
        logger.info("Starting timer: " + name);
    }
    
    public void stopTimer(String name) {
        logger.info("Stopping timer: " + name);
    }
}

public class MetricsManagerUsageExamples {

    // True Positive Examples (Vulnerable Code)
    
// {fact rule=missing-release-of-memory@v1.0 defects=1}
    public void bad_case_1() {
        // ruleid: java-missing-metrics-manager-pop
        MetricsManager metricsManager = MetricsManager.get();
        metricsManager.recordMetric("requests", 1);
        // Missing pop() call
    }
    
    public void bad_case_2(HttpServletRequest request) {
        String operation = request.getParameter("operation");
        // ruleid: java-missing-metrics-manager-pop
        MetricsManager metrics = MetricsManager.get();
        metrics.startTimer(operation);
        metrics.stopTimer(operation);
        // No pop() call before method exit
    }
    
    public void bad_case_3() {
        try {
            // ruleid: java-missing-metrics-manager-pop
            MetricsManager metrics = MetricsManager.get();
            metrics.recordMetric("process_start", System.currentTimeMillis());
            // Some processing that might throw an exception
            int result = 100 / 0; // Will throw ArithmeticException
            metrics.recordMetric("process_end", System.currentTimeMillis());
            // Missing pop() in normal flow and exception handler
        } catch (Exception e) {
            // Exception handler without pop()
            System.err.println("Error: " + e.getMessage());
        }
    }
    
    public void bad_case_4() {
        // ruleid: java-missing-metrics-manager-pop
        MetricsManager.get().recordMetric("direct_call", 1);
        // No variable to call pop() on
    }
    
    public void bad_case_5(boolean condition) {
        // ruleid: java-missing-metrics-manager-pop
        MetricsManager metrics = MetricsManager.get();
        if (condition) {
            metrics.recordMetric("condition_true", 1);
            return; // Early return without pop()
        }
        metrics.recordMetric("condition_false", 1);
        // No pop() call in any branch
    }
    
    public void bad_case_6() {
        for (int i = 0; i < 5; i++) {
            // ruleid: java-missing-metrics-manager-pop
            MetricsManager metrics = MetricsManager.get();
            metrics.recordMetric("iteration_" + i, i);
            // Missing pop() in loop
        }
    }
    
    public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userId = request.getParameter("userId");
        // ruleid: java-missing-metrics-manager-pop
        MetricsManager metrics = MetricsManager.get();
        metrics.startTimer("user_lookup");
        
        // Simulate user lookup
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        metrics.stopTimer("user_lookup");
        response.getWriter().write("User: " + userId);
        // Missing pop() call
    }
    
    public void bad_case_8() {
        // ruleid: java-missing-metrics-manager-pop
        MetricsManager metrics = MetricsManager.get();
        
        try {
            metrics.startTimer("operation");
            // Simulate work
            Thread.sleep(50);
            metrics.stopTimer("operation");
            
            // Missing pop() in try block
        } catch (InterruptedException e) {
            metrics.recordMetric("operation_interrupted", 1);
            // Missing pop() in catch block
        }
    }
    
    public void bad_case_9(Map<String, String> config) {
        // ruleid: java-missing-metrics-manager-pop
        MetricsManager metrics = MetricsManager.get();
        
        for (Map.Entry<String, String> entry : config.entrySet()) {
            metrics.recordMetric("config_" + entry.getKey(), entry.getValue().length());
        }
        
        if (config.isEmpty()) {
            metrics.recordMetric("empty_config", 1);
            return; // Early return without pop()
        }
        
        // No pop() call in normal flow either
    }
    
    public void bad_case_10() {
        Runnable task = () -> {
            // ruleid: java-missing-metrics-manager-pop
            MetricsManager metrics = MetricsManager.get();
            metrics.recordMetric("async_task", 1);
            // Missing pop() in lambda
        };
        
        new Thread(task).start();
    }
    
    public void bad_case_11(HttpServletRequest request) {
        String action = request.getParameter("action");
        
        switch (action) {
            case "create":
                // ruleid: java-missing-metrics-manager-pop
                MetricsManager metrics1 = MetricsManager.get();
                metrics1.recordMetric("create_action", 1);
                break;
            case "update":
                // ruleid: java-missing-metrics-manager-pop
                MetricsManager metrics2 = MetricsManager.get();
                metrics2.recordMetric("update_action", 1);
                break;
            default:
                // ruleid: java-missing-metrics-manager-pop
                MetricsManager metrics3 = MetricsManager.get();
                metrics3.recordMetric("other_action", 1);
                break;
        }
        // No pop() calls in any case
    }
    
    public void bad_case_12() {
        // ruleid: java-missing-metrics-manager-pop
        MetricsManager metrics = MetricsManager.get();
        
        try {
            metrics.startTimer("critical_operation");
            performCriticalOperation();
            metrics.stopTimer("critical_operation");
        } finally {
            // Even the finally block is missing the pop() call
            metrics.recordMetric("operation_completed", 1);
        }
    }
    
    private void performCriticalOperation() {
        // Simulate some critical operation
    }
    
    public void bad_case_13(HttpServletRequest request) {
        // ruleid: java-missing-metrics-manager-pop
        MetricsManager metrics = MetricsManager.get();
        
        String[] params = request.getParameterValues("items");
        if (params != null) {
            metrics.recordMetric("item_count", params.length);
            
            for (String item : params) {
                processItem(item, metrics);
            }
        }
        
        // No pop() call before method exit
    }
    
    private void processItem(String item, MetricsManager metrics) {
        metrics.recordMetric("item_length", item.length());
    }
    
    public void bad_case_14() {
        // ruleid: java-missing-metrics-manager-pop
        final MetricsManager metrics = MetricsManager.get();
        
        Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {
                metrics.recordMetric("shutdown_hook", 1);
                // No pop() call in shutdown hook
            }
        });
        
        metrics.recordMetric("application_started", 1);
        // No pop() call in main flow
    }
    
    public void bad_case_15(HttpServletRequest request) {
        int count = 0;
        try {
            count = Integer.parseInt(request.getParameter("count"));
        } catch (NumberFormatException e) {
            count = 0;
        }
        
        // ruleid: java-missing-metrics-manager-pop
        MetricsManager metrics = MetricsManager.get();
        metrics.recordMetric("request_count", count);
        
        if (count <= 0) {
            metrics.recordMetric("invalid_count", 1);
        } else if (count > 100) {
            metrics.recordMetric("large_count", 1);
        } else {
            metrics.recordMetric("normal_count", 1);
        }
        
        // No pop() call in any flow path
    }
    
    // True Negative Examples (Safe Code)
    
    public void good_case_1() {
        // ok: java-missing-metrics-manager-pop
        MetricsManager metricsManager = MetricsManager.get();
        try {
            metricsManager.recordMetric("requests", 1);
        } finally {
            metricsManager.pop();
        }
    }
    
    public void good_case_2(HttpServletRequest request) {
        String operation = request.getParameter("operation");
        // ok: java-missing-metrics-manager-pop
        MetricsManager metrics = MetricsManager.get();
        try {
            metrics.startTimer(operation);
            metrics.stopTimer(operation);
        } finally {
            metrics.pop();
        }
    }
    
    public void good_case_3() {
        // ok: java-missing-metrics-manager-pop
        MetricsManager metrics = MetricsManager.get();
        try {
            metrics.recordMetric("process_start", System.currentTimeMillis());
            try {
                // Some processing that might throw an exception
                int result = 100 / 0; // Will throw ArithmeticException
            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
            }
            metrics.recordMetric("process_end", System.currentTimeMillis());
        } finally {
            metrics.pop();
        }
    }
    
    public void good_case_4() {
        // ok: java-missing-metrics-manager-pop
        MetricsManager metrics = MetricsManager.get();
        try {
            metrics.recordMetric("direct_call", 1);
        } finally {
            metrics.pop();
        }
    }
    
    public void good_case_5(boolean condition) {
        // ok: java-missing-metrics-manager-pop
        MetricsManager metrics = MetricsManager.get();
        try {
            if (condition) {
                metrics.recordMetric("condition_true", 1);
                return; // Early return is safe because of finally block
            }
            metrics.recordMetric("condition_false", 1);
        } finally {
            metrics.pop();
        }
    }
    
    public void good_case_6() {
        for (int i = 0; i < 5; i++) {
            // ok: java-missing-metrics-manager-pop
            MetricsManager metrics = MetricsManager.get();
            try {
                metrics.recordMetric("iteration_" + i, i);
            } finally {
                metrics.pop();
            }
        }
    }
    
    public void good_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String userId = request.getParameter("userId");
        // ok: java-missing-metrics-manager-pop
        MetricsManager metrics = MetricsManager.get();
        try {
            metrics.startTimer("user_lookup");
            
            // Simulate user lookup
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            
            metrics.stopTimer("user_lookup");
            response.getWriter().write("User: " + userId);
        } finally {
            metrics.pop();
        }
    }
    
    public void good_case_8() {
        // ok: java-missing-metrics-manager-pop
        MetricsManager metrics = MetricsManager.get();
        
        try {
            try {
                metrics.startTimer("operation");
                // Simulate work
                Thread.sleep(50);
            } catch (InterruptedException e) {
                metrics.recordMetric("operation_interrupted", 1);
            } finally {
                metrics.stopTimer("operation");
            }
        } finally {
            metrics.pop();
        }
    }
    
    public void good_case_9(Map<String, String> config) {
        // ok: java-missing-metrics-manager-pop
        MetricsManager metrics = MetricsManager.get();
        
        try {
            for (Map.Entry<String, String> entry : config.entrySet()) {
                metrics.recordMetric("config_" + entry.getKey(), entry.getValue().length());
            }
            
            if (config.isEmpty()) {
                metrics.recordMetric("empty_config", 1);
                return; // Early return is safe with finally block
            }
        } finally {
            metrics.pop();
        }
    }
    
    public void good_case_10() {
        Runnable task = () -> {
            // ok: java-missing-metrics-manager-pop
            MetricsManager metrics = MetricsManager.get();
            try {
                metrics.recordMetric("async_task", 1);
            } finally {
                metrics.pop();
            }
        };
        
        new Thread(task).start();
    }
    
    public void good_case_11(HttpServletRequest request) {
        String action = request.getParameter("action");
        
        // ok: java-missing-metrics-manager-pop
        MetricsManager metrics = MetricsManager.get();
        try {
            switch (action) {
                case "create":
                    metrics.recordMetric("create_action", 1);
                    break;
                case "update":
                    metrics.recordMetric("update_action", 1);
                    break;
                default:
                    metrics.recordMetric("other_action", 1);
                    break;
            }
        } finally {
            metrics.pop();
        }
    }
    
    public void good_case_12() {
        // ok: java-missing-metrics-manager-pop
        MetricsManager metrics = MetricsManager.get();
        
        try {
            metrics.startTimer("critical_operation");
            try {
                performCriticalOperation();
            } finally {
                metrics.stopTimer("critical_operation");
            }
            metrics.recordMetric("operation_completed", 1);
        } finally {
            metrics.pop();
        }
    }
    
    public void good_case_13(HttpServletRequest request) {
        // ok: java-missing-metrics-manager-pop
        MetricsManager metrics = MetricsManager.get();
        
        try {
            String[] params = request.getParameterValues("items");
            if (params != null) {
                metrics.recordMetric("item_count", params.length);
                
                for (String item : params) {
                    processItemSafely(item, metrics);
                }
            }
        } finally {
            metrics.pop();
        }
    }
    
    private void processItemSafely(String item, MetricsManager metrics) {
        metrics.recordMetric("item_length", item.length());
    }
    
    public void good_case_14() {
        // ok: java-missing-metrics-manager-pop
        final MetricsManager metrics = MetricsManager.get();
        
        try {
            Runtime.getRuntime().addShutdownHook(new Thread() {
                @Override
                public void run() {
                    // Create a new metrics manager for the shutdown hook
                    MetricsManager shutdownMetrics = MetricsManager.get();
                    try {
                        shutdownMetrics.recordMetric("shutdown_hook", 1);
                    } finally {
                        shutdownMetrics.pop();
                    }
                }
            });
            
            metrics.recordMetric("application_started", 1);
        } finally {
            metrics.pop();
        }
    }
    
    public void good_case_15(HttpServletRequest request) {
        int count = 0;
        try {
            count = Integer.parseInt(request.getParameter("count"));
        } catch (NumberFormatException e) {
            count = 0;
        }
        
        // ok: java-missing-metrics-manager-pop
        MetricsManager metrics = MetricsManager.get();
        try {
            metrics.recordMetric("request_count", count);
            
            if (count <= 0) {
                metrics.recordMetric("invalid_count", 1);
            } else if (count > 100) {
                metrics.recordMetric("large_count", 1);
            } else {
                metrics.recordMetric("normal_count", 1);
            }
        } finally {
            metrics.pop();
        }
    }
}
// {/fact}

@WebServlet("/metrics-example")
class MetricsServletExample extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        // This is just a container class to demonstrate servlet context
        // The actual test cases are in the MetricsManagerUsageExamples class
        new MetricsManagerUsageExamples().good_case_7(request, response);
    }
}