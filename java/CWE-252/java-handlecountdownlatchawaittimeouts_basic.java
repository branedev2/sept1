import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

public class CountDownLatchAwaitTimeoutExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
    public void bad_case_1() {
        CountDownLatch latch = new CountDownLatch(1);
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            latch.await(1000, TimeUnit.MILLISECONDS);
            // Proceed without checking if await returned true or false
            System.out.println("Proceeding regardless of whether timeout occurred");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void bad_case_2() {
        CountDownLatch startSignal = new CountDownLatch(1);
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            startSignal.await(500, TimeUnit.MILLISECONDS);
            // No check of return value before proceeding with critical operation
            performCriticalOperation();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void bad_case_3() {
        CountDownLatch doneSignal = new CountDownLatch(5);
        ExecutorService executor = Executors.newFixedThreadPool(5);
        
        for (int i = 0; i < 5; i++) {
            executor.execute(() -> {
                try {
                    Thread.sleep(2000);
                    doneSignal.countDown();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            doneSignal.await(1, TimeUnit.SECONDS);
            // Ignoring the return value and assuming all tasks completed
            System.out.println("All tasks completed");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            executor.shutdown();
        }
    }

    public void bad_case_4() {
        CountDownLatch latch = new CountDownLatch(3);
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            latch.await(100, TimeUnit.MILLISECONDS);
            // Using result of operation that might not be complete
            processResults();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void bad_case_5() {
        CountDownLatch latch = new CountDownLatch(1);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        
        executor.submit(() -> {
            try {
                Thread.sleep(5000); // Simulate long operation
                latch.countDown();
                return true;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        });
        
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            latch.await(1, TimeUnit.SECONDS);
            // Proceed without checking if the operation completed
            System.out.println("Operation completed");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            executor.shutdown();
        }
    }

    public void bad_case_6() {
        CountDownLatch connectionLatch = new CountDownLatch(1);
        AtomicBoolean connected = new AtomicBoolean(false);
        
        // Simulate connection attempt in another thread
        new Thread(() -> {
            try {
                Thread.sleep(3000); // Simulate slow connection
                connected.set(true);
                connectionLatch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).start();
        
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            connectionLatch.await(1, TimeUnit.SECONDS);
            // Using connection without checking if it's established
            if (connected.get()) {
                System.out.println("Using connection");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void bad_case_7() {
        CountDownLatch initLatch = new CountDownLatch(1);
        final boolean[] initialized = {false};
        
        // Initialize in background
        new Thread(() -> {
            try {
                Thread.sleep(2000);
                initialized[0] = true;
                initLatch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).start();
        
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            initLatch.await(500, TimeUnit.MILLISECONDS);
            // Using system assuming initialization completed
            useInitializedSystem(initialized[0]);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void bad_case_8() {
        CountDownLatch latch = new CountDownLatch(2);
        
        // Start two worker threads
        for (int i = 0; i < 2; i++) {
            int workerId = i;
            new Thread(() -> {
                try {
                    Thread.sleep(workerId * 1000 + 1000);
                    latch.countDown();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }).start();
        }
        
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            latch.await(1500, TimeUnit.MILLISECONDS);
            // Continue with next phase regardless of workers completion
            System.out.println("Moving to next phase");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void bad_case_9() {
        CountDownLatch readyLatch = new CountDownLatch(3);
        
        // Simulate services starting up
        for (int i = 0; i < 3; i++) {
            final int serviceId = i;
            new Thread(() -> {
                try {
                    // Service 2 takes longer than our timeout
                    if (serviceId == 2) {
                        Thread.sleep(3000);
                    } else {
                        Thread.sleep(500);
                    }
                    readyLatch.countDown();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }).start();
        }
        
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            readyLatch.await(1, TimeUnit.SECONDS);
            // Start application without checking if all services are ready
            startApplication();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void bad_case_10() {
        CountDownLatch completionLatch = new CountDownLatch(1);
        StringBuilder result = new StringBuilder();
        
        // Simulate async operation
        new Thread(() -> {
            try {
                Thread.sleep(2000);
                result.append("Operation result");
                completionLatch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).start();
        
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            completionLatch.await(500, TimeUnit.MILLISECONDS);
            // Use result without checking if operation completed
            System.out.println("Result: " + result.toString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void bad_case_11() {
        final CountDownLatch latch = new CountDownLatch(1);
        final String[] response = {null};
        
        // Simulate network request
        new Thread(() -> {
            try {
                Thread.sleep(3000); // Simulate slow network
                response[0] = "Response data";
                latch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).start();
        
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            latch.await(1, TimeUnit.SECONDS);
            // Process response without checking if it was received
            processResponse(response[0]);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void bad_case_12() {
        CountDownLatch barrier = new CountDownLatch(4);
        
        // Start 4 tasks
        for (int i = 0; i < 4; i++) {
            final int taskId = i;
            new Thread(() -> {
                try {
                    // Last task takes much longer
                    if (taskId == 3) {
                        Thread.sleep(5000);
                    } else {
                        Thread.sleep(500);
                    }
                    barrier.countDown();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }).start();
        }
        
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            barrier.await(2, TimeUnit.SECONDS);
            // Continue with aggregation without checking if all tasks completed
            aggregateResults();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void bad_case_13() {
        CountDownLatch startupLatch = new CountDownLatch(1);
        boolean[] ready = {false};
        
        // Initialize system in background
        new Thread(() -> {
            try {
                Thread.sleep(4000); // Long initialization
                ready[0] = true;
                startupLatch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).start();
        
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            startupLatch.await(2, TimeUnit.SECONDS);
            // Proceed with operations assuming system is ready
            if (ready[0]) {
                performOperations();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void bad_case_14() {
        CountDownLatch shutdownLatch = new CountDownLatch(3);
        
        // Simulate services shutting down
        for (int i = 0; i < 3; i++) {
            final int serviceId = i;
            new Thread(() -> {
                try {
                    // Service 1 hangs during shutdown
                    if (serviceId == 1) {
                        Thread.sleep(10000);
                    } else {
                        Thread.sleep(500);
                        shutdownLatch.countDown();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }).start();
        }
        
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            shutdownLatch.await(3, TimeUnit.SECONDS);
            // Exit application without checking if all services shut down properly
            System.out.println("Application shutdown complete");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void bad_case_15() {
        CountDownLatch dataLatch = new CountDownLatch(1);
        final Object[] data = {null};
        
        // Load data asynchronously
        new Thread(() -> {
            try {
                Thread.sleep(3000); // Slow data loading
                data[0] = loadData();
                dataLatch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).start();
        
        try {
            // ruleid: java-handlecountdownlatchawaittimeouts
            dataLatch.await(1, TimeUnit.SECONDS);
            // Use data without checking if it was loaded
            processData(data[0]);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // True Negative Examples (Safe Code)

    public void good_case_1() {
        CountDownLatch latch = new CountDownLatch(1);
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            boolean completed = latch.await(1000, TimeUnit.MILLISECONDS);
            if (completed) {
                System.out.println("Latch count reached zero");
            } else {
                System.out.println("Timeout occurred before latch count reached zero");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_2() {
        CountDownLatch startSignal = new CountDownLatch(1);
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            if (startSignal.await(500, TimeUnit.MILLISECONDS)) {
                // Only proceed with critical operation if await returns true
                performCriticalOperation();
            } else {
                System.out.println("Timeout waiting for start signal");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_3() {
        CountDownLatch doneSignal = new CountDownLatch(5);
        ExecutorService executor = Executors.newFixedThreadPool(5);
        
        for (int i = 0; i < 5; i++) {
            executor.execute(() -> {
                try {
                    Thread.sleep(2000);
                    doneSignal.countDown();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            boolean allTasksCompleted = doneSignal.await(1, TimeUnit.SECONDS);
            if (allTasksCompleted) {
                System.out.println("All tasks completed");
            } else {
                System.out.println("Timeout: Not all tasks completed");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            executor.shutdown();
        }
    }

    public void good_case_4() {
        CountDownLatch latch = new CountDownLatch(3);
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            if (latch.await(100, TimeUnit.MILLISECONDS)) {
                // Only process results if all operations completed
                processResults();
            } else {
                System.out.println("Operation timed out, results may be incomplete");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_5() {
        CountDownLatch latch = new CountDownLatch(1);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        
        executor.submit(() -> {
            try {
                Thread.sleep(5000); // Simulate long operation
                latch.countDown();
                return true;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        });
        
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            boolean completed = latch.await(1, TimeUnit.SECONDS);
            if (completed) {
                System.out.println("Operation completed");
            } else {
                System.out.println("Operation timed out");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            executor.shutdown();
        }
    }

    public void good_case_6() {
        CountDownLatch connectionLatch = new CountDownLatch(1);
        AtomicBoolean connected = new AtomicBoolean(false);
        
        // Simulate connection attempt in another thread
        new Thread(() -> {
            try {
                Thread.sleep(3000); // Simulate slow connection
                connected.set(true);
                connectionLatch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).start();
        
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            boolean connectionEstablished = connectionLatch.await(1, TimeUnit.SECONDS);
            if (connectionEstablished && connected.get()) {
                System.out.println("Using connection");
            } else {
                System.out.println("Connection timeout");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_7() {
        CountDownLatch initLatch = new CountDownLatch(1);
        final boolean[] initialized = {false};
        
        // Initialize in background
        new Thread(() -> {
            try {
                Thread.sleep(2000);
                initialized[0] = true;
                initLatch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).start();
        
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            boolean initCompleted = initLatch.await(500, TimeUnit.MILLISECONDS);
            if (initCompleted && initialized[0]) {
                useInitializedSystem(initialized[0]);
            } else {
                System.out.println("System initialization timed out");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_8() {
        CountDownLatch latch = new CountDownLatch(2);
        
        // Start two worker threads
        for (int i = 0; i < 2; i++) {
            int workerId = i;
            new Thread(() -> {
                try {
                    Thread.sleep(workerId * 1000 + 1000);
                    latch.countDown();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }).start();
        }
        
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            boolean allWorkersCompleted = latch.await(1500, TimeUnit.MILLISECONDS);
            if (allWorkersCompleted) {
                System.out.println("All workers completed, moving to next phase");
            } else {
                System.out.println("Timeout waiting for workers, some tasks may be incomplete");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_9() {
        CountDownLatch readyLatch = new CountDownLatch(3);
        
        // Simulate services starting up
        for (int i = 0; i < 3; i++) {
            final int serviceId = i;
            new Thread(() -> {
                try {
                    // Service 2 takes longer than our timeout
                    if (serviceId == 2) {
                        Thread.sleep(3000);
                    } else {
                        Thread.sleep(500);
                    }
                    readyLatch.countDown();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }).start();
        }
        
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            boolean allServicesReady = readyLatch.await(1, TimeUnit.SECONDS);
            if (allServicesReady) {
                startApplication();
            } else {
                System.out.println("Not all services started in time, aborting application startup");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_10() {
        CountDownLatch completionLatch = new CountDownLatch(1);
        StringBuilder result = new StringBuilder();
        
        // Simulate async operation
        new Thread(() -> {
            try {
                Thread.sleep(2000);
                result.append("Operation result");
                completionLatch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).start();
        
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            boolean operationCompleted = completionLatch.await(500, TimeUnit.MILLISECONDS);
            if (operationCompleted) {
                System.out.println("Result: " + result.toString());
            } else {
                System.out.println("Operation timed out, no result available");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_11() {
        final CountDownLatch latch = new CountDownLatch(1);
        final String[] response = {null};
        
        // Simulate network request
        new Thread(() -> {
            try {
                Thread.sleep(3000); // Simulate slow network
                response[0] = "Response data";
                latch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).start();
        
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            boolean responseReceived = latch.await(1, TimeUnit.SECONDS);
            if (responseReceived && response[0] != null) {
                processResponse(response[0]);
            } else {
                System.out.println("Request timed out, no response to process");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_12() {
        CountDownLatch barrier = new CountDownLatch(4);
        
        // Start 4 tasks
        for (int i = 0; i < 4; i++) {
            final int taskId = i;
            new Thread(() -> {
                try {
                    // Last task takes much longer
                    if (taskId == 3) {
                        Thread.sleep(5000);
                    } else {
                        Thread.sleep(500);
                    }
                    barrier.countDown();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }).start();
        }
        
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            boolean allTasksCompleted = barrier.await(2, TimeUnit.SECONDS);
            if (allTasksCompleted) {
                aggregateResults();
            } else {
                System.out.println("Not all tasks completed in time, aggregation may be incomplete");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_13() {
        CountDownLatch startupLatch = new CountDownLatch(1);
        boolean[] ready = {false};
        
        // Initialize system in background
        new Thread(() -> {
            try {
                Thread.sleep(4000); // Long initialization
                ready[0] = true;
                startupLatch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).start();
        
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            boolean systemReady = startupLatch.await(2, TimeUnit.SECONDS);
            if (systemReady && ready[0]) {
                performOperations();
            } else {
                System.out.println("System initialization timed out, cannot perform operations");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_14() {
        CountDownLatch shutdownLatch = new CountDownLatch(3);
        
        // Simulate services shutting down
        for (int i = 0; i < 3; i++) {
            final int serviceId = i;
            new Thread(() -> {
                try {
                    // Service 1 hangs during shutdown
                    if (serviceId == 1) {
                        Thread.sleep(10000);
                    } else {
                        Thread.sleep(500);
                        shutdownLatch.countDown();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }).start();
        }
        
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            boolean allShutdown = shutdownLatch.await(3, TimeUnit.SECONDS);
            if (allShutdown) {
                System.out.println("All services shut down properly");
            } else {
                System.out.println("Some services did not shut down in time, forcing exit");
                // Force shutdown of remaining services
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void good_case_15() {
        CountDownLatch dataLatch = new CountDownLatch(1);
        final Object[] data = {null};
        
        // Load data asynchronously
        new Thread(() -> {
            try {
                Thread.sleep(3000); // Slow data loading
                data[0] = loadData();
                dataLatch.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).start();
        
        try {
            // ok: java-handlecountdownlatchawaittimeouts
            boolean dataLoaded = dataLatch.await(1, TimeUnit.SECONDS);
            if (dataLoaded && data[0] != null) {
                processData(data[0]);
            } else {
                System.out.println("Data loading timed out, cannot process");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // Helper methods to make the examples compile
    private void performCriticalOperation() {
        System.out.println("Performing critical operation");
    }
    
    private void processResults() {
        System.out.println("Processing results");
    }
    
    private void aggregateResults() {
        System.out.println("Aggregating results");
    }
    
    private void performOperations() {
        System.out.println("Performing operations");
    }
    
    private void startApplication() {
        System.out.println("Starting application");
    }
    
    private void processResponse(String response) {
        System.out.println("Processing response: " + response);
    }
    
    private void processData(Object data) {
        System.out.println("Processing data: " + data);
    }
    
    private void useInitializedSystem(boolean initialized) {
        System.out.println("Using initialized system: " + initialized);
    }
    
    private Object loadData() {
        return "Sample data";
    }
}
// {/fact}