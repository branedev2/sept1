import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.lang.Thread;

public class NonDaemonThreadExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=zip-bomb-attack@v1.0 defects=1}
    public void bad_case_1() {
        // ruleid: java-non-daemon-thread
        Thread thread = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(1000);
                    System.out.println("Background task running");
                } catch (InterruptedException e) {
                    break;
                }
            }
        });
        thread.start();
    }

    public void bad_case_2() {
        // ruleid: java-non-daemon-thread
        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                processData();
            }
        });
        thread.start();
    }

    public void bad_case_3() {
        Runnable task = () -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    Thread.sleep(5000);
                    System.out.println("Monitoring system resources");
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        };
        // ruleid: java-non-daemon-thread
        Thread monitorThread = new Thread(task);
        monitorThread.start();
    }

    public void bad_case_4() {
        // ruleid: java-non-daemon-thread
        Thread workerThread = new Thread(() -> {
            try {
                performLongRunningTask();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }, "WorkerThread");
        workerThread.setPriority(Thread.MAX_PRIORITY);
        workerThread.start();
    }

    public void bad_case_5() {
        class CustomThread extends Thread {
            @Override
            public void run() {
                while (!isInterrupted()) {
                    try {
                        Thread.sleep(1000);
                        System.out.println("Custom thread running");
                    } catch (InterruptedException e) {
                        interrupt();
                        break;
                    }
                }
            }
        }
        
        // ruleid: java-non-daemon-thread
        CustomThread thread = new CustomThread();
        thread.start();
    }

    public void bad_case_6() {
        final AtomicBoolean running = new AtomicBoolean(true);
        
        // ruleid: java-non-daemon-thread
        Thread backgroundThread = new Thread() {
            @Override
            public void run() {
                while (running.get()) {
                    try {
                        Thread.sleep(100);
                        System.out.println("Processing queue");
                    } catch (InterruptedException e) {
                        break;
                    }
                }
            }
        };
        backgroundThread.start();
    }

    public void bad_case_7() {
        // ruleid: java-non-daemon-thread
        new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(60000);
                    cleanupResources();
                } catch (InterruptedException e) {
                    return;
                }
            }
        }).start();
    }

    public void bad_case_8() {
        Runnable heartbeatTask = () -> {
            while (true) {
                try {
                    sendHeartbeat();
                    Thread.sleep(30000);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        };
        
        // ruleid: java-non-daemon-thread
        Thread heartbeatThread = new Thread(heartbeatTask);
        heartbeatThread.setName("HeartbeatThread");
        heartbeatThread.start();
    }

    public void bad_case_9() {
        // ruleid: java-non-daemon-thread
        Thread fileWatcher = new Thread(() -> {
            try {
                watchForFileChanges();
            } catch (Exception e) {
                System.err.println("File watching failed: " + e.getMessage());
            }
        });
        fileWatcher.setName("FileWatcherThread");
        fileWatcher.setPriority(Thread.MIN_PRIORITY);
        fileWatcher.start();
    }

    public void bad_case_10() {
        // Creating a thread explicitly setting daemon to false
        // ruleid: java-non-daemon-thread
        Thread explicitNonDaemon = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(1000);
                    System.out.println("Explicit non-daemon thread");
                } catch (InterruptedException e) {
                    break;
                }
            }
        });
        explicitNonDaemon.setDaemon(false);
        explicitNonDaemon.start();
    }

    public void bad_case_11() {
        class DataProcessorThread extends Thread {
            private final String dataSource;
            
            public DataProcessorThread(String dataSource) {
                this.dataSource = dataSource;
            }
            
            @Override
            public void run() {
                while (!isInterrupted()) {
                    try {
                        processDataFromSource(dataSource);
                        Thread.sleep(5000);
                    } catch (InterruptedException e) {
                        interrupt();
                        break;
                    }
                }
            }
        }
        
        // ruleid: java-non-daemon-thread
        DataProcessorThread processor = new DataProcessorThread("database");
        processor.start();
    }

    public void bad_case_12() {
        // ruleid: java-non-daemon-thread
        Thread cacheUpdater = new Thread(new Runnable() {
            @Override
            public void run() {
                while (true) {
                    try {
                        updateCache();
                        Thread.sleep(300000); // 5 minutes
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
            }
        }, "CacheUpdaterThread");
        cacheUpdater.start();
    }

    public void bad_case_13() {
        // Using ThreadFactory but not setting daemon status
        ThreadFactory factory = new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                // ruleid: java-non-daemon-thread
                Thread t = new Thread(r);
                t.setName("CustomThreadFactory-" + System.currentTimeMillis());
                return t;
            }
        };
        
        Thread thread = factory.newThread(() -> {
            while (true) {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    break;
                }
            }
        });
        thread.start();
    }

    public void bad_case_14() {
        // ruleid: java-non-daemon-thread
        Thread statusChecker = new Thread(() -> {
            try {
                while (!Thread.currentThread().isInterrupted()) {
                    checkSystemStatus();
                    Thread.sleep(10000);
                }
            } catch (InterruptedException e) {
                // Restore the interrupted status
                Thread.currentThread().interrupt();
            }
        });
        statusChecker.setName("StatusCheckerThread");
        statusChecker.start();
    }

    public void bad_case_15() {
        // Creating multiple non-daemon threads
        for (int i = 0; i < 5; i++) {
            final int id = i;
            // ruleid: java-non-daemon-thread
            Thread worker = new Thread(() -> {
                try {
                    System.out.println("Worker " + id + " started");
                    performTask(id);
                } catch (Exception e) {
                    System.err.println("Worker " + id + " failed: " + e.getMessage());
                }
            });
            worker.setName("Worker-" + id);
            worker.start();
        }
    }

    // True Negative Examples (Safe Code)

    public void good_case_1() {
        // ok: java-non-daemon-thread
        Thread thread = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(1000);
                    System.out.println("Background task running");
                } catch (InterruptedException e) {
                    break;
                }
            }
        });
        thread.setDaemon(true);
        thread.start();
    }

    public void good_case_2() {
        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                processData();
            }
        });
        // ok: java-non-daemon-thread
        thread.setDaemon(true);
        thread.start();
    }

    public void good_case_3() {
        Runnable task = () -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    Thread.sleep(5000);
                    System.out.println("Monitoring system resources");
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        };
        Thread monitorThread = new Thread(task);
        // ok: java-non-daemon-thread
        monitorThread.setDaemon(true);
        monitorThread.start();
    }

    public void good_case_4() {
        // Using ExecutorService with daemon threads
        ThreadFactory daemonFactory = new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r);
                // ok: java-non-daemon-thread
                t.setDaemon(true);
                return t;
            }
        };
        
        ExecutorService executor = Executors.newFixedThreadPool(5, daemonFactory);
        executor.submit(() -> performLongRunningTask());
    }

    public void good_case_5() {
        class CustomDaemonThread extends Thread {
            public CustomDaemonThread() {
                // ok: java-non-daemon-thread
                setDaemon(true);
            }
            
            @Override
            public void run() {
                while (!isInterrupted()) {
                    try {
                        Thread.sleep(1000);
                        System.out.println("Custom daemon thread running");
                    } catch (InterruptedException e) {
                        interrupt();
                        break;
                    }
                }
            }
        }
        
        CustomDaemonThread thread = new CustomDaemonThread();
        thread.start();
    }

    public void good_case_6() {
        final AtomicBoolean running = new AtomicBoolean(true);
        
        Thread backgroundThread = new Thread() {
            @Override
            public void run() {
                while (running.get()) {
                    try {
                        Thread.sleep(100);
                        System.out.println("Processing queue");
                    } catch (InterruptedException e) {
                        break;
                    }
                }
            }
        };
        // ok: java-non-daemon-thread
        backgroundThread.setDaemon(true);
        backgroundThread.start();
    }

    public void good_case_7() {
        Thread cleanupThread = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(60000);
                    cleanupResources();
                } catch (InterruptedException e) {
                    return;
                }
            }
        });
        // ok: java-non-daemon-thread
        cleanupThread.setDaemon(true);
        cleanupThread.start();
    }

    public void good_case_8() {
        // Using ScheduledExecutorService with daemon threads
        ThreadFactory daemonFactory = r -> {
            Thread t = new Thread(r);
            // ok: java-non-daemon-thread
            t.setDaemon(true);
            t.setName("ScheduledTask-" + System.currentTimeMillis());
            return t;
        };
        
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1, daemonFactory);
        scheduler.scheduleAtFixedRate(
            () -> sendHeartbeat(),
            0,
            30,
            TimeUnit.SECONDS
        );
    }

    public void good_case_9() {
        Thread fileWatcher = new Thread(() -> {
            try {
                watchForFileChanges();
            } catch (Exception e) {
                System.err.println("File watching failed: " + e.getMessage());
            }
        });
        fileWatcher.setName("FileWatcherThread");
        // ok: java-non-daemon-thread
        fileWatcher.setDaemon(true);
        fileWatcher.setPriority(Thread.MIN_PRIORITY);
        fileWatcher.start();
    }

    public void good_case_10() {
        // Using CompletableFuture with daemon threads
        ThreadFactory daemonFactory = r -> {
            Thread t = new Thread(r);
            // ok: java-non-daemon-thread
            t.setDaemon(true);
            return t;
        };
        
        ExecutorService executor = Executors.newFixedThreadPool(2, daemonFactory);
        CompletableFuture.supplyAsync(() -> fetchData(), executor)
            .thenAccept(data -> processData(data));
    }

    public void good_case_11() {
        class DaemonDataProcessorThread extends Thread {
            private final String dataSource;
            
            public DaemonDataProcessorThread(String dataSource) {
                this.dataSource = dataSource;
                // ok: java-non-daemon-thread
                setDaemon(true);
            }
            
            @Override
            public void run() {
                while (!isInterrupted()) {
                    try {
                        processDataFromSource(dataSource);
                        Thread.sleep(5000);
                    } catch (InterruptedException e) {
                        interrupt();
                        break;
                    }
                }
            }
        }
        
        DaemonDataProcessorThread processor = new DaemonDataProcessorThread("database");
        processor.start();
    }

    public void good_case_12() {
        // Using ForkJoinPool with daemon threads
        ForkJoinPool.ForkJoinWorkerThreadFactory factory = pool -> {
            ForkJoinWorkerThread worker = ForkJoinPool.defaultForkJoinWorkerThreadFactory.newThread(pool);
            // ok: java-non-daemon-thread
            worker.setDaemon(true);
            return worker;
        };
        
        ForkJoinPool customPool = new ForkJoinPool(
            Runtime.getRuntime().availableProcessors(),
            factory,
            null,
            false
        );
        
        customPool.submit(() -> processLargeDataSet());
    }

    public void good_case_13() {
        // Using ThreadPoolExecutor with daemon threads
        ThreadFactory daemonFactory = new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r);
                // ok: java-non-daemon-thread
                t.setDaemon(true);
                t.setName("CustomThreadPool-" + System.currentTimeMillis());
                return t;
            }
        };
        
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
            2, 5, 
            60, TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(),
            daemonFactory
        );
        
        executor.execute(() -> performBackgroundTask());
    }

    public void good_case_14() {
        Thread statusChecker = new Thread(() -> {
            try {
                while (!Thread.currentThread().isInterrupted()) {
                    checkSystemStatus();
                    Thread.sleep(10000);
                }
            } catch (InterruptedException e) {
                // Restore the interrupted status
                Thread.currentThread().interrupt();
            }
        });
        statusChecker.setName("StatusCheckerThread");
        // ok: java-non-daemon-thread
        statusChecker.setDaemon(true);
        statusChecker.start();
    }

    public void good_case_15() {
        // Creating multiple daemon threads
        for (int i = 0; i < 5; i++) {
            final int id = i;
            Thread worker = new Thread(() -> {
                try {
                    System.out.println("Worker " + id + " started");
                    performTask(id);
                } catch (Exception e) {
                    System.err.println("Worker " + id + " failed: " + e.getMessage());
                }
            });
            worker.setName("Worker-" + id);
            // ok: java-non-daemon-thread
            worker.setDaemon(true);
            worker.start();
        }
    }

    // Helper methods to make the examples compile
    private void processData() { /* Implementation */ }
    private void performLongRunningTask() { /* Implementation */ }
    private void cleanupResources() { /* Implementation */ }
    private void sendHeartbeat() { /* Implementation */ }
    private void watchForFileChanges() { /* Implementation */ }
    private void processDataFromSource(String source) { /* Implementation */ }
    private void updateCache() { /* Implementation */ }
    private void checkSystemStatus() { /* Implementation */ }
    private void performTask(int id) { /* Implementation */ }
    private String fetchData() { return "data"; }
    private void processData(String data) { /* Implementation */ }
    private void processLargeDataSet() { /* Implementation */ }
    private void performBackgroundTask() { /* Implementation */ }
}
// {/fact}