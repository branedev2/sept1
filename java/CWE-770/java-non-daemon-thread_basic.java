import java.util.concurrent.*;
import java.util.ArrayList;
import java.util.List;

public class NonDaemonThreadExamples {

    // True Positives (Vulnerable Code)

// {fact rule=resource-allocation-without-limits@v1.0 defects=1}
    public void bad_case_1() {
        // ruleid: java-non-daemon-thread
        Thread thread = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(1000);
                    System.out.println("Background task running...");
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });
        thread.start();
    }

    public void bad_case_2() {
        Runnable task = () -> {
            try {
                Thread.sleep(5000);
                System.out.println("Task completed");
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        };
        // ruleid: java-non-daemon-thread
        Thread thread = new Thread(task);
        thread.start();
    }

    public void bad_case_3() {
        // ruleid: java-non-daemon-thread
        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                processData();
            }
        });
        thread.start();
    }

    public void bad_case_4() {
        // ruleid: java-non-daemon-thread
        Thread thread = new Thread();
        thread.start();
    }

    public void bad_case_5() {
        // ruleid: java-non-daemon-thread
        Thread thread = new Thread(() -> {
            System.out.println("Processing in background");
        });
        thread.setDaemon(false); // Explicitly setting as non-daemon
        thread.start();
    }

    public void bad_case_6() {
        class WorkerThread extends Thread {
            @Override
            public void run() {
                System.out.println("Custom worker thread running");
            }
        }
        
        // ruleid: java-non-daemon-thread
        WorkerThread workerThread = new WorkerThread();
        workerThread.start();
    }

    public void bad_case_7() {
        for (int i = 0; i < 5; i++) {
            // ruleid: java-non-daemon-thread
            Thread thread = new Thread(() -> {
                processData();
            });
            thread.start();
        }
    }

    public void bad_case_8() {
        List<Thread> threads = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            // ruleid: java-non-daemon-thread
            Thread thread = new Thread(() -> {
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            });
            threads.add(thread);
        }
        
        for (Thread thread : threads) {
            thread.start();
        }
    }

    public void bad_case_9() {
        // ruleid: java-non-daemon-thread
        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                while (!Thread.currentThread().isInterrupted()) {
                    System.out.println("Monitoring system status...");
                    try {
                        Thread.sleep(10000);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
            }
        });
        thread.setPriority(Thread.MAX_PRIORITY);
        thread.start();
    }

    public void bad_case_10() {
        ThreadGroup group = new ThreadGroup("WorkerGroup");
        // ruleid: java-non-daemon-thread
        Thread thread = new Thread(group, () -> {
            System.out.println("Thread in custom group");
        });
        thread.start();
    }

    public void bad_case_11() {
        // ruleid: java-non-daemon-thread
        Thread thread = new Thread(() -> {
            System.out.println("Thread with name");
        }, "NamedThread");
        thread.start();
    }

    public void bad_case_12() {
        class DataProcessor implements Runnable {
            @Override
            public void run() {
                System.out.println("Processing data");
            }
        }
        
        // ruleid: java-non-daemon-thread
        Thread thread = new Thread(new DataProcessor());
        thread.start();
    }

    public void bad_case_13() {
        Runnable task = () -> System.out.println("Simple task");
        // ruleid: java-non-daemon-thread
        new Thread(task).start();
    }

    public void bad_case_14() {
        // ruleid: java-non-daemon-thread
        Thread thread = new Thread() {
            @Override
            public void run() {
                System.out.println("Anonymous thread subclass");
            }
        };
        thread.start();
    }

    public void bad_case_15() {
        ThreadGroup group = new ThreadGroup("ServiceGroup");
        Runnable task = () -> System.out.println("Service task");
        // ruleid: java-non-daemon-thread
        Thread thread = new Thread(group, task, "ServiceThread");
        thread.start();
    }

    // True Negatives (Secure Code)

    public void good_case_1() {
        // ok: java-non-daemon-thread
        Thread thread = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(1000);
                    System.out.println("Background task running...");
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });
        thread.setDaemon(true);
        thread.start();
    }

    public void good_case_2() {
        Runnable task = () -> {
            try {
                Thread.sleep(5000);
                System.out.println("Task completed");
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        };
        // ok: java-non-daemon-thread
        Thread thread = new Thread(task);
        thread.setDaemon(true);
        thread.start();
    }

    public void good_case_3() {
        // Using ExecutorService instead of raw threads
        // ok: java-non-daemon-thread
        ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            return t;
        });
        executor.submit(() -> processData());
        executor.shutdown();
    }

    public void good_case_4() {
        class DaemonWorker extends Thread {
            public DaemonWorker() {
                // ok: java-non-daemon-thread
                setDaemon(true);
            }
            
            @Override
            public void run() {
                System.out.println("Daemon worker running");
            }
        }
        
        DaemonWorker worker = new DaemonWorker();
        worker.start();
    }

    public void good_case_5() {
        // ok: java-non-daemon-thread
        ThreadFactory daemonFactory = r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            return t;
        };
        
        Thread thread = daemonFactory.newThread(() -> {
            System.out.println("Using thread factory");
        });
        thread.start();
    }

    public void good_case_6() {
        // ok: java-non-daemon-thread
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1, r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            return t;
        });
        
        scheduler.scheduleAtFixedRate(() -> {
            System.out.println("Scheduled task");
        }, 0, 5, TimeUnit.SECONDS);
    }

    public void good_case_7() {
        for (int i = 0; i < 5; i++) {
            // ok: java-non-daemon-thread
            Thread thread = new Thread(() -> {
                processData();
            });
            thread.setDaemon(true);
            thread.start();
        }
    }

    public void good_case_8() {
        // ok: java-non-daemon-thread
        ExecutorService executor = Executors.newFixedThreadPool(
            4,
            r -> {
                Thread t = new Thread(r);
                t.setDaemon(true);
                return t;
            }
        );
        
        for (int i = 0; i < 10; i++) {
            final int taskId = i;
            executor.submit(() -> System.out.println("Task " + taskId + " executed"));
        }
        executor.shutdown();
    }

    public void good_case_9() {
        // Using CompletableFuture with daemon threads
        // ok: java-non-daemon-thread
        Executor executor = CompletableFuture.delayedExecutor(
            100, TimeUnit.MILLISECONDS, 
            r -> {
                Thread t = new Thread(r);
                t.setDaemon(true);
                return t;
            }
        );
        
        CompletableFuture.supplyAsync(() -> "Result", executor)
            .thenAccept(System.out::println);
    }

    public void good_case_10() {
        ThreadGroup group = new ThreadGroup("DaemonGroup");
        // ok: java-non-daemon-thread
        Thread thread = new Thread(group, () -> {
            System.out.println("Thread in daemon group");
        });
        thread.setDaemon(true);
        thread.start();
    }

    public void good_case_11() {
        // ok: java-non-daemon-thread
        ForkJoinPool customPool = new ForkJoinPool(
            Runtime.getRuntime().availableProcessors(),
            ForkJoinPool.defaultForkJoinWorkerThreadFactory,
            (t, e) -> System.err.println("Uncaught exception: " + e),
            true  // asyncMode = true creates daemon threads
        );
        
        customPool.submit(() -> System.out.println("Task in custom ForkJoinPool"));
    }

    public void good_case_12() {
        // ok: java-non-daemon-thread
        Thread thread = new Thread(() -> {
            System.out.println("Thread with name");
        }, "DaemonThread");
        thread.setDaemon(true);
        thread.start();
    }

    public void good_case_13() {
        // Using Timer (which uses daemon threads by default)
        // ok: java-non-daemon-thread
        Timer timer = new Timer(true);  // daemon = true
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                System.out.println("Timer task executed");
            }
        }, 1000, 5000);
    }

    public void good_case_14() {
        // ok: java-non-daemon-thread
        Thread thread = new Thread() {
            {
                setDaemon(true);  // Setting daemon in initializer block
            }
            
            @Override
            public void run() {
                System.out.println("Anonymous daemon thread subclass");
            }
        };
        thread.start();
    }

    public void good_case_15() {
        // Using virtual threads (Project Loom) which are daemon by default
        // ok: java-non-daemon-thread
        try {
            Thread virtualThread = Thread.ofVirtual().start(() -> {
                System.out.println("Virtual thread running");
            });
        } catch (UnsupportedOperationException e) {
            // Fallback for environments without virtual thread support
            Thread thread = new Thread(() -> {
                System.out.println("Regular daemon thread as fallback");
            });
            thread.setDaemon(true);
            thread.start();
        }
    }

    // Helper method
    private void processData() {
        System.out.println("Processing data...");
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
// {/fact}