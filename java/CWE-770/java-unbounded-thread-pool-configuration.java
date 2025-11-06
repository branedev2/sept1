import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class ThreadPoolExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=resource-allocation-without-limits@v1.0 defects=1}
    public void bad_case_1() {
        // Creating a thread pool with unbounded work queue
        // ruleid: java-unbounded-thread-pool-configuration
        ExecutorService executor = new ThreadPoolExecutor(
            10, // core pool size
            100, // max pool size
            60L, // keep alive time
            TimeUnit.SECONDS,
            new LinkedBlockingQueue<>() // Unbounded queue with no capacity limit
        );
        
        for (int i = 0; i < 10000; i++) {
            executor.submit(() -> {
                // Some task
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
    }

    public void bad_case_2() {
        // Using Executors.newCachedThreadPool() which can create unlimited threads
        // ruleid: java-unbounded-thread-pool-configuration
        ExecutorService executor = Executors.newCachedThreadPool();
        
        for (int i = 0; i < 10000; i++) {
            executor.submit(() -> {
                // Task that might take some time
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
    }

    public void bad_case_3() {
        // Using Executors.newFixedThreadPool but with LinkedBlockingQueue (unbounded)
        // ruleid: java-unbounded-thread-pool-configuration
        ExecutorService executor = Executors.newFixedThreadPool(10);
        
        // This is vulnerable because newFixedThreadPool uses an unbounded LinkedBlockingQueue internally
        for (int i = 0; i < 5000; i++) {
            executor.submit(() -> {
                // Resource-intensive task
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
    }

    public void bad_case_4() {
        // Using ThreadPoolExecutor with PriorityBlockingQueue (unbounded)
        // ruleid: java-unbounded-thread-pool-configuration
        ExecutorService executor = new ThreadPoolExecutor(
            5,
            50,
            30,
            TimeUnit.SECONDS,
            new PriorityBlockingQueue<>() // Unbounded priority queue
        );
        
        for (int i = 0; i < 1000; i++) {
            executor.submit(() -> {
                // Task with priority
                try {
                    Thread.sleep(300);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
    }

    public void bad_case_5() {
        // Using Executors.newSingleThreadExecutor() which uses unbounded queue
        // ruleid: java-unbounded-thread-pool-configuration
        ExecutorService executor = Executors.newSingleThreadExecutor();
        
        // Single thread with unbounded queue can lead to OOM if tasks pile up
        for (int i = 0; i < 10000; i++) {
            executor.submit(() -> {
                // Long-running task
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
    }

    public void bad_case_6() {
        // Custom ThreadFactory with unbounded queue
        ThreadFactory threadFactory = new ThreadFactory() {
            private final AtomicInteger counter = new AtomicInteger(0);
            
            @Override
            public Thread newThread(Runnable r) {
                Thread thread = new Thread(r);
                thread.setName("CustomThread-" + counter.incrementAndGet());
                return thread;
            }
        };
        
        // ruleid: java-unbounded-thread-pool-configuration
        ExecutorService executor = new ThreadPoolExecutor(
            10,
            100,
            60L,
            TimeUnit.SECONDS,
            new LinkedTransferQueue<>(), // Unbounded queue
            threadFactory
        );
        
        for (int i = 0; i < 5000; i++) {
            executor.submit(() -> {
                // Task logic
                try {
                    Thread.sleep(150);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
    }

    public void bad_case_7() {
        // Using ScheduledThreadPoolExecutor with default unbounded delay queue
        // ruleid: java-unbounded-thread-pool-configuration
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(5);
        
        // Scheduling many tasks can lead to unbounded queue growth
        for (int i = 0; i < 10000; i++) {
            scheduler.schedule(() -> {
                // Scheduled task
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }, i % 100, TimeUnit.MILLISECONDS);
        }
    }

    public void bad_case_8() {
        // Using ForkJoinPool with potentially unbounded task submission
        // ruleid: java-unbounded-thread-pool-configuration
        ForkJoinPool forkJoinPool = new ForkJoinPool();
        
        // Submitting many tasks without proper control
        for (int i = 0; i < 10000; i++) {
            forkJoinPool.submit(() -> {
                // Compute-intensive task
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return null;
            });
        }
    }

    public void bad_case_9() {
        // Using ThreadPoolExecutor with SynchronousQueue but unlimited max threads
        // ruleid: java-unbounded-thread-pool-configuration
        ExecutorService executor = new ThreadPoolExecutor(
            10,
            Integer.MAX_VALUE, // Effectively unlimited max threads
            60L,
            TimeUnit.SECONDS,
            new SynchronousQueue<>()
        );
        
        for (int i = 0; i < 10000; i++) {
            executor.submit(() -> {
                // Task logic
                try {
                    Thread.sleep(300);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
    }

    public void bad_case_10() {
        // Using newWorkStealingPool without bounds
        // ruleid: java-unbounded-thread-pool-configuration
        ExecutorService executor = Executors.newWorkStealingPool();
        
        // Can lead to excessive resource usage
        for (int i = 0; i < 5000; i++) {
            executor.submit(() -> {
                // Task that might fork other tasks
                try {
                    Thread.sleep(150);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
    }

    public void bad_case_11() {
        // Custom rejection handler but still using unbounded queue
        RejectedExecutionHandler handler = new ThreadPoolExecutor.CallerRunsPolicy();
        
        // ruleid: java-unbounded-thread-pool-configuration
        ExecutorService executor = new ThreadPoolExecutor(
            5,
            50,
            30L,
            TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(), // Unbounded queue
            Executors.defaultThreadFactory(),
            handler
        );
        
        for (int i = 0; i < 1000; i++) {
            executor.submit(() -> {
                // Task with rejection handling
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
    }

    public void bad_case_12() {
        // Using DelayQueue which is unbounded
        // ruleid: java-unbounded-thread-pool-configuration
        ExecutorService executor = new ThreadPoolExecutor(
            10,
            100,
            60L,
            TimeUnit.SECONDS,
            new DelayQueue<>() // Unbounded delay queue
        );
        
        for (int i = 0; i < 5000; i++) {
            executor.submit(() -> {
                // Task with delay
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
    }

    public void bad_case_13() {
        // Using ConcurrentLinkedQueue adapter which is unbounded
        // ruleid: java-unbounded-thread-pool-configuration
        ExecutorService executor = new ThreadPoolExecutor(
            5,
            50,
            60L,
            TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(Integer.MAX_VALUE) // Effectively unbounded
        );
        
        for (int i = 0; i < 10000; i++) {
            executor.submit(() -> {
                // Task logic
                try {
                    Thread.sleep(150);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
    }

    public void bad_case_14() {
        // Using very large but finite queue size (practically unbounded)
        // ruleid: java-unbounded-thread-pool-configuration
        ExecutorService executor = new ThreadPoolExecutor(
            10,
            100,
            60L,
            TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(Integer.MAX_VALUE / 2) // Extremely large queue
        );
        
        for (int i = 0; i < 5000; i++) {
            executor.submit(() -> {
                // Task logic
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
    }

    public void bad_case_15() {
        // Using CompletableFuture with default executor (ForkJoinPool.commonPool())
        // which can be unbounded in certain configurations
        // ruleid: java-unbounded-thread-pool-configuration
        for (int i = 0; i < 10000; i++) {
            CompletableFuture.runAsync(() -> {
                // Task that might take time
                try {
                    Thread.sleep(300);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
    }

    // True Negative Examples (Secure Code)

    public void good_case_1() {
        // Using ThreadPoolExecutor with bounded ArrayBlockingQueue
        // ok: java-unbounded-thread-pool-configuration
        ExecutorService executor = new ThreadPoolExecutor(
            10, // core pool size
            100, // max pool size
            60L, // keep alive time
            TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(1000) // Bounded queue with capacity limit
        );
        
        for (int i = 0; i < 5000; i++) {
            executor.submit(() -> {
                // Some task
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
    }

    public void good_case_2() {
        // Using ThreadPoolExecutor with SynchronousQueue and reasonable max threads
        // ok: java-unbounded-thread-pool-configuration
        ExecutorService executor = new ThreadPoolExecutor(
            10,
            100, // Reasonable max threads
            60L,
            TimeUnit.SECONDS,
            new SynchronousQueue<>() // No queueing, but limited max threads
        );
        
        for (int i = 0; i < 5000; i++) {
            executor.submit(() -> {
                // Task logic
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
    }

    public void good_case_3() {
        // Using bounded LinkedBlockingQueue with explicit capacity
        // ok: java-unbounded-thread-pool-configuration
        ExecutorService executor = new ThreadPoolExecutor(
            5,
            50,
            30L,
            TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(2000) // Bounded with explicit capacity
        );
        
        for (int i = 0; i < 5000; i++) {
            executor.submit(() -> {
                // Resource-intensive task
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
    }

    public void good_case_4() {
        // Using custom thread factory with bounded queue
        ThreadFactory threadFactory = new ThreadFactory() {
            private final AtomicInteger counter = new AtomicInteger(0);
            
            @Override
            public Thread newThread(Runnable r) {
                Thread thread = new Thread(r);
                thread.setName("CustomThread-" + counter.incrementAndGet());
                return thread;
            }
        };
        
        // ok: java-unbounded-thread-pool-configuration
        ExecutorService executor = new ThreadPoolExecutor(
            10,
            100,
            60L,
            TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(500), // Bounded queue
            threadFactory
        );
        
        for (int i = 0; i < 1000; i++) {
            executor.submit(() -> {
                // Task logic
                try {
                    Thread.sleep(150);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
    }

    public void good_case_5() {
        // Using rejection handler with bounded queue
        RejectedExecutionHandler handler = new ThreadPoolExecutor.CallerRunsPolicy();
        
        // ok: java-unbounded-thread-pool-configuration
        ExecutorService executor = new ThreadPoolExecutor(
            5,
            50,
            30L,
            TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(1000), // Bounded queue
            Executors.defaultThreadFactory(),
            handler
        );
        
        for (int i = 0; i < 5000; i++) {
            executor.submit(() -> {
                // Task with rejection handling
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
    }

    public void good_case_6() {
        // Using custom executor service with bounded queue and custom rejection policy
        RejectedExecutionHandler customHandler = (r, executor) -> {
            System.out.println("Task rejected, applying backpressure");
            try {
                // Wait and retry with backoff
                Thread.sleep(100);
                executor.execute(r);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (RejectedExecutionException e) {
                System.err.println("Task ultimately rejected");
            }
        };
        
        // ok: java-unbounded-thread-pool-configuration
        ExecutorService executor = new ThreadPoolExecutor(
            10,
            50,
            60L,
            TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(2000), // Bounded queue
            customHandler
        );
        
        for (int i = 0; i < 5000; i++) {
            executor.submit(() -> {
                // Task logic
                try {
                    Thread.sleep(150);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
    }

    public void good_case_7() {
        // Using ScheduledThreadPoolExecutor with custom bounded queue
        // ok: java-unbounded-thread-pool-configuration
        ScheduledThreadPoolExecutor scheduler = new ScheduledThreadPoolExecutor(
            5,
            new ThreadPoolExecutor.AbortPolicy()
        );
        scheduler.setMaximumPoolSize(20); // Set maximum pool size
        scheduler.setKeepAliveTime(60L, TimeUnit.SECONDS);
        
        // Limiting the number of scheduled tasks
        int maxTasks = 1000;
        for (int i = 0; i < maxTasks; i++) {
            scheduler.schedule(() -> {
                // Scheduled task
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }, i % 100, TimeUnit.MILLISECONDS);
        }
    }

    public void good_case_8() {
        // Using ForkJoinPool with parallelism limit
        int processors = Runtime.getRuntime().availableProcessors();
        // ok: java-unbounded-thread-pool-configuration
        ForkJoinPool forkJoinPool = new ForkJoinPool(
            processors, // Parallelism level based on available processors
            ForkJoinPool.defaultForkJoinWorkerThreadFactory,
            null,
            true
        );
        
        // Controlled submission with monitoring
        int taskCount = 1000;
        for (int i = 0; i < taskCount; i++) {
            if (forkJoinPool.getQueuedSubmissionCount() < 100) { // Monitor queue size
                forkJoinPool.submit(() -> {
                    // Compute-intensive task
                    try {
                        Thread.sleep(200);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    return null;
                });
            } else {
                try {
                    Thread.sleep(50); // Back off if too many submissions
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    public void good_case_9() {
        // Using Executors.newFixedThreadPool with wrapper to limit queue
        int nThreads = 10;
        int queueCapacity = 1000;
        
        // ok: java-unbounded-thread-pool-configuration
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
            nThreads,
            nThreads,
            0L,
            TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<>(queueCapacity)
        );
        
        // This is a safe alternative to Executors.newFixedThreadPool
        for (int i = 0; i < 5000; i++) {
            try {
                executor.submit(() -> {
                    // Task logic
                    try {
                        Thread.sleep(300);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                });
            } catch (RejectedExecutionException e) {
                System.out.println("Task rejected, queue full");
                // Handle rejection appropriately
            }
        }
    }

    public void good_case_10() {
        // Using bounded work stealing pool
        int parallelism = Runtime.getRuntime().availableProcessors();
        // ok: java-unbounded-thread-pool-configuration
        ExecutorService executor = Executors.newWorkStealingPool(parallelism);
        
        // Limiting the number of tasks
        int maxTasks = parallelism * 100; // Reasonable limit based on parallelism
        for (int i = 0; i < maxTasks; i++) {
            executor.submit(() -> {
                // Task that might fork other tasks
                try {
                    Thread.sleep(150);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
    }

    public void good_case_11() {
        // Using CompletableFuture with custom bounded executor
        // ok: java-unbounded-thread-pool-configuration
        ExecutorService customExecutor = new ThreadPoolExecutor(
            10,
            50,
            60L,
            TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(1000) // Bounded queue
        );
        
        for (int i = 0; i < 5000; i++) {
            CompletableFuture.runAsync(() -> {
                // Task that might take time
                try {
                    Thread.sleep(300);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }, customExecutor); // Using custom bounded executor
        }
    }

    public void good_case_12() {
        // Using ThreadPoolExecutor with bounded PriorityBlockingQueue
        // ok: java-unbounded-thread-pool-configuration
        ExecutorService executor = new ThreadPoolExecutor(
            5,
            50,
            30,
            TimeUnit.SECONDS,
            new PriorityBlockingQueue<>(1000) // Bounded priority queue
        );
        
        for (int i = 0; i < 1000; i++) {
            executor.submit(() -> {
                // Task with priority
                try {
                    Thread.sleep(300);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
    }

    public void good_case_13() {
        // Using a semaphore to limit concurrent task submission
        int maxConcurrentTasks = 1000;
        Semaphore semaphore = new Semaphore(maxConcurrentTasks);
        
        // ok: java-unbounded-thread-pool-configuration
        ExecutorService executor = new ThreadPoolExecutor(
            10,
            100,
            60L,
            TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(500) // Bounded queue
        );
        
        for (int i = 0; i < 10000; i++) {
            try {
                semaphore.acquire(); // Acquire permit before submitting
                executor.submit(() -> {
                    try {
                        // Task logic
                        Thread.sleep(200);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        semaphore.release(); // Release permit when done
                    }
                });
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    public void good_case_14() {
        // Using a custom ThreadPoolExecutor with core threads timeout
        // ok: java-unbounded-thread-pool-configuration
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
            10,
            50,
            60L,
            TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(2000) // Bounded queue
        );
        executor.allowCoreThreadTimeOut(true); // Allow core threads to timeout
        
        for (int i = 0; i < 5000; i++) {
            executor.submit(() -> {
                // Task logic
                try {
                    Thread.sleep(150);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
    }

    public void good_case_15() {
        // Using a thread pool with dynamic scaling based on system load
        int corePoolSize = Runtime.getRuntime().availableProcessors();
        int maxPoolSize = corePoolSize * 2;
        
        // ok: java-unbounded-thread-pool-configuration
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
            corePoolSize,
            maxPoolSize,
            60L,
            TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(1000) // Bounded queue
        ) {
            @Override
            protected void beforeExecute(Thread t, Runnable r) {
                // Monitor system resources before execution
                double systemLoad = getSystemLoadAverage();
                if (systemLoad > 0.8) {
                    // Temporarily reduce max pool size if system is under high load
                    this.setMaximumPoolSize(corePoolSize);
                } else {
                    // Restore max pool size if load is acceptable
                    this.setMaximumPoolSize(maxPoolSize);
                }
            }
        };
        
        for (int i = 0; i < 5000; i++) {
            executor.submit(() -> {
                // Task logic
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
    }
    
    // Helper method for good_case_15
    private double getSystemLoadAverage() {
        return Math.random(); // Simplified for example; in real code, would use system metrics
    }
}
// {/fact}