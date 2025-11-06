import java.util.concurrent.*;
import java.util.ArrayList;
import java.util.List;

public class ThreadPoolExamples {

    // TRUE POSITIVES (Vulnerable configurations)

// {fact rule=resource-allocation-without-limits@v1.0 defects=1}
    public void bad_case_1() {
        // Creating an executor service with unbounded work queue
        // ruleid: java-unbounded-thread-pool-configuration
        ExecutorService executorService = new ThreadPoolExecutor(
                10, // core pool size
                10, // max pool size
                60L, TimeUnit.SECONDS, // keep alive time
                new LinkedBlockingQueue<>() // unbounded queue with no capacity limit
        );
        
        executorService.submit(() -> System.out.println("Task executed"));
    }

    public void bad_case_2() {
        // Creating a cached thread pool which can grow unbounded
        // ruleid: java-unbounded-thread-pool-configuration
        ExecutorService executorService = Executors.newCachedThreadPool();
        
        for (int i = 0; i < 1000; i++) {
            executorService.submit(() -> {
                try {
                    Thread.sleep(10000); // Long-running task
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
    }

    public void bad_case_3() {
        int corePoolSize = 5;
        // ruleid: java-unbounded-thread-pool-configuration
        ExecutorService executorService = new ThreadPoolExecutor(
                corePoolSize,
                Integer.MAX_VALUE, // Effectively unbounded max threads
                60L, TimeUnit.SECONDS,
                new SynchronousQueue<>()
        );
        
        for (int i = 0; i < 100; i++) {
            executorService.execute(() -> System.out.println("Executing task"));
        }
    }

    public void bad_case_4() {
        // Custom thread factory with unbounded queue
        ThreadFactory threadFactory = Executors.defaultThreadFactory();
        // ruleid: java-unbounded-thread-pool-configuration
        ExecutorService executorService = new ThreadPoolExecutor(
                4, 4,
                0L, TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>(), // Unbounded queue
                threadFactory
        );
        
        executorService.submit(() -> System.out.println("Task submitted"));
    }

    public void bad_case_5() {
        // ruleid: java-unbounded-thread-pool-configuration
        ExecutorService executorService = Executors.newFixedThreadPool(10);
        // Fixed thread pool uses unbounded LinkedBlockingQueue internally
        
        for (int i = 0; i < 1000; i++) {
            final int taskId = i;
            executorService.submit(() -> System.out.println("Task " + taskId));
        }
    }

    public void bad_case_6() {
        // ruleid: java-unbounded-thread-pool-configuration
        ScheduledExecutorService scheduledExecutorService = Executors.newScheduledThreadPool(5);
        // ScheduledThreadPool can have unbounded queue of scheduled tasks
        
        for (int i = 0; i < 1000; i++) {
            final int taskId = i;
            scheduledExecutorService.schedule(
                    () -> System.out.println("Scheduled task " + taskId),
                    1, TimeUnit.SECONDS
            );
        }
    }

    public void bad_case_7() {
        // ruleid: java-unbounded-thread-pool-configuration
        ExecutorService executorService = Executors.newSingleThreadExecutor();
        // Single thread executor uses unbounded LinkedBlockingQueue internally
        
        for (int i = 0; i < 10000; i++) {
            final int taskId = i;
            executorService.submit(() -> {
                try {
                    Thread.sleep(100);
                    System.out.println("Task " + taskId);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
    }

    public void bad_case_8() {
        int processors = Runtime.getRuntime().availableProcessors();
        // ruleid: java-unbounded-thread-pool-configuration
        ForkJoinPool forkJoinPool = new ForkJoinPool(
                processors * 2, // Parallelism level
                ForkJoinPool.defaultForkJoinWorkerThreadFactory,
                null,
                false // asyncMode
        );
        // ForkJoinPool can have unbounded tasks
        
        forkJoinPool.submit(() -> System.out.println("ForkJoin task"));
    }

    public void bad_case_9() {
        // Creating a thread pool with rejection handler but still unbounded queue
        RejectedExecutionHandler handler = new ThreadPoolExecutor.CallerRunsPolicy();
        // ruleid: java-unbounded-thread-pool-configuration
        ExecutorService executorService = new ThreadPoolExecutor(
                2, 4,
                60, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(), // Still unbounded
                Executors.defaultThreadFactory(),
                handler
        );
        
        executorService.submit(() -> System.out.println("Task with rejection handler"));
    }

    public void bad_case_10() {
        // ruleid: java-unbounded-thread-pool-configuration
        ExecutorCompletionService<String> completionService = new ExecutorCompletionService<>(
                Executors.newFixedThreadPool(5) // Uses unbounded queue internally
        );
        
        completionService.submit(() -> "Result from task");
    }

    public void bad_case_11() {
        // Dynamic thread pool with unbounded queue
        int coreSize = Runtime.getRuntime().availableProcessors();
        int maxSize = coreSize * 2;
        
        // ruleid: java-unbounded-thread-pool-configuration
        ExecutorService executorService = new ThreadPoolExecutor(
                coreSize,
                maxSize,
                60, TimeUnit.SECONDS,
                new LinkedBlockingDeque<>() // Unbounded deque
        );
        
        executorService.submit(() -> System.out.println("Task in dynamic pool"));
    }

    public void bad_case_12() {
        // ruleid: java-unbounded-thread-pool-configuration
        ExecutorService executorService = new ScheduledThreadPoolExecutor(
                5, // core pool size
                Executors.defaultThreadFactory()
        );
        // ScheduledThreadPoolExecutor can have unbounded delayed tasks
        
        ((ScheduledThreadPoolExecutor) executorService).scheduleAtFixedRate(
                () -> System.out.println("Periodic task"),
                0, 5, TimeUnit.SECONDS
        );
    }

    public void bad_case_13() {
        // Creating a custom thread pool with PriorityBlockingQueue (unbounded)
        // ruleid: java-unbounded-thread-pool-configuration
        ExecutorService executorService = new ThreadPoolExecutor(
                2, 4,
                60, TimeUnit.SECONDS,
                new PriorityBlockingQueue<>() // Unbounded priority queue
        );
        
        executorService.submit(() -> System.out.println("Priority task"));
    }

    public void bad_case_14() {
        // Using factory method that creates unbounded queue internally
        // ruleid: java-unbounded-thread-pool-configuration
        ExecutorService executorService = Executors.newWorkStealingPool();
        // Work stealing pool can have unbounded tasks
        
        executorService.submit(() -> System.out.println("Work stealing task"));
    }

    public void bad_case_15() {
        // Creating a thread pool with custom thread factory but unbounded queue
        ThreadFactory namedThreadFactory = r -> {
            Thread t = new Thread(r);
            t.setName("custom-thread");
            return t;
        };
        
        // ruleid: java-unbounded-thread-pool-configuration
        ExecutorService executorService = new ThreadPoolExecutor(
                5, 10,
                60, TimeUnit.SECONDS,
                new LinkedTransferQueue<>(), // Unbounded transfer queue
                namedThreadFactory
        );
        
        executorService.submit(() -> System.out.println("Named thread task"));
    }

    // TRUE NEGATIVES (Safe configurations)

    public void good_case_1() {
        // Creating an executor service with bounded work queue
        // ok: java-unbounded-thread-pool-configuration
        ExecutorService executorService = new ThreadPoolExecutor(
                10, // core pool size
                20, // max pool size
                60L, TimeUnit.SECONDS, // keep alive time
                new ArrayBlockingQueue<>(100) // bounded queue with capacity limit
        );
        
        executorService.submit(() -> System.out.println("Task executed"));
    }

    public void good_case_2() {
        // Creating a cached thread pool with custom rejection handler
        RejectedExecutionHandler handler = new ThreadPoolExecutor.AbortPolicy();
        
        // ok: java-unbounded-thread-pool-configuration
        ExecutorService executorService = new ThreadPoolExecutor(
                0, 100, // Limited max size
                60L, TimeUnit.SECONDS,
                new SynchronousQueue<>(),
                Executors.defaultThreadFactory(),
                handler
        );
        
        executorService.submit(() -> System.out.println("Task with limit"));
    }

    public void good_case_3() {
        int corePoolSize = 5;
        int maxPoolSize = 10;
        
        // ok: java-unbounded-thread-pool-configuration
        ExecutorService executorService = new ThreadPoolExecutor(
                corePoolSize,
                maxPoolSize, // Bounded max threads
                60L, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(500) // Bounded queue
        );
        
        for (int i = 0; i < 100; i++) {
            executorService.execute(() -> System.out.println("Executing task"));
        }
    }

    public void good_case_4() {
        // Custom thread factory with bounded queue
        ThreadFactory threadFactory = Executors.defaultThreadFactory();
        
        // ok: java-unbounded-thread-pool-configuration
        ExecutorService executorService = new ThreadPoolExecutor(
                4, 8,
                0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(200), // Bounded queue
                threadFactory,
                new ThreadPoolExecutor.CallerRunsPolicy()
        );
        
        executorService.submit(() -> System.out.println("Task submitted"));
    }

    public void good_case_5() {
        // Creating a custom bounded thread pool
        // ok: java-unbounded-thread-pool-configuration
        ExecutorService executorService = new ThreadPoolExecutor(
                5, 10,
                60, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(1000), // Bounded queue with capacity
                new ThreadPoolExecutor.DiscardOldestPolicy()
        );
        
        for (int i = 0; i < 1000; i++) {
            final int taskId = i;
            executorService.submit(() -> System.out.println("Task " + taskId));
        }
    }

    public void good_case_6() {
        // ok: java-unbounded-thread-pool-configuration
        ScheduledExecutorService scheduledExecutorService = new ScheduledThreadPoolExecutor(
                5, // core pool size
                new ThreadPoolExecutor.AbortPolicy() // Rejection policy
        );
        
        ((ScheduledThreadPoolExecutor) scheduledExecutorService).setMaximumPoolSize(10);
        ((ScheduledThreadPoolExecutor) scheduledExecutorService).setKeepAliveTime(60, TimeUnit.SECONDS);
        
        scheduledExecutorService.schedule(
                () -> System.out.println("Scheduled task"),
                1, TimeUnit.SECONDS
        );
    }

    public void good_case_7() {
        // ok: java-unbounded-thread-pool-configuration
        ExecutorService executorService = new ThreadPoolExecutor(
                1, 1, // Single thread
                0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(5000), // Bounded queue
                Executors.defaultThreadFactory(),
                new ThreadPoolExecutor.AbortPolicy()
        );
        
        for (int i = 0; i < 100; i++) {
            final int taskId = i;
            try {
                executorService.submit(() -> System.out.println("Task " + taskId));
            } catch (RejectedExecutionException e) {
                System.out.println("Task rejected: " + taskId);
            }
        }
    }

    public void good_case_8() {
        int processors = Runtime.getRuntime().availableProcessors();
        
        // ok: java-unbounded-thread-pool-configuration
        ExecutorService executorService = new ThreadPoolExecutor(
                processors,
                processors,
                0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(processors * 100), // Bounded queue based on processors
                new ThreadPoolExecutor.CallerRunsPolicy()
        );
        
        executorService.submit(() -> System.out.println("Processor-scaled task"));
    }

    public void good_case_9() {
        // Creating a thread pool with rejection handler and bounded queue
        RejectedExecutionHandler handler = (r, executor) -> {
            System.out.println("Task rejected, implementing custom logic");
            // Custom handling logic
        };
        
        // ok: java-unbounded-thread-pool-configuration
        ExecutorService executorService = new ThreadPoolExecutor(
                2, 4,
                60, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(50), // Bounded queue
                Executors.defaultThreadFactory(),
                handler
        );
        
        executorService.submit(() -> System.out.println("Task with custom rejection handler"));
    }

    public void good_case_10() {
        // Creating a bounded completion service
        // ok: java-unbounded-thread-pool-configuration
        ExecutorService boundedExecutor = new ThreadPoolExecutor(
                5, 10,
                60, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(200)
        );
        
        ExecutorCompletionService<String> completionService = new ExecutorCompletionService<>(boundedExecutor);
        completionService.submit(() -> "Result from bounded task");
    }

    public void good_case_11() {
        // Dynamic thread pool with bounded queue
        int coreSize = Runtime.getRuntime().availableProcessors();
        int maxSize = coreSize * 2;
        int queueSize = maxSize * 10; // Queue size proportional to max threads
        
        // ok: java-unbounded-thread-pool-configuration
        ExecutorService executorService = new ThreadPoolExecutor(
                coreSize,
                maxSize,
                60, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(queueSize), // Bounded queue
                new ThreadPoolExecutor.CallerRunsPolicy()
        );
        
        executorService.submit(() -> System.out.println("Task in bounded dynamic pool"));
    }

    public void good_case_12() {
        // ok: java-unbounded-thread-pool-configuration
        ScheduledThreadPoolExecutor scheduledExecutor = new ScheduledThreadPoolExecutor(
                5, // core pool size
                Executors.defaultThreadFactory(),
                new ThreadPoolExecutor.DiscardPolicy()
        );
        
        // Set queue capacity limit
        scheduledExecutor.setMaximumPoolSize(10);
        // Set removal policy for cancelled tasks
        scheduledExecutor.setRemoveOnCancelPolicy(true);
        
        scheduledExecutor.schedule(
                () -> System.out.println("Limited scheduled task"),
                5, TimeUnit.SECONDS
        );
    }

    public void good_case_13() {
        // Creating a custom thread pool with bounded PriorityBlockingQueue
        // ok: java-unbounded-thread-pool-configuration
        ExecutorService executorService = new ThreadPoolExecutor(
                2, 4,
                60, TimeUnit.SECONDS,
                new PriorityBlockingQueue<>(100), // Bounded priority queue with initial capacity
                new ThreadPoolExecutor.AbortPolicy()
        );
        
        executorService.submit(() -> System.out.println("Bounded priority task"));
    }

    public void good_case_14() {
        // Using a semaphore to limit concurrent tasks
        final Semaphore semaphore = new Semaphore(50); // Limit to 50 concurrent tasks
        
        // ok: java-unbounded-thread-pool-configuration
        ExecutorService executorService = Executors.newFixedThreadPool(10);
        
        for (int i = 0; i < 1000; i++) {
            final int taskId = i;
            try {
                semaphore.acquire(); // Acquire permit before submitting task
                executorService.submit(() -> {
                    try {
                        System.out.println("Semaphore-limited task " + taskId);
                    } finally {
                        semaphore.release(); // Release permit when task completes
                    }
                });
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    public void good_case_15() {
        // Using a custom bounded executor service wrapper
        final int maxQueuedTasks = 200;
        final List<Runnable> taskQueue = new ArrayList<>(maxQueuedTasks);
        
        // ok: java-unbounded-thread-pool-configuration
        ExecutorService boundedExecutor = new ThreadPoolExecutor(
                5, 10,
                60, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(maxQueuedTasks),
                (r, executor) -> {
                    synchronized (taskQueue) {
                        if (taskQueue.size() < maxQueuedTasks) {
                            taskQueue.add(r);
                        } else {
                            System.out.println("Task rejected, queue full");
                        }
                    }
                }
        );
        
        boundedExecutor.submit(() -> System.out.println("Task in custom bounded executor"));
    }
}
// {/fact}