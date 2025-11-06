import com.google.inject.*;
import com.google.inject.name.Named;
import com.google.inject.name.Names;
import java.util.concurrent.*;
import javax.inject.Singleton;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class GuiceThreadPoolExamples {

    // TRUE POSITIVES - Thread pools created outside Guice modules

// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        // Creating thread pool directly in a controller or service class
        // ruleid: java-guice-insecure-thread-pool
        ExecutorService executorService = Executors.newFixedThreadPool(10);
        
        executorService.submit(() -> {
            System.out.println("Processing task from request: " + request.getParameter("taskId"));
        });
    }
    
    @Singleton
    public class bad_case_2 {
        private final ExecutorService executorService;
        
        public bad_case_2() {
            // Creating thread pool in a constructor of a service
            // ruleid: java-guice-insecure-thread-pool
            this.executorService = Executors.newCachedThreadPool();
        }
        
        public void processRequest(String data) {
            executorService.execute(() -> {
                System.out.println("Processing: " + data);
            });
        }
    }
    
    public class UserService {
        // Static thread pool created outside Guice's lifecycle
        // ruleid: java-guice-insecure-thread-pool
        private static final ScheduledExecutorService SCHEDULER = 
            Executors.newScheduledThreadPool(4);
            
        public void bad_case_3(HttpServletRequest request) {
            String userId = request.getParameter("userId");
            SCHEDULER.schedule(() -> {
                System.out.println("Processing user: " + userId);
            }, 1000, TimeUnit.MILLISECONDS);
        }
    }
    
    public class bad_case_4 {
        public void processData(HttpServletRequest request) {
            int threadCount = Integer.parseInt(request.getParameter("threads"));
            // Creating thread pool with dynamic size based on request parameter
            // ruleid: java-guice-insecure-thread-pool
            ThreadPoolExecutor executor = new ThreadPoolExecutor(
                threadCount, threadCount * 2, 
                60L, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>()
            );
            
            executor.execute(() -> {
                System.out.println("Processing with dynamic thread count");
            });
        }
    }
    
    @Singleton
    public class bad_case_5 {
        private ExecutorService executorService;
        
        public void initializeService() {
            // Lazy initialization of thread pool outside Guice control
            // ruleid: java-guice-insecure-thread-pool
            if (executorService == null) {
                executorService = Executors.newFixedThreadPool(5);
            }
        }
        
        public void processTask(Runnable task) {
            initializeService();
            executorService.submit(task);
        }
    }
    
    public class bad_case_6 {
        public void handleRequest(HttpServletRequest request, HttpServletResponse response) {
            // Creating a single-use thread pool for a specific request
            // ruleid: java-guice-insecure-thread-pool
            ExecutorService singleUseExecutor = Executors.newSingleThreadExecutor();
            
            singleUseExecutor.submit(() -> {
                try {
                    String data = request.getParameter("data");
                    response.getWriter().write("Processed: " + data);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
            
            singleUseExecutor.shutdown();
        }
    }
    
    @Singleton
    public class bad_case_7 {
        private final ConcurrentHashMap<String, ExecutorService> executorMap = new ConcurrentHashMap<>();
        
        public void processForCustomer(String customerId, Runnable task) {
            // Creating multiple thread pools on demand
            // ruleid: java-guice-insecure-thread-pool
            ExecutorService executor = executorMap.computeIfAbsent(customerId, 
                k -> Executors.newFixedThreadPool(3));
                
            executor.submit(task);
        }
    }
    
    public class bad_case_8 {
        public void startBackgroundTask(HttpServletRequest request) {
            String priority = request.getParameter("priority");
            int threads = "high".equals(priority) ? 10 : 2;
            
            // Creating thread pool with conditional configuration
            // ruleid: java-guice-insecure-thread-pool
            ExecutorService executor = Executors.newFixedThreadPool(threads);
            
            executor.submit(() -> {
                System.out.println("Background task running with priority: " + priority);
            });
        }
    }
    
    public class bad_case_9 implements AutoCloseable {
        private final ExecutorService executorService;
        
        public bad_case_9() {
            // Creating thread pool in a resource-managed class
            // ruleid: java-guice-insecure-thread-pool
            this.executorService = Executors.newWorkStealingPool();
        }
        
        public void process(Runnable task) {
            executorService.submit(task);
        }
        
        @Override
        public void close() {
            executorService.shutdown();
        }
    }
    
    public class bad_case_10 {
        public void handleBatchProcessing(HttpServletRequest request) {
            int batchSize = Integer.parseInt(request.getParameter("batchSize"));
            
            // Creating a thread pool with custom rejection policy
            // ruleid: java-guice-insecure-thread-pool
            ThreadPoolExecutor executor = new ThreadPoolExecutor(
                5, 10, 60, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(batchSize),
                new ThreadPoolExecutor.CallerRunsPolicy()
            );
            
            for (int i = 0; i < batchSize; i++) {
                final int taskId = i;
                executor.execute(() -> System.out.println("Processing task: " + taskId));
            }
        }
    }
    
    public class bad_case_11 {
        public void schedulePeriodicTask() {
            // Creating a scheduled thread pool for periodic tasks
            // ruleid: java-guice-insecure-thread-pool
            ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);
            
            scheduler.scheduleAtFixedRate(
                () -> System.out.println("Periodic health check"),
                0, 5, TimeUnit.MINUTES
            );
        }
    }
    
    @Singleton
    public class bad_case_12 {
        private ExecutorService executorService;
        
        public void configureExecutor(int threadCount) {
            // Reconfiguring thread pool after initialization
            // ruleid: java-guice-insecure-thread-pool
            if (executorService != null) {
                executorService.shutdown();
            }
            executorService = Executors.newFixedThreadPool(threadCount);
        }
        
        public void executeTask(Runnable task) {
            if (executorService == null) {
                // ruleid: java-guice-insecure-thread-pool
                executorService = Executors.newFixedThreadPool(3);
            }
            executorService.submit(task);
        }
    }
    
    public class bad_case_13 {
        public void processWithTimeout(HttpServletRequest request) {
            String data = request.getParameter("data");
            long timeout = Long.parseLong(request.getParameter("timeout"));
            
            // Creating a thread pool with custom thread factory
            // ruleid: java-guice-insecure-thread-pool
            ExecutorService executor = Executors.newFixedThreadPool(2, r -> {
                Thread t = new Thread(r);
                t.setDaemon(true);
                return t;
            });
            
            Future<?> future = executor.submit(() -> {
                System.out.println("Processing: " + data);
            });
            
            try {
                future.get(timeout, TimeUnit.MILLISECONDS);
            } catch (Exception e) {
                future.cancel(true);
            }
        }
    }
    
    public class bad_case_14 {
        private static class TaskProcessor {
            // Creating thread pool in a nested class
            // ruleid: java-guice-insecure-thread-pool
            private final ExecutorService executor = Executors.newFixedThreadPool(4);
            
            public void process(Runnable task) {
                executor.submit(task);
            }
        }
        
        public void handleRequest(HttpServletRequest request) {
            TaskProcessor processor = new TaskProcessor();
            processor.process(() -> {
                System.out.println("Processing request: " + request.getRequestURI());
            });
        }
    }
    
    public class bad_case_15 {
        public void dynamicThreadPoolCreation(HttpServletRequest request) {
            String poolType = request.getParameter("poolType");
            
            // Creating different types of thread pools based on request parameter
            ExecutorService executor;
            if ("fixed".equals(poolType)) {
                // ruleid: java-guice-insecure-thread-pool
                executor = Executors.newFixedThreadPool(5);
            } else if ("cached".equals(poolType)) {
                // ruleid: java-guice-insecure-thread-pool
                executor = Executors.newCachedThreadPool();
            } else {
                // ruleid: java-guice-insecure-thread-pool
                executor = Executors.newSingleThreadExecutor();
            }
            
            executor.submit(() -> {
                System.out.println("Task executed with pool type: " + poolType);
            });
        }
    }

    // TRUE NEGATIVES - Thread pools properly managed through Guice

    public class ThreadPoolModule extends AbstractModule {
        @Override
        protected void configure() {
            // No specific bindings needed here
        }
        
        @Provides
        @Singleton
        // ok: java-guice-insecure-thread-pool
        public ExecutorService provideExecutorService() {
            return Executors.newFixedThreadPool(10);
        }
    }
    
    public class good_case_1 {
        private final ExecutorService executorService;
        
        @Inject
        public good_case_1(ExecutorService executorService) {
            // ok: java-guice-insecure-thread-pool
            this.executorService = executorService;
        }
        
        public void processRequest(HttpServletRequest request) {
            String data = request.getParameter("data");
            executorService.submit(() -> {
                System.out.println("Processing: " + data);
            });
        }
    }
    
    public class ScheduledExecutorModule extends AbstractModule {
        @Override
        protected void configure() {
            // No specific bindings needed here
        }
        
        @Provides
        @Singleton
        // ok: java-guice-insecure-thread-pool
        public ScheduledExecutorService provideScheduledExecutorService() {
            return Executors.newScheduledThreadPool(4);
        }
    }
    
    public class good_case_2 {
        private final ScheduledExecutorService scheduler;
        
        @Inject
        public good_case_2(ScheduledExecutorService scheduler) {
            // ok: java-guice-insecure-thread-pool
            this.scheduler = scheduler;
        }
        
        public void scheduleTask(Runnable task, long delay) {
            scheduler.schedule(task, delay, TimeUnit.MILLISECONDS);
        }
    }
    
    public class NamedThreadPoolModule extends AbstractModule {
        @Override
        protected void configure() {
            // No specific bindings needed here
        }
        
        @Provides
        @Named("ioThreadPool")
        @Singleton
        // ok: java-guice-insecure-thread-pool
        public ExecutorService provideIoThreadPool() {
            return Executors.newFixedThreadPool(20);
        }
        
        @Provides
        @Named("computeThreadPool")
        @Singleton
        // ok: java-guice-insecure-thread-pool
        public ExecutorService provideComputeThreadPool() {
            return Executors.newWorkStealingPool();
        }
    }
    
    public class good_case_3 {
        private final ExecutorService ioExecutor;
        private final ExecutorService computeExecutor;
        
        @Inject
        public good_case_3(
                @Named("ioThreadPool") ExecutorService ioExecutor,
                @Named("computeThreadPool") ExecutorService computeExecutor) {
            // ok: java-guice-insecure-thread-pool
            this.ioExecutor = ioExecutor;
            this.computeExecutor = computeExecutor;
        }
        
        public void processRequest(HttpServletRequest request) {
            String operation = request.getParameter("operation");
            
            if ("io".equals(operation)) {
                ioExecutor.submit(() -> System.out.println("IO operation"));
            } else {
                computeExecutor.submit(() -> System.out.println("Compute operation"));
            }
        }
    }
    
    public class ConfigurableThreadPoolModule extends AbstractModule {
        private final int threadCount;
        
        public ConfigurableThreadPoolModule(int threadCount) {
            this.threadCount = threadCount;
        }
        
        @Override
        protected void configure() {
            // No specific bindings needed here
        }
        
        @Provides
        @Singleton
        // ok: java-guice-insecure-thread-pool
        public ExecutorService provideExecutorService() {
            return Executors.newFixedThreadPool(threadCount);
        }
    }
    
    public class good_case_4 {
        private final ExecutorService executorService;
        
        @Inject
        public good_case_4(ExecutorService executorService) {
            // ok: java-guice-insecure-thread-pool
            this.executorService = executorService;
        }
        
        public void executeTask(Runnable task) {
            executorService.submit(task);
        }
    }
    
    public class CustomThreadPoolModule extends AbstractModule {
        @Override
        protected void configure() {
            // No specific bindings needed here
        }
        
        @Provides
        @Singleton
        // ok: java-guice-insecure-thread-pool
        public ThreadPoolExecutor provideCustomThreadPool() {
            return new ThreadPoolExecutor(
                5, 10, 60, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(),
                new ThreadPoolExecutor.CallerRunsPolicy()
            );
        }
    }
    
    public class good_case_5 {
        private final ThreadPoolExecutor executor;
        
        @Inject
        public good_case_5(ThreadPoolExecutor executor) {
            // ok: java-guice-insecure-thread-pool
            this.executor = executor;
        }
        
        public void processRequest(HttpServletRequest request) {
            String data = request.getParameter("data");
            executor.execute(() -> {
                System.out.println("Processing: " + data);
            });
        }
    }
    
    public class ThreadFactoryModule extends AbstractModule {
        @Override
        protected void configure() {
            // No specific bindings needed here
        }
        
        @Provides
        @Singleton
        // ok: java-guice-insecure-thread-pool
        public ThreadFactory provideThreadFactory() {
            return r -> {
                Thread t = new Thread(r);
                t.setDaemon(true);
                return t;
            };
        }
        
        @Provides
        @Singleton
        // ok: java-guice-insecure-thread-pool
        public ExecutorService provideExecutorService(ThreadFactory threadFactory) {
            return Executors.newFixedThreadPool(10, threadFactory);
        }
    }
    
    public class good_case_6 {
        private final ExecutorService executorService;
        
        @Inject
        public good_case_6(ExecutorService executorService) {
            // ok: java-guice-insecure-thread-pool
            this.executorService = executorService;
        }
        
        public void processRequest(HttpServletRequest request) {
            executorService.submit(() -> {
                System.out.println("Processing with custom thread factory");
            });
        }
    }
    
    public class LifecycleManagedThreadPoolModule extends AbstractModule {
        @Override
        protected void configure() {
            // No specific bindings needed here
        }
        
        @Provides
        @Singleton
        // ok: java-guice-insecure-thread-pool
        public ExecutorService provideExecutorService() {
            return Executors.newCachedThreadPool();
        }
    }
    
    public class good_case_7 implements AutoCloseable {
        private final ExecutorService executorService;
        
        @Inject
        public good_case_7(ExecutorService executorService) {
            // ok: java-guice-insecure-thread-pool
            this.executorService = executorService;
        }
        
        public void processTask(Runnable task) {
            executorService.submit(task);
        }
        
        @Override
        public void close() {
            // Proper cleanup handled by lifecycle management
        }
    }
    
    public class MultipleThreadPoolsModule extends AbstractModule {
        @Override
        protected void configure() {
            // No specific bindings needed here
        }
        
        @Provides
        @Singleton
        @Named("fastExecutor")
        // ok: java-guice-insecure-thread-pool
        public ExecutorService provideFastExecutor() {
            return Executors.newFixedThreadPool(20);
        }
        
        @Provides
        @Singleton
        @Named("reliableExecutor")
        // ok: java-guice-insecure-thread-pool
        public ExecutorService provideReliableExecutor() {
            return Executors.newFixedThreadPool(5);
        }
    }
    
    public class good_case_8 {
        private final ExecutorService fastExecutor;
        private final ExecutorService reliableExecutor;
        
        @Inject
        public good_case_8(
                @Named("fastExecutor") ExecutorService fastExecutor,
                @Named("reliableExecutor") ExecutorService reliableExecutor) {
            // ok: java-guice-insecure-thread-pool
            this.fastExecutor = fastExecutor;
            this.reliableExecutor = reliableExecutor;
        }
        
        public void processRequest(HttpServletRequest request) {
            String priority = request.getParameter("priority");
            
            if ("high".equals(priority)) {
                fastExecutor.submit(() -> System.out.println("Fast processing"));
            } else {
                reliableExecutor.submit(() -> System.out.println("Reliable processing"));
            }
        }
    }
    
    public class ScheduledTaskModule extends AbstractModule {
        @Override
        protected void configure() {
            // No specific bindings needed here
        }
        
        @Provides
        @Singleton
        // ok: java-guice-insecure-thread-pool
        public ScheduledExecutorService provideScheduler() {
            return Executors.newScheduledThreadPool(2);
        }
    }
    
    public class good_case_9 {
        private final ScheduledExecutorService scheduler;
        
        @Inject
        public good_case_9(ScheduledExecutorService scheduler) {
            // ok: java-guice-insecure-thread-pool
            this.scheduler = scheduler;
            
            // Schedule periodic tasks using injected scheduler
            scheduler.scheduleAtFixedRate(
                () -> System.out.println("Periodic health check"),
                0, 5, TimeUnit.MINUTES
            );
        }
    }
    
    public class DynamicThreadPoolModule extends AbstractModule {
        @Override
        protected void configure() {
            // No specific bindings needed here
        }
        
        @Provides
        @Singleton
        // ok: java-guice-insecure-thread-pool
        public ExecutorService provideExecutorService() {
            int processors = Runtime.getRuntime().availableProcessors();
            return Executors.newFixedThreadPool(processors * 2);
        }
    }
    
    public class good_case_10 {
        private final ExecutorService executorService;
        
        @Inject
        public good_case_10(ExecutorService executorService) {
            // ok: java-guice-insecure-thread-pool
            this.executorService = executorService;
        }
        
        public void processRequest(HttpServletRequest request) {
            executorService.submit(() -> {
                System.out.println("Processing with dynamically sized thread pool");
            });
        }
    }
    
    public class WorkStealingPoolModule extends AbstractModule {
        @Override
        protected void configure() {
            // No specific bindings needed here
        }
        
        @Provides
        @Singleton
        // ok: java-guice-insecure-thread-pool
        public ExecutorService provideWorkStealingPool() {
            return Executors.newWorkStealingPool();
        }
    }
    
    public class good_case_11 {
        private final ExecutorService executorService;
        
        @Inject
        public good_case_11(ExecutorService executorService) {
            // ok: java-guice-insecure-thread-pool
            this.executorService = executorService;
        }
        
        public void processParallelTasks(HttpServletRequest request) {
            int taskCount = Integer.parseInt(request.getParameter("taskCount"));
            
            for (int i = 0; i < taskCount; i++) {
                final int taskId = i;
                executorService.submit(() -> {
                    System.out.println("Processing task: " + taskId);
                });
            }
        }
    }
    
    public class SingleThreadExecutorModule extends AbstractModule {
        @Override
        protected void configure() {
            // No specific bindings needed here
        }
        
        @Provides
        @Singleton
        @Named("sequentialExecutor")
        // ok: java-guice-insecure-thread-pool
        public ExecutorService provideSingleThreadExecutor() {
            return Executors.newSingleThreadExecutor();
        }
    }
    
    public class good_case_12 {
        private final ExecutorService sequentialExecutor;
        
        @Inject
        public good_case_12(@Named("sequentialExecutor") ExecutorService sequentialExecutor) {
            // ok: java-guice-insecure-thread-pool
            this.sequentialExecutor = sequentialExecutor;
        }
        
        public void processSequentialTasks(HttpServletRequest request) {
            String data = request.getParameter("data");
            
            sequentialExecutor.submit(() -> {
                System.out.println("Sequential processing: " + data);
            });
        }
    }
    
    public class RejectionHandlerModule extends AbstractModule {
        @Override
        protected void configure() {
            // No specific bindings needed here
        }
        
        @Provides
        @Singleton
        // ok: java-guice-insecure-thread-pool
        public RejectedExecutionHandler provideRejectionHandler() {
            return new ThreadPoolExecutor.CallerRunsPolicy();
        }
        
        @Provides
        @Singleton
        // ok: java-guice-insecure-thread-pool
        public ThreadPoolExecutor provideThreadPoolExecutor(RejectedExecutionHandler rejectionHandler) {
            return new ThreadPoolExecutor(
                5, 10, 60, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(100),
                rejectionHandler
            );
        }
    }
    
    public class good_case_13 {
        private final ThreadPoolExecutor executor;
        
        @Inject
        public good_case_13(ThreadPoolExecutor executor) {
            // ok: java-guice-insecure-thread-pool
            this.executor = executor;
        }
        
        public void processBatchRequest(HttpServletRequest request) {
            int batchSize = Integer.parseInt(request.getParameter("batchSize"));
            
            for (int i = 0; i < batchSize; i++) {
                final int taskId = i;
                executor.execute(() -> {
                    System.out.println("Processing batch item: " + taskId);
                });
            }
        }
    }
    
    public class ThreadPoolFactoryModule extends AbstractModule {
        @Override
        protected void configure() {
            // No specific bindings needed here
        }
        
        @Provides
        @Singleton
        // ok: java-guice-insecure-thread-pool
        public ThreadPoolFactory provideThreadPoolFactory() {
            return new ThreadPoolFactory();
        }
    }
    
    public class ThreadPoolFactory {
        public ExecutorService createFixedThreadPool(int nThreads) {
            return Executors.newFixedThreadPool(nThreads);
        }
        
        public ExecutorService createCachedThreadPool() {
            return Executors.newCachedThreadPool();
        }
    }
    
    public class good_case_14 {
        private final ThreadPoolFactory threadPoolFactory;
        private ExecutorService executorService;
        
        @Inject
        public good_case_14(ThreadPoolFactory threadPoolFactory) {
            // ok: java-guice-insecure-thread-pool
            this.threadPoolFactory = threadPoolFactory;
        }
        
        public void initializeWithSize(int size) {
            // Still using factory provided by Guice
            executorService = threadPoolFactory.createFixedThreadPool(size);
        }
        
        public void processTask(Runnable task) {
            if (executorService == null) {
                executorService = threadPoolFactory.createCachedThreadPool();
            }
            executorService.submit(task);
        }
    }
    
    public class ConfigurableExecutorModule extends AbstractModule {
        private final ExecutorConfiguration config;
        
        public ConfigurableExecutorModule(ExecutorConfiguration config) {
            this.config = config;
        }
        
        @Override
        protected void configure() {
            // No specific bindings needed here
        }
        
        @Provides
        @Singleton
        // ok: java-guice-insecure-thread-pool
        public ExecutorService provideConfigurableExecutor() {
            if (config.isWorkStealing()) {
                return Executors.newWorkStealingPool(config.getThreadCount());
            } else if (config.isCached()) {
                return Executors.newCachedThreadPool();
            } else {
                return Executors.newFixedThreadPool(config.getThreadCount());
            }
        }
    }
    
    public class ExecutorConfiguration {
        private final int threadCount;
        private final boolean workStealing;
        private final boolean cached;
        
        public ExecutorConfiguration(int threadCount, boolean workStealing, boolean cached) {
            this.threadCount = threadCount;
            this.workStealing = workStealing;
            this.cached = cached;
        }
        
        public int getThreadCount() {
            return threadCount;
        }
        
        public boolean isWorkStealing() {
            return workStealing;
        }
        
        public boolean isCached() {
            return cached;
        }
    }
    
    public class good_case_15 {
        private final ExecutorService executorService;
        
        @Inject
        public good_case_15(ExecutorService executorService) {
            // ok: java-guice-insecure-thread-pool
            this.executorService = executorService;
        }
        
        public void processRequest(HttpServletRequest request) {
            String data = request.getParameter("data");
            executorService.submit(() -> {
                System.out.println("Processing with configurable executor: " + data);
            });
        }
    }
}
// {/fact}