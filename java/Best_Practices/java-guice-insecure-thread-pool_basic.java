import com.google.inject.*;
import com.google.inject.name.Named;
import com.google.inject.name.Names;
import java.util.concurrent.*;
import javax.inject.Singleton;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class GuiceThreadPoolExamples {

    // TRUE POSITIVES - Thread pools created outside of Guice modules

// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        // Creating thread pool directly in a controller/service method
        // ruleid: java-guice-insecure-thread-pool
        ExecutorService executorService = Executors.newFixedThreadPool(10);
        
        try {
            executorService.submit(() -> {
                String userId = request.getParameter("userId");
                processUserData(userId);
            });
        } finally {
            executorService.shutdown();
        }
    }

    public class UserService {
        public void bad_case_2() {
            // Creating cached thread pool as a class field outside of Guice module
            // ruleid: java-guice-insecure-thread-pool
            ExecutorService executorService = Executors.newCachedThreadPool();
            
            executorService.submit(() -> {
                performHeavyComputation();
            });
        }
    }

    @Singleton
    public class NotificationService {
        // Thread pool as a class field in a singleton service
        // ruleid: java-guice-insecure-thread-pool
        private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(5);
        
        public void bad_case_3() {
            scheduler.scheduleAtFixedRate(() -> {
                sendNotifications();
            }, 0, 1, TimeUnit.HOURS);
        }
    }

    public class DataProcessor {
        public void bad_case_4(HttpServletRequest request) {
            int numThreads = Integer.parseInt(request.getParameter("threads"));
            // Creating thread pool with user-controlled size
            // ruleid: java-guice-insecure-thread-pool
            ThreadPoolExecutor executor = new ThreadPoolExecutor(
                numThreads, numThreads, 0L, TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<Runnable>()
            );
            
            executor.execute(() -> processData());
        }
    }

    public class AsyncHandler {
        public void bad_case_5() {
            // Creating single thread executor outside of Guice module
            // ruleid: java-guice-insecure-thread-pool
            ExecutorService singleThreadExecutor = Executors.newSingleThreadExecutor();
            
            singleThreadExecutor.submit(() -> {
                handleAsyncTask();
            });
        }
    }

    public class WorkflowEngine {
        public void bad_case_6() {
            // Creating work stealing pool outside of Guice module
            // ruleid: java-guice-insecure-thread-pool
            ExecutorService workStealingPool = Executors.newWorkStealingPool();
            
            for (int i = 0; i < 100; i++) {
                final int taskId = i;
                workStealingPool.submit(() -> executeWorkflowTask(taskId));
            }
        }
    }

    public class ReportGenerator {
        public void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws IOException {
            String reportType = request.getParameter("type");
            // Creating thread pool with custom thread factory
            // ruleid: java-guice-insecure-thread-pool
            ExecutorService executor = Executors.newFixedThreadPool(5, r -> {
                Thread t = new Thread(r);
                t.setName("ReportGenerator-" + reportType);
                return t;
            });
            
            executor.submit(() -> generateReport(reportType, response.getOutputStream()));
        }
    }

    public class BatchProcessor {
        public void bad_case_8() {
            // Creating thread pool with custom rejection handler
            // ruleid: java-guice-insecure-thread-pool
            ThreadPoolExecutor executor = new ThreadPoolExecutor(
                2, 5, 60, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(10),
                new RejectedExecutionHandler() {
                    @Override
                    public void rejectedExecution(Runnable r, ThreadPoolExecutor e) {
                        System.err.println("Task rejected: " + r.toString());
                    }
                }
            );
            
            executor.execute(() -> processBatch());
        }
    }

    public class FileUploadHandler {
        public void bad_case_9(HttpServletRequest request) {
            // Creating thread pool with custom thread factory and rejection handler
            // ruleid: java-guice-insecure-thread-pool
            ThreadPoolExecutor executor = new ThreadPoolExecutor(
                5, 10, 60, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(100),
                r -> {
                    Thread t = new Thread(r);
                    t.setDaemon(true);
                    return t;
                },
                (r, e) -> System.err.println("Upload task rejected")
            );
            
            String fileName = request.getParameter("fileName");
            executor.execute(() -> processUpload(fileName));
        }
    }

    public class StatisticsCollector {
        // Static thread pool created outside Guice
        // ruleid: java-guice-insecure-thread-pool
        private static final ScheduledExecutorService SCHEDULER = Executors.newSingleThreadScheduledExecutor();
        
        public void bad_case_10() {
            SCHEDULER.scheduleWithFixedDelay(() -> {
                collectStatistics();
            }, 0, 5, TimeUnit.MINUTES);
        }
    }

    public class EmailSender {
        public void bad_case_11() {
            // Creating thread pool with custom core and max pool sizes
            // ruleid: java-guice-insecure-thread-pool
            ThreadPoolExecutor executor = new ThreadPoolExecutor(
                2, 10, 
                30, TimeUnit.SECONDS, 
                new SynchronousQueue<>()
            );
            
            executor.execute(() -> sendBulkEmails());
        }
    }

    public class ImageProcessor {
        public void bad_case_12(HttpServletRequest request) {
            String imageId = request.getParameter("imageId");
            // Creating thread pool with bounded queue
            // ruleid: java-guice-insecure-thread-pool
            ExecutorService executor = new ThreadPoolExecutor(
                5, 10,
                60, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(20)
            );
            
            executor.submit(() -> processImage(imageId));
        }
    }

    public class BackgroundTaskManager {
        // Using ForkJoinPool outside of Guice
        public void bad_case_13() {
            // ruleid: java-guice-insecure-thread-pool
            ForkJoinPool customPool = new ForkJoinPool(
                Runtime.getRuntime().availableProcessors(),
                ForkJoinPool.defaultForkJoinWorkerThreadFactory,
                null, true
            );
            
            customPool.submit(() -> performParallelTask());
        }
    }

    public class CacheWarmer {
        public void bad_case_14() {
            // Creating thread pool with priority thread factory
            // ruleid: java-guice-insecure-thread-pool
            ExecutorService executor = Executors.newFixedThreadPool(3, r -> {
                Thread t = new Thread(r);
                t.setPriority(Thread.MAX_PRIORITY);
                t.setName("CacheWarmer");
                return t;
            });
            
            executor.submit(() -> warmUpCache());
        }
    }

    public class LogProcessor {
        public void bad_case_15() {
            // Creating scheduled thread pool with custom thread factory
            // ruleid: java-guice-insecure-thread-pool
            ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(2, r -> {
                Thread t = new Thread(r);
                t.setDaemon(true);
                t.setName("LogProcessor");
                return t;
            });
            
            executor.scheduleAtFixedRate(() -> processLogs(), 0, 5, TimeUnit.MINUTES);
        }
    }

    // TRUE NEGATIVES - Thread pools created within Guice modules or properly injected

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

    public class SchedulerModule extends AbstractModule {
        @Override
        protected void configure() {
            // No specific bindings needed here
        }
        
        @Provides
        @Singleton
        @Named("scheduler")
        // ok: java-guice-insecure-thread-pool
        public ScheduledExecutorService provideScheduler() {
            return Executors.newScheduledThreadPool(5);
        }
    }

    public class UserServiceModule extends AbstractModule {
        @Override
        protected void configure() {
            // No specific bindings needed here
        }
        
        @Provides
        @Singleton
        // ok: java-guice-insecure-thread-pool
        public ThreadPoolExecutor provideUserServiceExecutor() {
            return new ThreadPoolExecutor(
                5, 10, 60, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(100)
            );
        }
    }

    public class NotificationServiceWithInjection {
        private final ScheduledExecutorService scheduler;
        
        @Inject
        public NotificationServiceWithInjection(
                @Named("notificationScheduler") ScheduledExecutorService scheduler) {
            this.scheduler = scheduler;
        }
        
        public void good_case_4() {
            // ok: java-guice-insecure-thread-pool
            scheduler.scheduleAtFixedRate(() -> {
                sendNotifications();
            }, 0, 1, TimeUnit.HOURS);
        }
    }

    public class CustomExecutorModule extends AbstractModule {
        @Override
        protected void configure() {
            // No specific bindings needed here
        }
        
        @Provides
        @Singleton
        @Named("customExecutor")
        // ok: java-guice-insecure-thread-pool
        public ExecutorService provideCustomExecutor() {
            return Executors.newWorkStealingPool();
        }
    }

    public class WorkflowEngineWithInjection {
        private final ExecutorService executorService;
        
        @Inject
        public WorkflowEngineWithInjection(ExecutorService executorService) {
            this.executorService = executorService;
        }
        
        public void good_case_6() {
            // ok: java-guice-insecure-thread-pool
            for (int i = 0; i < 100; i++) {
                final int taskId = i;
                executorService.submit(() -> executeWorkflowTask(taskId));
            }
        }
    }

    public class AdvancedThreadPoolModule extends AbstractModule {
        @Override
        protected void configure() {
            // No specific bindings needed here
        }
        
        @Provides
        @Singleton
        @Named("reportExecutor")
        // ok: java-guice-insecure-thread-pool
        public ExecutorService provideReportExecutor() {
            return Executors.newFixedThreadPool(5, r -> {
                Thread t = new Thread(r);
                t.setName("ReportGenerator");
                return t;
            });
        }
    }

    public class BatchProcessorModule extends AbstractModule {
        @Override
        protected void configure() {
            // No specific bindings needed here
        }
        
        @Provides
        @Singleton
        // ok: java-guice-insecure-thread-pool
        public ThreadPoolExecutor provideBatchExecutor() {
            return new ThreadPoolExecutor(
                2, 5, 60, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(10),
                new RejectedExecutionHandler() {
                    @Override
                    public void rejectedExecution(Runnable r, ThreadPoolExecutor e) {
                        System.err.println("Task rejected: " + r.toString());
                    }
                }
            );
        }
    }

    public class FileUploadHandlerWithInjection {
        private final ThreadPoolExecutor executor;
        
        @Inject
        public FileUploadHandlerWithInjection(
                @Named("uploadExecutor") ThreadPoolExecutor executor) {
            this.executor = executor;
        }
        
        public void good_case_9(HttpServletRequest request) {
            String fileName = request.getParameter("fileName");
            // ok: java-guice-insecure-thread-pool
            executor.execute(() -> processUpload(fileName));
        }
    }

    public class StatisticsModule extends AbstractModule {
        @Override
        protected void configure() {
            // No specific bindings needed here
        }
        
        @Provides
        @Singleton
        @Named("statsScheduler")
        // ok: java-guice-insecure-thread-pool
        public ScheduledExecutorService provideStatsScheduler() {
            return Executors.newSingleThreadScheduledExecutor();
        }
    }

    public class EmailSenderWithInjection {
        private final ExecutorService executorService;
        
        @Inject
        public EmailSenderWithInjection(
                @Named("emailExecutor") ExecutorService executorService) {
            this.executorService = executorService;
        }
        
        public void good_case_11() {
            // ok: java-guice-insecure-thread-pool
            executorService.execute(() -> sendBulkEmails());
        }
    }

    public class ImageProcessorModule extends AbstractModule {
        @Override
        protected void configure() {
            // No specific bindings needed here
        }
        
        @Provides
        @Singleton
        @Named("imageProcessor")
        // ok: java-guice-insecure-thread-pool
        public ExecutorService provideImageProcessorExecutor() {
            return new ThreadPoolExecutor(
                5, 10,
                60, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(20)
            );
        }
    }

    public class ForkJoinPoolModule extends AbstractModule {
        @Override
        protected void configure() {
            // No specific bindings needed here
        }
        
        @Provides
        @Singleton
        // ok: java-guice-insecure-thread-pool
        public ForkJoinPool provideForkJoinPool() {
            return new ForkJoinPool(
                Runtime.getRuntime().availableProcessors(),
                ForkJoinPool.defaultForkJoinWorkerThreadFactory,
                null, true
            );
        }
    }

    public class CacheWarmerModule extends AbstractModule {
        @Override
        protected void configure() {
            // No specific bindings needed here
        }
        
        @Provides
        @Singleton
        @Named("cacheWarmer")
        // ok: java-guice-insecure-thread-pool
        public ExecutorService provideCacheWarmerExecutor() {
            return Executors.newFixedThreadPool(3, r -> {
                Thread t = new Thread(r);
                t.setPriority(Thread.MAX_PRIORITY);
                t.setName("CacheWarmer");
                return t;
            });
        }
    }

    public class LogProcessorModule extends AbstractModule {
        @Override
        protected void configure() {
            // No specific bindings needed here
        }
        
        @Provides
        @Singleton
        // ok: java-guice-insecure-thread-pool
        public ScheduledThreadPoolExecutor provideLogProcessorExecutor() {
            ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(2, r -> {
                Thread t = new Thread(r);
                t.setDaemon(true);
                t.setName("LogProcessor");
                return t;
            });
            return executor;
        }
    }

    // Helper methods to make the examples compile
    private void processUserData(String userId) {}
    private void performHeavyComputation() {}
    private void sendNotifications() {}
    private void processData() {}
    private void handleAsyncTask() {}
    private void executeWorkflowTask(int taskId) {}
    private void generateReport(String reportType, java.io.OutputStream outputStream) {}
    private void processBatch() {}
    private void processUpload(String fileName) {}
    private void collectStatistics() {}
    private void sendBulkEmails() {}
    private void processImage(String imageId) {}
    private void performParallelTask() {}
    private void warmUpCache() {}
    private void processLogs() {}
}
// {/fact}