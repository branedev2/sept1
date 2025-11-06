import com.amazonaws.services.cloudwatch.AmazonCloudWatch;
import com.amazonaws.services.cloudwatch.AmazonCloudWatchClientBuilder;
import com.amazonaws.services.cloudwatch.model.Dimension;
import com.amazonaws.services.cloudwatch.model.MetricDatum;
import com.amazonaws.services.cloudwatch.model.PutMetricDataRequest;
import com.amazonaws.services.cloudwatch.model.PutMetricDataResult;
import com.amazonaws.services.cloudwatch.model.StandardUnit;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Queue;
import java.util.LinkedList;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import software.amazon.awssdk.services.cloudwatch.CloudWatchAsyncClient;
import software.amazon.awssdk.services.cloudwatch.CloudWatchClient;
import software.amazon.awssdk.services.cloudwatch.model.MetricData;

public class LambdaMetricsExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=sync-metric-publish@v1.0 defects=1}
    public void bad_case_1(Context context) {
        AmazonCloudWatch cloudWatch = AmazonCloudWatchClientBuilder.defaultClient();
        
        MetricDatum datum = new MetricDatum()
            .withMetricName("ProcessingTime")
            .withUnit(StandardUnit.Milliseconds)
            .withValue(100.0);
            
        PutMetricDataRequest request = new PutMetricDataRequest()
            .withNamespace("MyLambdaFunction")
            .withMetricData(datum);
            
        // ruleid: java-sync-metric-publish
        cloudWatch.putMetricData(request);
        
        // Continue with Lambda function execution
        processRequest(context);
    }
    
    public void bad_case_2(Map<String, Object> event, Context context) {
        AmazonCloudWatch cw = AmazonCloudWatchClientBuilder.standard()
            .withRegion("us-west-2")
            .build();
            
        // Calculate execution metrics
        double executionTime = calculateExecutionTime();
        
        MetricDatum datum = new MetricDatum()
            .withMetricName("ExecutionLatency")
            .withUnit(StandardUnit.Milliseconds)
            .withValue(executionTime);
            
        // ruleid: java-sync-metric-publish
        cw.putMetricData(new PutMetricDataRequest()
            .withNamespace("LambdaMetrics")
            .withMetricData(datum));
            
        // Process the main business logic
        processBusinessLogic(event);
    }
    
    public void bad_case_3(String input, Context context) {
        // Process input
        String result = processInput(input);
        
        // Publish metrics synchronously
        AmazonCloudWatch cloudWatch = AmazonCloudWatchClientBuilder.defaultClient();
        
        List<MetricDatum> metricData = new ArrayList<>();
        metricData.add(new MetricDatum()
            .withMetricName("InputSize")
            .withUnit(StandardUnit.Bytes)
            .withValue((double) input.length()));
            
        metricData.add(new MetricDatum()
            .withMetricName("OutputSize")
            .withUnit(StandardUnit.Bytes)
            .withValue((double) result.length()));
            
        // ruleid: java-sync-metric-publish
        cloudWatch.putMetricData(new PutMetricDataRequest()
            .withNamespace("DataProcessing")
            .withMetricData(metricData));
            
        return;
    }
    
    public String bad_case_4(Map<String, String> event) {
        long startTime = System.currentTimeMillis();
        
        // Process the request
        String response = doSomeWork(event);
        
        // Calculate processing time
        long processingTime = System.currentTimeMillis() - startTime;
        
        // Publish metrics
        AmazonCloudWatch cloudWatch = AmazonCloudWatchClientBuilder.defaultClient();
        
        Dimension dimension = new Dimension()
            .withName("FunctionName")
            .withValue("ProcessingFunction");
            
        MetricDatum datum = new MetricDatum()
            .withMetricName("ProcessingDuration")
            .withUnit(StandardUnit.Milliseconds)
            .withValue((double) processingTime)
            .withDimensions(dimension);
            
        // ruleid: java-sync-metric-publish
        PutMetricDataResult result = cloudWatch.putMetricData(
            new PutMetricDataRequest()
                .withNamespace("LambdaPerformance")
                .withMetricData(datum));
                
        return response;
    }
    
    public class LambdaHandler implements RequestHandler<Map<String, Object>, String> {
        private final AmazonCloudWatch cloudWatch = AmazonCloudWatchClientBuilder.defaultClient();
        
        @Override
        public String handleRequest(Map<String, Object> input, Context context) {
            // Process request
            String result = processRequest(input);
            
            // Track success/failure
            int status = isSuccessful(result) ? 1 : 0;
            
            MetricDatum successMetric = new MetricDatum()
                .withMetricName("SuccessCount")
                .withUnit(StandardUnit.Count)
                .withValue((double) status);
                
            // ruleid: java-sync-metric-publish
            cloudWatch.putMetricData(new PutMetricDataRequest()
                .withNamespace("RequestProcessing")
                .withMetricData(successMetric));
                
            return result;
        }
        
        private String processRequest(Map<String, Object> input) {
            // Implementation
            return "processed";
        }
        
        private boolean isSuccessful(String result) {
            return true;
        }
    }
    
    public void bad_case_5(Context context) {
        CloudWatchClient cloudWatchClient = CloudWatchClient.create();
        
        // Create metric data
        software.amazon.awssdk.services.cloudwatch.model.MetricDatum datum = 
            software.amazon.awssdk.services.cloudwatch.model.MetricDatum.builder()
                .metricName("FunctionInvocation")
                .unit("Count")
                .value(1.0)
                .build();
                
        // ruleid: java-sync-metric-publish
        cloudWatchClient.putMetricData(
            software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest.builder()
                .namespace("LambdaMonitoring")
                .metricData(datum)
                .build());
                
        // Continue with function execution
        processData(context);
    }
    
    public void bad_case_6(Map<String, Object> event) {
        // Process event
        Object result = processEvent(event);
        
        // Track metrics for different event types
        String eventType = (String) event.get("type");
        
        AmazonCloudWatch cloudWatch = AmazonCloudWatchClientBuilder.defaultClient();
        
        Dimension typeDimension = new Dimension()
            .withName("EventType")
            .withValue(eventType);
            
        MetricDatum datum = new MetricDatum()
            .withMetricName("EventProcessed")
            .withUnit(StandardUnit.Count)
            .withValue(1.0)
            .withDimensions(typeDimension);
            
        // ruleid: java-sync-metric-publish
        cloudWatch.putMetricData(new PutMetricDataRequest()
            .withNamespace("EventProcessing")
            .withMetricData(datum));
    }
    
    public void bad_case_7() {
        AmazonCloudWatch cloudWatch = AmazonCloudWatchClientBuilder.defaultClient();
        
        // Create multiple metrics
        List<MetricDatum> metrics = new ArrayList<>();
        
        // Add CPU usage metric
        metrics.add(new MetricDatum()
            .withMetricName("CPUUtilization")
            .withUnit(StandardUnit.Percent)
            .withValue(getCpuUsage()));
            
        // Add memory usage metric
        metrics.add(new MetricDatum()
            .withMetricName("MemoryUtilization")
            .withUnit(StandardUnit.Percent)
            .withValue(getMemoryUsage()));
            
        // ruleid: java-sync-metric-publish
        cloudWatch.putMetricData(new PutMetricDataRequest()
            .withNamespace("LambdaResources")
            .withMetricData(metrics));
    }
    
    public void bad_case_8(String userId, Context context) {
        // Process user data
        Map<String, Object> userData = getUserData(userId);
        
        // Track user activity
        AmazonCloudWatch cloudWatch = AmazonCloudWatchClientBuilder.defaultClient();
        
        Dimension userDimension = new Dimension()
            .withName("UserId")
            .withValue(userId);
            
        MetricDatum datum = new MetricDatum()
            .withMetricName("UserActivity")
            .withUnit(StandardUnit.Count)
            .withValue(1.0)
            .withDimensions(userDimension);
            
        // ruleid: java-sync-metric-publish
        PutMetricDataResult result = cloudWatch.putMetricData(
            new PutMetricDataRequest()
                .withNamespace("UserTracking")
                .withMetricData(datum));
    }
    
    public void bad_case_9(Context context) {
        try {
            // Perform some operation
            performOperation();
            
            // Track successful operation
            AmazonCloudWatch cloudWatch = AmazonCloudWatchClientBuilder.defaultClient();
            
            MetricDatum datum = new MetricDatum()
                .withMetricName("SuccessfulOperation")
                .withUnit(StandardUnit.Count)
                .withValue(1.0);
                
            // ruleid: java-sync-metric-publish
            cloudWatch.putMetricData(new PutMetricDataRequest()
                .withNamespace("OperationMetrics")
                .withMetricData(datum));
                
        } catch (Exception e) {
            // Track failed operation
            AmazonCloudWatch cloudWatch = AmazonCloudWatchClientBuilder.defaultClient();
            
            MetricDatum datum = new MetricDatum()
                .withMetricName("FailedOperation")
                .withUnit(StandardUnit.Count)
                .withValue(1.0);
                
            // ruleid: java-sync-metric-publish
            cloudWatch.putMetricData(new PutMetricDataRequest()
                .withNamespace("OperationMetrics")
                .withMetricData(datum));
        }
    }
    
    public void bad_case_10(String region, Context context) {
        // Create CloudWatch client for specific region
        AmazonCloudWatch cloudWatch = AmazonCloudWatchClientBuilder.standard()
            .withRegion(region)
            .build();
            
        // Create metric with timestamp
        MetricDatum datum = new MetricDatum()
            .withMetricName("RegionalProcessing")
            .withUnit(StandardUnit.Count)
            .withValue(1.0)
            .withTimestamp(new java.util.Date());
            
        // ruleid: java-sync-metric-publish
        cloudWatch.putMetricData(new PutMetricDataRequest()
            .withNamespace("RegionalMetrics")
            .withMetricData(datum));
    }
    
    public void bad_case_11(Map<String, Double> metrics) {
        AmazonCloudWatch cloudWatch = AmazonCloudWatchClientBuilder.defaultClient();
        List<MetricDatum> metricData = new ArrayList<>();
        
        // Convert all metrics to CloudWatch format
        for (Map.Entry<String, Double> entry : metrics.entrySet()) {
            metricData.add(new MetricDatum()
                .withMetricName(entry.getKey())
                .withUnit(StandardUnit.None)
                .withValue(entry.getValue()));
        }
        
        // ruleid: java-sync-metric-publish
        cloudWatch.putMetricData(new PutMetricDataRequest()
            .withNamespace("BatchMetrics")
            .withMetricData(metricData));
    }
    
    public void bad_case_12(Context context) {
        CloudWatchClient cloudWatchClient = CloudWatchClient.builder()
            .region(software.amazon.awssdk.regions.Region.US_EAST_1)
            .build();
            
        // Create metric data
        software.amazon.awssdk.services.cloudwatch.model.MetricDatum datum = 
            software.amazon.awssdk.services.cloudwatch.model.MetricDatum.builder()
                .metricName("ApiLatency")
                .unit("Milliseconds")
                .value(getApiLatency())
                .build();
                
        // ruleid: java-sync-metric-publish
        cloudWatchClient.putMetricData(
            software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest.builder()
                .namespace("ApiPerformance")
                .metricData(datum)
                .build());
    }
    
    public void bad_case_13(String transactionId) {
        // Process transaction
        boolean success = processTransaction(transactionId);
        
        // Report transaction status
        AmazonCloudWatch cloudWatch = AmazonCloudWatchClientBuilder.defaultClient();
        
        Dimension transactionDimension = new Dimension()
            .withName("TransactionId")
            .withValue(transactionId);
            
        MetricDatum datum = new MetricDatum()
            .withMetricName(success ? "SuccessfulTransaction" : "FailedTransaction")
            .withUnit(StandardUnit.Count)
            .withValue(1.0)
            .withDimensions(transactionDimension);
            
        // ruleid: java-sync-metric-publish
        cloudWatch.putMetricData(new PutMetricDataRequest()
            .withNamespace("Transactions")
            .withMetricData(datum));
    }
    
    public void bad_case_14(Context context) {
        // Initialize CloudWatch client
        AmazonCloudWatch cloudWatch = AmazonCloudWatchClientBuilder.defaultClient();
        
        // Get remaining time in milliseconds
        long remainingTime = context.getRemainingTimeInMillis();
        
        // Report remaining execution time
        MetricDatum datum = new MetricDatum()
            .withMetricName("RemainingExecutionTime")
            .withUnit(StandardUnit.Milliseconds)
            .withValue((double) remainingTime);
            
        // ruleid: java-sync-metric-publish
        cloudWatch.putMetricData(new PutMetricDataRequest()
            .withNamespace("LambdaExecution")
            .withMetricData(datum));
    }
    
    public void bad_case_15(String functionName) {
        // Create CloudWatch client
        CloudWatchClient cloudWatchClient = CloudWatchClient.create();
        
        // Create metric with function name dimension
        software.amazon.awssdk.services.cloudwatch.model.Dimension dimension = 
            software.amazon.awssdk.services.cloudwatch.model.Dimension.builder()
                .name("FunctionName")
                .value(functionName)
                .build();
                
        software.amazon.awssdk.services.cloudwatch.model.MetricDatum datum = 
            software.amazon.awssdk.services.cloudwatch.model.MetricDatum.builder()
                .metricName("Invocation")
                .unit("Count")
                .value(1.0)
                .dimensions(dimension)
                .build();
                
        // ruleid: java-sync-metric-publish
        cloudWatchClient.putMetricData(
            software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest.builder()
                .namespace("LambdaInvocations")
                .metricData(datum)
                .build());
    }
    
    // True Negative Examples (Safe Code)
    
    public void good_case_1(Context context) {
        final AmazonCloudWatch cloudWatch = AmazonCloudWatchClientBuilder.defaultClient();
        
        MetricDatum datum = new MetricDatum()
            .withMetricName("ProcessingTime")
            .withUnit(StandardUnit.Milliseconds)
            .withValue(100.0);
            
        PutMetricDataRequest request = new PutMetricDataRequest()
            .withNamespace("MyLambdaFunction")
            .withMetricData(datum);
            
        // ok: java-sync-metric-publish
        CompletableFuture.runAsync(() -> {
            cloudWatch.putMetricData(request);
        });
        
        // Continue with Lambda function execution
        processRequest(context);
    }
    
    public void good_case_2(Map<String, Object> event, Context context) {
        final AmazonCloudWatch cw = AmazonCloudWatchClientBuilder.standard()
            .withRegion("us-west-2")
            .build();
            
        // Calculate execution metrics
        double executionTime = calculateExecutionTime();
        
        MetricDatum datum = new MetricDatum()
            .withMetricName("ExecutionLatency")
            .withUnit(StandardUnit.Milliseconds)
            .withValue(executionTime);
            
        final PutMetricDataRequest request = new PutMetricDataRequest()
            .withNamespace("LambdaMetrics")
            .withMetricData(datum);
            
        // ok: java-sync-metric-publish
        new Thread(() -> {
            cw.putMetricData(request);
        }).start();
        
        // Process the main business logic
        processBusinessLogic(event);
    }
    
    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private static final Queue<MetricDatum> metricQueue = new ConcurrentLinkedQueue<>();
    
    public void good_case_3(String input, Context context) {
        // Process input
        String result = processInput(input);
        
        // Queue metrics for async publishing
        metricQueue.add(new MetricDatum()
            .withMetricName("InputSize")
            .withUnit(StandardUnit.Bytes)
            .withValue((double) input.length()));
            
        metricQueue.add(new MetricDatum()
            .withMetricName("OutputSize")
            .withUnit(StandardUnit.Bytes)
            .withValue((double) result.length()));
            
        // ok: java-sync-metric-publish
        scheduler.schedule(this::publishQueuedMetrics, 100, TimeUnit.MILLISECONDS);
        
        return;
    }
    
    private void publishQueuedMetrics() {
        List<MetricDatum> batch = new ArrayList<>();
        MetricDatum datum;
        
        while ((datum = metricQueue.poll()) != null && batch.size() < 20) {
            batch.add(datum);
        }
        
        if (!batch.isEmpty()) {
            final AmazonCloudWatch cloudWatch = AmazonCloudWatchClientBuilder.defaultClient();
            final PutMetricDataRequest request = new PutMetricDataRequest()
                .withNamespace("DataProcessing")
                .withMetricData(batch);
                
            CompletableFuture.runAsync(() -> {
                cloudWatch.putMetricData(request);
            });
        }
    }
    
    public String good_case_4(Map<String, String> event) {
        long startTime = System.currentTimeMillis();
        
        // Process the request
        String response = doSomeWork(event);
        
        // Calculate processing time
        long processingTime = System.currentTimeMillis() - startTime;
        
        // Publish metrics asynchronously
        final AmazonCloudWatch cloudWatch = AmazonCloudWatchClientBuilder.defaultClient();
        
        Dimension dimension = new Dimension()
            .withName("FunctionName")
            .withValue("ProcessingFunction");
            
        final MetricDatum datum = new MetricDatum()
            .withMetricName("ProcessingDuration")
            .withUnit(StandardUnit.Milliseconds)
            .withValue((double) processingTime)
            .withDimensions(dimension);
            
        final PutMetricDataRequest request = new PutMetricDataRequest()
            .withNamespace("LambdaPerformance")
            .withMetricData(datum);
            
        // ok: java-sync-metric-publish
        ExecutorService executor = Executors.newSingleThreadExecutor();
        executor.submit(() -> {
            cloudWatch.putMetricData(request);
            executor.shutdown();
        });
                
        return response;
    }
    
    public class AsyncMetricsHandler implements RequestHandler<Map<String, Object>, String> {
        private final CloudWatchAsyncClient cloudWatchAsync = CloudWatchAsyncClient.create();
        
        @Override
        public String handleRequest(Map<String, Object> input, Context context) {
            // Process request
            String result = processRequest(input);
            
            // Track success/failure
            int status = isSuccessful(result) ? 1 : 0;
            
            software.amazon.awssdk.services.cloudwatch.model.MetricDatum successMetric = 
                software.amazon.awssdk.services.cloudwatch.model.MetricDatum.builder()
                    .metricName("SuccessCount")
                    .unit("Count")
                    .value((double) status)
                    .build();
                    
            // ok: java-sync-metric-publish
            cloudWatchAsync.putMetricData(
                software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest.builder()
                    .namespace("RequestProcessing")
                    .metricData(successMetric)
                    .build());
                    
            return result;
        }
        
        private String processRequest(Map<String, Object> input) {
            // Implementation
            return "processed";
        }
        
        private boolean isSuccessful(String result) {
            return true;
        }
    }
    
    private static final ExecutorService metricsExecutor = Executors.newCachedThreadPool();
    
    public void good_case_5(Context context) {
        // Create metric data
        software.amazon.awssdk.services.cloudwatch.model.MetricDatum datum = 
            software.amazon.awssdk.services.cloudwatch.model.MetricDatum.builder()
                .metricName("FunctionInvocation")
                .unit("Count")
                .value(1.0)
                .build();
                
        final software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest request =
            software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest.builder()
                .namespace("LambdaMonitoring")
                .metricData(datum)
                .build();
                
        // ok: java-sync-metric-publish
        metricsExecutor.execute(() -> {
            CloudWatchClient cloudWatchClient = CloudWatchClient.create();
            cloudWatchClient.putMetricData(request);
        });
                
        // Continue with function execution
        processData(context);
    }
    
    private static class MetricsPublisher {
        private final AmazonCloudWatch cloudWatch;
        private final ExecutorService executor;
        
        public MetricsPublisher() {
            this.cloudWatch = AmazonCloudWatchClientBuilder.defaultClient();
            this.executor = Executors.newSingleThreadExecutor();
        }
        
        public void publishMetric(String metricName, double value, String namespace) {
            MetricDatum datum = new MetricDatum()
                .withMetricName(metricName)
                .withUnit(StandardUnit.None)
                .withValue(value);
                
            final PutMetricDataRequest request = new PutMetricDataRequest()
                .withNamespace(namespace)
                .withMetricData(datum);
                
            executor.submit(() -> cloudWatch.putMetricData(request));
        }
        
        public void shutdown() {
            executor.shutdown();
        }
    }
    
    public void good_case_6(Map<String, Object> event) {
        // Process event
        Object result = processEvent(event);
        
        // Track metrics for different event types
        String eventType = (String) event.get("type");
        
        MetricsPublisher publisher = new MetricsPublisher();
        
        // ok: java-sync-metric-publish
        publisher.publishMetric("EventProcessed", 1.0, "EventProcessing");
    }
    
    public void good_case_7() {
        final AmazonCloudWatch cloudWatch = AmazonCloudWatchClientBuilder.defaultClient();
        
        // Create multiple metrics
        List<MetricDatum> metrics = new ArrayList<>();
        
        // Add CPU usage metric
        metrics.add(new MetricDatum()
            .withMetricName("CPUUtilization")
            .withUnit(StandardUnit.Percent)
            .withValue(getCpuUsage()));
            
        // Add memory usage metric
        metrics.add(new MetricDatum()
            .withMetricName("MemoryUtilization")
            .withUnit(StandardUnit.Percent)
            .withValue(getMemoryUsage()));
            
        final PutMetricDataRequest request = new PutMetricDataRequest()
            .withNamespace("LambdaResources")
            .withMetricData(metrics);
            
        // ok: java-sync-metric-publish
        CompletableFuture.runAsync(() -> {
            try {
                cloudWatch.putMetricData(request);
            } catch (Exception e) {
                System.err.println("Failed to publish metrics: " + e.getMessage());
            }
        });
    }
    
    private static class BatchMetricsPublisher {
        private final CloudWatchAsyncClient cloudWatchAsync;
        private final List<software.amazon.awssdk.services.cloudwatch.model.MetricDatum> metricBuffer;
        private final String namespace;
        
        public BatchMetricsPublisher(String namespace) {
            this.cloudWatchAsync = CloudWatchAsyncClient.create();
            this.metricBuffer = new ArrayList<>();
            this.namespace = namespace;
        }
        
        public void addMetric(String name, double value) {
            software.amazon.awssdk.services.cloudwatch.model.MetricDatum datum = 
                software.amazon.awssdk.services.cloudwatch.model.MetricDatum.builder()
                    .metricName(name)
                    .value(value)
                    .unit("None")
                    .build();
                    
            metricBuffer.add(datum);
        }
        
        public void publishAsync() {
            if (metricBuffer.isEmpty()) {
                return;
            }
            
            List<software.amazon.awssdk.services.cloudwatch.model.MetricDatum> batchToSend = 
                new ArrayList<>(metricBuffer);
            metricBuffer.clear();
            
            // ok: java-sync-metric-publish
            cloudWatchAsync.putMetricData(
                software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest.builder()
                    .namespace(namespace)
                    .metricData(batchToSend)
                    .build());
        }
    }
    
    public void good_case_8(String userId, Context context) {
        // Process user data
        Map<String, Object> userData = getUserData(userId);
        
        // Track user activity
        BatchMetricsPublisher publisher = new BatchMetricsPublisher("UserTracking");
        publisher.addMetric("UserActivity", 1.0);
        
        // ok: java-sync-metric-publish
        publisher.publishAsync();
    }
    
    public void good_case_9(Context context) {
        final CloudWatchAsyncClient cloudWatchAsync = CloudWatchAsyncClient.create();
        
        try {
            // Perform some operation
            performOperation();
            
            // Track successful operation
            software.amazon.awssdk.services.cloudwatch.model.MetricDatum successDatum = 
                software.amazon.awssdk.services.cloudwatch.model.MetricDatum.builder()
                    .metricName("SuccessfulOperation")
                    .unit("Count")
                    .value(1.0)
                    .build();
                    
            // ok: java-sync-metric-publish
            cloudWatchAsync.putMetricData(
                software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest.builder()
                    .namespace("OperationMetrics")
                    .metricData(successDatum)
                    .build());
                    
        } catch (Exception e) {
            // Track failed operation
            software.amazon.awssdk.services.cloudwatch.model.MetricDatum failureDatum = 
                software.amazon.awssdk.services.cloudwatch.model.MetricDatum.builder()
                    .metricName("FailedOperation")
                    .unit("Count")
                    .value(1.0)
                    .build();
                    
            // ok: java-sync-metric-publish
            cloudWatchAsync.putMetricData(
                software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest.builder()
                    .namespace("OperationMetrics")
                    .metricData(failureDatum)
                    .build());
        }
    }
    
    private static final Map<String, CloudWatchAsyncClient> regionClients = new HashMap<>();
    
    public void good_case_10(String region, Context context) {
        // Get or create CloudWatch async client for specific region
        CloudWatchAsyncClient cloudWatchAsync = regionClients.computeIfAbsent(region, r -> 
            CloudWatchAsyncClient.builder()
                .region(software.amazon.awssdk.regions.Region.of(r))
                .build());
            
        // Create metric with timestamp
        software.amazon.awssdk.services.cloudwatch.model.MetricDatum datum = 
            software.amazon.awssdk.services.cloudwatch.model.MetricDatum.builder()
                .metricName("RegionalProcessing")
                .unit("Count")
                .value(1.0)
                .timestamp(java.time.Instant.now())
                .build();
                
        // ok: java-sync-metric-publish
        cloudWatchAsync.putMetricData(
            software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest.builder()
                .namespace("RegionalMetrics")
                .metricData(datum)
                .build());
    }
    
    public void good_case_11(Map<String, Double> metrics) {
        final CloudWatchAsyncClient cloudWatchAsync = CloudWatchAsyncClient.create();
        List<software.amazon.awssdk.services.cloudwatch.model.MetricDatum> metricData = new ArrayList<>();
        
        // Convert all metrics to CloudWatch format
        for (Map.Entry<String, Double> entry : metrics.entrySet()) {
            metricData.add(
                software.amazon.awssdk.services.cloudwatch.model.MetricDatum.builder()
                    .metricName(entry.getKey())
                    .unit("None")
                    .value(entry.getValue())
                    .build());
        }
        
        // ok: java-sync-metric-publish
        cloudWatchAsync.putMetricData(
            software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest.builder()
                .namespace("BatchMetrics")
                .metricData(metricData)
                .build());
    }
    
    private static class MetricsBuffer {
        private static final int FLUSH_SIZE = 20;
        private static final long FLUSH_INTERVAL_MS = 1000;
        private final List<MetricDatum> buffer = new ArrayList<>();
        private final String namespace;
        private final ScheduledExecutorService scheduler;
        private final AmazonCloudWatch cloudWatch;
        
        public MetricsBuffer(String namespace) {
            this.namespace = namespace;
            this.cloudWatch = AmazonCloudWatchClientBuilder.defaultClient();
            this.scheduler = Executors.newScheduledThreadPool(1);
            
            // Schedule periodic flush
            scheduler.scheduleAtFixedRate(this::flush, 
                FLUSH_INTERVAL_MS, FLUSH_INTERVAL_MS, TimeUnit.MILLISECONDS);
        }
        
        public synchronized void addMetric(MetricDatum datum) {
            buffer.add(datum);
            
            if (buffer.size() >= FLUSH_SIZE) {
                flush();
            }
        }
        
        public synchronized void flush() {
            if (buffer.isEmpty()) {
                return;
            }
            
            List<MetricDatum> batchToSend = new ArrayList<>(buffer);
            buffer.clear();
            
            final PutMetricDataRequest request = new PutMetricDataRequest()
                .withNamespace(namespace)
                .withMetricData(batchToSend);
                
            CompletableFuture.runAsync(() -> cloudWatch.putMetricData(request));
        }
        
        public void shutdown() {
            flush();
            scheduler.shutdown();
        }
    }
    
    private static final MetricsBuffer metricsBuffer = new MetricsBuffer("ApiPerformance");
    
    public void good_case_12(Context context) {
        // Create metric data
        MetricDatum datum = new MetricDatum()
            .withMetricName("ApiLatency")
            .withUnit(StandardUnit.Milliseconds)
            .withValue(getApiLatency());
            
        // ok: java-sync-metric-publish
        metricsBuffer.addMetric(datum);
    }
    
    public void good_case_13(String transactionId) {
        // Process transaction
        boolean success = processTransaction(transactionId);
        
        // Report transaction status asynchronously
        final AmazonCloudWatch cloudWatch = AmazonCloudWatchClientBuilder.defaultClient();
        
        Dimension transactionDimension = new Dimension()
            .withName("TransactionId")
            .withValue(transactionId);
            
        final MetricDatum datum = new MetricDatum()
            .withMetricName(success ? "SuccessfulTransaction" : "FailedTransaction")
            .withUnit(StandardUnit.Count)
            .withValue(1.0)
            .withDimensions(transactionDimension);
            
        final PutMetricDataRequest request = new PutMetricDataRequest()
            .withNamespace("Transactions")
            .withMetricData(datum);
            
        // ok: java-sync-metric-publish
        new Thread(() -> {
            try {
                cloudWatch.putMetricData(request);
            } catch (Exception e) {
                System.err.println("Failed to publish transaction metric: " + e.getMessage());
            }
        }).start();
    }
    
    public void good_case_14(Context context) {
        // Initialize CloudWatch async client
        final CloudWatchAsyncClient cloudWatchAsync = CloudWatchAsyncClient.create();
        
        // Get remaining time in milliseconds
        long remainingTime = context.getRemainingTimeInMillis();
        
        // Report remaining execution time asynchronously
        software.amazon.awssdk.services.cloudwatch.model.MetricDatum datum = 
            software.amazon.awssdk.services.cloudwatch.model.MetricDatum.builder()
                .metricName("RemainingExecutionTime")
                .unit("Milliseconds")
                .value((double) remainingTime)
                .build();
                
        // ok: java-sync-metric-publish
        cloudWatchAsync.putMetricData(
            software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest.builder()
                .namespace("LambdaExecution")
                .metricData(datum)
                .build());
    }
    
    public void good_case_15(String functionName) {
        // Create CloudWatch async client
        final CloudWatchAsyncClient cloudWatchAsync = CloudWatchAsyncClient.create();
        
        // Create metric with function name dimension
        software.amazon.awssdk.services.cloudwatch.model.Dimension dimension = 
            software.amazon.awssdk.services.cloudwatch.model.Dimension.builder()
                .name("FunctionName")
                .value(functionName)
                .build();
                
        software.amazon.awssdk.services.cloudwatch.model.MetricDatum datum = 
            software.amazon.awssdk.services.cloudwatch.model.MetricDatum.builder()
                .metricName("Invocation")
                .unit("Count")
                .value(1.0)
                .dimensions(dimension)
                .build();
                
        // ok: java-sync-metric-publish
        cloudWatchAsync.putMetricData(
            software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest.builder()
                .namespace("LambdaInvocations")
                .metricData(datum)
                .build());
    }
    
    // Helper methods to make the examples compile
    private void processRequest(Context context) {}
    private double calculateExecutionTime() { return 100.0; }
    private void processBusinessLogic(Map<String, Object> event) {}
    private String processInput(String input) { return input; }
    private String doSomeWork(Map<String, String> event) { return "result"; }
    private void processData(Context context) {}
    private Object processEvent(Map<String, Object> event) { return new Object(); }
    private double getCpuUsage() { return 50.0; }
    private double getMemoryUsage() { return 60.0; }
    private Map<String, Object> getUserData(String userId) { return new HashMap<>(); }
    private void performOperation() {}
    private double getApiLatency() { return 200.0; }
    private boolean processTransaction(String transactionId) { return true; }
}
// {/fact}