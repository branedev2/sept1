import com.amazonaws.services.cloudwatch.AmazonCloudWatch;
import com.amazonaws.services.cloudwatch.AmazonCloudWatchClientBuilder;
import com.amazonaws.services.cloudwatch.model.Dimension;
import com.amazonaws.services.cloudwatch.model.MetricDatum;
import com.amazonaws.services.cloudwatch.model.PutMetricDataRequest;
import com.amazonaws.services.cloudwatch.model.PutMetricDataResult;
import com.amazonaws.services.cloudwatch.model.StandardUnit;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.lambda.model.PublishVersionRequest;
import software.amazon.awssdk.services.cloudwatch.CloudWatchClient;
import software.amazon.awssdk.services.cloudwatch.CloudWatchAsyncClient;
import software.amazon.awssdk.services.cloudwatch.model.PutMetricDataResponse;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.LambdaAsyncClient;
import software.amazon.awssdk.services.cloudwatch.model.MetricDatum;
import software.amazon.awssdk.services.cloudwatch.model.Dimension;
import software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest;
import software.amazon.awssdk.services.cloudwatch.model.StandardUnit;
import com.amazonaws.services.cloudwatchevents.AmazonCloudWatchEvents;
import com.amazonaws.services.cloudwatchevents.AmazonCloudWatchEventsClientBuilder;
import com.amazonaws.services.cloudwatchevents.model.PutEventsRequest;
import com.amazonaws.services.cloudwatchevents.model.PutEventsRequestEntry;
import software.amazon.awssdk.services.cloudwatchevents.CloudWatchEventsClient;
import software.amazon.awssdk.services.cloudwatchevents.CloudWatchEventsAsyncClient;
import software.amazon.awssdk.services.cloudwatchevents.model.PutEventsRequest;
import software.amazon.awssdk.services.cloudwatchevents.model.PutEventsRequestEntry;
import com.amazonaws.services.logs.AWSLogs;
import com.amazonaws.services.logs.AWSLogsClientBuilder;
import com.amazonaws.services.logs.model.PutLogEventsRequest;
import com.amazonaws.services.logs.model.InputLogEvent;
import software.amazon.awssdk.services.cloudwatchlogs.CloudWatchLogsClient;
import software.amazon.awssdk.services.cloudwatchlogs.CloudWatchLogsAsyncClient;
import software.amazon.awssdk.services.cloudwatchlogs.model.PutLogEventsRequest;
import software.amazon.awssdk.services.cloudwatchlogs.model.InputLogEvent;
import com.amazonaws.services.applicationautoscaling.AWSApplicationAutoScaling;
import com.amazonaws.services.applicationautoscaling.AWSApplicationAutoScalingClientBuilder;
import com.amazonaws.services.applicationautoscaling.model.PutMetricAlarmRequest;
import software.amazon.awssdk.services.applicationautoscaling.ApplicationAutoScalingClient;
import software.amazon.awssdk.services.applicationautoscaling.ApplicationAutoScalingAsyncClient;
import io.micrometer.cloudwatch2.CloudWatchMeterRegistry;
import io.micrometer.cloudwatch2.CloudWatchConfig;
import io.micrometer.core.instrument.Clock;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.cloudwatch.CloudWatchMeterRegistry;
import io.micrometer.cloudwatch.CloudWatchConfig;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.time.Duration;
import java.time.Instant;
import javax.servlet.http.HttpServletRequest;
import java.util.function.Consumer;

// Security Issue: Synchronous publishing of AWS Lambda metrics can lead to performance bottlenecks and increased latency

// True Positive Examples (Vulnerable/Insecure Code)

public class SyncMetricPublishExamples {
    
// {fact rule=sync-metric-publish@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        String requestId = request.getParameter("requestId");
        AmazonCloudWatch cloudWatch = AmazonCloudWatchClientBuilder.defaultClient();
        
        Dimension dimension = new Dimension()
            .withName("RequestId")
            .withValue(requestId);
        
        MetricDatum datum = new MetricDatum()
            .withMetricName("ProcessingTime")
            .withUnit(StandardUnit.Milliseconds)
            .withValue(100.0)
            .withDimensions(dimension);
        
        PutMetricDataRequest request1 = new PutMetricDataRequest()
            .withNamespace("MyLambdaFunction")
            .withMetricData(datum);
        
        // ruleid: java-sync-metric-publish
        cloudWatch.putMetricData(request1);
        
        // Continue with request processing
        System.out.println("Request processed");
    }
    
    public void bad_case_2(HttpServletRequest request) {
        String userId = request.getParameter("userId");
        CloudWatchClient cloudWatchClient = CloudWatchClient.create();
        
        software.amazon.awssdk.services.cloudwatch.model.Dimension dimension = 
            software.amazon.awssdk.services.cloudwatch.model.Dimension.builder()
                .name("UserId")
                .value(userId)
                .build();
        
        software.amazon.awssdk.services.cloudwatch.model.MetricDatum datum = 
            software.amazon.awssdk.services.cloudwatch.model.MetricDatum.builder()
                .metricName("UserActivity")
                .unit(StandardUnit.COUNT)
                .value(1.0)
                .dimensions(dimension)
                .build();
        
        PutMetricDataRequest request = 
            software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest.builder()
                .namespace("UserService")
                .metricData(datum)
                .build();
        
        // ruleid: java-sync-metric-publish
        cloudWatchClient.putMetricData(request);
        
        // Process user request
        System.out.println("User activity recorded");
    }
    
    public void bad_case_3(HttpServletRequest request) {
        String transactionId = request.getParameter("transactionId");
        double amount = Double.parseDouble(request.getParameter("amount"));
        
        // Initialize Micrometer with CloudWatch
        CloudWatchConfig cloudWatchConfig = new CloudWatchConfig() {
            @Override
            public String get(String key) {
                return null;
            }
            
            @Override
            public String namespace() {
                return "PaymentService";
            }
        };
        
        MeterRegistry registry = new io.micrometer.cloudwatch.CloudWatchMeterRegistry(
            cloudWatchConfig, Clock.SYSTEM, null);
        
        Counter counter = registry.counter("payment.processed", "transactionId", transactionId);
        counter.increment(amount);
        
        // ruleid: java-sync-metric-publish
        ((CloudWatchMeterRegistry) registry).publish();
        
        // Continue with payment processing
        System.out.println("Payment processed");
    }
    
    public void bad_case_4(HttpServletRequest request) {
        String logGroupName = request.getParameter("logGroup");
        String logStreamName = request.getParameter("logStream");
        String message = request.getParameter("message");
        
        AWSLogs awsLogs = AWSLogsClientBuilder.defaultClient();
        
        InputLogEvent logEvent = new InputLogEvent()
            .withTimestamp(System.currentTimeMillis())
            .withMessage(message);
        
        List<InputLogEvent> logEvents = new ArrayList<>();
        logEvents.add(logEvent);
        
        PutLogEventsRequest putLogEventsRequest = new PutLogEventsRequest()
            .withLogGroupName(logGroupName)
            .withLogStreamName(logStreamName)
            .withLogEvents(logEvents);
        
        // ruleid: java-sync-metric-publish
        awsLogs.putLogEvents(putLogEventsRequest);
        
        // Continue with application logic
        System.out.println("Log event published");
    }
    
    public void bad_case_5(HttpServletRequest request) {
        String eventName = request.getParameter("eventName");
        
        AmazonCloudWatchEvents cloudWatchEvents = 
            AmazonCloudWatchEventsClientBuilder.defaultClient();
        
        PutEventsRequestEntry entry = new PutEventsRequestEntry()
            .withDetail("{\"state\": \"STARTED\"}")
            .withDetailType("Process State Change")
            .withSource("com.mycompany.myapp")
            .withResources("arn:aws:lambda:us-west-2:123456789012:function:my-function");
        
        PutEventsRequest eventsRequest = new PutEventsRequest()
            .withEntries(entry);
        
        // ruleid: java-sync-metric-publish
        cloudWatchEvents.putEvents(eventsRequest);
        
        // Continue processing
        System.out.println("Event published");
    }
    
    @RestController
    public class MetricsController {
        public void bad_case_6(HttpServletRequest request) {
            String apiName = request.getParameter("apiName");
            long startTime = System.currentTimeMillis();
            
            // Simulate API processing
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            
            long endTime = System.currentTimeMillis();
            long duration = endTime - startTime;
            
            CloudWatchLogsClient logsClient = CloudWatchLogsClient.create();
            
            software.amazon.awssdk.services.cloudwatchlogs.model.InputLogEvent logEvent = 
                software.amazon.awssdk.services.cloudwatchlogs.model.InputLogEvent.builder()
                    .timestamp(System.currentTimeMillis())
                    .message("API " + apiName + " took " + duration + " ms")
                    .build();
            
            software.amazon.awssdk.services.cloudwatchlogs.model.PutLogEventsRequest putRequest = 
                software.amazon.awssdk.services.cloudwatchlogs.model.PutLogEventsRequest.builder()
                    .logGroupName("API-Metrics")
                    .logStreamName("api-performance")
                    .logEvents(logEvent)
                    .build();
            
            // ruleid: java-sync-metric-publish
            logsClient.putLogEvents(putRequest);
            
            // Return API response
            System.out.println("API metrics logged");
        }
    }
    
    public void bad_case_7(HttpServletRequest request) {
        String functionName = request.getParameter("functionName");
        
        LambdaClient lambdaClient = LambdaClient.create();
        
        // Create custom metrics for Lambda function
        CloudWatchClient cloudWatchClient = CloudWatchClient.create();
        
        software.amazon.awssdk.services.cloudwatch.model.Dimension dimension = 
            software.amazon.awssdk.services.cloudwatch.model.Dimension.builder()
                .name("FunctionName")
                .value(functionName)
                .build();
        
        software.amazon.awssdk.services.cloudwatch.model.MetricDatum datum = 
            software.amazon.awssdk.services.cloudwatch.model.MetricDatum.builder()
                .metricName("FunctionInvocation")
                .unit(StandardUnit.COUNT)
                .value(1.0)
                .dimensions(dimension)
                .build();
        
        software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest request = 
            software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest.builder()
                .namespace("LambdaMonitoring")
                .metricData(datum)
                .build();
        
        // ruleid: java-sync-metric-publish
        cloudWatchClient.putMetricData(request);
        
        // Invoke Lambda function
        System.out.println("Lambda function metrics published");
    }
    
    public void bad_case_8(HttpServletRequest request) {
        String metricName = request.getParameter("metricName");
        double value = Double.parseDouble(request.getParameter("value"));
        
        // Initialize Micrometer with CloudWatch v2
        CloudWatchConfig cloudWatchConfig = new io.micrometer.cloudwatch2.CloudWatchConfig() {
            @Override
            public String get(String key) {
                return null;
            }
            
            @Override
            public String namespace() {
                return "CustomMetrics";
            }
        };
        
        MeterRegistry registry = new io.micrometer.cloudwatch2.CloudWatchMeterRegistry(
            cloudWatchConfig, Clock.SYSTEM, null);
        
        Timer timer = registry.timer(metricName);
        timer.record(Duration.ofMillis((long)value));
        
        // ruleid: java-sync-metric-publish
        ((io.micrometer.cloudwatch2.CloudWatchMeterRegistry) registry).publish();
        
        // Continue with application logic
        System.out.println("Custom metric published");
    }
    
    public void bad_case_9(HttpServletRequest request) {
        String eventSource = request.getParameter("eventSource");
        
        CloudWatchEventsClient eventsClient = CloudWatchEventsClient.create();
        
        software.amazon.awssdk.services.cloudwatchevents.model.PutEventsRequestEntry entry = 
            software.amazon.awssdk.services.cloudwatchevents.model.PutEventsRequestEntry.builder()
                .detail("{\"action\": \"update\", \"result\": \"success\"}")
                .detailType("ResourceUpdate")
                .source(eventSource)
                .resources("arn:aws:ec2:us-east-1:123456789012:instance/i-abcdef")
                .build();
        
        software.amazon.awssdk.services.cloudwatchevents.model.PutEventsRequest eventsRequest = 
            software.amazon.awssdk.services.cloudwatchevents.model.PutEventsRequest.builder()
                .entries(entry)
                .build();
        
        // ruleid: java-sync-metric-publish
        eventsClient.putEvents(eventsRequest);
        
        // Continue with application logic
        System.out.println("CloudWatch event published");
    }
    
    public class LambdaHandler implements RequestHandler<Map<String, Object>, String> {
        public void bad_case_10(HttpServletRequest request) {
            String requestSource = request.getParameter("source");
            
            AmazonCloudWatch cloudWatch = AmazonCloudWatchClientBuilder.defaultClient();
            
            List<MetricDatum> metricData = new ArrayList<>();
            
            MetricDatum datum1 = new MetricDatum()
                .withMetricName("RequestCount")
                .withUnit(StandardUnit.Count)
                .withValue(1.0)
                .withDimensions(new Dimension().withName("Source").withValue(requestSource));
            
            MetricDatum datum2 = new MetricDatum()
                .withMetricName("ProcessingTime")
                .withUnit(StandardUnit.Milliseconds)
                .withValue(150.0)
                .withDimensions(new Dimension().withName("Source").withValue(requestSource));
            
            metricData.add(datum1);
            metricData.add(datum2);
            
            PutMetricDataRequest metricRequest = new PutMetricDataRequest()
                .withNamespace("RequestProcessing")
                .withMetricData(metricData);
            
            // ruleid: java-sync-metric-publish
            cloudWatch.putMetricData(metricRequest);
            
            // Process the request
            System.out.println("Request metrics published");
        }
    }
    
    public void bad_case_11(HttpServletRequest request) {
        String serviceName = request.getParameter("service");
        
        // Using AWS SDK v1 for ApplicationAutoScaling
        AWSApplicationAutoScaling autoScaling = 
            AWSApplicationAutoScalingClientBuilder.defaultClient();
        
        // Create CloudWatch client for custom metrics
        AmazonCloudWatch cloudWatch = AmazonCloudWatchClientBuilder.defaultClient();
        
        MetricDatum scalingMetric = new MetricDatum()
            .withMetricName("ServiceLoad")
            .withUnit(StandardUnit.Count)
            .withValue(5.0)
            .withDimensions(new Dimension().withName("ServiceName").withValue(serviceName));
        
        PutMetricDataRequest metricRequest = new PutMetricDataRequest()
            .withNamespace("AutoScalingMetrics")
            .withMetricData(scalingMetric);
        
        // ruleid: java-sync-metric-publish
        cloudWatch.putMetricData(metricRequest);
        
        // Continue with autoscaling configuration
        System.out.println("Autoscaling metrics published");
    }
    
    public void bad_case_12(HttpServletRequest request) {
        String region = request.getParameter("region");
        String instanceId = request.getParameter("instanceId");
        
        // Using AWS SDK v2 for CloudWatch
        CloudWatchClient cloudWatchClient = CloudWatchClient.create();
        
        software.amazon.awssdk.services.cloudwatch.model.Dimension dimension1 = 
            software.amazon.awssdk.services.cloudwatch.model.Dimension.builder()
                .name("Region")
                .value(region)
                .build();
        
        software.amazon.awssdk.services.cloudwatch.model.Dimension dimension2 = 
            software.amazon.awssdk.services.cloudwatch.model.Dimension.builder()
                .name("InstanceId")
                .value(instanceId)
                .build();
        
        software.amazon.awssdk.services.cloudwatch.model.MetricDatum datum = 
            software.amazon.awssdk.services.cloudwatch.model.MetricDatum.builder()
                .metricName("CPUUtilization")
                .unit(StandardUnit.PERCENT)
                .value(75.5)
                .dimensions(dimension1, dimension2)
                .build();
        
        software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest request = 
            software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest.builder()
                .namespace("EC2Monitoring")
                .metricData(datum)
                .build();
        
        // ruleid: java-sync-metric-publish
        cloudWatchClient.putMetricData(request);
        
        // Continue with instance monitoring
        System.out.println("EC2 metrics published");
    }
    
    public void bad_case_13(HttpServletRequest request) {
        String appName = request.getParameter("appName");
        
        // Using AWS SDK v1 for CloudWatch Logs
        AWSLogs logsClient = AWSLogsClientBuilder.defaultClient();
        
        List<InputLogEvent> logEvents = new ArrayList<>();
        logEvents.add(new InputLogEvent()
            .withTimestamp(System.currentTimeMillis())
            .withMessage("Application " + appName + " started"));
        logEvents.add(new InputLogEvent()
            .withTimestamp(System.currentTimeMillis() + 100)
            .withMessage("Application " + appName + " initialized"));
        
        PutLogEventsRequest logRequest = new PutLogEventsRequest()
            .withLogGroupName("ApplicationLogs")
            .withLogStreamName(appName + "-" + System.currentTimeMillis())
            .withLogEvents(logEvents);
        
        // ruleid: java-sync-metric-publish
        logsClient.putLogEvents(logRequest);
        
        // Continue with application startup
        System.out.println("Application startup logs published");
    }
    
    public void bad_case_14(HttpServletRequest request) {
        String databaseName = request.getParameter("database");
        
        // Using AWS SDK v2 for CloudWatch Logs
        CloudWatchLogsClient logsClient = CloudWatchLogsClient.create();
        
        List<software.amazon.awssdk.services.cloudwatchlogs.model.InputLogEvent> logEvents = 
            new ArrayList<>();
        
        logEvents.add(software.amazon.awssdk.services.cloudwatchlogs.model.InputLogEvent.builder()
            .timestamp(System.currentTimeMillis())
            .message("Database " + databaseName + " connection established")
            .build());
        
        software.amazon.awssdk.services.cloudwatchlogs.model.PutLogEventsRequest logRequest = 
            software.amazon.awssdk.services.cloudwatchlogs.model.PutLogEventsRequest.builder()
                .logGroupName("DatabaseLogs")
                .logStreamName(databaseName)
                .logEvents(logEvents)
                .build();
        
        // ruleid: java-sync-metric-publish
        logsClient.putLogEvents(logRequest);
        
        // Continue with database operations
        System.out.println("Database connection logs published");
    }
    
    public void bad_case_15(HttpServletRequest request) {
        String apiGatewayId = request.getParameter("apiGatewayId");
        
        // Using AWS SDK v2 for CloudWatch Events
        CloudWatchEventsClient eventsClient = CloudWatchEventsClient.create();
        
        software.amazon.awssdk.services.cloudwatchevents.model.PutEventsRequestEntry entry = 
            software.amazon.awssdk.services.cloudwatchevents.model.PutEventsRequestEntry.builder()
                .detail("{\"status\": \"deployed\", \"version\": \"1.0.0\"}")
                .detailType("API Deployment")
                .source("com.mycompany.apigateway")
                .resources("arn:aws:apigateway:" + apiGatewayId)
                .build();
        
        software.amazon.awssdk.services.cloudwatchevents.model.PutEventsRequest eventsRequest = 
            software.amazon.awssdk.services.cloudwatchevents.model.PutEventsRequest.builder()
                .entries(entry)
                .build();
        
        // ruleid: java-sync-metric-publish
        eventsClient.putEvents(eventsRequest);
        
        // Continue with API Gateway deployment
        System.out.println("API Gateway deployment event published");
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    public void good_case_1(HttpServletRequest request) {
        String requestId = request.getParameter("requestId");
        AmazonCloudWatch cloudWatch = AmazonCloudWatchClientBuilder.defaultClient();
        
        Dimension dimension = new Dimension()
            .withName("RequestId")
            .withValue(requestId);
        
        MetricDatum datum = new MetricDatum()
            .withMetricName("ProcessingTime")
            .withUnit(StandardUnit.Milliseconds)
            .withValue(100.0)
            .withDimensions(dimension);
        
        PutMetricDataRequest metricRequest = new PutMetricDataRequest()
            .withNamespace("MyLambdaFunction")
            .withMetricData(datum);
        
        // Use a separate thread for metric publishing
        ExecutorService executor = Executors.newSingleThreadExecutor();
        
        // ok: java-sync-metric-publish
        executor.submit(() -> {
            cloudWatch.putMetricData(metricRequest);
        });
        
        // Continue with request processing without waiting
        System.out.println("Request processed");
    }
    
    public void good_case_2(HttpServletRequest request) {
        String userId = request.getParameter("userId");
        CloudWatchAsyncClient cloudWatchClient = CloudWatchAsyncClient.create();
        
        software.amazon.awssdk.services.cloudwatch.model.Dimension dimension = 
            software.amazon.awssdk.services.cloudwatch.model.Dimension.builder()
                .name("UserId")
                .value(userId)
                .build();
        
        software.amazon.awssdk.services.cloudwatch.model.MetricDatum datum = 
            software.amazon.awssdk.services.cloudwatch.model.MetricDatum.builder()
                .metricName("UserActivity")
                .unit(StandardUnit.COUNT)
                .value(1.0)
                .dimensions(dimension)
                .build();
        
        software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest request = 
            software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest.builder()
                .namespace("UserService")
                .metricData(datum)
                .build();
        
        // ok: java-sync-metric-publish
        CompletableFuture<PutMetricDataResponse> future = cloudWatchClient.putMetricData(request);
        
        // Process user request without waiting for metric publishing
        System.out.println("User activity being recorded asynchronously");
    }
    
    public void good_case_3(HttpServletRequest request) {
        String transactionId = request.getParameter("transactionId");
        double amount = Double.parseDouble(request.getParameter("amount"));
        
        // Initialize Micrometer with CloudWatch
        CloudWatchConfig cloudWatchConfig = new CloudWatchConfig() {
            @Override
            public String get(String key) {
                return null;
            }
            
            @Override
            public String namespace() {
                return "PaymentService";
            }
            
            @Override
            public Duration step() {
                return Duration.ofMinutes(1); // Publish metrics every minute
            }
        };
        
        // ok: java-sync-metric-publish
        MeterRegistry registry = new io.micrometer.cloudwatch.CloudWatchMeterRegistry(
            cloudWatchConfig, Clock.SYSTEM, null);
        
        Counter counter = registry.counter("payment.processed", "transactionId", transactionId);
        counter.increment(amount);
        
        // Continue with payment processing without explicit publish
        System.out.println("Payment processed, metrics will be published on schedule");
    }
    
    public void good_case_4(HttpServletRequest request) {
        String logGroupName = request.getParameter("logGroup");
        String logStreamName = request.getParameter("logStream");
        String message = request.getParameter("message");
        
        // Using AWS SDK v2 async client
        CloudWatchLogsAsyncClient logsClient = CloudWatchLogsAsyncClient.create();
        
        software.amazon.awssdk.services.cloudwatchlogs.model.InputLogEvent logEvent = 
            software.amazon.awssdk.services.cloudwatchlogs.model.InputLogEvent.builder()
                .timestamp(System.currentTimeMillis())
                .message(message)
                .build();
        
        software.amazon.awssdk.services.cloudwatchlogs.model.PutLogEventsRequest putLogEventsRequest = 
            software.amazon.awssdk.services.cloudwatchlogs.model.PutLogEventsRequest.builder()
                .logGroupName(logGroupName)
                .logStreamName(logStreamName)
                .logEvents(logEvent)
                .build();
        
        // ok: java-sync-metric-publish
        logsClient.putLogEvents(putLogEventsRequest);
        
        // Continue with application logic
        System.out.println("Log event being published asynchronously");
    }
    
    public void good_case_5(HttpServletRequest request) {
        String eventName = request.getParameter("eventName");
        
        // Using AWS SDK v2 async client
        CloudWatchEventsAsyncClient cloudWatchEvents = CloudWatchEventsAsyncClient.create();
        
        software.amazon.awssdk.services.cloudwatchevents.model.PutEventsRequestEntry entry = 
            software.amazon.awssdk.services.cloudwatchevents.model.PutEventsRequestEntry.builder()
                .detail("{\"state\": \"STARTED\"}")
                .detailType("Process State Change")
                .source("com.mycompany.myapp")
                .resources("arn:aws:lambda:us-west-2:123456789012:function:my-function")
                .build();
        
        software.amazon.awssdk.services.cloudwatchevents.model.PutEventsRequest eventsRequest = 
            software.amazon.awssdk.services.cloudwatchevents.model.PutEventsRequest.builder()
                .entries(entry)
                .build();
        
        // ok: java-sync-metric-publish
        cloudWatchEvents.putEvents(eventsRequest);
        
        // Continue processing
        System.out.println("Event being published asynchronously");
    }
    
    @RestController
    public class MetricsController {
        public void good_case_6(HttpServletRequest request) {
            String apiName = request.getParameter("apiName");
            long startTime = System.currentTimeMillis();
            
            // Simulate API processing
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            
            long endTime = System.currentTimeMillis();
            long duration = endTime - startTime;
            
            CloudWatchLogsAsyncClient logsClient = CloudWatchLogsAsyncClient.create();
            
            software.amazon.awssdk.services.cloudwatchlogs.model.InputLogEvent logEvent = 
                software.amazon.awssdk.services.cloudwatchlogs.model.InputLogEvent.builder()
                    .timestamp(System.currentTimeMillis())
                    .message("API " + apiName + " took " + duration + " ms")
                    .build();
            
            software.amazon.awssdk.services.cloudwatchlogs.model.PutLogEventsRequest putRequest = 
                software.amazon.awssdk.services.cloudwatchlogs.model.PutLogEventsRequest.builder()
                    .logGroupName("API-Metrics")
                    .logStreamName("api-performance")
                    .logEvents(logEvent)
                    .build();
            
            // ok: java-sync-metric-publish
            logsClient.putLogEvents(putRequest)
                .whenComplete((response, error) -> {
                    if (error != null) {
                        System.err.println("Error publishing metrics: " + error.getMessage());
                    }
                });
            
            // Return API response
            System.out.println("API metrics being logged asynchronously");
        }
    }
    
    public void good_case_7(HttpServletRequest request) {
        String functionName = request.getParameter("functionName");
        
        LambdaAsyncClient lambdaClient = LambdaAsyncClient.create();
        
        // Create custom metrics for Lambda function
        CloudWatchAsyncClient cloudWatchClient = CloudWatchAsyncClient.create();
        
        software.amazon.awssdk.services.cloudwatch.model.Dimension dimension = 
            software.amazon.awssdk.services.cloudwatch.model.Dimension.builder()
                .name("FunctionName")
                .value(functionName)
                .build();
        
        software.amazon.awssdk.services.cloudwatch.model.MetricDatum datum = 
            software.amazon.awssdk.services.cloudwatch.model.MetricDatum.builder()
                .metricName("FunctionInvocation")
                .unit(StandardUnit.COUNT)
                .value(1.0)
                .dimensions(dimension)
                .build();
        
        software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest request = 
            software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest.builder()
                .namespace("LambdaMonitoring")
                .metricData(datum)
                .build();
        
        // ok: java-sync-metric-publish
        cloudWatchClient.putMetricData(request)
            .whenComplete((response, error) -> {
                if (error != null) {
                    System.err.println("Error publishing metrics: " + error.getMessage());
                }
            });
        
        // Invoke Lambda function
        System.out.println("Lambda function metrics being published asynchronously");
    }
    
    public void good_case_8(HttpServletRequest request) {
        String metricName = request.getParameter("metricName");
        double value = Double.parseDouble(request.getParameter("value"));
        
        // Initialize Micrometer with CloudWatch v2 with appropriate step size
        CloudWatchConfig cloudWatchConfig = new io.micrometer.cloudwatch2.CloudWatchConfig() {
            @Override
            public String get(String key) {
                return null;
            }
            
            @Override
            public String namespace() {
                return "CustomMetrics";
            }
            
            @Override
            public Duration step() {
                return Duration.ofMinutes(1); // Publish metrics every minute
            }
        };
        
        // ok: java-sync-metric-publish
        MeterRegistry registry = new io.micrometer.cloudwatch2.CloudWatchMeterRegistry(
            cloudWatchConfig, Clock.SYSTEM, null);
        
        Timer timer = registry.timer(metricName);
        timer.record(Duration.ofMillis((long)value));
        
        // Continue with application logic without explicit publish
        System.out.println("Custom metric recorded, will be published on schedule");
    }
    
    public void good_case_9(HttpServletRequest request) {
        String eventSource = request.getParameter("eventSource");
        
        // Using AWS SDK v2 async client
        CloudWatchEventsAsyncClient eventsClient = CloudWatchEventsAsyncClient.create();
        
        software.amazon.awssdk.services.cloudwatchevents.model.PutEventsRequestEntry entry = 
            software.amazon.awssdk.services.cloudwatchevents.model.PutEventsRequestEntry.builder()
                .detail("{\"action\": \"update\", \"result\": \"success\"}")
                .detailType("ResourceUpdate")
                .source(eventSource)
                .resources("arn:aws:ec2:us-east-1:123456789012:instance/i-abcdef")
                .build();
        
        software.amazon.awssdk.services.cloudwatchevents.model.PutEventsRequest eventsRequest = 
            software.amazon.awssdk.services.cloudwatchevents.model.PutEventsRequest.builder()
                .entries(entry)
                .build();
        
        // ok: java-sync-metric-publish
        CompletableFuture<?> future = eventsClient.putEvents(eventsRequest);
        
        // Continue with application logic
        System.out.println("CloudWatch event being published asynchronously");
    }
    
    public class LambdaHandler implements RequestHandler<Map<String, Object>, String> {
        public void good_case_10(HttpServletRequest request) {
            String requestSource = request.getParameter("source");
            
            // Using a background thread for metric publishing
            ExecutorService executor = Executors.newSingleThreadExecutor();
            
            // ok: java-sync-metric-publish
            executor.submit(() -> {
                AmazonCloudWatch cloudWatch = AmazonCloudWatchClientBuilder.defaultClient();
                
                List<MetricDatum> metricData = new ArrayList<>();
                
                MetricDatum datum1 = new MetricDatum()
                    .withMetricName("RequestCount")
                    .withUnit(StandardUnit.Count)
                    .withValue(1.0)
                    .withDimensions(new Dimension().withName("Source").withValue(requestSource));
                
                MetricDatum datum2 = new MetricDatum()
                    .withMetricName("ProcessingTime")
                    .withUnit(StandardUnit.Milliseconds)
                    .withValue(150.0)
                    .withDimensions(new Dimension().withName("Source").withValue(requestSource));
                
                metricData.add(datum1);
                metricData.add(datum2);
                
                PutMetricDataRequest metricRequest = new PutMetricDataRequest()
                    .withNamespace("RequestProcessing")
                    .withMetricData(metricData);
                
                cloudWatch.putMetricData(metricRequest);
            });
            
            // Process the request
            System.out.println("Request metrics being published in background");
        }
    }
    
    public void good_case_11(HttpServletRequest request) {
        String serviceName = request.getParameter("service");
        
        // Using AWS SDK v2 async client for ApplicationAutoScaling
        ApplicationAutoScalingAsyncClient autoScaling = ApplicationAutoScalingAsyncClient.create();
        
        // Create CloudWatch async client for custom metrics
        CloudWatchAsyncClient cloudWatch = CloudWatchAsyncClient.create();
        
        software.amazon.awssdk.services.cloudwatch.model.Dimension dimension = 
            software.amazon.awssdk.services.cloudwatch.model.Dimension.builder()
                .name("ServiceName")
                .value(serviceName)
                .build();
        
        software.amazon.awssdk.services.cloudwatch.model.MetricDatum scalingMetric = 
            software.amazon.awssdk.services.cloudwatch.model.MetricDatum.builder()
                .metricName("ServiceLoad")
                .unit(StandardUnit.COUNT)
                .value(5.0)
                .dimensions(dimension)
                .build();
        
        software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest metricRequest = 
            software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest.builder()
                .namespace("AutoScalingMetrics")
                .metricData(scalingMetric)
                .build();
        
        // ok: java-sync-metric-publish
        cloudWatch.putMetricData(metricRequest);
        
        // Continue with autoscaling configuration
        System.out.println("Autoscaling metrics being published asynchronously");
    }
    
    public void good_case_12(HttpServletRequest request) {
        String region = request.getParameter("region");
        String instanceId = request.getParameter("instanceId");
        
        // Using AWS SDK v2 async client for CloudWatch
        CloudWatchAsyncClient cloudWatchClient = CloudWatchAsyncClient.create();
        
        software.amazon.awssdk.services.cloudwatch.model.Dimension dimension1 = 
            software.amazon.awssdk.services.cloudwatch.model.Dimension.builder()
                .name("Region")
                .value(region)
                .build();
        
        software.amazon.awssdk.services.cloudwatch.model.Dimension dimension2 = 
            software.amazon.awssdk.services.cloudwatch.model.Dimension.builder()
                .name("InstanceId")
                .value(instanceId)
                .build();
        
        software.amazon.awssdk.services.cloudwatch.model.MetricDatum datum = 
            software.amazon.awssdk.services.cloudwatch.model.MetricDatum.builder()
                .metricName("CPUUtilization")
                .unit(StandardUnit.PERCENT)
                .value(75.5)
                .dimensions(dimension1, dimension2)
                .build();
        
        software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest request = 
            software.amazon.awssdk.services.cloudwatch.model.PutMetricDataRequest.builder()
                .namespace("EC2Monitoring")
                .metricData(datum)
                .build();
        
        // ok: java-sync-metric-publish
        CompletableFuture<PutMetricDataResponse> future = cloudWatchClient.putMetricData(request);
        
        // Continue with instance monitoring
        System.out.println("EC2 metrics being published asynchronously");
    }
    
    public void good_case_13(HttpServletRequest request) {
        String appName = request.getParameter("appName");
        
        // Using a background thread for log publishing
        ExecutorService executor = Executors.newSingleThreadExecutor();
        
        // ok: java-sync-metric-publish
        executor.submit(() -> {
            AWSLogs logsClient = AWSLogsClientBuilder.defaultClient();
            
            List<InputLogEvent> logEvents = new ArrayList<>();
            logEvents.add(new InputLogEvent()
                .withTimestamp(System.currentTimeMillis())
                .withMessage("Application " + appName + " started"));
            logEvents.add(new InputLogEvent()
                .withTimestamp(System.currentTimeMillis() + 100)
                .withMessage("Application " + appName + " initialized"));
            
            PutLogEventsRequest logRequest = new PutLogEventsRequest()
                .withLogGroupName("ApplicationLogs")
                .withLogStreamName(appName + "-" + System.currentTimeMillis())
                .withLogEvents(logEvents);
            
            logsClient.putLogEvents(logRequest);
        });
        
        // Continue with application startup
        System.out.println("Application startup logs being published in background");
    }
    
    public void good_case_14(HttpServletRequest request) {
        String databaseName = request.getParameter("database");
        
        // Using AWS SDK v2 async client for CloudWatch Logs
        CloudWatchLogsAsyncClient logsClient = CloudWatchLogsAsyncClient.create();
        
        List<software.amazon.awssdk.services.cloudwatchlogs.model.InputLogEvent> logEvents = 
            new ArrayList<>();
        
        logEvents.add(software.amazon.awssdk.services.cloudwatchlogs.model.InputLogEvent.builder()
            .timestamp(System.currentTimeMillis())
            .message("Database " + databaseName + " connection established")
            .build());
        
        software.amazon.awssdk.services.cloudwatchlogs.model.PutLogEventsRequest logRequest = 
            software.amazon.awssdk.services.cloudwatchlogs.model.PutLogEventsRequest.builder()
                .logGroupName("DatabaseLogs")
                .logStreamName(databaseName)
                .logEvents(logEvents)
                .build();
        
        // ok: java-sync-metric-publish
        logsClient.putLogEvents(logRequest)
            .whenComplete((response, error) -> {
                if (error != null) {
                    System.err.println("Error publishing logs: " + error.getMessage());
                }
            });
        
        // Continue with database operations
        System.out.println("Database connection logs being published asynchronously");
    }
    
    public void good_case_15(HttpServletRequest request) {
        String apiGatewayId = request.getParameter("apiGatewayId");
        
        // Using AWS SDK v2 async client for CloudWatch Events
        CloudWatchEventsAsyncClient eventsClient = CloudWatchEventsAsyncClient.create();
        
        software.amazon.awssdk.services.cloudwatchevents.model.PutEventsRequestEntry entry = 
            software.amazon.awssdk.services.cloudwatchevents.model.PutEventsRequestEntry.builder()
                .detail("{\"status\": \"deployed\", \"version\": \"1.0.0\"}")
                .detailType("API Deployment")
                .source("com.mycompany.apigateway")
                .resources("arn:aws:apigateway:" + apiGatewayId)
                .build();
        
        software.amazon.awssdk.services.cloudwatchevents.model.PutEventsRequest eventsRequest = 
            software.amazon.awssdk.services.cloudwatchevents.model.PutEventsRequest.builder()
                .entries(entry)
                .build();
        
        // ok: java-sync-metric-publish
        CompletableFuture<?> future = eventsClient.putEvents(eventsRequest);
        future.whenComplete((response, error) -> {
            if (error != null) {
                System.err.println("Error publishing event: " + error.getMessage());
            }
        });
        
        // Continue with API Gateway deployment
        System.out.println("API Gateway deployment event being published asynchronously");
    }
}
// {/fact}