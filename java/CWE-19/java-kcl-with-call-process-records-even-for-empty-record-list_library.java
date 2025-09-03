import com.amazonaws.services.kinesis.clientlibrary.lib.worker.KinesisClientLibConfiguration;
import com.amazonaws.services.kinesis.clientlibrary.lib.worker.InitialPositionInStream;
import com.amazonaws.services.kinesis.clientlibrary.interfaces.v2.IRecordProcessorFactory;
import com.amazonaws.services.kinesis.clientlibrary.lib.worker.Worker;
import com.amazonaws.services.kinesis.clientlibrary.interfaces.v2.IRecordProcessor;
import com.amazonaws.services.kinesis.clientlibrary.interfaces.v2.IRecordProcessorFactory;
import com.amazonaws.services.kinesis.clientlibrary.types.InitializationInput;
import com.amazonaws.services.kinesis.clientlibrary.types.ProcessRecordsInput;
import com.amazonaws.services.kinesis.clientlibrary.types.ShutdownInput;
import com.amazonaws.services.kinesis.metrics.interfaces.MetricsLevel;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.cloudwatch.AmazonCloudWatchClientBuilder;
import com.amazonaws.services.kinesis.AmazonKinesisClientBuilder;
import software.amazon.kinesis.coordinator.Scheduler;
import software.amazon.kinesis.common.ConfigsBuilder;
import software.amazon.kinesis.common.InitialPositionInStreamExtended;
import software.amazon.kinesis.processor.ShardRecordProcessorFactory;
import software.amazon.kinesis.processor.ShardRecordProcessor;
import software.amazon.kinesis.processor.RecordProcessorCheckpointer;
import software.amazon.kinesis.retrieval.KinesisClientRecord;
import software.amazon.kinesis.retrieval.RetrievalConfig;
import software.amazon.kinesis.retrieval.polling.PollingConfig;
import software.amazon.awssdk.services.kinesis.KinesisAsyncClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudwatch.CloudWatchAsyncClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
import software.amazon.kinesis.leases.LeaseManagementConfig;
import software.amazon.kinesis.metrics.MetricsConfig;
import software.amazon.kinesis.processor.ProcessorConfig;
import software.amazon.kinesis.coordinator.CoordinatorConfig;
import software.amazon.kinesis.lifecycle.events.*;

import java.util.UUID;
import java.util.List;

// Security Issue: Failing to process empty records from Kinesis streams by not setting withCallProcessRecordsEvenForEmptyRecordList to TRUE

// True Positive Examples (Vulnerable/Insecure Code)
public class KinesisConfigurationExamples {

// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
    public static void bad_case_1() {
        // Basic KCL v1 configuration without setting withCallProcessRecordsEvenForEmptyRecordList
        String applicationName = "MyKinesisApp";
        String streamName = "MyKinesisStream";
        String workerId = UUID.randomUUID().toString();
        
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
                applicationName,
                streamName,
                new DefaultAWSCredentialsProviderChain(),
                workerId);
        
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        config.withInitialPositionInStream(InitialPositionInStream.LATEST);
        
        // Missing withCallProcessRecordsEvenForEmptyRecordList(true)
        
        IRecordProcessorFactory recordProcessorFactory = createSampleRecordProcessorFactory();
        Worker worker = new Worker(recordProcessorFactory, config);
        worker.run();
    }

    public static void bad_case_2() {
        // KCL v1 with explicit setting to false
        String applicationName = "EnterpriseDataProcessor";
        String streamName = "HighVolumeStream";
        String workerId = UUID.randomUUID().toString();
        
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
                applicationName,
                streamName,
                new DefaultAWSCredentialsProviderChain(),
                workerId);
        
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        config.withCallProcessRecordsEvenForEmptyRecordList(false);
        
        IRecordProcessorFactory recordProcessorFactory = createSampleRecordProcessorFactory();
        Worker worker = new Worker(recordProcessorFactory, config);
        worker.run();
    }

    public static void bad_case_3() {
        // KCL v1 with multiple configuration options but missing the critical one
        String applicationName = "AnalyticsProcessor";
        String streamName = "UserActivityStream";
        String workerId = UUID.randomUUID().toString();
        
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
                applicationName,
                streamName,
                new DefaultAWSCredentialsProviderChain(),
                workerId);
        
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        config.withInitialPositionInStream(InitialPositionInStream.TRIM_HORIZON)
              .withMetricsLevel(MetricsLevel.DETAILED)
              .withMaxRecords(1000)
              .withIdleTimeBetweenReadsInMillis(250);
        
        // Missing withCallProcessRecordsEvenForEmptyRecordList(true)
        
        IRecordProcessorFactory recordProcessorFactory = createSampleRecordProcessorFactory();
        Worker worker = new Worker(recordProcessorFactory, config);
        worker.run();
    }

    public static void bad_case_4() {
        // KCL v1 with chained configuration but explicitly setting to false
        String applicationName = "RealTimeMonitoring";
        String streamName = "SystemMetricsStream";
        
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
                applicationName,
                streamName,
                new DefaultAWSCredentialsProviderChain(),
                UUID.randomUUID().toString())
                .withInitialPositionInStream(InitialPositionInStream.LATEST)
                .withCallProcessRecordsEvenForEmptyRecordList(false)
                .withMaxRecords(500);
        
        IRecordProcessorFactory recordProcessorFactory = createSampleRecordProcessorFactory();
        Worker worker = new Worker(recordProcessorFactory, config);
        worker.run();
    }

    public static void bad_case_5() {
        // KCL v1 with region specification but missing empty record processing
        String applicationName = "GlobalDataCollector";
        String streamName = "InternationalEvents";
        String workerId = UUID.randomUUID().toString();
        String region = "us-west-2";
        
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
                applicationName,
                streamName,
                new DefaultAWSCredentialsProviderChain(),
                workerId);
        
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        config.withRegionName(region)
              .withInitialPositionInStream(InitialPositionInStream.LATEST)
              .withFailoverTimeMillis(10000);
        
        // Missing withCallProcessRecordsEvenForEmptyRecordList(true)
        
        IRecordProcessorFactory recordProcessorFactory = createSampleRecordProcessorFactory();
        Worker worker = new Worker(recordProcessorFactory, config);
        worker.run();
    }

    public static void bad_case_6() {
        // KCL v2 configuration without setting processEmptyRecordList
        String streamName = "CustomerEventsStream";
        String applicationName = "CustomerAnalytics";
        Region region = Region.US_EAST_1;
        
        KinesisAsyncClient kinesisClient = KinesisAsyncClient.builder()
                .region(region)
                .build();
                
        DynamoDbAsyncClient dynamoClient = DynamoDbAsyncClient.builder()
                .region(region)
                .build();
                
        CloudWatchAsyncClient cloudWatchClient = CloudWatchAsyncClient.builder()
                .region(region)
                .build();
                
        ConfigsBuilder configsBuilder = new ConfigsBuilder(
                streamName,
                applicationName,
                kinesisClient,
                dynamoClient,
                cloudWatchClient,
                UUID.randomUUID().toString(),
                createShardRecordProcessorFactory());
        
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        Scheduler scheduler = new Scheduler(
                configsBuilder.checkpointConfig(),
                configsBuilder.coordinatorConfig(),
                configsBuilder.leaseManagementConfig(),
                configsBuilder.lifecycleConfig(),
                configsBuilder.metricsConfig(),
                configsBuilder.processorConfig(),
                configsBuilder.retrievalConfig());
        
        // Missing processEmptyRecordList setting
        
        scheduler.run();
    }

    public static void bad_case_7() {
        // KCL v2 with explicit ProcessorConfig but missing processEmptyRecordList
        String streamName = "PaymentTransactions";
        String applicationName = "PaymentProcessor";
        Region region = Region.EU_WEST_1;
        
        KinesisAsyncClient kinesisClient = KinesisAsyncClient.builder()
                .region(region)
                .build();
                
        DynamoDbAsyncClient dynamoClient = DynamoDbAsyncClient.builder()
                .region(region)
                .build();
                
        CloudWatchAsyncClient cloudWatchClient = CloudWatchAsyncClient.builder()
                .region(region)
                .build();
                
        ConfigsBuilder configsBuilder = new ConfigsBuilder(
                streamName,
                applicationName,
                kinesisClient,
                dynamoClient,
                cloudWatchClient,
                UUID.randomUUID().toString(),
                createShardRecordProcessorFactory());
        
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        ProcessorConfig processorConfig = configsBuilder.processorConfig()
                .maxPendingProcessRecordsInput(10);
        
        // Missing processEmptyRecordList(true)
        
        Scheduler scheduler = new Scheduler(
                configsBuilder.checkpointConfig(),
                configsBuilder.coordinatorConfig(),
                configsBuilder.leaseManagementConfig(),
                configsBuilder.lifecycleConfig(),
                configsBuilder.metricsConfig(),
                processorConfig,
                configsBuilder.retrievalConfig());
                
        scheduler.run();
    }

    public static void bad_case_8() {
        // KCL v2 with explicit ProcessorConfig set to false
        String streamName = "LogAggregation";
        String applicationName = "LogProcessor";
        Region region = Region.AP_NORTHEAST_1;
        
        KinesisAsyncClient kinesisClient = KinesisAsyncClient.builder()
                .region(region)
                .build();
                
        DynamoDbAsyncClient dynamoClient = DynamoDbAsyncClient.builder()
                .region(region)
                .build();
                
        CloudWatchAsyncClient cloudWatchClient = CloudWatchAsyncClient.builder()
                .region(region)
                .build();
                
        ConfigsBuilder configsBuilder = new ConfigsBuilder(
                streamName,
                applicationName,
                kinesisClient,
                dynamoClient,
                cloudWatchClient,
                UUID.randomUUID().toString(),
                createShardRecordProcessorFactory());
        
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        ProcessorConfig processorConfig = configsBuilder.processorConfig()
                .processEmptyRecordList(false);
        
        Scheduler scheduler = new Scheduler(
                configsBuilder.checkpointConfig(),
                configsBuilder.coordinatorConfig(),
                configsBuilder.leaseManagementConfig(),
                configsBuilder.lifecycleConfig(),
                configsBuilder.metricsConfig(),
                processorConfig,
                configsBuilder.retrievalConfig());
                
        scheduler.run();
    }

    public static void bad_case_9() {
        // KCL v2 with multiple configurations but missing processEmptyRecordList
        String streamName = "IoTSensorData";
        String applicationName = "SensorAnalytics";
        Region region = Region.US_WEST_2;
        
        KinesisAsyncClient kinesisClient = KinesisAsyncClient.builder()
                .region(region)
                .build();
                
        DynamoDbAsyncClient dynamoClient = DynamoDbAsyncClient.builder()
                .region(region)
                .build();
                
        CloudWatchAsyncClient cloudWatchClient = CloudWatchAsyncClient.builder()
                .region(region)
                .build();
                
        ConfigsBuilder configsBuilder = new ConfigsBuilder(
                streamName,
                applicationName,
                kinesisClient,
                dynamoClient,
                cloudWatchClient,
                UUID.randomUUID().toString(),
                createShardRecordProcessorFactory());
        
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        ProcessorConfig processorConfig = configsBuilder.processorConfig()
                .maxPendingProcessRecordsInput(20)
                .callbackThreadPool(Executors.newFixedThreadPool(5));
        
        // Missing processEmptyRecordList(true)
        
        Scheduler scheduler = new Scheduler(
                configsBuilder.checkpointConfig(),
                configsBuilder.coordinatorConfig(),
                configsBuilder.leaseManagementConfig(),
                configsBuilder.lifecycleConfig(),
                configsBuilder.metricsConfig(),
                processorConfig,
                configsBuilder.retrievalConfig());
                
        scheduler.run();
    }

    public static void bad_case_10() {
        // KCL v1 with builder pattern but missing the critical setting
        String applicationName = "FinancialDataProcessor";
        String streamName = "StockTrades";
        String workerId = UUID.randomUUID().toString();
        
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
                applicationName,
                streamName,
                new DefaultAWSCredentialsProviderChain(),
                workerId)
                .withInitialPositionInStream(InitialPositionInStream.TRIM_HORIZON)
                .withIdleTimeBetweenReadsInMillis(500)
                .withMaxRecords(1000)
                .withMetricsLevel(MetricsLevel.SUMMARY);
        
        // Missing withCallProcessRecordsEvenForEmptyRecordList(true)
        
        IRecordProcessorFactory recordProcessorFactory = createSampleRecordProcessorFactory();
        Worker worker = new Worker(recordProcessorFactory, config);
        worker.run();
    }

    public static void bad_case_11() {
        // KCL v2 with custom clients but missing processEmptyRecordList
        String streamName = "UserClickstream";
        String applicationName = "ClickstreamAnalytics";
        Region region = Region.EU_CENTRAL_1;
        
        KinesisAsyncClient kinesisClient = KinesisAsyncClient.builder()
                .region(region)
                .build();
                
        DynamoDbAsyncClient dynamoClient = DynamoDbAsyncClient.builder()
                .region(region)
                .build();
                
        CloudWatchAsyncClient cloudWatchClient = CloudWatchAsyncClient.builder()
                .region(region)
                .build();
        
        ShardRecordProcessorFactory recordProcessorFactory = createShardRecordProcessorFactory();
        
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        RetrievalConfig retrievalConfig = new RetrievalConfig(
                kinesisClient,
                streamName,
                applicationName)
                .retrievalSpecificConfig(new PollingConfig(streamName, kinesisClient));
                
        LeaseManagementConfig leaseManagementConfig = new LeaseManagementConfig(
                applicationName,
                dynamoClient,
                kinesisClient,
                streamName);
                
        CoordinatorConfig coordinatorConfig = new CoordinatorConfig(applicationName);
        
        ProcessorConfig processorConfig = new ProcessorConfig(recordProcessorFactory);
        // Missing processEmptyRecordList(true)
        
        MetricsConfig metricsConfig = new MetricsConfig(cloudWatchClient, applicationName);
        
        Scheduler scheduler = new Scheduler(
                retrievalConfig,
                processorConfig,
                leaseManagementConfig,
                coordinatorConfig,
                metricsConfig);
                
        scheduler.run();
    }

    public static void bad_case_12() {
        // KCL v1 with custom worker factory but missing the critical setting
        String applicationName = "NotificationService";
        String streamName = "UserNotifications";
        String workerId = UUID.randomUUID().toString();
        
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
                applicationName,
                streamName,
                new DefaultAWSCredentialsProviderChain(),
                workerId)
                .withMaxRecords(500)
                .withIdleTimeBetweenReadsInMillis(1000)
                .withInitialPositionInStream(InitialPositionInStream.LATEST);
        
        // Missing withCallProcessRecordsEvenForEmptyRecordList(true)
        
        IRecordProcessorFactory recordProcessorFactory = createSampleRecordProcessorFactory();
        
        Worker.Builder workerBuilder = new Worker.Builder()
                .recordProcessorFactory(recordProcessorFactory)
                .config(config);
                
        Worker worker = workerBuilder.build();
        worker.run();
    }

    public static void bad_case_13() {
        // KCL v2 with enhanced fan-out but missing processEmptyRecordList
        String streamName = "AuditEvents";
        String applicationName = "AuditProcessor";
        Region region = Region.US_EAST_2;
        
        KinesisAsyncClient kinesisClient = KinesisAsyncClient.builder()
                .region(region)
                .build();
                
        DynamoDbAsyncClient dynamoClient = DynamoDbAsyncClient.builder()
                .region(region)
                .build();
                
        CloudWatchAsyncClient cloudWatchClient = CloudWatchAsyncClient.builder()
                .region(region)
                .build();
                
        ConfigsBuilder configsBuilder = new ConfigsBuilder(
                streamName,
                applicationName,
                kinesisClient,
                dynamoClient,
                cloudWatchClient,
                UUID.randomUUID().toString(),
                createShardRecordProcessorFactory());
        
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        RetrievalConfig retrievalConfig = configsBuilder.retrievalConfig()
                .retrievalSpecificConfig(
                        new FanOutConfig(kinesisClient)
                                .streamName(streamName)
                                .applicationName(applicationName));
        
        ProcessorConfig processorConfig = configsBuilder.processorConfig();
        // Missing processEmptyRecordList(true)
        
        Scheduler scheduler = new Scheduler(
                configsBuilder.checkpointConfig(),
                configsBuilder.coordinatorConfig(),
                configsBuilder.leaseManagementConfig(),
                configsBuilder.lifecycleConfig(),
                configsBuilder.metricsConfig(),
                processorConfig,
                retrievalConfig);
                
        scheduler.run();
    }

    public static void bad_case_14() {
        // KCL v1 with custom metrics factory but missing the critical setting
        String applicationName = "SecurityMonitoring";
        String streamName = "SecurityEvents";
        String workerId = UUID.randomUUID().toString();
        
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
                applicationName,
                streamName,
                new DefaultAWSCredentialsProviderChain(),
                workerId)
                .withMetricsLevel(MetricsLevel.DETAILED)
                .withMetricsBufferTimeMillis(10000)
                .withMetricsMaxQueueSize(10000)
                .withValidateSequenceNumberBeforeCheckpointing(true);
        
        // Missing withCallProcessRecordsEvenForEmptyRecordList(true)
        
        IRecordProcessorFactory recordProcessorFactory = createSampleRecordProcessorFactory();
        Worker worker = new Worker(recordProcessorFactory, config);
        worker.run();
    }

    public static void bad_case_15() {
        // KCL v2 with custom lease management but missing processEmptyRecordList
        String streamName = "MarketingCampaigns";
        String applicationName = "CampaignTracker";
        Region region = Region.CA_CENTRAL_1;
        
        KinesisAsyncClient kinesisClient = KinesisAsyncClient.builder()
                .region(region)
                .build();
                
        DynamoDbAsyncClient dynamoClient = DynamoDbAsyncClient.builder()
                .region(region)
                .build();
                
        CloudWatchAsyncClient cloudWatchClient = CloudWatchAsyncClient.builder()
                .region(region)
                .build();
                
        ConfigsBuilder configsBuilder = new ConfigsBuilder(
                streamName,
                applicationName,
                kinesisClient,
                dynamoClient,
                cloudWatchClient,
                UUID.randomUUID().toString(),
                createShardRecordProcessorFactory());
        
        LeaseManagementConfig leaseConfig = configsBuilder.leaseManagementConfig()
                .tableName("CustomLeaseTable")
                .billingMode(BillingMode.PAY_PER_REQUEST);
                
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        ProcessorConfig processorConfig = configsBuilder.processorConfig()
                .maxPendingProcessRecordsInput(100);
        
        // Missing processEmptyRecordList(true)
        
        Scheduler scheduler = new Scheduler(
                configsBuilder.checkpointConfig(),
                configsBuilder.coordinatorConfig(),
                leaseConfig,
                configsBuilder.lifecycleConfig(),
                configsBuilder.metricsConfig(),
                processorConfig,
                configsBuilder.retrievalConfig());
                
        scheduler.run();
    }

    // True Negative Examples (Safe/Secure Code)
    public static void good_case_1() {
        // Basic KCL v1 configuration with withCallProcessRecordsEvenForEmptyRecordList set to true
        String applicationName = "MyKinesisApp";
        String streamName = "MyKinesisStream";
        String workerId = UUID.randomUUID().toString();
        
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
                applicationName,
                streamName,
                new DefaultAWSCredentialsProviderChain(),
                workerId);
        
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        config.withInitialPositionInStream(InitialPositionInStream.LATEST)
              .withCallProcessRecordsEvenForEmptyRecordList(true);
        
        IRecordProcessorFactory recordProcessorFactory = createSampleRecordProcessorFactory();
        Worker worker = new Worker(recordProcessorFactory, config);
        worker.run();
    }

    public static void good_case_2() {
        // KCL v1 with multiple configuration options including the critical one
        String applicationName = "EnterpriseDataProcessor";
        String streamName = "HighVolumeStream";
        String workerId = UUID.randomUUID().toString();
        
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
                applicationName,
                streamName,
                new DefaultAWSCredentialsProviderChain(),
                workerId);
        
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        config.withInitialPositionInStream(InitialPositionInStream.TRIM_HORIZON)
              .withMetricsLevel(MetricsLevel.DETAILED)
              .withMaxRecords(1000)
              .withIdleTimeBetweenReadsInMillis(250)
              .withCallProcessRecordsEvenForEmptyRecordList(true);
        
        IRecordProcessorFactory recordProcessorFactory = createSampleRecordProcessorFactory();
        Worker worker = new Worker(recordProcessorFactory, config);
        worker.run();
    }

    public static void good_case_3() {
        // KCL v1 with chained configuration including the critical setting
        String applicationName = "RealTimeMonitoring";
        String streamName = "SystemMetricsStream";
        
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
                applicationName,
                streamName,
                new DefaultAWSCredentialsProviderChain(),
                UUID.randomUUID().toString())
                .withInitialPositionInStream(InitialPositionInStream.LATEST)
                .withCallProcessRecordsEvenForEmptyRecordList(true)
                .withMaxRecords(500);
        
        IRecordProcessorFactory recordProcessorFactory = createSampleRecordProcessorFactory();
        Worker worker = new Worker(recordProcessorFactory, config);
        worker.run();
    }

    public static void good_case_4() {
        // KCL v1 with region specification and empty record processing
        String applicationName = "GlobalDataCollector";
        String streamName = "InternationalEvents";
        String workerId = UUID.randomUUID().toString();
        String region = "us-west-2";
        
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
                applicationName,
                streamName,
                new DefaultAWSCredentialsProviderChain(),
                workerId);
        
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        config.withRegionName(region)
              .withInitialPositionInStream(InitialPositionInStream.LATEST)
              .withFailoverTimeMillis(10000)
              .withCallProcessRecordsEvenForEmptyRecordList(true);
        
        IRecordProcessorFactory recordProcessorFactory = createSampleRecordProcessorFactory();
        Worker worker = new Worker(recordProcessorFactory, config);
        worker.run();
    }

    public static void good_case_5() {
        // KCL v2 configuration with processEmptyRecordList set to true
        String streamName = "CustomerEventsStream";
        String applicationName = "CustomerAnalytics";
        Region region = Region.US_EAST_1;
        
        KinesisAsyncClient kinesisClient = KinesisAsyncClient.builder()
                .region(region)
                .build();
                
        DynamoDbAsyncClient dynamoClient = DynamoDbAsyncClient.builder()
                .region(region)
                .build();
                
        CloudWatchAsyncClient cloudWatchClient = CloudWatchAsyncClient.builder()
                .region(region)
                .build();
                
        ConfigsBuilder configsBuilder = new ConfigsBuilder(
                streamName,
                applicationName,
                kinesisClient,
                dynamoClient,
                cloudWatchClient,
                UUID.randomUUID().toString(),
                createShardRecordProcessorFactory());
        
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        ProcessorConfig processorConfig = configsBuilder.processorConfig()
                .processEmptyRecordList(true);
        
        Scheduler scheduler = new Scheduler(
                configsBuilder.checkpointConfig(),
                configsBuilder.coordinatorConfig(),
                configsBuilder.leaseManagementConfig(),
                configsBuilder.lifecycleConfig(),
                configsBuilder.metricsConfig(),
                processorConfig,
                configsBuilder.retrievalConfig());
                
        scheduler.run();
    }

    public static void good_case_6() {
        // KCL v2 with explicit ProcessorConfig and processEmptyRecordList set to true
        String streamName = "PaymentTransactions";
        String applicationName = "PaymentProcessor";
        Region region = Region.EU_WEST_1;
        
        KinesisAsyncClient kinesisClient = KinesisAsyncClient.builder()
                .region(region)
                .build();
                
        DynamoDbAsyncClient dynamoClient = DynamoDbAsyncClient.builder()
                .region(region)
                .build();
                
        CloudWatchAsyncClient cloudWatchClient = CloudWatchAsyncClient.builder()
                .region(region)
                .build();
                
        ConfigsBuilder configsBuilder = new ConfigsBuilder(
                streamName,
                applicationName,
                kinesisClient,
                dynamoClient,
                cloudWatchClient,
                UUID.randomUUID().toString(),
                createShardRecordProcessorFactory());
        
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        ProcessorConfig processorConfig = configsBuilder.processorConfig()
                .maxPendingProcessRecordsInput(10)
                .processEmptyRecordList(true);
        
        Scheduler scheduler = new Scheduler(
                configsBuilder.checkpointConfig(),
                configsBuilder.coordinatorConfig(),
                configsBuilder.leaseManagementConfig(),
                configsBuilder.lifecycleConfig(),
                configsBuilder.metricsConfig(),
                processorConfig,
                configsBuilder.retrievalConfig());
                
        scheduler.run();
    }

    public static void good_case_7() {
        // KCL v2 with multiple configurations including processEmptyRecordList
        String streamName = "IoTSensorData";
        String applicationName = "SensorAnalytics";
        Region region = Region.US_WEST_2;
        
        KinesisAsyncClient kinesisClient = KinesisAsyncClient.builder()
                .region(region)
                .build();
                
        DynamoDbAsyncClient dynamoClient = DynamoDbAsyncClient.builder()
                .region(region)
                .build();
                
        CloudWatchAsyncClient cloudWatchClient = CloudWatchAsyncClient.builder()
                .region(region)
                .build();
                
        ConfigsBuilder configsBuilder = new ConfigsBuilder(
                streamName,
                applicationName,
                kinesisClient,
                dynamoClient,
                cloudWatchClient,
                UUID.randomUUID().toString(),
                createShardRecordProcessorFactory());
        
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        ProcessorConfig processorConfig = configsBuilder.processorConfig()
                .maxPendingProcessRecordsInput(20)
                .callbackThreadPool(Executors.newFixedThreadPool(5))
                .processEmptyRecordList(true);
        
        Scheduler scheduler = new Scheduler(
                configsBuilder.checkpointConfig(),
                configsBuilder.coordinatorConfig(),
                configsBuilder.leaseManagementConfig(),
                configsBuilder.lifecycleConfig(),
                configsBuilder.metricsConfig(),
                processorConfig,
                configsBuilder.retrievalConfig());
                
        scheduler.run();
    }

    public static void good_case_8() {
        // KCL v1 with builder pattern including the critical setting
        String applicationName = "FinancialDataProcessor";
        String streamName = "StockTrades";
        String workerId = UUID.randomUUID().toString();
        
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
                applicationName,
                streamName,
                new DefaultAWSCredentialsProviderChain(),
                workerId)
                .withInitialPositionInStream(InitialPositionInStream.TRIM_HORIZON)
                .withIdleTimeBetweenReadsInMillis(500)
                .withMaxRecords(1000)
                .withMetricsLevel(MetricsLevel.SUMMARY)
                .withCallProcessRecordsEvenForEmptyRecordList(true);
        
        IRecordProcessorFactory recordProcessorFactory = createSampleRecordProcessorFactory();
        Worker worker = new Worker(recordProcessorFactory, config);
        worker.run();
    }

    public static void good_case_9() {
        // KCL v2 with custom clients and processEmptyRecordList set to true
        String streamName = "UserClickstream";
        String applicationName = "ClickstreamAnalytics";
        Region region = Region.EU_CENTRAL_1;
        
        KinesisAsyncClient kinesisClient = KinesisAsyncClient.builder()
                .region(region)
                .build();
                
        DynamoDbAsyncClient dynamoClient = DynamoDbAsyncClient.builder()
                .region(region)
                .build();
                
        CloudWatchAsyncClient cloudWatchClient = CloudWatchAsyncClient.builder()
                .region(region)
                .build();
        
        ShardRecordProcessorFactory recordProcessorFactory = createShardRecordProcessorFactory();
        
        RetrievalConfig retrievalConfig = new RetrievalConfig(
                kinesisClient,
                streamName,
                applicationName)
                .retrievalSpecificConfig(new PollingConfig(streamName, kinesisClient));
                
        LeaseManagementConfig leaseManagementConfig = new LeaseManagementConfig(
                applicationName,
                dynamoClient,
                kinesisClient,
                streamName);
                
        CoordinatorConfig coordinatorConfig = new CoordinatorConfig(applicationName);
        
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        ProcessorConfig processorConfig = new ProcessorConfig(recordProcessorFactory)
                .processEmptyRecordList(true);
        
        MetricsConfig metricsConfig = new MetricsConfig(cloudWatchClient, applicationName);
        
        Scheduler scheduler = new Scheduler(
                retrievalConfig,
                processorConfig,
                leaseManagementConfig,
                coordinatorConfig,
                metricsConfig);
                
        scheduler.run();
    }

    public static void good_case_10() {
        // KCL v1 with custom worker factory and the critical setting
        String applicationName = "NotificationService";
        String streamName = "UserNotifications";
        String workerId = UUID.randomUUID().toString();
        
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
                applicationName,
                streamName,
                new DefaultAWSCredentialsProviderChain(),
                workerId)
                .withMaxRecords(500)
                .withIdleTimeBetweenReadsInMillis(1000)
                .withInitialPositionInStream(InitialPositionInStream.LATEST)
                .withCallProcessRecordsEvenForEmptyRecordList(true);
        
        IRecordProcessorFactory recordProcessorFactory = createSampleRecordProcessorFactory();
        
        Worker.Builder workerBuilder = new Worker.Builder()
                .recordProcessorFactory(recordProcessorFactory)
                .config(config);
                
        Worker worker = workerBuilder.build();
        worker.run();
    }

    public static void good_case_11() {
        // KCL v2 with enhanced fan-out and processEmptyRecordList set to true
        String streamName = "AuditEvents";
        String applicationName = "AuditProcessor";
        Region region = Region.US_EAST_2;
        
        KinesisAsyncClient kinesisClient = KinesisAsyncClient.builder()
                .region(region)
                .build();
                
        DynamoDbAsyncClient dynamoClient = DynamoDbAsyncClient.builder()
                .region(region)
                .build();
                
        CloudWatchAsyncClient cloudWatchClient = CloudWatchAsyncClient.builder()
                .region(region)
                .build();
                
        ConfigsBuilder configsBuilder = new ConfigsBuilder(
                streamName,
                applicationName,
                kinesisClient,
                dynamoClient,
                cloudWatchClient,
                UUID.randomUUID().toString(),
                createShardRecordProcessorFactory());
        
        RetrievalConfig retrievalConfig = configsBuilder.retrievalConfig()
                .retrievalSpecificConfig(
                        new FanOutConfig(kinesisClient)
                                .streamName(streamName)
                                .applicationName(applicationName));
        
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        ProcessorConfig processorConfig = configsBuilder.processorConfig()
                .processEmptyRecordList(true);
        
        Scheduler scheduler = new Scheduler(
                configsBuilder.checkpointConfig(),
                configsBuilder.coordinatorConfig(),
                configsBuilder.leaseManagementConfig(),
                configsBuilder.lifecycleConfig(),
                configsBuilder.metricsConfig(),
                processorConfig,
                retrievalConfig);
                
        scheduler.run();
    }

    public static void good_case_12() {
        // KCL v1 with custom metrics factory and the critical setting
        String applicationName = "SecurityMonitoring";
        String streamName = "SecurityEvents";
        String workerId = UUID.randomUUID().toString();
        
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
                applicationName,
                streamName,
                new DefaultAWSCredentialsProviderChain(),
                workerId)
                .withMetricsLevel(MetricsLevel.DETAILED)
                .withMetricsBufferTimeMillis(10000)
                .withMetricsMaxQueueSize(10000)
                .withValidateSequenceNumberBeforeCheckpointing(true)
                .withCallProcessRecordsEvenForEmptyRecordList(true);
        
        IRecordProcessorFactory recordProcessorFactory = createSampleRecordProcessorFactory();
        Worker worker = new Worker(recordProcessorFactory, config);
        worker.run();
    }

    public static void good_case_13() {
        // KCL v2 with custom lease management and processEmptyRecordList set to true
        String streamName = "MarketingCampaigns";
        String applicationName = "CampaignTracker";
        Region region = Region.CA_CENTRAL_1;
        
        KinesisAsyncClient kinesisClient = KinesisAsyncClient.builder()
                .region(region)
                .build();
                
        DynamoDbAsyncClient dynamoClient = DynamoDbAsyncClient.builder()
                .region(region)
                .build();
                
        CloudWatchAsyncClient cloudWatchClient = CloudWatchAsyncClient.builder()
                .region(region)
                .build();
                
        ConfigsBuilder configsBuilder = new ConfigsBuilder(
                streamName,
                applicationName,
                kinesisClient,
                dynamoClient,
                cloudWatchClient,
                UUID.randomUUID().toString(),
                createShardRecordProcessorFactory());
        
        LeaseManagementConfig leaseConfig = configsBuilder.leaseManagementConfig()
                .tableName("CustomLeaseTable")
                .billingMode(BillingMode.PAY_PER_REQUEST);
                
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        ProcessorConfig processorConfig = configsBuilder.processorConfig()
                .maxPendingProcessRecordsInput(100)
                .processEmptyRecordList(true);
        
        Scheduler scheduler = new Scheduler(
                configsBuilder.checkpointConfig(),
                configsBuilder.coordinatorConfig(),
                leaseConfig,
                configsBuilder.lifecycleConfig(),
                configsBuilder.metricsConfig(),
                processorConfig,
                configsBuilder.retrievalConfig());
                
        scheduler.run();
    }

    public static void good_case_14() {
        // KCL v1 with separate setting of the critical parameter
        String applicationName = "AnalyticsProcessor";
        String streamName = "UserActivityStream";
        String workerId = UUID.randomUUID().toString();
        
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
                applicationName,
                streamName,
                new DefaultAWSCredentialsProviderChain(),
                workerId);
        
        config.withInitialPositionInStream(InitialPositionInStream.TRIM_HORIZON);
        config.withMetricsLevel(MetricsLevel.DETAILED);
        config.withMaxRecords(1000);
        config.withIdleTimeBetweenReadsInMillis(250);
        
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        config.withCallProcessRecordsEvenForEmptyRecordList(true);
        
        IRecordProcessorFactory recordProcessorFactory = createSampleRecordProcessorFactory();
        Worker worker = new Worker(recordProcessorFactory, config);
        worker.run();
    }

    public static void good_case_15() {
        // KCL v2 with direct scheduler creation and processEmptyRecordList set to true
        String streamName = "LogAggregation";
        String applicationName = "LogProcessor";
        Region region = Region.AP_NORTHEAST_1;
        
        KinesisAsyncClient kinesisClient = KinesisAsyncClient.builder()
                .region(region)
                .build();
                
        DynamoDbAsyncClient dynamoClient = DynamoDbAsyncClient.builder()
                .region(region)
                .build();
                
        CloudWatchAsyncClient cloudWatchClient = CloudWatchAsyncClient.builder()
                .region(region)
                .build();
                
        ConfigsBuilder configsBuilder = new ConfigsBuilder(
                streamName,
                applicationName,
                kinesisClient,
                dynamoClient,
                cloudWatchClient,
                UUID.randomUUID().toString(),
                createShardRecordProcessorFactory());
        
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        ProcessorConfig processorConfig = new ProcessorConfig(
                createShardRecordProcessorFactory())
                .processEmptyRecordList(true);
        
        Scheduler scheduler = new Scheduler(
                configsBuilder.checkpointConfig(),
                configsBuilder.coordinatorConfig(),
                configsBuilder.leaseManagementConfig(),
                configsBuilder.lifecycleConfig(),
                configsBuilder.metricsConfig(),
                processorConfig,
                configsBuilder.retrievalConfig());
                
        scheduler.run();
    }

    // Helper methods
    private static IRecordProcessorFactory createSampleRecordProcessorFactory() {
        return () -> new IRecordProcessor() {
            @Override
            public void initialize(InitializationInput initializationInput) {}

            @Override
            public void processRecords(ProcessRecordsInput processRecordsInput) {}

            @Override
            public void shutdown(ShutdownInput shutdownInput) {}
        };
    }

    private static ShardRecordProcessorFactory createShardRecordProcessorFactory() {
        return () -> new ShardRecordProcessor() {
            @Override
            public void initialize(InitializationInput initializationInput) {}

            @Override
            public void processRecords(ProcessRecordsInput processRecordsInput) {}

            @Override
            public void leaseLost(LeaseLostInput leaseLostInput) {}

            @Override
            public void shardEnded(ShardEndedInput shardEndedInput) {}

            @Override
            public void shutdownRequested(ShutdownRequestedInput shutdownRequestedInput) {}
        };
    }
}
// {/fact}