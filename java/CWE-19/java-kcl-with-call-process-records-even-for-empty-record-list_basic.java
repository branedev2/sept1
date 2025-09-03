import com.amazonaws.services.kinesis.clientlibrary.interfaces.IRecordProcessorFactory;
import com.amazonaws.services.kinesis.clientlibrary.interfaces.v2.IRecordProcessor;
import com.amazonaws.services.kinesis.clientlibrary.interfaces.v2.IRecordProcessorFactory;
import com.amazonaws.services.kinesis.clientlibrary.lib.worker.KinesisClientLibConfiguration;
import com.amazonaws.services.kinesis.clientlibrary.lib.worker.Worker;
import com.amazonaws.services.kinesis.clientlibrary.lib.worker.WorkerBuilder;
import com.amazonaws.services.kinesis.clientlibrary.lib.worker.ShutdownReason;
import com.amazonaws.services.kinesis.clientlibrary.types.InitializationInput;
import com.amazonaws.services.kinesis.clientlibrary.types.ProcessRecordsInput;
import com.amazonaws.services.kinesis.clientlibrary.types.ShutdownInput;
import com.amazonaws.services.kinesis.metrics.interfaces.MetricsLevel;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.kinesis.AmazonKinesis;
import com.amazonaws.services.kinesis.AmazonKinesisClientBuilder;
import com.amazonaws.services.cloudwatch.AmazonCloudWatch;
import com.amazonaws.services.cloudwatch.AmazonCloudWatchClientBuilder;

import java.util.UUID;

public class KCLExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
    public void bad_case_1() {
        IRecordProcessorFactory recordProcessorFactory = new SampleRecordProcessorFactory();
        
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        Worker worker = new Worker.Builder()
            .recordProcessorFactory(recordProcessorFactory)
            .config(new KinesisClientLibConfiguration(
                "myApp",
                "myStreamName",
                new DefaultAWSCredentialsProviderChain(),
                "worker-" + UUID.randomUUID()))
            .build();
        
        Thread workerThread = new Thread(worker);
        workerThread.start();
    }

    public void bad_case_2() {
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        Worker worker = new Worker.Builder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(new KinesisClientLibConfiguration(
                "myApp",
                "myStreamName",
                new DefaultAWSCredentialsProviderChain(),
                "worker-" + UUID.randomUUID())
                .withMaxRecords(1000)
                .withIdleTimeBetweenReadsInMillis(500))
            .build();
        
        worker.run();
    }

    public void bad_case_3() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.defaultClient();
        AmazonCloudWatch cloudWatchClient = AmazonCloudWatchClientBuilder.defaultClient();
        
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        Worker worker = new WorkerBuilder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(new KinesisClientLibConfiguration(
                "myApp",
                "myStreamName",
                new DefaultAWSCredentialsProviderChain(),
                "worker-" + UUID.randomUUID()))
            .kinesisClient(kinesisClient)
            .dynamoDBClient(dynamoDBClient)
            .cloudWatchClient(cloudWatchClient)
            .build();
        
        worker.run();
    }

    public void bad_case_4() {
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
            "myApp",
            "myStreamName",
            new DefaultAWSCredentialsProviderChain(),
            "worker-" + UUID.randomUUID());
        
        config.withInitialPositionInStream(InitialPositionInStream.LATEST);
        config.withMaxRecords(10000);
        
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        Worker worker = new Worker.Builder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(config)
            .build();
        
        Thread t = new Thread(worker);
        t.start();
    }

    public void bad_case_5() {
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        Worker worker = new Worker.Builder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(new KinesisClientLibConfiguration(
                "myApp",
                "myStreamName",
                new DefaultAWSCredentialsProviderChain(),
                "worker-" + UUID.randomUUID())
                .withCallProcessRecordsEvenForEmptyRecordList(false))
            .build();
        
        worker.run();
    }

    public void bad_case_6() {
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
            "myApp",
            "myStreamName",
            new DefaultAWSCredentialsProviderChain(),
            "worker-" + UUID.randomUUID());
        
        boolean processEmptyRecords = false;
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        config.withCallProcessRecordsEvenForEmptyRecordList(processEmptyRecords);
        
        Worker worker = new Worker.Builder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(config)
            .build();
        
        worker.run();
    }

    public void bad_case_7() {
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
            "myApp",
            "myStreamName",
            new DefaultAWSCredentialsProviderChain(),
            "worker-" + UUID.randomUUID());
        
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        config.withMetricsLevel(MetricsLevel.DETAILED)
             .withInitialPositionInStream(InitialPositionInStream.TRIM_HORIZON);
        
        Worker worker = new Worker.Builder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(config)
            .build();
        
        worker.run();
    }

    public void bad_case_8() {
        String appName = "criticalDataProcessor";
        String streamName = "financialTransactions";
        
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
            appName,
            streamName,
            new DefaultAWSCredentialsProviderChain(),
            "worker-" + UUID.randomUUID());
        
        Worker worker = new Worker.Builder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(config)
            .build();
        
        worker.run();
    }

    public void bad_case_9() {
        // Creating a configuration with multiple settings but missing the critical one
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
            "myApp",
            "myStreamName",
            new DefaultAWSCredentialsProviderChain(),
            "worker-" + UUID.randomUUID());
        
        config.withMaxRecords(1000)
             .withIdleTimeBetweenReadsInMillis(250)
             .withFailoverTimeMillis(10000)
             .withShardSyncIntervalMillis(60000);
        
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        Worker worker = new Worker.Builder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(config)
            .build();
        
        worker.run();
    }

    public void bad_case_10() {
        // Using conditional logic but still not setting the flag
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
            "myApp",
            "myStreamName",
            new DefaultAWSCredentialsProviderChain(),
            "worker-" + UUID.randomUUID());
        
        boolean isHighThroughputMode = true;
        
        if (isHighThroughputMode) {
            config.withMaxRecords(10000)
                 .withIdleTimeBetweenReadsInMillis(1);
        } else {
            config.withMaxRecords(100)
                 .withIdleTimeBetweenReadsInMillis(1000);
        }
        
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        Worker worker = new Worker.Builder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(config)
            .build();
        
        worker.run();
    }

    public void bad_case_11() {
        // Using a method to create the configuration but still missing the setting
        KinesisClientLibConfiguration config = createBasicConfig("myApp", "myStreamName");
        
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        Worker worker = new Worker.Builder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(config)
            .build();
        
        worker.run();
    }

    private KinesisClientLibConfiguration createBasicConfig(String appName, String streamName) {
        return new KinesisClientLibConfiguration(
            appName,
            streamName,
            new DefaultAWSCredentialsProviderChain(),
            "worker-" + UUID.randomUUID())
            .withMaxRecords(1000)
            .withIdleTimeBetweenReadsInMillis(500);
    }

    public void bad_case_12() {
        // Creating multiple workers with the same config issue
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
            "myApp",
            "myStreamName",
            new DefaultAWSCredentialsProviderChain(),
            "worker-" + UUID.randomUUID());
        
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        Worker worker1 = new Worker.Builder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(config)
            .build();
        
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        Worker worker2 = new Worker.Builder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(config)
            .build();
        
        Thread t1 = new Thread(worker1);
        Thread t2 = new Thread(worker2);
        t1.start();
        t2.start();
    }

    public void bad_case_13() {
        // Using a builder pattern but still missing the setting
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        Worker worker = new WorkerBuilder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(new KinesisClientLibConfiguration(
                "myApp",
                "myStreamName",
                new DefaultAWSCredentialsProviderChain(),
                "worker-" + UUID.randomUUID()))
            .kinesisClient(AmazonKinesisClientBuilder.defaultClient())
            .dynamoDBClient(AmazonDynamoDBClientBuilder.defaultClient())
            .cloudWatchClient(AmazonCloudWatchClientBuilder.defaultClient())
            .build();
        
        worker.run();
    }

    public void bad_case_14() {
        // Setting other properties but not the empty records flag
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
            "myApp",
            "myStreamName",
            new DefaultAWSCredentialsProviderChain(),
            "worker-" + UUID.randomUUID());
        
        config.withMaxLeasesForWorker(10)
             .withMaxLeasesToStealAtOneTime(2)
             .withShardPrioritization(new NoOpShardPrioritization());
        
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        Worker worker = new Worker.Builder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(config)
            .build();
        
        worker.run();
    }

    public void bad_case_15() {
        // Setting the flag to false explicitly in a complex configuration
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
            "myApp",
            "myStreamName",
            new DefaultAWSCredentialsProviderChain(),
            "worker-" + UUID.randomUUID());
        
        // ruleid: java-kcl-with-call-process-records-even-for-empty-record-list
        config.withMaxRecords(1000)
             .withIdleTimeBetweenReadsInMillis(250)
             .withCallProcessRecordsEvenForEmptyRecordList(false)
             .withFailoverTimeMillis(10000);
        
        Worker worker = new Worker.Builder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(config)
            .build();
        
        worker.run();
    }

    // True Negative Examples (Secure Code)

    public void good_case_1() {
        IRecordProcessorFactory recordProcessorFactory = new SampleRecordProcessorFactory();
        
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        Worker worker = new Worker.Builder()
            .recordProcessorFactory(recordProcessorFactory)
            .config(new KinesisClientLibConfiguration(
                "myApp",
                "myStreamName",
                new DefaultAWSCredentialsProviderChain(),
                "worker-" + UUID.randomUUID())
                .withCallProcessRecordsEvenForEmptyRecordList(true))
            .build();
        
        Thread workerThread = new Thread(worker);
        workerThread.start();
    }

    public void good_case_2() {
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
            "myApp",
            "myStreamName",
            new DefaultAWSCredentialsProviderChain(),
            "worker-" + UUID.randomUUID());
        
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        config.withCallProcessRecordsEvenForEmptyRecordList(true);
        
        Worker worker = new Worker.Builder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(config)
            .build();
        
        worker.run();
    }

    public void good_case_3() {
        AmazonKinesis kinesisClient = AmazonKinesisClientBuilder.defaultClient();
        AmazonDynamoDB dynamoDBClient = AmazonDynamoDBClientBuilder.defaultClient();
        AmazonCloudWatch cloudWatchClient = AmazonCloudWatchClientBuilder.defaultClient();
        
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        Worker worker = new WorkerBuilder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(new KinesisClientLibConfiguration(
                "myApp",
                "myStreamName",
                new DefaultAWSCredentialsProviderChain(),
                "worker-" + UUID.randomUUID())
                .withCallProcessRecordsEvenForEmptyRecordList(true))
            .kinesisClient(kinesisClient)
            .dynamoDBClient(dynamoDBClient)
            .cloudWatchClient(cloudWatchClient)
            .build();
        
        worker.run();
    }

    public void good_case_4() {
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
            "myApp",
            "myStreamName",
            new DefaultAWSCredentialsProviderChain(),
            "worker-" + UUID.randomUUID());
        
        config.withInitialPositionInStream(InitialPositionInStream.LATEST);
        config.withMaxRecords(10000);
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        config.withCallProcessRecordsEvenForEmptyRecordList(true);
        
        Worker worker = new Worker.Builder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(config)
            .build();
        
        Thread t = new Thread(worker);
        t.start();
    }

    public void good_case_5() {
        boolean processEmptyRecords = true;
        
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        Worker worker = new Worker.Builder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(new KinesisClientLibConfiguration(
                "myApp",
                "myStreamName",
                new DefaultAWSCredentialsProviderChain(),
                "worker-" + UUID.randomUUID())
                .withCallProcessRecordsEvenForEmptyRecordList(processEmptyRecords))
            .build();
        
        worker.run();
    }

    public void good_case_6() {
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
            "myApp",
            "myStreamName",
            new DefaultAWSCredentialsProviderChain(),
            "worker-" + UUID.randomUUID());
        
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        config.withMetricsLevel(MetricsLevel.DETAILED)
             .withInitialPositionInStream(InitialPositionInStream.TRIM_HORIZON)
             .withCallProcessRecordsEvenForEmptyRecordList(true);
        
        Worker worker = new Worker.Builder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(config)
            .build();
        
        worker.run();
    }

    public void good_case_7() {
        String appName = "criticalDataProcessor";
        String streamName = "financialTransactions";
        
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
            appName,
            streamName,
            new DefaultAWSCredentialsProviderChain(),
            "worker-" + UUID.randomUUID())
            .withCallProcessRecordsEvenForEmptyRecordList(true);
        
        Worker worker = new Worker.Builder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(config)
            .build();
        
        worker.run();
    }

    public void good_case_8() {
        // Creating a configuration with multiple settings including the critical one
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
            "myApp",
            "myStreamName",
            new DefaultAWSCredentialsProviderChain(),
            "worker-" + UUID.randomUUID())
            .withMaxRecords(1000)
            .withIdleTimeBetweenReadsInMillis(250)
            .withFailoverTimeMillis(10000)
            .withShardSyncIntervalMillis(60000)
            .withCallProcessRecordsEvenForEmptyRecordList(true);
        
        Worker worker = new Worker.Builder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(config)
            .build();
        
        worker.run();
    }

    public void good_case_9() {
        // Using conditional logic and setting the flag appropriately
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
            "myApp",
            "myStreamName",
            new DefaultAWSCredentialsProviderChain(),
            "worker-" + UUID.randomUUID());
        
        boolean isHighThroughputMode = true;
        
        if (isHighThroughputMode) {
            config.withMaxRecords(10000)
                 .withIdleTimeBetweenReadsInMillis(1);
        } else {
            config.withMaxRecords(100)
                 .withIdleTimeBetweenReadsInMillis(1000);
        }
        
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        config.withCallProcessRecordsEvenForEmptyRecordList(true);
        
        Worker worker = new Worker.Builder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(config)
            .build();
        
        worker.run();
    }

    public void good_case_10() {
        // Using a method to create the configuration with the proper setting
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        KinesisClientLibConfiguration config = createSecureConfig("myApp", "myStreamName");
        
        Worker worker = new Worker.Builder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(config)
            .build();
        
        worker.run();
    }

    private KinesisClientLibConfiguration createSecureConfig(String appName, String streamName) {
        return new KinesisClientLibConfiguration(
            appName,
            streamName,
            new DefaultAWSCredentialsProviderChain(),
            "worker-" + UUID.randomUUID())
            .withMaxRecords(1000)
            .withIdleTimeBetweenReadsInMillis(500)
            .withCallProcessRecordsEvenForEmptyRecordList(true);
    }

    public void good_case_11() {
        // Creating multiple workers with the correct config
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
            "myApp",
            "myStreamName",
            new DefaultAWSCredentialsProviderChain(),
            "worker-" + UUID.randomUUID())
            .withCallProcessRecordsEvenForEmptyRecordList(true);
        
        Worker worker1 = new Worker.Builder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(config)
            .build();
        
        Worker worker2 = new Worker.Builder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(config)
            .build();
        
        Thread t1 = new Thread(worker1);
        Thread t2 = new Thread(worker2);
        t1.start();
        t2.start();
    }

    public void good_case_12() {
        // Using a builder pattern with the correct setting
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        Worker worker = new WorkerBuilder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(new KinesisClientLibConfiguration(
                "myApp",
                "myStreamName",
                new DefaultAWSCredentialsProviderChain(),
                "worker-" + UUID.randomUUID())
                .withCallProcessRecordsEvenForEmptyRecordList(true))
            .kinesisClient(AmazonKinesisClientBuilder.defaultClient())
            .dynamoDBClient(AmazonDynamoDBClientBuilder.defaultClient())
            .cloudWatchClient(AmazonCloudWatchClientBuilder.defaultClient())
            .build();
        
        worker.run();
    }

    public void good_case_13() {
        // Setting multiple properties including the empty records flag
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
            "myApp",
            "myStreamName",
            new DefaultAWSCredentialsProviderChain(),
            "worker-" + UUID.randomUUID())
            .withMaxLeasesForWorker(10)
            .withMaxLeasesToStealAtOneTime(2)
            .withShardPrioritization(new NoOpShardPrioritization())
            .withCallProcessRecordsEvenForEmptyRecordList(true);
        
        Worker worker = new Worker.Builder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(config)
            .build();
        
        worker.run();
    }

    public void good_case_14() {
        // Using environment variables to determine configuration but still setting the flag
        String appName = System.getenv("KCL_APP_NAME") != null ? 
                         System.getenv("KCL_APP_NAME") : "defaultApp";
        String streamName = System.getenv("KCL_STREAM_NAME") != null ? 
                           System.getenv("KCL_STREAM_NAME") : "defaultStream";
        
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
            appName,
            streamName,
            new DefaultAWSCredentialsProviderChain(),
            "worker-" + UUID.randomUUID())
            .withCallProcessRecordsEvenForEmptyRecordList(true);
        
        Worker worker = new Worker.Builder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(config)
            .build();
        
        worker.run();
    }

    public void good_case_15() {
        // Setting the flag to true explicitly in a complex configuration
        // ok: java-kcl-with-call-process-records-even-for-empty-record-list
        KinesisClientLibConfiguration config = new KinesisClientLibConfiguration(
            "myApp",
            "myStreamName",
            new DefaultAWSCredentialsProviderChain(),
            "worker-" + UUID.randomUUID())
            .withMaxRecords(1000)
            .withIdleTimeBetweenReadsInMillis(250)
            .withCallProcessRecordsEvenForEmptyRecordList(true)
            .withFailoverTimeMillis(10000);
        
        Worker worker = new Worker.Builder()
            .recordProcessorFactory(new SampleRecordProcessorFactory())
            .config(config)
            .build();
        
        worker.run();
    }

    // Sample implementation of IRecordProcessorFactory
    private static class SampleRecordProcessorFactory implements IRecordProcessorFactory {
        @Override
        public IRecordProcessor createProcessor() {
            return new SampleRecordProcessor();
        }
    }

    // Sample implementation of IRecordProcessor
    private static class SampleRecordProcessor implements IRecordProcessor {
        @Override
        public void initialize(InitializationInput initializationInput) {
            // Implementation
        }

        @Override
        public void processRecords(ProcessRecordsInput processRecordsInput) {
            // Implementation
        }

        @Override
        public void shutdown(ShutdownInput shutdownInput) {
            // Implementation
        }
    }
}
// {/fact}