import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.waiters.AmazonS3Waiters;
import com.amazonaws.waiters.Waiter;
import com.amazonaws.waiters.WaiterParameters;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2ClientBuilder;
import com.amazonaws.services.ec2.model.DescribeInstancesRequest;
import com.amazonaws.services.ec2.model.DescribeInstancesResult;
import com.amazonaws.services.ec2.model.Instance;
import com.amazonaws.services.ec2.model.Reservation;
import com.amazonaws.services.ec2.waiters.AmazonEC2Waiters;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.model.DescribeTableRequest;
import com.amazonaws.services.dynamodbv2.model.TableDescription;
import com.amazonaws.services.dynamodbv2.waiters.AmazonDynamoDBWaiters;
import com.amazonaws.services.rds.AmazonRDS;
import com.amazonaws.services.rds.AmazonRDSClientBuilder;
import com.amazonaws.services.rds.model.DBInstance;
import com.amazonaws.services.rds.model.DescribeDBInstancesRequest;
import com.amazonaws.services.rds.model.DescribeDBInstancesResult;
import com.amazonaws.services.rds.waiters.AmazonRDSWaiters;
import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.lambda.model.GetFunctionRequest;
import com.amazonaws.services.lambda.model.GetFunctionResult;

import java.util.List;
import java.util.concurrent.TimeUnit;

public class AwsPollingExamples {

    // True Positives (Custom polling implementations that should be detected)

// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
    public void bad_case_1() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "my-bucket";
        String key = "my-object";
        
        boolean objectExists = false;
        int maxRetries = 20;
        int retryCount = 0;
        
        while (!objectExists && retryCount < maxRetries) {
            try {
                // ruleid: java-polling-to-waiters
                S3Object object = s3Client.getObject(bucketName, key);
                objectExists = true;
                System.out.println("Object found!");
            } catch (Exception e) {
                retryCount++;
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    public void bad_case_2() {
        AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard().build();
        String instanceId = "i-1234567890abcdef0";
        
        boolean instanceRunning = false;
        int maxAttempts = 30;
        int attempt = 0;
        
        while (!instanceRunning && attempt < maxAttempts) {
            DescribeInstancesRequest request = new DescribeInstancesRequest().withInstanceIds(instanceId);
            // ruleid: java-polling-to-waiters
            DescribeInstancesResult result = ec2Client.describeInstances(request);
            
            for (Reservation reservation : result.getReservations()) {
                for (Instance instance : reservation.getInstances()) {
                    if ("running".equals(instance.getState().getName())) {
                        instanceRunning = true;
                        break;
                    }
                }
            }
            
            if (!instanceRunning) {
                attempt++;
                try {
                    Thread.sleep(5000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    public void bad_case_3() {
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
        String tableName = "my-table";
        
        boolean tableActive = false;
        int maxRetries = 25;
        int retryCount = 0;
        
        while (!tableActive && retryCount < maxRetries) {
            DescribeTableRequest request = new DescribeTableRequest().withTableName(tableName);
            try {
                // ruleid: java-polling-to-waiters
                TableDescription tableDescription = dynamoDbClient.describeTable(request).getTable();
                if ("AC_REDACTED_TWILIO_ID".equals(tableDescription.getTableStatus())) {
                    tableActive = true;
                    System.out.println("Table is active!");
                } else {
                    retryCount++;
                    try {
                        Thread.sleep(2000);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
            } catch (Exception e) {
                retryCount++;
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    public void bad_case_4() {
        AmazonRDS rdsClient = AmazonRDSClientBuilder.standard().build();
        String dbInstanceId = "my-db-instance";
        
        boolean dbAvailable = false;
        int maxAttempts = 60;
        int attempt = 0;
        
        while (!dbAvailable && attempt < maxAttempts) {
            DescribeDBInstancesRequest request = new DescribeDBInstancesRequest()
                .withDBInstanceIdentifier(dbInstanceId);
            
            try {
                // ruleid: java-polling-to-waiters
                DescribeDBInstancesResult result = rdsClient.describeDBInstances(request);
                DBInstance dbInstance = result.getDBInstances().get(0);
                
                if ("available".equalsIgnoreCase(dbInstance.getDBInstanceStatus())) {
                    dbAvailable = true;
                    System.out.println("Database instance is available!");
                } else {
                    attempt++;
                    try {
                        Thread.sleep(10000);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
            } catch (Exception e) {
                attempt++;
                try {
                    Thread.sleep(10000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    public void bad_case_5() {
        AWSLambda lambdaClient = AWSLambdaClientBuilder.standard().build();
        String functionName = "my-function";
        
        boolean functionActive = false;
        int maxRetries = 15;
        int retryCount = 0;
        
        while (!functionActive && retryCount < maxRetries) {
            GetFunctionRequest request = new GetFunctionRequest().withFunctionName(functionName);
            try {
                // ruleid: java-polling-to-waiters
                GetFunctionResult result = lambdaClient.getFunction(request);
                if ("Active".equals(result.getConfiguration().getState())) {
                    functionActive = true;
                    System.out.println("Lambda function is active!");
                } else {
                    retryCount++;
                    try {
                        Thread.sleep(3000);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
            } catch (Exception e) {
                retryCount++;
                try {
                    Thread.sleep(3000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    public void bad_case_6() {
        AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard().build();
        String instanceId = "i-0abcdef1234567890";
        
        boolean instanceStopped = false;
        int pollCount = 0;
        int maxPolls = 30;
        
        do {
            DescribeInstancesRequest request = new DescribeInstancesRequest()
                .withInstanceIds(instanceId);
            
            // ruleid: java-polling-to-waiters
            DescribeInstancesResult result = ec2Client.describeInstances(request);
            Instance instance = result.getReservations().get(0).getInstances().get(0);
            
            if ("stopped".equals(instance.getState().getName())) {
                instanceStopped = true;
            } else {
                pollCount++;
                try {
                    TimeUnit.SECONDS.sleep(10);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        } while (!instanceStopped && pollCount < maxPolls);
    }

    public void bad_case_7() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "new-bucket-creation";
        
        boolean bucketExists = false;
        int attempts = 0;
        int maxAttempts = 20;
        
        while (!bucketExists && attempts < maxAttempts) {
            try {
                // ruleid: java-polling-to-waiters
                if (s3Client.doesBucketExistV2(bucketName)) {
                    bucketExists = true;
                    System.out.println("Bucket exists and is accessible!");
                } else {
                    attempts++;
                    try {
                        Thread.sleep(2500);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
            } catch (Exception e) {
                attempts++;
                try {
                    Thread.sleep(2500);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    public void bad_case_8() {
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
        String tableName = "users-table";
        
        boolean tableDeleted = false;
        int retries = 0;
        int maxRetries = 40;
        
        while (!tableDeleted && retries < maxRetries) {
            try {
                DescribeTableRequest request = new DescribeTableRequest().withTableName(tableName);
                // ruleid: java-polling-to-waiters
                dynamoDbClient.describeTable(request);
                // Table still exists, wait and retry
                retries++;
                try {
                    Thread.sleep(5000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            } catch (Exception e) {
                // Table doesn't exist anymore
                tableDeleted = true;
                System.out.println("Table has been deleted!");
            }
        }
    }

    public void bad_case_9() {
        AmazonRDS rdsClient = AmazonRDSClientBuilder.standard().build();
        String snapshotId = "my-db-snapshot";
        
        boolean snapshotAvailable = false;
        int pollAttempts = 0;
        int maxPolls = 50;
        
        while (!snapshotAvailable && pollAttempts < maxPolls) {
            try {
                // ruleid: java-polling-to-waiters
                DescribeDBInstancesResult result = rdsClient.describeDBInstances(
                    new DescribeDBInstancesRequest().withDBInstanceIdentifier(snapshotId));
                
                String status = result.getDBInstances().get(0).getDBInstanceStatus();
                if ("available".equalsIgnoreCase(status)) {
                    snapshotAvailable = true;
                    System.out.println("Snapshot is available!");
                } else {
                    pollAttempts++;
                    try {
                        Thread.sleep(15000);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
            } catch (Exception e) {
                pollAttempts++;
                try {
                    Thread.sleep(15000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    public void bad_case_10() {
        AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard().build();
        String volumeId = "vol-0abcdef1234567890";
        
        boolean volumeAvailable = false;
        int checkCount = 0;
        int maxChecks = 24;
        
        for (int i = 0; i < maxChecks && !volumeAvailable; i++) {
            try {
                // ruleid: java-polling-to-waiters
                DescribeInstancesResult result = ec2Client.describeInstances(
                    new DescribeInstancesRequest().withInstanceIds("i-attached-to-volume"));
                
                // Check if volume is attached to instance
                List<Instance> instances = result.getReservations().get(0).getInstances();
                if (instances.isEmpty() || instances.get(0).getBlockDeviceMappings().isEmpty()) {
                    // Volume is detached
                    volumeAvailable = true;
                } else {
                    try {
                        Thread.sleep(5000);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
            } catch (Exception e) {
                checkCount++;
                try {
                    Thread.sleep(5000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    public void bad_case_11() {
        AWSLambda lambdaClient = AWSLambdaClientBuilder.standard().build();
        String functionName = "data-processor";
        
        boolean functionUpdated = false;
        int attempts = 0;
        int maxAttempts = 10;
        
        while (!functionUpdated && attempts < maxAttempts) {
            GetFunctionRequest request = new GetFunctionRequest().withFunctionName(functionName);
            try {
                // ruleid: java-polling-to-waiters
                GetFunctionResult result = lambdaClient.getFunction(request);
                String lastUpdateStatus = result.getConfiguration().getLastUpdateStatus();
                
                if ("Successful".equals(lastUpdateStatus)) {
                    functionUpdated = true;
                    System.out.println("Lambda function update completed!");
                } else if ("Failed".equals(lastUpdateStatus)) {
                    throw new RuntimeException("Function update failed: " + 
                        result.getConfiguration().getLastUpdateStatusReason());
                } else {
                    attempts++;
                    try {
                        Thread.sleep(2000);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
            } catch (Exception e) {
                attempts++;
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    public void bad_case_12() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String sourceBucket = "source-bucket";
        String sourceKey = "large-file.zip";
        String destBucket = "destination-bucket";
        String destKey = "copied-large-file.zip";
        
        s3Client.copyObject(sourceBucket, sourceKey, destBucket, destKey);
        
        boolean copyCompleted = false;
        int checkCount = 0;
        int maxChecks = 30;
        
        while (!copyCompleted && checkCount < maxChecks) {
            try {
                // ruleid: java-polling-to-waiters
                s3Client.getObjectMetadata(destBucket, destKey);
                copyCompleted = true;
                System.out.println("Copy operation completed!");
            } catch (Exception e) {
                checkCount++;
                try {
                    Thread.sleep(5000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    public void bad_case_13() {
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
        String tableName = "high-traffic-table";
        
        boolean backupCompleted = false;
        int pollCount = 0;
        int maxPolls = 20;
        
        while (!backupCompleted && pollCount < maxPolls) {
            try {
                DescribeTableRequest request = new DescribeTableRequest().withTableName(tableName);
                // ruleid: java-polling-to-waiters
                TableDescription tableDesc = dynamoDbClient.describeTable(request).getTable();
                
                if (tableDesc.getBackupSummary() != null && 
                    "COMPLETED".equals(tableDesc.getBackupSummary().getBackupStatus())) {
                    backupCompleted = true;
                    System.out.println("Backup completed successfully!");
                } else {
                    pollCount++;
                    try {
                        Thread.sleep(10000);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
            } catch (Exception e) {
                pollCount++;
                try {
                    Thread.sleep(10000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    public void bad_case_14() {
        AmazonRDS rdsClient = AmazonRDSClientBuilder.standard().build();
        String dbClusterId = "my-aurora-cluster";
        
        boolean clusterAvailable = false;
        int attempts = 0;
        int maxAttempts = 45;
        
        while (!clusterAvailable && attempts < maxAttempts) {
            try {
                // ruleid: java-polling-to-waiters
                DescribeDBInstancesResult result = rdsClient.describeDBInstances(
                    new DescribeDBInstancesRequest().withDBInstanceIdentifier(dbClusterId + "-instance"));
                
                DBInstance instance = result.getDBInstances().get(0);
                if ("available".equalsIgnoreCase(instance.getDBInstanceStatus())) {
                    clusterAvailable = true;
                    System.out.println("DB Cluster is available!");
                } else {
                    attempts++;
                    try {
                        Thread.sleep(20000);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
            } catch (Exception e) {
                attempts++;
                try {
                    Thread.sleep(20000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    public void bad_case_15() {
        AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard().build();
        String securityGroupId = "sg-0abcdef1234567890";
        
        boolean ruleApplied = false;
        int checkCount = 0;
        int maxChecks = 15;
        
        while (!ruleApplied && checkCount < maxChecks) {
            // ruleid: java-polling-to-waiters
            DescribeInstancesResult result = ec2Client.describeInstances(
                new DescribeInstancesRequest().withFilters(
                    new com.amazonaws.services.ec2.model.Filter("instance-state-name", List.of("running")),
                    new com.amazonaws.services.ec2.model.Filter("security-groups.group-id", List.of(securityGroupId))
                )
            );
            
            if (!result.getReservations().isEmpty() && 
                !result.getReservations().get(0).getInstances().isEmpty()) {
                ruleApplied = true;
                System.out.println("Security group rule has been applied to instances!");
            } else {
                checkCount++;
                try {
                    Thread.sleep(3000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    // True Negatives (Using AWS waiters properly)

    public void good_case_1() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "my-bucket";
        String key = "my-object";
        
        // ok: java-polling-to-waiters
        AmazonS3Waiters waiters = s3Client.waiters();
        Waiter<GetObjectRequest> objectExists = waiters.objectExists();
        objectExists.run(new WaiterParameters<>(new GetObjectRequest(bucketName, key)));
        System.out.println("Object exists!");
    }

    public void good_case_2() {
        AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard().build();
        String instanceId = "i-1234567890abcdef0";
        
        // ok: java-polling-to-waiters
        AmazonEC2Waiters waiters = ec2Client.waiters();
        waiters.instanceRunning().run(
            new WaiterParameters<>(new DescribeInstancesRequest().withInstanceIds(instanceId))
        );
        System.out.println("Instance is now running!");
    }

    public void good_case_3() {
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
        String tableName = "my-table";
        
        // ok: java-polling-to-waiters
        AmazonDynamoDBWaiters waiters = AmazonDynamoDBWaiters.using(dynamoDbClient);
        waiters.tableExists().run(
            new WaiterParameters<>(new DescribeTableRequest().withTableName(tableName))
        );
        System.out.println("Table exists and is active!");
    }

    public void good_case_4() {
        AmazonRDS rdsClient = AmazonRDSClientBuilder.standard().build();
        String dbInstanceId = "my-db-instance";
        
        // ok: java-polling-to-waiters
        AmazonRDSWaiters waiters = rdsClient.waiters();
        waiters.dBInstanceAvailable().run(
            new WaiterParameters<>(new DescribeDBInstancesRequest().withDBInstanceIdentifier(dbInstanceId))
        );
        System.out.println("Database instance is available!");
    }

    public void good_case_5() {
        AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard().build();
        String instanceId = "i-0abcdef1234567890";
        
        // ok: java-polling-to-waiters
        AmazonEC2Waiters waiters = ec2Client.waiters();
        waiters.instanceStopped().run(
            new WaiterParameters<>(new DescribeInstancesRequest().withInstanceIds(instanceId))
        );
        System.out.println("Instance has stopped!");
    }

    public void good_case_6() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "new-bucket-creation";
        
        // Create the bucket
        s3Client.createBucket(bucketName);
        
        // ok: java-polling-to-waiters
        AmazonS3Waiters waiters = s3Client.waiters();
        waiters.bucketExists().run(
            new WaiterParameters<>(new com.amazonaws.services.s3.model.HeadBucketRequest(bucketName))
        );
        System.out.println("Bucket exists and is accessible!");
    }

    public void good_case_7() {
        AmazonDynamoDB dynamoDbClient = AmazonDynamoDBClientBuilder.standard().build();
        String tableName = "users-table";
        
        // Delete the table
        dynamoDbClient.deleteTable(tableName);
        
        // ok: java-polling-to-waiters
        AmazonDynamoDBWaiters waiters = AmazonDynamoDBWaiters.using(dynamoDbClient);
        waiters.tableNotExists().run(
            new WaiterParameters<>(new DescribeTableRequest().withTableName(tableName))
        );
        System.out.println("Table has been deleted!");
    }

    public void good_case_8() {
        AmazonRDS rdsClient = AmazonRDSClientBuilder.standard().build();
        String dbSnapshotId = "my-db-snapshot";
        
        // ok: java-polling-to-waiters
        AmazonRDSWaiters waiters = rdsClient.waiters();
        waiters.dBSnapshotAvailable().run(
            new WaiterParameters<>(
                new com.amazonaws.services.rds.model.DescribeDBSnapshotsRequest()
                    .withDBSnapshotIdentifier(dbSnapshotId)
            )
        );
        System.out.println("DB Snapshot is available!");
    }

    public void good_case_9() {
        AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard().build();
        String volumeId = "vol-0abcdef1234567890";
        
        // ok: java-polling-to-waiters
        AmazonEC2Waiters waiters = ec2Client.waiters();
        waiters.volumeAvailable().run(
            new WaiterParameters<>(
                new com.amazonaws.services.ec2.model.DescribeVolumesRequest()
                    .withVolumeIds(volumeId)
            )
        );
        System.out.println("Volume is available!");
    }

    public void good_case_10() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String sourceBucket = "source-bucket";
        String sourceKey = "large-file.zip";
        String destBucket = "destination-bucket";
        String destKey = "copied-large-file.zip";
        
        s3Client.copyObject(sourceBucket, sourceKey, destBucket, destKey);
        
        // ok: java-polling-to-waiters
        AmazonS3Waiters waiters = s3Client.waiters();
        waiters.objectExists().run(
            new WaiterParameters<>(new GetObjectRequest(destBucket, destKey))
        );
        System.out.println("Copy operation completed!");
    }

    public void good_case_11() {
        AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard().build();
        String instanceId = "i-0abcdef1234567890";
        
        // ok: java-polling-to-waiters
        AmazonEC2Waiters waiters = ec2Client.waiters();
        waiters.instanceStatusOk().run(
            new WaiterParameters<>(
                new com.amazonaws.services.ec2.model.DescribeInstanceStatusRequest()
                    .withInstanceIds(instanceId)
            )
        );
        System.out.println("Instance status checks are OK!");
    }

    public void good_case_12() {
        AmazonRDS rdsClient = AmazonRDSClientBuilder.standard().build();
        String dbClusterId = "my-aurora-cluster";
        
        // ok: java-polling-to-waiters
        AmazonRDSWaiters waiters = rdsClient.waiters();
        waiters.dBClusterAvailable().run(
            new WaiterParameters<>(
                new com.amazonaws.services.rds.model.DescribeDBClustersRequest()
                    .withDBClusterIdentifier(dbClusterId)
            )
        );
        System.out.println("DB Cluster is available!");
    }

    public void good_case_13() {
        AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard().build();
        String snapshotId = "snap-0abcdef1234567890";
        
        // ok: java-polling-to-waiters
        AmazonEC2Waiters waiters = ec2Client.waiters();
        waiters.snapshotCompleted().run(
            new WaiterParameters<>(
                new com.amazonaws.services.ec2.model.DescribeSnapshotsRequest()
                    .withSnapshotIds(snapshotId)
            )
        );
        System.out.println("Snapshot is completed!");
    }

    public void good_case_14() {
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard().build();
        String bucketName = "my-bucket";
        
        // ok: java-polling-to-waiters
        AmazonS3Waiters waiters = s3Client.waiters();
        waiters.bucketNotExists().run(
            new WaiterParameters<>(new com.amazonaws.services.s3.model.HeadBucketRequest(bucketName))
        );
        System.out.println("Bucket no longer exists!");
    }

    public void good_case_15() {
        AmazonEC2 ec2Client = AmazonEC2ClientBuilder.standard().build();
        String instanceId = "i-0abcdef1234567890";
        
        // ok: java-polling-to-waiters
        AmazonEC2Waiters waiters = ec2Client.waiters();
        waiters.instanceTerminated().run(
            new WaiterParameters<>(new DescribeInstancesRequest().withInstanceIds(instanceId))
        );
        System.out.println("Instance has been terminated!");
    }
}
// {/fact}