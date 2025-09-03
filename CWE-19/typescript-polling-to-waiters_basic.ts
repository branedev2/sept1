import * as AWS from 'aws-sdk';
import { sleep } from 'some-sleep-library';

// True Positive Examples (Bad Cases)

// Custom polling implementation for checking if an EC2 instance is running
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_1() {
  const ec2 = new AWS.EC2();
  const instanceId = 'i-1234567890abcdef0';
  
  // Custom polling implementation
  const checkInstanceStatus = async () => {
    // ruleid: typescript-polling-to-waiters
    let isRunning = false;
    while (!isRunning) {
      const data = await ec2.describeInstances({ InstanceIds: [instanceId] }).promise();
      const state = data.Reservations[0].Instances[0].State.Name;
      if (state === 'running') {
        isRunning = true;
      } else {
        await sleep(5000); // Wait for 5 seconds before checking again
      }
    }
    console.log('Instance is now running');
  };
  
  checkInstanceStatus();
}
// {/fact}

// Custom polling for S3 bucket existence
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_2() {
  const s3 = new AWS.S3();
  const bucketName = 'my-new-bucket';
  
  const checkBucketExists = async () => {
    let bucketExists = false;
    let attempts = 0;
    
    // ruleid: typescript-polling-to-waiters
    while (!bucketExists && attempts < 10) {
      try {
        await s3.headBucket({ Bucket: bucketName }).promise();
        bucketExists = true;
      } catch (error) {
        attempts++;
        await new Promise(resolve => setTimeout(resolve, 3000));
      }
    }
    
    if (bucketExists) {
      console.log('Bucket is ready to use');
    } else {
      console.log('Bucket creation timed out');
    }
  };
  
  checkBucketExists();
}
// {/fact}

// Custom polling for DynamoDB table status
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_3() {
  const dynamodb = new AWS.DynamoDB();
  const tableName = 'Users';
  
  const waitForTableActive = async () => {
    let tableActive = false;
    
    // ruleid: typescript-polling-to-waiters
    while (!tableActive) {
      const response = await dynamodb.describeTable({ TableName: tableName }).promise();
      if (response.Table.TableStatus === 'ACTIVE') {
        tableActive = true;
      } else {
        console.log('Table is still being created. Waiting...');
        await sleep(10000);
      }
    }
    
    console.log('Table is now active');
  };
  
  waitForTableActive();
}
// {/fact}

// Custom polling for Lambda function creation
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_4() {
  const lambda = new AWS.Lambda();
  const functionName = 'processData';
  
  const checkFunctionExists = async () => {
    let exists = false;
    let retries = 0;
    
    // ruleid: typescript-polling-to-waiters
    do {
      try {
        await lambda.getFunction({ FunctionName: functionName }).promise();
        exists = true;
      } catch (error) {
        retries++;
        await new Promise(r => setTimeout(r, 2000));
      }
    } while (!exists && retries < 15);
    
    if (exists) {
      console.log('Lambda function is ready');
    } else {
      throw new Error('Lambda function creation failed');
    }
  };
  
  checkFunctionExists();
}
// {/fact}

// Custom polling for ECS task status
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_5() {
  const ecs = new AWS.ECS();
  const cluster = 'production';
  const taskId = 'arn:aws:ecs:us-west-2:123456789012:task/default/1234567890abcdef0';
  
  const waitForTaskStopped = async () => {
    // ruleid: typescript-polling-to-waiters
    let isStopped = false;
    
    while (!isStopped) {
      const response = await ecs.describeTasks({
        cluster: cluster,
        tasks: [taskId]
      }).promise();
      
      if (response.tasks[0].lastStatus === 'STOPPED') {
        isStopped = true;
      } else {
        await sleep(5000);
      }
    }
    
    console.log('Task has stopped');
  };
  
  waitForTaskStopped();
}
// {/fact}

// Custom polling for CloudFormation stack creation
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_6() {
  const cloudformation = new AWS.CloudFormation();
  const stackName = 'NetworkStack';
  
  const monitorStackCreation = async () => {
    let stackCreated = false;
    let stackFailed = false;
    
    // ruleid: typescript-polling-to-waiters
    while (!stackCreated && !stackFailed) {
      const response = await cloudformation.describeStacks({
        StackName: stackName
      }).promise();
      
      const status = response.Stacks[0].StackStatus;
      
      if (status === 'CREATE_COMPLETE') {
        stackCreated = true;
      } else if (status.includes('FAILED') || status.includes('ROLLBACK')) {
        stackFailed = true;
      } else {
        console.log(`Stack status: ${status}`);
        await new Promise(resolve => setTimeout(resolve, 10000));
      }
    }
    
    if (stackCreated) {
      console.log('Stack created successfully');
    } else {
      console.log('Stack creation failed');
    }
  };
  
  monitorStackCreation();
}
// {/fact}

// Custom polling for RDS instance availability
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_7() {
  const rds = new AWS.RDS();
  const dbInstanceId = 'production-db';
  
  const waitForDbAvailable = async () => {
    // ruleid: typescript-polling-to-waiters
    let isAvailable = false;
    
    while (!isAvailable) {
      const response = await rds.describeDBInstances({
        DBInstanceIdentifier: dbInstanceId
      }).promise();
      
      if (response.DBInstances[0].DBInstanceStatus === 'available') {
        isAvailable = true;
      } else {
        console.log('Database is still initializing...');
        await sleep(30000);
      }
    }
    
    console.log('Database is now available');
  };
  
  waitForDbAvailable();
}
// {/fact}

// Custom polling for SQS queue existence
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_8() {
  const sqs = new AWS.SQS();
  const queueName = 'processing-queue';
  
  const checkQueueExists = async () => {
    let queueUrl: string | null = null;
    let attempts = 0;
    
    // ruleid: typescript-polling-to-waiters
    while (!queueUrl && attempts < 5) {
      try {
        const response = await sqs.getQueueUrl({
          QueueName: queueName
        }).promise();
        
        queueUrl = response.QueueUrl;
      } catch (error) {
        attempts++;
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }
    
    if (queueUrl) {
      console.log(`Queue URL: ${queueUrl}`);
    } else {
      console.log('Queue does not exist');
    }
  };
  
  checkQueueExists();
}
// {/fact}

// Custom polling for Step Functions execution completion
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_9() {
  const stepfunctions = new AWS.StepFunctions();
  const executionArn = 'arn:aws:states:us-west-2:123456789012:execution:MyStateMachine:execution1';
  
  const waitForExecutionCompletion = async () => {
    // ruleid: typescript-polling-to-waiters
    let isComplete = false;
    
    while (!isComplete) {
      const response = await stepfunctions.describeExecution({
        executionArn: executionArn
      }).promise();
      
      if (['SUCCEEDED', 'FAILED', 'TIMED_OUT', 'ABORTED'].includes(response.status)) {
        isComplete = true;
      } else {
        await sleep(5000);
      }
    }
    
    console.log('Step Functions execution completed');
  };
  
  waitForExecutionCompletion();
}
// {/fact}

// Custom polling for SNS topic creation
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_10() {
  const sns = new AWS.SNS();
  const topicName = 'alerts';
  
  const checkTopicExists = async () => {
    let topicArn: string | null = null;
    let retries = 0;
    
    // ruleid: typescript-polling-to-waiters
    do {
      const response = await sns.listTopics().promise();
      
      const matchingTopic = response.Topics.find(topic => 
        topic.TopicArn.split(':').pop() === topicName
      );
      
      if (matchingTopic) {
        topicArn = matchingTopic.TopicArn;
      } else {
        retries++;
        await new Promise(r => setTimeout(r, 1000));
      }
    } while (!topicArn && retries < 10);
    
    if (topicArn) {
      console.log(`Topic ARN: ${topicArn}`);
    } else {
      console.log('Topic not found');
    }
  };
  
  checkTopicExists();
}
// {/fact}

// Custom polling for Batch job completion
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_11() {
  const batch = new AWS.Batch();
  const jobId = '76cb3c66-1a00-4700-98e5-example';
  
  const monitorJobStatus = async () => {
    // ruleid: typescript-polling-to-waiters
    let jobComplete = false;
    
    while (!jobComplete) {
      const response = await batch.describeJobs({
        jobs: [jobId]
      }).promise();
      
      const status = response.jobs[0].status;
      
      if (['SUCCEEDED', 'FAILED'].includes(status)) {
        jobComplete = true;
      } else {
        console.log(`Job status: ${status}`);
        await sleep(10000);
      }
    }
    
    console.log('Batch job processing completed');
  };
  
  monitorJobStatus();
}
// {/fact}

// Custom polling for CodeBuild project completion
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_12() {
  const codebuild = new AWS.CodeBuild();
  const buildId = 'demo-project:12345678-1234-1234-1234-123456789012';
  
  const waitForBuildCompletion = async () => {
    // ruleid: typescript-polling-to-waiters
    let buildFinished = false;
    
    while (!buildFinished) {
      const response = await codebuild.batchGetBuilds({
        ids: [buildId]
      }).promise();
      
      const buildStatus = response.builds[0].buildStatus;
      
      if (['SUCCEEDED', 'FAILED', 'STOPPED'].includes(buildStatus)) {
        buildFinished = true;
      } else {
        console.log(`Build status: ${buildStatus}`);
        await new Promise(resolve => setTimeout(resolve, 30000));
      }
    }
    
    console.log('Build has completed');
  };
  
  waitForBuildCompletion();
}
// {/fact}

// Custom polling for Glue job run completion
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_13() {
  const glue = new AWS.Glue();
  const jobName = 'data-transformation';
  const runId = 'jr_1234567890abcdef0';
  
  const checkJobRunStatus = async () => {
    // ruleid: typescript-polling-to-waiters
    let isComplete = false;
    
    while (!isComplete) {
      const response = await glue.getJobRun({
        JobName: jobName,
        RunId: runId
      }).promise();
      
      const state = response.JobRun.JobRunState;
      
      if (['SUCCEEDED', 'FAILED', 'STOPPED', 'TIMEOUT'].includes(state)) {
        isComplete = true;
      } else {
        console.log(`Job run state: ${state}`);
        await sleep(15000);
      }
    }
    
    console.log('Glue job run completed');
  };
  
  checkJobRunStatus();
}
// {/fact}

// Custom polling for EKS cluster creation
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_14() {
  const eks = new AWS.EKS();
  const clusterName = 'production-cluster';
  
  const waitForClusterActive = async () => {
    // ruleid: typescript-polling-to-waiters
    let isActive = false;
    let attempts = 0;
    
    while (!isActive && attempts < 30) {
      try {
        const response = await eks.describeCluster({
          name: clusterName
        }).promise();
        
        if (response.cluster.status === 'ACTIVE') {
          isActive = true;
        } else {
          attempts++;
          console.log(`Cluster status: ${response.cluster.status}`);
          await new Promise(resolve => setTimeout(resolve, 60000));
        }
      } catch (error) {
        attempts++;
        await new Promise(resolve => setTimeout(resolve, 60000));
      }
    }
    
    if (isActive) {
      console.log('EKS cluster is now active');
    } else {
      console.log('Timed out waiting for cluster to become active');
    }
  };
  
  waitForClusterActive();
}
// {/fact}

// Custom polling for Elastic Beanstalk environment health
// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_15() {
  const elasticbeanstalk = new AWS.ElasticBeanstalk();
  const environmentName = 'production';
  
  const waitForEnvironmentHealth = async () => {
    // ruleid: typescript-polling-to-waiters
    let isHealthy = false;
    
    while (!isHealthy) {
      const response = await elasticbeanstalk.describeEnvironmentHealth({
        EnvironmentName: environmentName,
        AttributeNames: ['HealthStatus']
      }).promise();
      
      if (response.HealthStatus === 'Ok') {
        isHealthy = true;
      } else {
        console.log(`Environment health: ${response.HealthStatus}`);
        await sleep(30000);
      }
    }
    
    console.log('Environment is now healthy');
  };
  
  waitForEnvironmentHealth();
}
// {/fact}

// True Negative Examples (Good Cases)

// Using EC2 waiters properly
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_1() {
  const ec2 = new AWS.EC2();
  const instanceId = 'i-1234567890abcdef0';
  
  const checkInstanceStatus = async () => {
    // ok: typescript-polling-to-waiters
    const waiter = ec2.waitFor('instanceRunning', {
      InstanceIds: [instanceId]
    });
    
    try {
      await waiter.promise();
      console.log('Instance is now running');
    } catch (error) {
      console.error('Error waiting for instance to run:', error);
    }
  };
  
  checkInstanceStatus();
}
// {/fact}

// Using S3 waiters properly
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_2() {
  const s3 = new AWS.S3();
  const bucketName = 'my-new-bucket';
  
  const checkBucketExists = async () => {
    // ok: typescript-polling-to-waiters
    const waiter = s3.waitFor('bucketExists', {
      Bucket: bucketName,
      $waiter: {
        delay: 5,
        maxAttempts: 10
      }
    });
    
    try {
      await waiter.promise();
      console.log('Bucket is ready to use');
    } catch (error) {
      console.log('Bucket creation timed out');
    }
  };
  
  checkBucketExists();
}
// {/fact}

// Using DynamoDB waiters properly
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_3() {
  const dynamodb = new AWS.DynamoDB();
  const tableName = 'Users';
  
  const waitForTableActive = async () => {
    // ok: typescript-polling-to-waiters
    const waiter = dynamodb.waitFor('tableExists', {
      TableName: tableName
    });
    
    try {
      await waiter.promise();
      console.log('Table is now active');
    } catch (error) {
      console.error('Error waiting for table to become active:', error);
    }
  };
  
  waitForTableActive();
}
// {/fact}

// Using CloudFormation waiters properly
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_4() {
  const cloudformation = new AWS.CloudFormation();
  const stackName = 'NetworkStack';
  
  const monitorStackCreation = async () => {
    // ok: typescript-polling-to-waiters
    const waiter = cloudformation.waitFor('stackCreateComplete', {
      StackName: stackName
    });
    
    try {
      await waiter.promise();
      console.log('Stack created successfully');
    } catch (error) {
      console.log('Stack creation failed');
    }
  };
  
  monitorStackCreation();
}
// {/fact}

// Using RDS waiters properly
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_5() {
  const rds = new AWS.RDS();
  const dbInstanceId = 'production-db';
  
  const waitForDbAvailable = async () => {
    // ok: typescript-polling-to-waiters
    const waiter = rds.waitFor('dBInstanceAvailable', {
      DBInstanceIdentifier: dbInstanceId
    });
    
    try {
      await waiter.promise();
      console.log('Database is now available');
    } catch (error) {
      console.error('Error waiting for database to become available:', error);
    }
  };
  
  waitForDbAvailable();
}
// {/fact}

// Using ECS waiters properly
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_6() {
  const ecs = new AWS.ECS();
  const cluster = 'production';
  const taskId = 'arn:aws:ecs:us-west-2:123456789012:task/default/1234567890abcdef0';
  
  const waitForTaskStopped = async () => {
    // ok: typescript-polling-to-waiters
    const waiter = ecs.waitFor('tasksStoppedAll', {
      cluster: cluster,
      tasks: [taskId]
    });
    
    try {
      await waiter.promise();
      console.log('Task has stopped');
    } catch (error) {
      console.error('Error waiting for task to stop:', error);
    }
  };
  
  waitForTaskStopped();
}
// {/fact}

// Using custom waiter with AWS SDK v3
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_7() {
  import { EC2Client, DescribeInstancesCommand, waitUntilInstanceRunning } from "@aws-sdk/client-ec2";
  
  const waitForInstanceRunning = async () => {
    const client = new EC2Client({ region: "us-west-2" });
    const instanceId = 'i-1234567890abcdef0';
    
    try {
      // ok: typescript-polling-to-waiters
      await waitUntilInstanceRunning(
        {
          client,
          maxWaitTime: 300,
          minDelay: 5,
          maxDelay: 10
        }, 
        { InstanceIds: [instanceId] }
      );
      console.log('Instance is now running');
    } catch (error) {
      console.error('Error waiting for instance to run:', error);
    }
  };
  
  waitForInstanceRunning();
}
// {/fact}

// Using Lambda waiters properly
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_8() {
  const lambda = new AWS.Lambda();
  const functionName = 'processData';
  
  const checkFunctionExists = async () => {
    // ok: typescript-polling-to-waiters
    const waiter = lambda.waitFor('functionExists', {
      FunctionName: functionName,
      $waiter: {
        delay: 2,
        maxAttempts: 15
      }
    });
    
    try {
      await waiter.promise();
      console.log('Lambda function is ready');
    } catch (error) {
      throw new Error('Lambda function creation failed');
    }
  };
  
  checkFunctionExists();
}
// {/fact}

// Using AWS SDK v3 waiters for S3
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_9() {
  import { S3Client, HeadBucketCommand, waitUntilBucketExists } from "@aws-sdk/client-s3";
  
  const waitForBucket = async () => {
    const client = new S3Client({ region: "us-east-1" });
    const bucketName = 'my-new-bucket';
    
    try {
      // ok: typescript-polling-to-waiters
      await waitUntilBucketExists(
        {
          client,
          maxWaitTime: 60
        },
        { Bucket: bucketName }
      );
      console.log('Bucket is now available');
    } catch (error) {
      console.error('Error waiting for bucket to exist:', error);
    }
  };
  
  waitForBucket();
}
// {/fact}

// Using AWS SDK v3 waiters for DynamoDB
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_10() {
  import { DynamoDBClient, DescribeTableCommand, waitUntilTableExists } from "@aws-sdk/client-dynamodb";
  
  const waitForTable = async () => {
    const client = new DynamoDBClient({ region: "us-west-2" });
    const tableName = 'Users';
    
    try {
      // ok: typescript-polling-to-waiters
      await waitUntilTableExists(
        {
          client,
          maxWaitTime: 300
        },
        { TableName: tableName }
      );
      console.log('Table is now active');
    } catch (error) {
      console.error('Error waiting for table to become active:', error);
    }
  };
  
  waitForTable();
}
// {/fact}

// Using CloudFormation waiters with custom configuration
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_11() {
  const cloudformation = new AWS.CloudFormation();
  const stackName = 'NetworkStack';
  
  const monitorStackCreation = async () => {
    // ok: typescript-polling-to-waiters
    const waiter = cloudformation.waitFor('stackCreateComplete', {
      StackName: stackName,
      $waiter: {
        delay: 15,
        maxAttempts: 40
      }
    });
    
    try {
      await waiter.promise();
      console.log('Stack created successfully');
    } catch (error) {
      console.log('Stack creation failed or timed out');
    }
  };
  
  monitorStackCreation();
}
// {/fact}

// Using AWS SDK v3 waiters for ECS
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_12() {
  import { ECSClient, DescribeTasksCommand, waitUntilTasksStopped } from "@aws-sdk/client-ecs";
  
  const waitForTaskToStop = async () => {
    const client = new ECSClient({ region: "us-east-1" });
    const cluster = 'production';
    const taskId = 'arn:aws:ecs:us-east-1:123456789012:task/default/1234567890abcdef0';
    
    try {
      // ok: typescript-polling-to-waiters
      await waitUntilTasksStopped(
        {
          client,
          maxWaitTime: 120
        },
        {
          cluster: cluster,
          tasks: [taskId]
        }
      );
      console.log('Task has stopped');
    } catch (error) {
      console.error('Error waiting for task to stop:', error);
    }
  };
  
  waitForTaskToStop();
}
// {/fact}

// Using AWS SDK v3 waiters for RDS
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_13() {
  import { RDSClient, DescribeDBInstancesCommand, waitUntilDBInstanceAvailable } from "@aws-sdk/client-rds";
  
  const waitForDatabase = async () => {
    const client = new RDSClient({ region: "us-west-2" });
    const dbInstanceId = 'production-db';
    
    try {
      // ok: typescript-polling-to-waiters
      await waitUntilDBInstanceAvailable(
        {
          client,
          maxWaitTime: 600,
          minDelay: 30,
          maxDelay: 60
        },
        { DBInstanceIdentifier: dbInstanceId }
      );
      console.log('Database is now available');
    } catch (error) {
      console.error('Error waiting for database to become available:', error);
    }
  };
  
  waitForDatabase();
}
// {/fact}

// Using AWS SDK v2 waiters with callback pattern
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_14() {
  const ec2 = new AWS.EC2();
  const instanceId = 'i-1234567890abcdef0';
  
  const checkInstanceStatus = () => {
    // ok: typescript-polling-to-waiters
    ec2.waitFor('instanceRunning', {
      InstanceIds: [instanceId]
    }, (err, data) => {
      if (err) {
        console.error('Error waiting for instance to run:', err);
      } else {
        console.log('Instance is now running');
      }
    });
  };
  
  checkInstanceStatus();
}
// {/fact}

// Using AWS SDK v3 waiters for CloudFormation
// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_15() {
  import { CloudFormationClient, DescribeStacksCommand, waitUntilStackCreateComplete } from "@aws-sdk/client-cloudformation";
  
  const waitForStackCreation = async () => {
    const client = new CloudFormationClient({ region: "us-east-1" });
    const stackName = 'NetworkStack';
    
    try {
      // ok: typescript-polling-to-waiters
      await waitUntilStackCreateComplete(
        {
          client,
          maxWaitTime: 900
        },
        { StackName: stackName }
      );
      console.log('Stack created successfully');
    } catch (error) {
      console.log('Stack creation failed or timed out');
    }
  };
  
  waitForStackCreation();
}
// {/fact}