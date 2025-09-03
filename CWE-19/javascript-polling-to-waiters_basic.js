const AWS = require('aws-sdk');
const axios = require('axios');

// True Positive Examples (Custom Polling)

// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_1() {
  const ec2 = new AWS.EC2();
  const instanceId = 'i-1234567890abcdef0';
  
  // Custom polling for instance state
  function checkInstanceState() {
    // ruleid: javascript-polling-to-waiters
    return ec2.describeInstances({ InstanceIds: [instanceId] }).promise()
      .then(data => {
        const state = data.Reservations[0].Instances[0].State.Name;
        if (state === 'running') {
          console.log('Instance is running');
          return true;
        } else {
          console.log('Instance is still starting, waiting...');
          return new Promise(resolve => setTimeout(() => resolve(checkInstanceState()), 5000));
        }
      });
  }
  
  return checkInstanceState();
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_2() {
  const s3 = new AWS.S3();
  const bucketName = 'my-test-bucket';
  
  // Custom polling for bucket existence
  function checkBucketExists() {
    // ruleid: javascript-polling-to-waiters
    return s3.headBucket({ Bucket: bucketName }).promise()
      .then(() => {
        console.log('Bucket exists');
        return true;
      })
      .catch(err => {
        if (err.statusCode === 404) {
          console.log('Bucket does not exist yet, waiting...');
          return new Promise(resolve => setTimeout(() => resolve(checkBucketExists()), 3000));
        }
        throw err;
      });
  }
  
  return checkBucketExists();
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_3() {
  const dynamodb = new AWS.DynamoDB();
  const tableName = 'Users';
  
  let attempts = 0;
  const maxAttempts = 20;
  
  // Custom polling for table status
  function checkTableStatus() {
    // ruleid: javascript-polling-to-waiters
    return dynamodb.describeTable({ TableName: tableName }).promise()
      .then(data => {
        if (data.Table.TableStatus === 'ACTIVE') {
          console.log('Table is active');
          return data.Table;
        } else {
          attempts++;
          if (attempts >= maxAttempts) {
            throw new Error('Max attempts reached waiting for table to be active');
          }
          console.log(`Table status: ${data.Table.TableStatus}, waiting...`);
          return new Promise(resolve => setTimeout(() => resolve(checkTableStatus()), 2000));
        }
      });
  }
  
  return checkTableStatus();
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_4() {
  const lambda = new AWS.Lambda();
  const functionName = 'processData';
  
  // Custom polling for Lambda function state
  function checkFunctionState() {
    // ruleid: javascript-polling-to-waiters
    return lambda.getFunction({ FunctionName: functionName }).promise()
      .then(data => {
        if (data.Configuration.State === 'Active') {
          console.log('Function is active');
          return data.Configuration;
        } else {
          console.log(`Function state: ${data.Configuration.State}, waiting...`);
          return new Promise(resolve => setTimeout(() => resolve(checkFunctionState()), 2500));
        }
      })
      .catch(err => {
        if (err.statusCode === 404) {
          console.log('Function not found, waiting...');
          return new Promise(resolve => setTimeout(() => resolve(checkFunctionState()), 2500));
        }
        throw err;
      });
  }
  
  return checkFunctionState();
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_5() {
  const cloudformation = new AWS.CloudFormation();
  const stackName = 'NetworkStack';
  
  // Custom polling for stack status
  function checkStackStatus() {
    // ruleid: javascript-polling-to-waiters
    return cloudformation.describeStacks({ StackName: stackName }).promise()
      .then(data => {
        const status = data.Stacks[0].StackStatus;
        if (status === 'CREATE_COMPLETE') {
          console.log('Stack creation complete');
          return data.Stacks[0];
        } else if (status.includes('FAILED') || status.includes('ROLLBACK')) {
          throw new Error(`Stack creation failed with status: ${status}`);
        } else {
          console.log(`Stack status: ${status}, waiting...`);
          return new Promise(resolve => setTimeout(() => resolve(checkStackStatus()), 10000));
        }
      });
  }
  
  return checkStackStatus();
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_6() {
  const ecs = new AWS.ECS();
  const cluster = 'production';
  const service = 'web-app';
  
  // Custom polling for ECS service stability
  function checkServiceStability() {
    // ruleid: javascript-polling-to-waiters
    return ecs.describeServices({
      cluster: cluster,
      services: [service]
    }).promise()
      .then(data => {
        const serviceData = data.services[0];
        if (serviceData.runningCount === serviceData.desiredCount) {
          console.log('Service is stable');
          return serviceData;
        } else {
          console.log(`Service not stable yet. Running: ${serviceData.runningCount}, Desired: ${serviceData.desiredCount}`);
          return new Promise(resolve => setTimeout(() => resolve(checkServiceStability()), 5000));
        }
      });
  }
  
  return checkServiceStability();
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_7() {
  const rds = new AWS.RDS();
  const dbInstanceId = 'production-db';
  
  // Custom polling for RDS instance availability
  function checkDbStatus() {
    // ruleid: javascript-polling-to-waiters
    return rds.describeDBInstances({ DBInstanceIdentifier: dbInstanceId }).promise()
      .then(data => {
        const status = data.DBInstances[0].DBInstanceStatus;
        if (status === 'available') {
          console.log('Database is available');
          return data.DBInstances[0];
        } else {
          console.log(`Database status: ${status}, waiting...`);
          return new Promise(resolve => setTimeout(() => resolve(checkDbStatus()), 15000));
        }
      });
  }
  
  return checkDbStatus();
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_8() {
  const sqs = new AWS.SQS();
  const queueUrl = 'https://sqs.us-east-1.amazonaws.com/123456789012/myQueue';
  
  // Custom polling for message availability
  function pollForMessages(maxAttempts = 10) {
    let attempts = 0;
    
    function checkForMessages() {
      // ruleid: javascript-polling-to-waiters
      return sqs.receiveMessage({
        QueueUrl: queueUrl,
        MaxNumberOfMessages: 1,
        WaitTimeSeconds: 1
      }).promise()
        .then(data => {
          if (data.Messages && data.Messages.length > 0) {
            console.log('Message received');
            return data.Messages[0];
          } else {
            attempts++;
            if (attempts >= maxAttempts) {
              throw new Error('No messages found after maximum attempts');
            }
            console.log('No messages yet, polling again...');
            return new Promise(resolve => setTimeout(() => resolve(checkForMessages()), 2000));
          }
        });
    }
    
    return checkForMessages();
  }
  
  return pollForMessages();
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_9() {
  const sns = new AWS.SNS();
  const topicArn = 'arn:aws:sns:us-east-1:123456789012:my-topic';
  const subscriptionArn = 'arn:aws:sns:us-east-1:123456789012:my-topic:subscription-id';
  
  // Custom polling for subscription confirmation
  function checkSubscriptionStatus() {
    // ruleid: javascript-polling-to-waiters
    return sns.listSubscriptionsByTopic({ TopicArn: topicArn }).promise()
      .then(data => {
        const subscription = data.Subscriptions.find(sub => sub.SubscriptionArn === subscriptionArn);
        if (subscription && subscription.SubscriptionArn !== 'PendingConfirmation') {
          console.log('Subscription is confirmed');
          return subscription;
        } else {
          console.log('Subscription still pending, waiting...');
          return new Promise(resolve => setTimeout(() => resolve(checkSubscriptionStatus()), 5000));
        }
      });
  }
  
  return checkSubscriptionStatus();
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_10() {
  const cloudfront = new AWS.CloudFront();
  const distributionId = 'E1EXAMPLE';
  
  // Custom polling for CloudFront distribution deployment
  function checkDistributionStatus() {
    // ruleid: javascript-polling-to-waiters
    return cloudfront.getDistribution({ Id: distributionId }).promise()
      .then(data => {
        if (data.Distribution.Status === 'Deployed') {
          console.log('Distribution is deployed');
          return data.Distribution;
        } else {
          console.log('Distribution still deploying, waiting...');
          return new Promise(resolve => setTimeout(() => resolve(checkDistributionStatus()), 20000));
        }
      });
  }
  
  return checkDistributionStatus();
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_11() {
  const apigateway = new AWS.APIGateway();
  const restApiId = 'abc123';
  const stageName = 'prod';
  
  // Custom polling for API deployment
  function checkDeploymentStatus() {
    // ruleid: javascript-polling-to-waiters
    return apigateway.getStage({
      restApiId: restApiId,
      stageName: stageName
    }).promise()
      .then(data => {
        if (data.deploymentId) {
          console.log('API is deployed');
          return data;
        } else {
          console.log('API not yet deployed, waiting...');
          return new Promise(resolve => setTimeout(() => resolve(checkDeploymentStatus()), 5000));
        }
      });
  }
  
  return checkDeploymentStatus();
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_12() {
  const stepfunctions = new AWS.StepFunctions();
  const executionArn = 'arn:aws:states:us-east-1:123456789012:execution:MyStateMachine:execution-id';
  
  // Custom polling for Step Functions execution status
  function checkExecutionStatus() {
    // ruleid: javascript-polling-to-waiters
    return stepfunctions.describeExecution({ executionArn }).promise()
      .then(data => {
        if (data.status === 'SUCCEEDED') {
          console.log('Execution succeeded');
          return data;
        } else if (data.status === 'FAILED' || data.status === 'TIMED_OUT' || data.status === 'ABORTED') {
          throw new Error(`Execution failed with status: ${data.status}`);
        } else {
          console.log(`Execution status: ${data.status}, waiting...`);
          return new Promise(resolve => setTimeout(() => resolve(checkExecutionStatus()), 3000));
        }
      });
  }
  
  return checkExecutionStatus();
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_13() {
  const batch = new AWS.Batch();
  const jobId = 'job-12345';
  
  // Custom polling for Batch job completion
  function checkJobStatus() {
    // ruleid: javascript-polling-to-waiters
    return batch.describeJobs({ jobs: [jobId] }).promise()
      .then(data => {
        const job = data.jobs[0];
        if (job.status === 'SUCCEEDED') {
          console.log('Job completed successfully');
          return job;
        } else if (job.status === 'FAILED') {
          throw new Error(`Job failed: ${job.statusReason}`);
        } else {
          console.log(`Job status: ${job.status}, waiting...`);
          return new Promise(resolve => setTimeout(() => resolve(checkJobStatus()), 10000));
        }
      });
  }
  
  return checkJobStatus();
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_14() {
  const codebuild = new AWS.CodeBuild();
  const buildId = 'my-project:build-id';
  
  // Custom polling for CodeBuild build completion
  function checkBuildStatus() {
    // ruleid: javascript-polling-to-waiters
    return codebuild.batchGetBuilds({ ids: [buildId] }).promise()
      .then(data => {
        const build = data.builds[0];
        if (build.buildComplete) {
          if (build.buildStatus === 'SUCCEEDED') {
            console.log('Build succeeded');
            return build;
          } else {
            throw new Error(`Build failed with status: ${build.buildStatus}`);
          }
        } else {
          console.log(`Build in progress, phase: ${build.currentPhase}, waiting...`);
          return new Promise(resolve => setTimeout(() => resolve(checkBuildStatus()), 30000));
        }
      });
  }
  
  return checkBuildStatus();
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
function bad_case_15() {
  const emr = new AWS.EMR();
  const clusterId = 'j-2AXXXXXXGAPLF';
  
  // Custom polling for EMR cluster state
  function checkClusterState() {
    // ruleid: javascript-polling-to-waiters
    return emr.describeCluster({ ClusterId: clusterId }).promise()
      .then(data => {
        const state = data.Cluster.Status.State;
        if (state === 'RUNNING') {
          console.log('Cluster is running');
          return data.Cluster;
        } else if (state === 'WAITING') {
          console.log('Cluster is waiting');
          return data.Cluster;
        } else if (state === 'TERMINATED' || state === 'TERMINATED_WITH_ERRORS') {
          throw new Error(`Cluster terminated with state: ${state}`);
        } else {
          console.log(`Cluster state: ${state}, waiting...`);
          return new Promise(resolve => setTimeout(() => resolve(checkClusterState()), 60000));
        }
      });
  }
  
  return checkClusterState();
}
// {/fact}

// True Negative Examples (Using AWS Waiters)

// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_1() {
  const ec2 = new AWS.EC2();
  const instanceId = 'i-1234567890abcdef0';
  
  // Using EC2 instance running waiter
  // ok: javascript-polling-to-waiters
  return ec2.waitFor('instanceRunning', {
    InstanceIds: [instanceId]
  }).promise()
    .then(data => {
      console.log('Instance is running');
      return data;
    });
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_2() {
  const s3 = new AWS.S3();
  const bucketName = 'my-test-bucket';
  
  // Using S3 bucket exists waiter
  // ok: javascript-polling-to-waiters
  return s3.waitFor('bucketExists', {
    Bucket: bucketName
  }).promise()
    .then(() => {
      console.log('Bucket exists');
      return true;
    });
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_3() {
  const dynamodb = new AWS.DynamoDB();
  const tableName = 'Users';
  
  // Using DynamoDB table exists waiter
  // ok: javascript-polling-to-waiters
  return dynamodb.waitFor('tableExists', {
    TableName: tableName
  }).promise()
    .then(data => {
      console.log('Table exists');
      return data;
    });
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_4() {
  const cloudformation = new AWS.CloudFormation();
  const stackName = 'NetworkStack';
  
  // Using CloudFormation stack create complete waiter
  // ok: javascript-polling-to-waiters
  return cloudformation.waitFor('stackCreateComplete', {
    StackName: stackName
  }).promise()
    .then(data => {
      console.log('Stack creation complete');
      return data;
    });
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_5() {
  const rds = new AWS.RDS();
  const dbInstanceId = 'production-db';
  
  // Using RDS DB instance available waiter
  // ok: javascript-polling-to-waiters
  return rds.waitFor('dBInstanceAvailable', {
    DBInstanceIdentifier: dbInstanceId
  }).promise()
    .then(data => {
      console.log('Database is available');
      return data;
    });
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_6() {
  const ec2 = new AWS.EC2();
  const snapshotId = 'snap-1234567890abcdef0';
  
  // Using EC2 snapshot completed waiter
  // ok: javascript-polling-to-waiters
  return ec2.waitFor('snapshotCompleted', {
    SnapshotIds: [snapshotId]
  }).promise()
    .then(data => {
      console.log('Snapshot is complete');
      return data;
    });
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_7() {
  const ec2 = new AWS.EC2();
  const volumeId = 'vol-1234567890abcdef0';
  
  // Using EC2 volume available waiter
  // ok: javascript-polling-to-waiters
  return ec2.waitFor('volumeAvailable', {
    VolumeIds: [volumeId]
  }).promise()
    .then(data => {
      console.log('Volume is available');
      return data;
    });
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_8() {
  const cloudformation = new AWS.CloudFormation();
  const stackName = 'NetworkStack';
  
  // Using CloudFormation stack delete complete waiter
  // ok: javascript-polling-to-waiters
  return cloudformation.waitFor('stackDeleteComplete', {
    StackName: stackName
  }).promise()
    .then(data => {
      console.log('Stack deletion complete');
      return data;
    });
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_9() {
  const ec2 = new AWS.EC2();
  const instanceId = 'i-1234567890abcdef0';
  
  // Using EC2 instance stopped waiter
  // ok: javascript-polling-to-waiters
  return ec2.waitFor('instanceStopped', {
    InstanceIds: [instanceId]
  }).promise()
    .then(data => {
      console.log('Instance is stopped');
      return data;
    });
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_10() {
  const ec2 = new AWS.EC2();
  const instanceId = 'i-1234567890abcdef0';
  
  // Using EC2 instance terminated waiter
  // ok: javascript-polling-to-waiters
  return ec2.waitFor('instanceTerminated', {
    InstanceIds: [instanceId]
  }).promise()
    .then(data => {
      console.log('Instance is terminated');
      return data;
    });
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_11() {
  const dynamodb = new AWS.DynamoDB();
  const tableName = 'Users';
  
  // Using DynamoDB table not exists waiter
  // ok: javascript-polling-to-waiters
  return dynamodb.waitFor('tableNotExists', {
    TableName: tableName
  }).promise()
    .then(() => {
      console.log('Table does not exist');
      return true;
    });
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_12() {
  const s3 = new AWS.S3();
  const bucketName = 'my-test-bucket';
  
  // Using S3 bucket not exists waiter
  // ok: javascript-polling-to-waiters
  return s3.waitFor('bucketNotExists', {
    Bucket: bucketName
  }).promise()
    .then(() => {
      console.log('Bucket does not exist');
      return true;
    });
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_13() {
  const ec2 = new AWS.EC2();
  const imageId = 'ami-1234567890abcdef0';
  
  // Using EC2 image available waiter
  // ok: javascript-polling-to-waiters
  return ec2.waitFor('imageAvailable', {
    ImageIds: [imageId]
  }).promise()
    .then(data => {
      console.log('AMI is available');
      return data;
    });
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_14() {
  // Direct API call without polling
  const ec2 = new AWS.EC2();
  const instanceId = 'i-1234567890abcdef0';
  
  // ok: javascript-polling-to-waiters
  return ec2.describeInstances({ InstanceIds: [instanceId] }).promise()
    .then(data => {
      console.log('Instance state:', data.Reservations[0].Instances[0].State.Name);
      return data;
    });
}
// {/fact}

// {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
function good_case_15() {
  // Using async/await with waiter instead of custom polling
  const ec2 = new AWS.EC2();
  const instanceId = 'i-1234567890abcdef0';
  
  async function waitForInstance() {
    try {
      // ok: javascript-polling-to-waiters
      const data = await ec2.waitFor('instanceRunning', {
        InstanceIds: [instanceId]
      }).promise();
      
      console.log('Instance is running');
      return data;
    } catch (error) {
      console.error('Error waiting for instance:', error);
      throw error;
    }
  }
  
  return waitForInstance();
}
// {/fact}