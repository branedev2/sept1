import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as emr from 'aws-cdk-lib/aws-emr';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';

// True Positives (Vulnerable Code Examples)

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_1(scope: Construct, id: string) {
  // Missing logUri property in EMR cluster configuration
  // ruleid: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'MyCluster',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
    },
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.3.0',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_2(scope: Construct, id: string) {
  // EMR cluster with undefined logUri
  const logUri = undefined;
  
  // ruleid: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'DataProcessingCluster',
    instances: {
      masterInstanceType: 'r5.2xlarge',
      slaveInstanceType: 'r5.xlarge',
      instanceCount: 5,
    },
    logUri: logUri, // undefined logUri
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.4.0',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_3(scope: Construct, id: string) {
  // EMR cluster with empty string logUri
  
  // ruleid: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'AnalyticsCluster',
    instances: {
      masterInstanceType: 'c5.2xlarge',
      slaveInstanceType: 'c5.xlarge',
      instanceCount: 10,
      ec2KeyName: 'my-key-pair',
    },
    logUri: '', // Empty string
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.2.0',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_4(scope: Construct, id: string) {
  // EMR cluster with null logUri
  const logUri = null;
  
  // ruleid: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'SparkCluster',
    instances: {
      masterInstanceType: 'm5.2xlarge',
      slaveInstanceType: 'm5.xlarge',
      instanceCount: 4,
    },
    logUri: logUri, // null logUri
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.5.0',
    applications: [{ name: 'Spark' }, { name: 'Hive' }],
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_5(scope: Construct, id: string) {
  // EMR cluster with commented out logUri
  
  // ruleid: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'HadoopCluster',
    instances: {
      masterInstanceType: 'r5.xlarge',
      slaveInstanceType: 'r5.large',
      instanceCount: 6,
    },
    // logUri: 's3://my-logs-bucket/emr-logs/',
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.1.0',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_6(scope: Construct, id: string, vpc: ec2.Vpc) {
  // EMR cluster with complex configuration but missing logUri
  const serviceRole = new iam.Role(scope, 'EMRServiceRole', {
    assumedBy: new iam.ServicePrincipal('elasticmapreduce.amazonaws.com'),
    managedPolicies: [
      iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AmazonEMRServicePolicy'),
    ],
  });

  const instanceProfile = new iam.CfnInstanceProfile(scope, 'EMRInstanceProfile', {
    roles: ['EMR_EC2_DefaultRole'],
  });

  // ruleid: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'ProductionETLCluster',
    instances: {
      masterInstanceType: 'm5.4xlarge',
      slaveInstanceType: 'm5.2xlarge',
      instanceCount: 20,
      ec2SubnetId: vpc.privateSubnets[0].subnetId,
      ec2KeyName: 'emr-key',
      additionalMasterSecurityGroups: ['sg-12345'],
      additionalSlaveSecurityGroups: ['sg-67890'],
    },
    applications: [
      { name: 'Spark' },
      { name: 'Hive' },
      { name: 'Pig' },
      { name: 'Hadoop' },
    ],
    jobFlowRole: instanceProfile.ref,
    serviceRole: serviceRole.roleName,
    releaseLabel: 'emr-6.6.0',
    visibleToAllUsers: true,
    tags: [
      { key: 'Environment', value: 'Production' },
      { key: 'Department', value: 'DataEngineering' },
    ],
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_7(scope: Construct, id: string) {
  // EMR cluster with conditional logic but missing logUri
  const isProd = process.env.ENVIRONMENT === 'production';
  const instanceType = isProd ? 'r5.4xlarge' : 'r5.xlarge';
  const instanceCount = isProd ? 10 : 3;
  
  // ruleid: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: isProd ? 'ProdDataCluster' : 'DevDataCluster',
    instances: {
      masterInstanceType: instanceType,
      slaveInstanceType: instanceType,
      instanceCount: instanceCount,
    },
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.3.0',
    visibleToAllUsers: !isProd,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_8(scope: Construct, id: string) {
  // EMR cluster with configurations but missing logUri
  
  // ruleid: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'ConfiguredCluster',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
    },
    configurations: [
      {
        classification: 'spark-defaults',
        configurationProperties: {
          'spark.executor.memory': '4g',
          'spark.driver.memory': '2g',
        },
      },
      {
        classification: 'hadoop-env',
        configurationProperties: {
          'HADOOP_DATANODE_HEAPSIZE': '2048',
        },
      },
    ],
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.4.0',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_9(scope: Construct, id: string) {
  // EMR cluster with steps but missing logUri
  
  // ruleid: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'StepsCluster',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
    },
    steps: [
      {
        name: 'Setup Hadoop Debugging',
        actionOnFailure: 'TERMINATE_CLUSTER',
        hadoopJarStep: {
          jar: 'command-runner.jar',
          args: ['state-pusher-script'],
        },
      },
      {
        name: 'Run Spark Job',
        actionOnFailure: 'CONTINUE',
        hadoopJarStep: {
          jar: 'command-runner.jar',
          args: ['spark-submit', '--class', 'com.example.Main', 's3://mybucket/app.jar'],
        },
      },
    ],
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.3.0',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_10(scope: Construct, id: string) {
  // EMR cluster with bootstrap actions but missing logUri
  
  // ruleid: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'BootstrapCluster',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
    },
    bootstrapActions: [
      {
        name: 'Install Dependencies',
        scriptBootstrapAction: {
          path: 's3://mybucket/scripts/install-dependencies.sh',
          args: ['arg1', 'arg2'],
        },
      },
      {
        name: 'Configure System',
        scriptBootstrapAction: {
          path: 's3://mybucket/scripts/configure-system.sh',
        },
      },
    ],
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.2.0',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_11(scope: Construct, id: string) {
  // EMR cluster with auto-termination but missing logUri
  
  // ruleid: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'AutoTerminateCluster',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
      keepJobFlowAliveWhenNoSteps: false,
      terminationProtected: false,
    },
    autoTerminationPolicy: {
      idleTimeout: 3600, // 1 hour
    },
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.5.0',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_12(scope: Construct, id: string) {
  // EMR cluster with spot instances but missing logUri
  
  // ruleid: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'SpotCluster',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 5,
      ec2KeyName: 'my-key',
      marketType: 'SPOT',
      bidPrice: '0.5',
    },
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.4.0',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_13(scope: Construct, id: string) {
  // EMR cluster with security configuration but missing logUri
  
  // ruleid: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'SecureCluster',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
    },
    securityConfiguration: 'MySecurityConfiguration',
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.3.0',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_14(scope: Construct, id: string) {
  // EMR cluster with kerberos configuration but missing logUri
  
  // ruleid: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'KerberosCluster',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
    },
    kerberosAttributes: {
      realm: 'EC2.INTERNAL',
      kdcAdminPassword: 'SecurePassword123',
      crossRealmTrustPrincipalPassword: 'AnotherSecurePassword456',
      adDomainJoinPassword: 'DomainPassword789',
      adDomainJoinUser: 'admin',
    },
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.2.0',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=1}
function bad_case_15(scope: Construct, id: string) {
  // EMR cluster with managed scaling but missing logUri
  
  // ruleid: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'ScalableCluster',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 2,
    },
    managedScalingPolicy: {
      computeLimits: {
        unitType: 'INSTANCES',
        minimumCapacityUnits: 2,
        maximumCapacityUnits: 10,
        maximumOnDemandCapacityUnits: 5,
        maximumCoreCapacityUnits: 8,
      },
    },
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.5.0',
  });
}
// {/fact}

// True Negatives (Secure Code Examples)

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_1(scope: Construct, id: string) {
  const logBucket = new s3.Bucket(scope, 'EMRLogBucket');
  
  // ok: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'MyCluster',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
    },
    logUri: `s3://${logBucket.bucketName}/emr-logs/`,
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.3.0',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_2(scope: Construct, id: string) {
  // Using an existing S3 bucket for logs
  
  // ok: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'DataProcessingCluster',
    instances: {
      masterInstanceType: 'r5.2xlarge',
      slaveInstanceType: 'r5.xlarge',
      instanceCount: 5,
    },
    logUri: 's3://existing-log-bucket/emr-logs/',
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.4.0',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_3(scope: Construct, id: string) {
  // Using a variable for logUri
  const logBucketName = 'my-company-logs';
  const logPrefix = 'emr/cluster-logs/';
  
  // ok: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'AnalyticsCluster',
    instances: {
      masterInstanceType: 'c5.2xlarge',
      slaveInstanceType: 'c5.xlarge',
      instanceCount: 10,
      ec2KeyName: 'my-key-pair',
    },
    logUri: `s3://${logBucketName}/${logPrefix}`,
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.2.0',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_4(scope: Construct, id: string) {
  // Using conditional logic to determine logUri
  const environment = process.env.ENVIRONMENT || 'dev';
  const logBucket = environment === 'prod' ? 'prod-logs-bucket' : 'dev-logs-bucket';
  
  // ok: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'SparkCluster',
    instances: {
      masterInstanceType: 'm5.2xlarge',
      slaveInstanceType: 'm5.xlarge',
      instanceCount: 4,
    },
    logUri: `s3://${logBucket}/emr-logs/${environment}/`,
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.5.0',
    applications: [{ name: 'Spark' }, { name: 'Hive' }],
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_5(scope: Construct, id: string) {
  // Creating a bucket with specific configurations for logs
  const logBucket = new s3.Bucket(scope, 'EMRLogBucket', {
    versioned: true,
    encryption: s3.BucketEncryption.S3_MANAGED,
    lifecycleRules: [
      {
        expiration: cdk.Duration.days(90),
        transitions: [
          {
            storageClass: s3.StorageClass.INFREQUENT_ACCESS,
            transitionAfter: cdk.Duration.days(30),
          },
          {
            storageClass: s3.StorageClass.GLACIER,
            transitionAfter: cdk.Duration.days(60),
          },
        ],
      },
    ],
  });
  
  // ok: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'HadoopCluster',
    instances: {
      masterInstanceType: 'r5.xlarge',
      slaveInstanceType: 'r5.large',
      instanceCount: 6,
    },
    logUri: `s3://${logBucket.bucketName}/hadoop-logs/`,
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.1.0',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_6(scope: Construct, id: string, vpc: ec2.Vpc) {
  // Complex EMR cluster with proper logging configuration
  const serviceRole = new iam.Role(scope, 'EMRServiceRole', {
    assumedBy: new iam.ServicePrincipal('elasticmapreduce.amazonaws.com'),
    managedPolicies: [
      iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AmazonEMRServicePolicy'),
    ],
  });

  const instanceProfile = new iam.CfnInstanceProfile(scope, 'EMRInstanceProfile', {
    roles: ['EMR_EC2_DefaultRole'],
  });
  
  const logBucket = new s3.Bucket(scope, 'EMRLogBucket');

  // ok: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'ProductionETLCluster',
    instances: {
      masterInstanceType: 'm5.4xlarge',
      slaveInstanceType: 'm5.2xlarge',
      instanceCount: 20,
      ec2SubnetId: vpc.privateSubnets[0].subnetId,
      ec2KeyName: 'emr-key',
      additionalMasterSecurityGroups: ['sg-12345'],
      additionalSlaveSecurityGroups: ['sg-67890'],
    },
    applications: [
      { name: 'Spark' },
      { name: 'Hive' },
      { name: 'Pig' },
      { name: 'Hadoop' },
    ],
    logUri: `s3://${logBucket.bucketName}/production-emr-logs/`,
    jobFlowRole: instanceProfile.ref,
    serviceRole: serviceRole.roleName,
    releaseLabel: 'emr-6.6.0',
    visibleToAllUsers: true,
    tags: [
      { key: 'Environment', value: 'Production' },
      { key: 'Department', value: 'DataEngineering' },
    ],
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_7(scope: Construct, id: string) {
  // EMR cluster with conditional logic and proper logging
  const isProd = process.env.ENVIRONMENT === 'production';
  const instanceType = isProd ? 'r5.4xlarge' : 'r5.xlarge';
  const instanceCount = isProd ? 10 : 3;
  const logBucket = isProd ? 'company-prod-logs' : 'company-dev-logs';
  
  // ok: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: isProd ? 'ProdDataCluster' : 'DevDataCluster',
    instances: {
      masterInstanceType: instanceType,
      slaveInstanceType: instanceType,
      instanceCount: instanceCount,
    },
    logUri: `s3://${logBucket}/emr-logs/${isProd ? 'prod' : 'dev'}/`,
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.3.0',
    visibleToAllUsers: !isProd,
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_8(scope: Construct, id: string) {
  // EMR cluster with configurations and proper logging
  const logBucket = new s3.Bucket(scope, 'EMRLogBucket');
  
  // ok: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'ConfiguredCluster',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
    },
    logUri: `s3://${logBucket.bucketName}/emr-logs/configured-cluster/`,
    configurations: [
      {
        classification: 'spark-defaults',
        configurationProperties: {
          'spark.executor.memory': '4g',
          'spark.driver.memory': '2g',
        },
      },
      {
        classification: 'hadoop-env',
        configurationProperties: {
          'HADOOP_DATANODE_HEAPSIZE': '2048',
        },
      },
    ],
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.4.0',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_9(scope: Construct, id: string) {
  // EMR cluster with steps and proper logging
  
  // ok: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'StepsCluster',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
    },
    logUri: 's3://company-emr-logs/steps-cluster/',
    steps: [
      {
        name: 'Setup Hadoop Debugging',
        actionOnFailure: 'TERMINATE_CLUSTER',
        hadoopJarStep: {
          jar: 'command-runner.jar',
          args: ['state-pusher-script'],
        },
      },
      {
        name: 'Run Spark Job',
        actionOnFailure: 'CONTINUE',
        hadoopJarStep: {
          jar: 'command-runner.jar',
          args: ['spark-submit', '--class', 'com.example.Main', 's3://mybucket/app.jar'],
        },
      },
    ],
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.3.0',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_10(scope: Construct, id: string) {
  // EMR cluster with bootstrap actions and proper logging
  const logBucket = new s3.Bucket(scope, 'EMRLogBucket');
  
  // ok: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'BootstrapCluster',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
    },
    logUri: `s3://${logBucket.bucketName}/bootstrap-cluster-logs/`,
    bootstrapActions: [
      {
        name: 'Install Dependencies',
        scriptBootstrapAction: {
          path: 's3://mybucket/scripts/install-dependencies.sh',
          args: ['arg1', 'arg2'],
        },
      },
      {
        name: 'Configure System',
        scriptBootstrapAction: {
          path: 's3://mybucket/scripts/configure-system.sh',
        },
      },
    ],
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.2.0',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_11(scope: Construct, id: string) {
  // EMR cluster with auto-termination and proper logging
  
  // ok: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'AutoTerminateCluster',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
      keepJobFlowAliveWhenNoSteps: false,
      terminationProtected: false,
    },
    logUri: 's3://emr-logs-bucket/auto-terminate-cluster/',
    autoTerminationPolicy: {
      idleTimeout: 3600, // 1 hour
    },
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.5.0',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_12(scope: Construct, id: string) {
  // EMR cluster with spot instances and proper logging
  
  // ok: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'SpotCluster',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 5,
      ec2KeyName: 'my-key',
      marketType: 'SPOT',
      bidPrice: '0.5',
    },
    logUri: 's3://emr-spot-cluster-logs/logs/',
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.4.0',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_13(scope: Construct, id: string) {
  // EMR cluster with security configuration and proper logging
  const logBucket = new s3.Bucket(scope, 'EMRSecureLogBucket', {
    encryption: s3.BucketEncryption.KMS,
  });
  
  // ok: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'SecureCluster',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
    },
    logUri: `s3://${logBucket.bucketName}/secure-cluster-logs/`,
    securityConfiguration: 'MySecurityConfiguration',
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.3.0',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_14(scope: Construct, id: string) {
  // EMR cluster with kerberos configuration and proper logging
  
  // ok: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'KerberosCluster',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 3,
    },
    logUri: 's3://kerberos-emr-logs/cluster-logs/',
    kerberosAttributes: {
      realm: 'EC2.INTERNAL',
      kdcAdminPassword: 'SecurePassword123',
      crossRealmTrustPrincipalPassword: 'AnotherSecurePassword456',
      adDomainJoinPassword: 'DomainPassword789',
      adDomainJoinUser: 'admin',
    },
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.2.0',
  });
}
// {/fact}

// {fact rule=insufficient-logging@v1.0 defects=0}
function good_case_15(scope: Construct, id: string) {
  // EMR cluster with managed scaling and proper logging
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  
  // ok: typescript-cdk-emrs-3-access-logging
  const cluster = new emr.CfnCluster(scope, 'MyEMRCluster', {
    name: 'ScalableCluster',
    instances: {
      masterInstanceType: 'm5.xlarge',
      slaveInstanceType: 'm5.large',
      instanceCount: 2,
    },
    logUri: `s3://emr-scaling-logs/cluster-${timestamp}/`,
    managedScalingPolicy: {
      computeLimits: {
        unitType: 'INSTANCES',
        minimumCapacityUnits: 2,
        maximumCapacityUnits: 10,
        maximumOnDemandCapacityUnits: 5,
        maximumCoreCapacityUnits: 8,
      },
    },
    jobFlowRole: 'EMR_EC2_DefaultRole',
    serviceRole: 'EMR_DefaultRole',
    releaseLabel: 'emr-6.5.0',
  });
}
// {/fact}