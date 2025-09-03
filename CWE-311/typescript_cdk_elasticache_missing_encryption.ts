import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as elasticache from 'aws-cdk-lib/aws-elasticache';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

// True Positive Examples (Vulnerable Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating a Redis cluster without encryption in transit
  // ruleid: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster without encryption',
    engine: 'redis',
    cacheNodeType: 'cache.t3.small',
    numCacheClusters: 2,
    automaticFailoverEnabled: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating a Redis cluster with encryption explicitly disabled
  // ruleid: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with encryption disabled',
    engine: 'redis',
    cacheNodeType: 'cache.t3.medium',
    numCacheClusters: 3,
    automaticFailoverEnabled: true,
    transitEncryptionEnabled: false,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3(scope: Construct, vpc: ec2.Vpc) {
  // Creating a Redis cluster with subnet group but no encryption
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'RedisSubnetGroup', {
    description: 'Subnet group for Redis',
    subnetIds: vpc.privateSubnets.map(subnet => subnet.subnetId),
  });
  
  // ruleid: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with subnet group but no encryption',
    engine: 'redis',
    cacheNodeType: 'cache.m5.large',
    numCacheClusters: 2,
    automaticFailoverEnabled: true,
    cacheSubnetGroupName: subnetGroup.ref,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Creating a Redis cluster with some security settings but missing transit encryption
  // ruleid: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with some security settings',
    engine: 'redis',
    cacheNodeType: 'cache.r5.large',
    numCacheClusters: 2,
    automaticFailoverEnabled: true,
    atRestEncryptionEnabled: true, // At-rest encryption is enabled, but transit encryption is missing
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Creating a Redis cluster with auth token but no transit encryption
  // ruleid: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with auth token but no encryption',
    engine: 'redis',
    cacheNodeType: 'cache.t3.small',
    numCacheClusters: 2,
    automaticFailoverEnabled: true,
    authToken: 'myAuthToken123',
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Creating a Redis cluster with engine version specified but no encryption
  // ruleid: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with engine version',
    engine: 'redis',
    engineVersion: '6.x',
    cacheNodeType: 'cache.t3.medium',
    numCacheClusters: 3,
    automaticFailoverEnabled: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7(scope: Construct, securityGroup: ec2.SecurityGroup) {
  // Creating a Redis cluster with security group but no encryption
  // ruleid: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with security group',
    engine: 'redis',
    cacheNodeType: 'cache.m5.large',
    numCacheClusters: 2,
    automaticFailoverEnabled: true,
    securityGroupIds: [securityGroup.securityGroupId],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Creating a Redis cluster with multi-AZ enabled but no encryption
  // ruleid: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with multi-AZ',
    engine: 'redis',
    cacheNodeType: 'cache.r5.large',
    numCacheClusters: 3,
    automaticFailoverEnabled: true,
    multiAzEnabled: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Creating a Redis cluster with port specified but no encryption
  // ruleid: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with custom port',
    engine: 'redis',
    cacheNodeType: 'cache.t3.small',
    numCacheClusters: 2,
    automaticFailoverEnabled: true,
    port: 6380,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating a Redis cluster with snapshot retention but no encryption
  // ruleid: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with snapshot retention',
    engine: 'redis',
    cacheNodeType: 'cache.m5.large',
    numCacheClusters: 2,
    automaticFailoverEnabled: true,
    snapshotRetentionLimit: 7,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Creating a Redis cluster with maintenance window but no encryption
  // ruleid: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with maintenance window',
    engine: 'redis',
    cacheNodeType: 'cache.t3.medium',
    numCacheClusters: 2,
    automaticFailoverEnabled: true,
    preferredMaintenanceWindow: 'sun:05:00-sun:09:00',
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating a Redis cluster with notification topic but no encryption
  // ruleid: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with notification topic',
    engine: 'redis',
    cacheNodeType: 'cache.r5.large',
    numCacheClusters: 2,
    automaticFailoverEnabled: true,
    notificationTopicArn: 'arn:aws:sns:us-east-1:123456789012:my-topic',
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating a Redis cluster with parameter group but no encryption
  // ruleid: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with parameter group',
    engine: 'redis',
    cacheNodeType: 'cache.t3.small',
    numCacheClusters: 2,
    automaticFailoverEnabled: true,
    cacheParameterGroupName: 'default.redis6.x',
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating a Redis cluster with tags but no encryption
  // ruleid: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with tags',
    engine: 'redis',
    cacheNodeType: 'cache.m5.large',
    numCacheClusters: 2,
    automaticFailoverEnabled: true,
    tags: [
      { key: 'Environment', value: 'Production' },
      { key: 'Owner', value: 'DataTeam' }
    ],
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating a Redis cluster with snapshot name but no encryption
  // ruleid: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with snapshot name',
    engine: 'redis',
    cacheNodeType: 'cache.r5.large',
    numCacheClusters: 2,
    automaticFailoverEnabled: true,
    snapshotName: 'redis-snapshot-001',
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating a Redis cluster with encryption in transit enabled
  // ok: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with encryption',
    engine: 'redis',
    cacheNodeType: 'cache.t3.small',
    numCacheClusters: 2,
    automaticFailoverEnabled: true,
    transitEncryptionEnabled: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Creating a Redis cluster with both at-rest and transit encryption
  // ok: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with both encryptions',
    engine: 'redis',
    cacheNodeType: 'cache.t3.medium',
    numCacheClusters: 3,
    automaticFailoverEnabled: true,
    atRestEncryptionEnabled: true,
    transitEncryptionEnabled: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3(scope: Construct, vpc: ec2.Vpc) {
  // Creating a Redis cluster with subnet group and encryption
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'RedisSubnetGroup', {
    description: 'Subnet group for Redis',
    subnetIds: vpc.privateSubnets.map(subnet => subnet.subnetId),
  });
  
  // ok: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with subnet group and encryption',
    engine: 'redis',
    cacheNodeType: 'cache.m5.large',
    numCacheClusters: 2,
    automaticFailoverEnabled: true,
    cacheSubnetGroupName: subnetGroup.ref,
    transitEncryptionEnabled: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Creating a Redis cluster with auth token and transit encryption
  // ok: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with auth token and encryption',
    engine: 'redis',
    cacheNodeType: 'cache.t3.small',
    numCacheClusters: 2,
    automaticFailoverEnabled: true,
    authToken: 'myAuthToken123',
    transitEncryptionEnabled: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Creating a Redis cluster with engine version and encryption
  // ok: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with engine version and encryption',
    engine: 'redis',
    engineVersion: '6.x',
    cacheNodeType: 'cache.t3.medium',
    numCacheClusters: 3,
    automaticFailoverEnabled: true,
    transitEncryptionEnabled: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6(scope: Construct, securityGroup: ec2.SecurityGroup) {
  // Creating a Redis cluster with security group and encryption
  // ok: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with security group and encryption',
    engine: 'redis',
    cacheNodeType: 'cache.m5.large',
    numCacheClusters: 2,
    automaticFailoverEnabled: true,
    securityGroupIds: [securityGroup.securityGroupId],
    transitEncryptionEnabled: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Creating a Redis cluster with multi-AZ and encryption
  // ok: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with multi-AZ and encryption',
    engine: 'redis',
    cacheNodeType: 'cache.r5.large',
    numCacheClusters: 3,
    automaticFailoverEnabled: true,
    multiAzEnabled: true,
    transitEncryptionEnabled: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Creating a Redis cluster with port specified and encryption
  // ok: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with custom port and encryption',
    engine: 'redis',
    cacheNodeType: 'cache.t3.small',
    numCacheClusters: 2,
    automaticFailoverEnabled: true,
    port: 6380,
    transitEncryptionEnabled: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Creating a Redis cluster with snapshot retention and encryption
  // ok: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with snapshot retention and encryption',
    engine: 'redis',
    cacheNodeType: 'cache.m5.large',
    numCacheClusters: 2,
    automaticFailoverEnabled: true,
    snapshotRetentionLimit: 7,
    transitEncryptionEnabled: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Creating a Redis cluster with maintenance window and encryption
  // ok: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with maintenance window and encryption',
    engine: 'redis',
    cacheNodeType: 'cache.t3.medium',
    numCacheClusters: 2,
    automaticFailoverEnabled: true,
    preferredMaintenanceWindow: 'sun:05:00-sun:09:00',
    transitEncryptionEnabled: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Creating a Redis cluster with notification topic and encryption
  // ok: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with notification topic and encryption',
    engine: 'redis',
    cacheNodeType: 'cache.r5.large',
    numCacheClusters: 2,
    automaticFailoverEnabled: true,
    notificationTopicArn: 'arn:aws:sns:us-east-1:123456789012:my-topic',
    transitEncryptionEnabled: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Creating a Redis cluster with parameter group and encryption
  // ok: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with parameter group and encryption',
    engine: 'redis',
    cacheNodeType: 'cache.t3.small',
    numCacheClusters: 2,
    automaticFailoverEnabled: true,
    cacheParameterGroupName: 'default.redis6.x',
    transitEncryptionEnabled: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Creating a Redis cluster with tags and encryption
  // ok: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with tags and encryption',
    engine: 'redis',
    cacheNodeType: 'cache.m5.large',
    numCacheClusters: 2,
    automaticFailoverEnabled: true,
    tags: [
      { key: 'Environment', value: 'Production' },
      { key: 'Owner', value: 'DataTeam' }
    ],
    transitEncryptionEnabled: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Creating a Redis cluster with snapshot name and encryption
  // ok: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with snapshot name and encryption',
    engine: 'redis',
    cacheNodeType: 'cache.r5.large',
    numCacheClusters: 2,
    automaticFailoverEnabled: true,
    snapshotName: 'redis-snapshot-001',
    transitEncryptionEnabled: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Creating a Redis cluster with all security features enabled
  // ok: typescript_cdk_elasticache_missing_encryption
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Fully secured Redis cluster',
    engine: 'redis',
    engineVersion: '6.x',
    cacheNodeType: 'cache.m5.large',
    numCacheClusters: 3,
    automaticFailoverEnabled: true,
    multiAzEnabled: true,
    atRestEncryptionEnabled: true,
    transitEncryptionEnabled: true,
    authToken: 'mySecureAuthToken',
    snapshotRetentionLimit: 14,
    tags: [
      { key: 'Environment', value: 'Production' },
      { key: 'SecurityLevel', value: 'High' }
    ],
  });
}
// {/fact}