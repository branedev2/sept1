import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as elasticache from 'aws-cdk-lib/aws-elasticache';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

// True Positive Examples (Vulnerable Code)

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating a Redis cluster without authentication
  // ruleid: typescript_cdk_elasticache_missing_redis_authorization
  const cluster = new elasticache.CfnCacheCluster(scope, 'RedisCluster', {
    cacheNodeType: 'cache.t3.micro',
    engine: 'redis',
    numCacheNodes: 1,
    clusterName: 'my-redis-cluster',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating a Redis replication group without authentication
  // ruleid: typescript_cdk_elasticache_missing_redis_authorization
  const replicationGroup = new elasticache.CfnReplicationGroup(scope, 'RedisReplicationGroup', {
    replicationGroupDescription: 'My Redis Replication Group',
    engine: 'redis',
    cacheNodeType: 'cache.t3.micro',
    numCacheClusters: 2,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_3(scope: Construct, vpc: ec2.Vpc) {
  // Creating a Redis cluster with subnet group but no auth
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'RedisSubnetGroup', {
    description: 'Subnet group for Redis',
    subnetIds: vpc.privateSubnets.map(subnet => subnet.subnetId),
  });

  // ruleid: typescript_cdk_elasticache_missing_redis_authorization
  const cluster = new elasticache.CfnCacheCluster(scope, 'RedisCluster', {
    cacheNodeType: 'cache.t3.micro',
    engine: 'redis',
    numCacheNodes: 1,
    cacheSubnetGroupName: subnetGroup.ref,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Creating a Redis cluster with explicit auth token set to null
  // ruleid: typescript_cdk_elasticache_missing_redis_authorization
  const replicationGroup = new elasticache.CfnReplicationGroup(scope, 'RedisReplicationGroup', {
    replicationGroupDescription: 'Redis with explicit null auth',
    engine: 'redis',
    cacheNodeType: 'cache.t3.micro',
    numCacheClusters: 2,
    authToken: null,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Creating a Redis cluster with empty string auth token
  // ruleid: typescript_cdk_elasticache_missing_redis_authorization
  const replicationGroup = new elasticache.CfnReplicationGroup(scope, 'RedisReplicationGroup', {
    replicationGroupDescription: 'Redis with empty auth',
    engine: 'redis',
    cacheNodeType: 'cache.t3.micro',
    numCacheClusters: 2,
    authToken: '',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Creating a Redis cluster with transit encryption but no auth
  // ruleid: typescript_cdk_elasticache_missing_redis_authorization
  const replicationGroup = new elasticache.CfnReplicationGroup(scope, 'RedisReplicationGroup', {
    replicationGroupDescription: 'Redis with transit encryption but no auth',
    engine: 'redis',
    cacheNodeType: 'cache.t3.micro',
    numCacheClusters: 2,
    transitEncryptionEnabled: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Creating a Redis cluster with multiple configuration options but no auth
  // ruleid: typescript_cdk_elasticache_missing_redis_authorization
  const cluster = new elasticache.CfnCacheCluster(scope, 'RedisCluster', {
    cacheNodeType: 'cache.t3.micro',
    engine: 'redis',
    numCacheNodes: 1,
    engineVersion: '6.x',
    port: 6379,
    preferredMaintenanceWindow: 'sun:05:00-sun:09:00',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Creating a Redis cluster with security groups but no auth
  // ruleid: typescript_cdk_elasticache_missing_redis_authorization
  const replicationGroup = new elasticache.CfnReplicationGroup(scope, 'RedisReplicationGroup', {
    replicationGroupDescription: 'Redis with security groups but no auth',
    engine: 'redis',
    cacheNodeType: 'cache.t3.micro',
    numCacheClusters: 2,
    securityGroupIds: ['sg-12345678'],
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Creating a Redis cluster with snapshot retention but no auth
  // ruleid: typescript_cdk_elasticache_missing_redis_authorization
  const replicationGroup = new elasticache.CfnReplicationGroup(scope, 'RedisReplicationGroup', {
    replicationGroupDescription: 'Redis with snapshot retention but no auth',
    engine: 'redis',
    cacheNodeType: 'cache.t3.micro',
    numCacheClusters: 2,
    snapshotRetentionLimit: 7,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating a Redis cluster with auto failover but no auth
  // ruleid: typescript_cdk_elasticache_missing_redis_authorization
  const replicationGroup = new elasticache.CfnReplicationGroup(scope, 'RedisReplicationGroup', {
    replicationGroupDescription: 'Redis with auto failover but no auth',
    engine: 'redis',
    cacheNodeType: 'cache.t3.micro',
    numCacheClusters: 2,
    automaticFailoverEnabled: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Creating a Redis cluster with parameter group but no auth
  const parameterGroup = new elasticache.CfnParameterGroup(scope, 'RedisParameterGroup', {
    cacheParameterGroupFamily: 'redis6.x',
    description: 'Redis parameter group',
    properties: {
      'maxmemory-policy': 'allkeys-lru',
    },
  });

  // ruleid: typescript_cdk_elasticache_missing_redis_authorization
  const cluster = new elasticache.CfnCacheCluster(scope, 'RedisCluster', {
    cacheNodeType: 'cache.t3.micro',
    engine: 'redis',
    numCacheNodes: 1,
    cacheParameterGroupName: parameterGroup.ref,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating a Redis cluster with tags but no auth
  // ruleid: typescript_cdk_elasticache_missing_redis_authorization
  const replicationGroup = new elasticache.CfnReplicationGroup(scope, 'RedisReplicationGroup', {
    replicationGroupDescription: 'Redis with tags but no auth',
    engine: 'redis',
    cacheNodeType: 'cache.t3.micro',
    numCacheClusters: 2,
    tags: [
      { key: 'Environment', value: 'Production' },
      { key: 'Owner', value: 'DataTeam' },
    ],
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating a Redis cluster with notification topic but no auth
  // ruleid: typescript_cdk_elasticache_missing_redis_authorization
  const replicationGroup = new elasticache.CfnReplicationGroup(scope, 'RedisReplicationGroup', {
    replicationGroupDescription: 'Redis with notification topic but no auth',
    engine: 'redis',
    cacheNodeType: 'cache.t3.micro',
    numCacheClusters: 2,
    notificationTopicArn: 'arn:aws:sns:us-east-1:123456789012:redis-notifications',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating a Redis cluster with multi-AZ but no auth
  // ruleid: typescript_cdk_elasticache_missing_redis_authorization
  const replicationGroup = new elasticache.CfnReplicationGroup(scope, 'RedisReplicationGroup', {
    replicationGroupDescription: 'Redis with multi-AZ but no auth',
    engine: 'redis',
    cacheNodeType: 'cache.t3.micro',
    numCacheClusters: 3,
    multiAzEnabled: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating a Redis cluster with at-rest encryption but no auth
  // ruleid: typescript_cdk_elasticache_missing_redis_authorization
  const replicationGroup = new elasticache.CfnReplicationGroup(scope, 'RedisReplicationGroup', {
    replicationGroupDescription: 'Redis with at-rest encryption but no auth',
    engine: 'redis',
    cacheNodeType: 'cache.t3.micro',
    numCacheClusters: 2,
    atRestEncryptionEnabled: true,
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating a Redis cluster with authentication
  // ok: typescript_cdk_elasticache_missing_redis_authorization
  const replicationGroup = new elasticache.CfnReplicationGroup(scope, 'RedisReplicationGroup', {
    replicationGroupDescription: 'Redis with auth',
    engine: 'redis',
    cacheNodeType: 'cache.t3.micro',
    numCacheClusters: 2,
    authToken: 'MySecurePassword123!',
    transitEncryptionEnabled: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Creating a Redis cluster with authentication from Secrets Manager
  const secret = new secretsmanager.Secret(scope, 'RedisAuthSecret', {
    generateSecretString: {
      passwordLength: 32,
      excludeCharacters: '"@/\\\'',
    },
  });
  
  // ok: typescript_cdk_elasticache_missing_redis_authorization
  const replicationGroup = new elasticache.CfnReplicationGroup(scope, 'RedisReplicationGroup', {
    replicationGroupDescription: 'Redis with auth from Secrets Manager',
    engine: 'redis',
    cacheNodeType: 'cache.t3.micro',
    numCacheClusters: 2,
    authToken: secret.secretValue.toString(),
    transitEncryptionEnabled: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_3(scope: Construct, vpc: ec2.Vpc) {
  // Creating a Redis cluster with subnet group and auth
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'RedisSubnetGroup', {
    description: 'Subnet group for Redis',
    subnetIds: vpc.privateSubnets.map(subnet => subnet.subnetId),
  });

  const authToken = 'MySecurePassword123!';
  
  // ok: typescript_cdk_elasticache_missing_redis_authorization
  const cluster = new elasticache.CfnReplicationGroup(scope, 'RedisReplicationGroup', {
    replicationGroupDescription: 'Redis with subnet group and auth',
    engine: 'redis',
    cacheNodeType: 'cache.t3.micro',
    numCacheClusters: 2,
    cacheSubnetGroupName: subnetGroup.ref,
    authToken: authToken,
    transitEncryptionEnabled: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Creating a Redis cluster with auth token from environment variable
  const authToken = process.env.REDIS_AUTH_TOKEN || 'DefaultSecurePassword123!';
  
  // ok: typescript_cdk_elasticache_missing_redis_authorization
  const replicationGroup = new elasticache.CfnReplicationGroup(scope, 'RedisReplicationGroup', {
    replicationGroupDescription: 'Redis with auth from env var',
    engine: 'redis',
    cacheNodeType: 'cache.t3.micro',
    numCacheClusters: 2,
    authToken: authToken,
    transitEncryptionEnabled: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Creating a Redis cluster with auth and transit encryption
  // ok: typescript_cdk_elasticache_missing_redis_authorization
  const replicationGroup = new elasticache.CfnReplicationGroup(scope, 'RedisReplicationGroup', {
    replicationGroupDescription: 'Redis with auth and transit encryption',
    engine: 'redis',
    cacheNodeType: 'cache.t3.micro',
    numCacheClusters: 2,
    authToken: 'MySecurePassword123!',
    transitEncryptionEnabled: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Creating a Redis cluster with auth and multiple configuration options
  // ok: typescript_cdk_elasticache_missing_redis_authorization
  const replicationGroup = new elasticache.CfnReplicationGroup(scope, 'RedisReplicationGroup', {
    replicationGroupDescription: 'Redis with auth and multiple configs',
    engine: 'redis',
    cacheNodeType: 'cache.t3.micro',
    numCacheClusters: 2,
    authToken: 'MySecurePassword123!',
    transitEncryptionEnabled: true,
    engineVersion: '6.x',
    port: 6379,
    preferredMaintenanceWindow: 'sun:05:00-sun:09:00',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Creating a Redis cluster with auth and security groups
  // ok: typescript_cdk_elasticache_missing_redis_authorization
  const replicationGroup = new elasticache.CfnReplicationGroup(scope, 'RedisReplicationGroup', {
    replicationGroupDescription: 'Redis with auth and security groups',
    engine: 'redis',
    cacheNodeType: 'cache.t3.micro',
    numCacheClusters: 2,
    authToken: 'MySecurePassword123!',
    transitEncryptionEnabled: true,
    securityGroupIds: ['sg-12345678'],
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Creating a Redis cluster with auth and snapshot retention
  // ok: typescript_cdk_elasticache_missing_redis_authorization
  const replicationGroup = new elasticache.CfnReplicationGroup(scope, 'RedisReplicationGroup', {
    replicationGroupDescription: 'Redis with auth and snapshot retention',
    engine: 'redis',
    cacheNodeType: 'cache.t3.micro',
    numCacheClusters: 2,
    authToken: 'MySecurePassword123!',
    transitEncryptionEnabled: true,
    snapshotRetentionLimit: 7,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Creating a Redis cluster with auth and auto failover
  // ok: typescript_cdk_elasticache_missing_redis_authorization
  const replicationGroup = new elasticache.CfnReplicationGroup(scope, 'RedisReplicationGroup', {
    replicationGroupDescription: 'Redis with auth and auto failover',
    engine: 'redis',
    cacheNodeType: 'cache.t3.micro',
    numCacheClusters: 2,
    authToken: 'MySecurePassword123!',
    transitEncryptionEnabled: true,
    automaticFailoverEnabled: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Creating a Redis cluster with auth and parameter group
  const parameterGroup = new elasticache.CfnParameterGroup(scope, 'RedisParameterGroup', {
    cacheParameterGroupFamily: 'redis6.x',
    description: 'Redis parameter group',
    properties: {
      'maxmemory-policy': 'allkeys-lru',
    },
  });

  // ok: typescript_cdk_elasticache_missing_redis_authorization
  const replicationGroup = new elasticache.CfnReplicationGroup(scope, 'RedisReplicationGroup', {
    replicationGroupDescription: 'Redis with auth and parameter group',
    engine: 'redis',
    cacheNodeType: 'cache.t3.micro',
    numCacheClusters: 2,
    authToken: 'MySecurePassword123!',
    transitEncryptionEnabled: true,
    cacheParameterGroupName: parameterGroup.ref,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Creating a Redis cluster with auth and tags
  // ok: typescript_cdk_elasticache_missing_redis_authorization
  const replicationGroup = new elasticache.CfnReplicationGroup(scope, 'RedisReplicationGroup', {
    replicationGroupDescription: 'Redis with auth and tags',
    engine: 'redis',
    cacheNodeType: 'cache.t3.micro',
    numCacheClusters: 2,
    authToken: 'MySecurePassword123!',
    transitEncryptionEnabled: true,
    tags: [
      { key: 'Environment', value: 'Production' },
      { key: 'Owner', value: 'DataTeam' },
    ],
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Creating a Redis cluster with auth and notification topic
  // ok: typescript_cdk_elasticache_missing_redis_authorization
  const replicationGroup = new elasticache.CfnReplicationGroup(scope, 'RedisReplicationGroup', {
    replicationGroupDescription: 'Redis with auth and notification topic',
    engine: 'redis',
    cacheNodeType: 'cache.t3.micro',
    numCacheClusters: 2,
    authToken: 'MySecurePassword123!',
    transitEncryptionEnabled: true,
    notificationTopicArn: 'arn:aws:sns:us-east-1:123456789012:redis-notifications',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Creating a Redis cluster with auth and multi-AZ
  // ok: typescript_cdk_elasticache_missing_redis_authorization
  const replicationGroup = new elasticache.CfnReplicationGroup(scope, 'RedisReplicationGroup', {
    replicationGroupDescription: 'Redis with auth and multi-AZ',
    engine: 'redis',
    cacheNodeType: 'cache.t3.micro',
    numCacheClusters: 3,
    authToken: 'MySecurePassword123!',
    transitEncryptionEnabled: true,
    multiAzEnabled: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Creating a Redis cluster with auth and at-rest encryption
  // ok: typescript_cdk_elasticache_missing_redis_authorization
  const replicationGroup = new elasticache.CfnReplicationGroup(scope, 'RedisReplicationGroup', {
    replicationGroupDescription: 'Redis with auth and at-rest encryption',
    engine: 'redis',
    cacheNodeType: 'cache.t3.micro',
    numCacheClusters: 2,
    authToken: 'MySecurePassword123!',
    transitEncryptionEnabled: true,
    atRestEncryptionEnabled: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Creating a Redis cluster with auth using a function to generate password
  function generateSecurePassword(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()';
    let password = '';
    for (let i = 0; i < 32; i++) {
      password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return password;
  }
  
  // ok: typescript_cdk_elasticache_missing_redis_authorization
  const replicationGroup = new elasticache.CfnReplicationGroup(scope, 'RedisReplicationGroup', {
    replicationGroupDescription: 'Redis with auth using generated password',
    engine: 'redis',
    cacheNodeType: 'cache.t3.micro',
    numCacheClusters: 2,
    authToken: generateSecurePassword(),
    transitEncryptionEnabled: true,
  });
}
// {/fact}