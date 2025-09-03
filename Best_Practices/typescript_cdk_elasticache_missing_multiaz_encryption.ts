import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as elasticache from 'aws-cdk-lib/aws-elasticache';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

// TRUE POSITIVES (Vulnerable cases)

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating ElastiCache Redis cluster without Multi-AZ configuration
  // ruleid: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster without Multi-AZ',
    engine: 'redis',
    cacheNodeType: 'cache.t3.small',
    numCacheClusters: 2,
    automaticFailoverEnabled: false, // Multi-AZ disabled
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating ElastiCache Redis cluster with explicit Multi-AZ disabled
  // ruleid: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with explicit Multi-AZ disabled',
    engine: 'redis',
    cacheNodeType: 'cache.t3.medium',
    numCacheClusters: 3,
    automaticFailoverEnabled: false,
    multiAzEnabled: false,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Creating ElastiCache Redis cluster with missing Multi-AZ configuration
  const vpc = new ec2.Vpc(scope, 'VPC');
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'SubnetGroup', {
    description: 'Subnet group for Redis',
    subnetIds: vpc.privateSubnets.map(subnet => subnet.subnetId),
  });
  
  // ruleid: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with missing Multi-AZ',
    engine: 'redis',
    cacheNodeType: 'cache.m5.large',
    numCacheClusters: 2,
    cacheSubnetGroupName: subnetGroup.ref,
    // Missing automaticFailoverEnabled and multiAzEnabled
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_4(scope: Construct, stackProps: cdk.StackProps) {
  // Creating ElastiCache Redis cluster with conditional Multi-AZ disabled
  const isProduction = stackProps.tags?.['Environment'] === 'production';
  
  // ruleid: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with conditional Multi-AZ',
    engine: 'redis',
    cacheNodeType: 'cache.r5.large',
    numCacheClusters: 2,
    automaticFailoverEnabled: false,
    multiAzEnabled: isProduction ? true : false, // Will be false in non-production
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Creating ElastiCache Redis cluster with only one node (can't have Multi-AZ)
  // ruleid: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Single node Redis cluster',
    engine: 'redis',
    cacheNodeType: 'cache.t3.micro',
    numCacheClusters: 1, // Single node, can't have Multi-AZ
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Creating ElastiCache Redis cluster with serverless configuration but no Multi-AZ
  // ruleid: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnServerlessCache(scope, 'ServerlessRedisCache', {
    engine: 'redis',
    serverlessCacheName: 'my-serverless-redis',
    // Missing Multi-AZ configuration
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  const props = {
    replicationGroupDescription: 'Redis cluster with props object',
    engine: 'redis',
    cacheNodeType: 'cache.t3.small',
    numCacheClusters: 2,
    automaticFailoverEnabled: false,
  };
  
  // ruleid: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', props);
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Creating ElastiCache Redis cluster with encryption but no Multi-AZ
  // ruleid: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with encryption but no Multi-AZ',
    engine: 'redis',
    cacheNodeType: 'cache.t3.medium',
    numCacheClusters: 2,
    atRestEncryptionEnabled: true, // Encryption enabled
    transitEncryptionEnabled: true, // Encryption in transit enabled
    automaticFailoverEnabled: false, // But Multi-AZ disabled
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Creating ElastiCache Redis cluster with Redis AUTH but no Multi-AZ
  // ruleid: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with AUTH but no Multi-AZ',
    engine: 'redis',
    cacheNodeType: 'cache.t3.medium',
    numCacheClusters: 2,
    authToken: 'MySecurePassword123', // Redis AUTH enabled
    transitEncryptionEnabled: true, // Required for AUTH
    automaticFailoverEnabled: false, // But Multi-AZ disabled
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating ElastiCache Redis cluster with cluster mode but no Multi-AZ
  // ruleid: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with cluster mode but no Multi-AZ',
    engine: 'redis',
    cacheNodeType: 'cache.m5.large',
    numNodeGroups: 2, // Cluster mode enabled
    replicasPerNodeGroup: 1,
    automaticFailoverEnabled: false, // But Multi-AZ disabled
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Creating ElastiCache Redis cluster with backup configuration but no Multi-AZ
  // ruleid: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with backup but no Multi-AZ',
    engine: 'redis',
    cacheNodeType: 'cache.t3.medium',
    numCacheClusters: 2,
    snapshotRetentionLimit: 7, // Backup retention of 7 days
    snapshotWindow: '05:00-09:00', // Backup window
    automaticFailoverEnabled: false, // But Multi-AZ disabled
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating ElastiCache Redis cluster with maintenance window but no Multi-AZ
  // ruleid: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with maintenance window but no Multi-AZ',
    engine: 'redis',
    cacheNodeType: 'cache.t3.medium',
    numCacheClusters: 2,
    preferredMaintenanceWindow: 'sun:23:00-mon:01:30', // Maintenance window
    automaticFailoverEnabled: false, // But Multi-AZ disabled
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating ElastiCache Redis cluster with parameter group but no Multi-AZ
  const parameterGroup = new elasticache.CfnParameterGroup(scope, 'RedisParams', {
    cacheParameterGroupFamily: 'redis6.x',
    description: 'Custom Redis parameters',
    properties: {
      'maxmemory-policy': 'volatile-lru',
    },
  });
  
  // ruleid: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with parameter group but no Multi-AZ',
    engine: 'redis',
    cacheNodeType: 'cache.t3.medium',
    numCacheClusters: 2,
    cacheParameterGroupName: parameterGroup.ref,
    automaticFailoverEnabled: false, // But Multi-AZ disabled
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating ElastiCache Redis cluster with security group but no Multi-AZ
  const vpc = new ec2.Vpc(scope, 'VPC');
  const securityGroup = new ec2.SecurityGroup(scope, 'RedisSecurityGroup', {
    vpc,
    description: 'Security group for Redis cluster',
  });
  
  // ruleid: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with security group but no Multi-AZ',
    engine: 'redis',
    cacheNodeType: 'cache.t3.medium',
    numCacheClusters: 2,
    securityGroupIds: [securityGroup.securityGroupId],
    automaticFailoverEnabled: false, // But Multi-AZ disabled
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating ElastiCache Redis cluster with tags but no Multi-AZ
  // ruleid: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with tags but no Multi-AZ',
    engine: 'redis',
    cacheNodeType: 'cache.t3.medium',
    numCacheClusters: 2,
    tags: [
      { key: 'Environment', value: 'Production' },
      { key: 'Owner', value: 'DataTeam' },
    ],
    automaticFailoverEnabled: false, // But Multi-AZ disabled
  });
}
// {/fact}

// TRUE NEGATIVES (Secure cases)

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating ElastiCache Redis cluster with Multi-AZ enabled
  // ok: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with Multi-AZ',
    engine: 'redis',
    cacheNodeType: 'cache.t3.small',
    numCacheClusters: 2,
    automaticFailoverEnabled: true, // Multi-AZ enabled
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Creating ElastiCache Redis cluster with explicit Multi-AZ enabled
  // ok: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with explicit Multi-AZ enabled',
    engine: 'redis',
    cacheNodeType: 'cache.t3.medium',
    numCacheClusters: 3,
    automaticFailoverEnabled: true,
    multiAzEnabled: true,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Creating ElastiCache Redis cluster with Multi-AZ and encryption
  const vpc = new ec2.Vpc(scope, 'VPC');
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'SubnetGroup', {
    description: 'Subnet group for Redis',
    subnetIds: vpc.privateSubnets.map(subnet => subnet.subnetId),
  });
  
  // ok: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with Multi-AZ and encryption',
    engine: 'redis',
    cacheNodeType: 'cache.m5.large',
    numCacheClusters: 2,
    cacheSubnetGroupName: subnetGroup.ref,
    automaticFailoverEnabled: true, // Multi-AZ enabled
    atRestEncryptionEnabled: true, // Encryption at rest
    transitEncryptionEnabled: true, // Encryption in transit
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_4(scope: Construct, stackProps: cdk.StackProps) {
  // Creating ElastiCache Redis cluster with conditional Multi-AZ always enabled
  const isProduction = stackProps.tags?.['Environment'] === 'production';
  const nodeType = isProduction ? 'cache.r5.large' : 'cache.t3.medium';
  
  // ok: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with conditional node type but Multi-AZ always enabled',
    engine: 'redis',
    cacheNodeType: nodeType,
    numCacheClusters: 2,
    automaticFailoverEnabled: true, // Multi-AZ always enabled
    multiAzEnabled: true,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Creating ElastiCache Redis cluster with cluster mode and Multi-AZ
  // ok: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with cluster mode and Multi-AZ',
    engine: 'redis',
    cacheNodeType: 'cache.m5.large',
    numNodeGroups: 2, // Cluster mode enabled
    replicasPerNodeGroup: 1,
    automaticFailoverEnabled: true, // Multi-AZ enabled
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Creating ElastiCache Redis cluster with serverless configuration and Multi-AZ
  // ok: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnServerlessCache(scope, 'ServerlessRedisCache', {
    engine: 'redis',
    serverlessCacheName: 'my-serverless-redis',
    multiAzEnabled: true, // Multi-AZ enabled for serverless
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_7(scope: Construct) {
  const props = {
    replicationGroupDescription: 'Redis cluster with props object and Multi-AZ',
    engine: 'redis',
    cacheNodeType: 'cache.t3.small',
    numCacheClusters: 2,
    automaticFailoverEnabled: true, // Multi-AZ enabled
  };
  
  // ok: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', props);
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Creating ElastiCache Redis cluster with encryption and Multi-AZ
  // ok: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with encryption and Multi-AZ',
    engine: 'redis',
    cacheNodeType: 'cache.t3.medium',
    numCacheClusters: 2,
    atRestEncryptionEnabled: true, // Encryption enabled
    transitEncryptionEnabled: true, // Encryption in transit enabled
    automaticFailoverEnabled: true, // Multi-AZ enabled
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Creating ElastiCache Redis cluster with Redis AUTH and Multi-AZ
  // ok: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with AUTH and Multi-AZ',
    engine: 'redis',
    cacheNodeType: 'cache.t3.medium',
    numCacheClusters: 2,
    authToken: 'MySecurePassword123', // Redis AUTH enabled
    transitEncryptionEnabled: true, // Required for AUTH
    automaticFailoverEnabled: true, // Multi-AZ enabled
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Creating ElastiCache Redis cluster with backup configuration and Multi-AZ
  // ok: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with backup and Multi-AZ',
    engine: 'redis',
    cacheNodeType: 'cache.t3.medium',
    numCacheClusters: 2,
    snapshotRetentionLimit: 7, // Backup retention of 7 days
    snapshotWindow: '05:00-09:00', // Backup window
    automaticFailoverEnabled: true, // Multi-AZ enabled
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Creating ElastiCache Redis cluster with maintenance window and Multi-AZ
  // ok: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with maintenance window and Multi-AZ',
    engine: 'redis',
    cacheNodeType: 'cache.t3.medium',
    numCacheClusters: 2,
    preferredMaintenanceWindow: 'sun:23:00-mon:01:30', // Maintenance window
    automaticFailoverEnabled: true, // Multi-AZ enabled
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Creating ElastiCache Redis cluster with parameter group and Multi-AZ
  const parameterGroup = new elasticache.CfnParameterGroup(scope, 'RedisParams', {
    cacheParameterGroupFamily: 'redis6.x',
    description: 'Custom Redis parameters',
    properties: {
      'maxmemory-policy': 'volatile-lru',
    },
  });
  
  // ok: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with parameter group and Multi-AZ',
    engine: 'redis',
    cacheNodeType: 'cache.t3.medium',
    numCacheClusters: 2,
    cacheParameterGroupName: parameterGroup.ref,
    automaticFailoverEnabled: true, // Multi-AZ enabled
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Creating ElastiCache Redis cluster with security group and Multi-AZ
  const vpc = new ec2.Vpc(scope, 'VPC');
  const securityGroup = new ec2.SecurityGroup(scope, 'RedisSecurityGroup', {
    vpc,
    description: 'Security group for Redis cluster',
  });
  
  // ok: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with security group and Multi-AZ',
    engine: 'redis',
    cacheNodeType: 'cache.t3.medium',
    numCacheClusters: 2,
    securityGroupIds: [securityGroup.securityGroupId],
    automaticFailoverEnabled: true, // Multi-AZ enabled
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Creating ElastiCache Redis cluster with tags and Multi-AZ
  // ok: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with tags and Multi-AZ',
    engine: 'redis',
    cacheNodeType: 'cache.t3.medium',
    numCacheClusters: 2,
    tags: [
      { key: 'Environment', value: 'Production' },
      { key: 'Owner', value: 'DataTeam' },
    ],
    automaticFailoverEnabled: true, // Multi-AZ enabled
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Using higher-level construct that defaults to Multi-AZ
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_elasticache_missing_multiaz_encryption
  new elasticache.CfnReplicationGroup(scope, 'RedisCluster', {
    replicationGroupDescription: 'Redis cluster with Multi-AZ',
    engine: 'redis',
    cacheNodeType: 'cache.t3.medium',
    numCacheClusters: 3,
    automaticFailoverEnabled: true, // Multi-AZ enabled
    multiAzEnabled: true, // Explicitly enabled
    atRestEncryptionEnabled: true, // With encryption
  });
}
// {/fact}