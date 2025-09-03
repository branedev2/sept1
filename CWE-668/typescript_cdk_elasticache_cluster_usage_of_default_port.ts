import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as elasticache from 'aws-cdk-lib/aws-elasticache';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

class ElastiCacheTestStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Setup VPC for all examples
    const vpc = new ec2.Vpc(this, 'VPC', {
      maxAzs: 2
    });

    // Setup security group for all examples
    const securityGroup = new ec2.SecurityGroup(this, 'CacheSecurityGroup', {
      vpc,
      description: 'Security group for ElastiCache clusters',
      allowAllOutbound: true
    });
  }
}

// True Positive Examples (Vulnerable Code)

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Redis cluster with default port (6379)
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'RedisSubnetGroup', {
    description: 'Subnet group for Redis cluster',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  // ruleid: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnCacheCluster(scope, 'RedisCluster', {
    cacheNodeType: 'cache.t3.micro',
    engine: 'redis',
    numCacheNodes: 1,
    cacheSubnetGroupName: subnetGroup.ref,
    // Default Redis port 6379 is used implicitly
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Memcached cluster with default port (11211)
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'MemcachedSubnetGroup', {
    description: 'Subnet group for Memcached cluster',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  // ruleid: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnCacheCluster(scope, 'MemcachedCluster', {
    cacheNodeType: 'cache.t3.micro',
    engine: 'memcached',
    numCacheNodes: 2,
    cacheSubnetGroupName: subnetGroup.ref,
    // Default Memcached port 11211 is used implicitly
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Redis cluster with explicitly specified default port
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'ExplicitRedisSubnetGroup', {
    description: 'Subnet group for Redis cluster',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  // ruleid: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnCacheCluster(scope, 'ExplicitRedisCluster', {
    cacheNodeType: 'cache.t3.micro',
    engine: 'redis',
    numCacheNodes: 1,
    cacheSubnetGroupName: subnetGroup.ref,
    port: 6379, // Explicitly using default Redis port
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Memcached cluster with explicitly specified default port
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'ExplicitMemcachedSubnetGroup', {
    description: 'Subnet group for Memcached cluster',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  // ruleid: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnCacheCluster(scope, 'ExplicitMemcachedCluster', {
    cacheNodeType: 'cache.t3.micro',
    engine: 'memcached',
    numCacheNodes: 2,
    cacheSubnetGroupName: subnetGroup.ref,
    port: 11211, // Explicitly using default Memcached port
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Redis replication group with default port
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'RedisReplicationSubnetGroup', {
    description: 'Subnet group for Redis replication group',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  // ruleid: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnReplicationGroup(scope, 'RedisReplicationGroup', {
    replicationGroupDescription: 'Redis replication group',
    cacheNodeType: 'cache.t3.micro',
    engine: 'redis',
    numCacheClusters: 2,
    cacheSubnetGroupName: subnetGroup.ref,
    // Default Redis port 6379 is used implicitly
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Redis replication group with explicitly specified default port
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'ExplicitRedisReplicationSubnetGroup', {
    description: 'Subnet group for Redis replication group',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  // ruleid: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnReplicationGroup(scope, 'ExplicitRedisReplicationGroup', {
    replicationGroupDescription: 'Redis replication group',
    cacheNodeType: 'cache.t3.micro',
    engine: 'redis',
    numCacheClusters: 2,
    cacheSubnetGroupName: subnetGroup.ref,
    port: 6379, // Explicitly using default Redis port
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Redis cluster with default port using variable
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'VariableRedisSubnetGroup', {
    description: 'Subnet group for Redis cluster',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  const redisPort = 6379; // Default Redis port in a variable

  // ruleid: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnCacheCluster(scope, 'VariableRedisCluster', {
    cacheNodeType: 'cache.t3.micro',
    engine: 'redis',
    numCacheNodes: 1,
    cacheSubnetGroupName: subnetGroup.ref,
    port: redisPort, // Using default Redis port via variable
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Memcached cluster with default port using variable
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'VariableMemcachedSubnetGroup', {
    description: 'Subnet group for Memcached cluster',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  const memcachedPort = 11211; // Default Memcached port in a variable

  // ruleid: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnCacheCluster(scope, 'VariableMemcachedCluster', {
    cacheNodeType: 'cache.t3.micro',
    engine: 'memcached',
    numCacheNodes: 2,
    cacheSubnetGroupName: subnetGroup.ref,
    port: memcachedPort, // Using default Memcached port via variable
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Redis cluster with default port using constant
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'ConstantRedisSubnetGroup', {
    description: 'Subnet group for Redis cluster',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  const REDIS_DEFAULT_PORT = 6379;

  // ruleid: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnCacheCluster(scope, 'ConstantRedisCluster', {
    cacheNodeType: 'cache.t3.micro',
    engine: 'redis',
    numCacheNodes: 1,
    cacheSubnetGroupName: subnetGroup.ref,
    port: REDIS_DEFAULT_PORT, // Using default Redis port via constant
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Memcached cluster with default port using constant
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'ConstantMemcachedSubnetGroup', {
    description: 'Subnet group for Memcached cluster',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  const MEMCACHED_DEFAULT_PORT = 11211;

  // ruleid: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnCacheCluster(scope, 'ConstantMemcachedCluster', {
    cacheNodeType: 'cache.t3.micro',
    engine: 'memcached',
    numCacheNodes: 2,
    cacheSubnetGroupName: subnetGroup.ref,
    port: MEMCACHED_DEFAULT_PORT, // Using default Memcached port via constant
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Redis cluster with default port using computed value
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'ComputedRedisSubnetGroup', {
    description: 'Subnet group for Redis cluster',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  const basePort = 6000;
  const portOffset = 379;
  const computedPort = basePort + portOffset; // Equals 6379

  // ruleid: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnCacheCluster(scope, 'ComputedRedisCluster', {
    cacheNodeType: 'cache.t3.micro',
    engine: 'redis',
    numCacheNodes: 1,
    cacheSubnetGroupName: subnetGroup.ref,
    port: computedPort, // Using computed value that equals default Redis port
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Memcached cluster with default port using computed value
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'ComputedMemcachedSubnetGroup', {
    description: 'Subnet group for Memcached cluster',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  const basePort = 11000;
  const portOffset = 211;
  const computedPort = basePort + portOffset; // Equals 11211

  // ruleid: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnCacheCluster(scope, 'ComputedMemcachedCluster', {
    cacheNodeType: 'cache.t3.micro',
    engine: 'memcached',
    numCacheNodes: 2,
    cacheSubnetGroupName: subnetGroup.ref,
    port: computedPort, // Using computed value that equals default Memcached port
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Redis serverless cache with default port
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'ServerlessRedisSubnetGroup', {
    description: 'Subnet group for Redis serverless cache',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  // ruleid: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnServerlessCache(scope, 'ServerlessRedisCache', {
    engine: 'redis',
    serverlessCacheName: 'my-serverless-redis',
    subnetIds: ['subnet-12345', 'subnet-67890'],
    // Default Redis port 6379 is used implicitly
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Redis global replication group with default port
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'GlobalRedisSubnetGroup', {
    description: 'Subnet group for Redis global replication group',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  // ruleid: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnGlobalReplicationGroup(scope, 'GlobalRedisReplicationGroup', {
    globalReplicationGroupIdSuffix: 'global-redis',
    members: [{
      replicationGroupId: 'primary-redis-group',
      replicationGroupRegion: 'us-east-1',
      role: 'PRIMARY'
    }],
    // Default Redis port 6379 is used implicitly
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Redis cluster with default port using environment variable but still default
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'EnvVarRedisSubnetGroup', {
    description: 'Subnet group for Redis cluster',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  // Even though we're using an environment variable, it's still set to the default port
  const redisPort = process.env.REDIS_PORT || 6379;

  // ruleid: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnCacheCluster(scope, 'EnvVarRedisCluster', {
    cacheNodeType: 'cache.t3.micro',
    engine: 'redis',
    numCacheNodes: 1,
    cacheSubnetGroupName: subnetGroup.ref,
    port: redisPort, // Using environment variable that defaults to default Redis port
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=code-injection@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Redis cluster with non-default port
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'SecureRedisSubnetGroup', {
    description: 'Subnet group for Redis cluster',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  // ok: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnCacheCluster(scope, 'SecureRedisCluster', {
    cacheNodeType: 'cache.t3.micro',
    engine: 'redis',
    numCacheNodes: 1,
    cacheSubnetGroupName: subnetGroup.ref,
    port: 6380, // Using non-default port for Redis
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Memcached cluster with non-default port
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'SecureMemcachedSubnetGroup', {
    description: 'Subnet group for Memcached cluster',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  // ok: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnCacheCluster(scope, 'SecureMemcachedCluster', {
    cacheNodeType: 'cache.t3.micro',
    engine: 'memcached',
    numCacheNodes: 2,
    cacheSubnetGroupName: subnetGroup.ref,
    port: 11212, // Using non-default port for Memcached
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Redis replication group with non-default port
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'SecureRedisReplicationSubnetGroup', {
    description: 'Subnet group for Redis replication group',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  // ok: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnReplicationGroup(scope, 'SecureRedisReplicationGroup', {
    replicationGroupDescription: 'Redis replication group',
    cacheNodeType: 'cache.t3.micro',
    engine: 'redis',
    numCacheClusters: 2,
    cacheSubnetGroupName: subnetGroup.ref,
    port: 8379, // Using non-default port for Redis
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Redis cluster with non-default port using variable
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'SecureVariableRedisSubnetGroup', {
    description: 'Subnet group for Redis cluster',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  const secureRedisPort = 9736; // Non-default Redis port in a variable

  // ok: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnCacheCluster(scope, 'SecureVariableRedisCluster', {
    cacheNodeType: 'cache.t3.micro',
    engine: 'redis',
    numCacheNodes: 1,
    cacheSubnetGroupName: subnetGroup.ref,
    port: secureRedisPort, // Using non-default Redis port via variable
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Memcached cluster with non-default port using variable
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'SecureVariableMemcachedSubnetGroup', {
    description: 'Subnet group for Memcached cluster',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  const secureMemcachedPort = 21211; // Non-default Memcached port in a variable

  // ok: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnCacheCluster(scope, 'SecureVariableMemcachedCluster', {
    cacheNodeType: 'cache.t3.micro',
    engine: 'memcached',
    numCacheNodes: 2,
    cacheSubnetGroupName: subnetGroup.ref,
    port: secureMemcachedPort, // Using non-default Memcached port via variable
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Redis cluster with non-default port using constant
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'SecureConstantRedisSubnetGroup', {
    description: 'Subnet group for Redis cluster',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  const SECURE_REDIS_PORT = 7379;

  // ok: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnCacheCluster(scope, 'SecureConstantRedisCluster', {
    cacheNodeType: 'cache.t3.micro',
    engine: 'redis',
    numCacheNodes: 1,
    cacheSubnetGroupName: subnetGroup.ref,
    port: SECURE_REDIS_PORT, // Using non-default Redis port via constant
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Memcached cluster with non-default port using constant
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'SecureConstantMemcachedSubnetGroup', {
    description: 'Subnet group for Memcached cluster',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  const SECURE_MEMCACHED_PORT = 12345;

  // ok: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnCacheCluster(scope, 'SecureConstantMemcachedCluster', {
    cacheNodeType: 'cache.t3.micro',
    engine: 'memcached',
    numCacheNodes: 2,
    cacheSubnetGroupName: subnetGroup.ref,
    port: SECURE_MEMCACHED_PORT, // Using non-default Memcached port via constant
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Redis cluster with non-default port using computed value
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'SecureComputedRedisSubnetGroup', {
    description: 'Subnet group for Redis cluster',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  const basePort = 7000;
  const portOffset = 379;
  const computedPort = basePort + portOffset; // Equals 7379

  // ok: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnCacheCluster(scope, 'SecureComputedRedisCluster', {
    cacheNodeType: 'cache.t3.micro',
    engine: 'redis',
    numCacheNodes: 1,
    cacheSubnetGroupName: subnetGroup.ref,
    port: computedPort, // Using computed value that equals non-default Redis port
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Memcached cluster with non-default port using computed value
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'SecureComputedMemcachedSubnetGroup', {
    description: 'Subnet group for Memcached cluster',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  const basePort = 12000;
  const portOffset = 211;
  const computedPort = basePort + portOffset; // Equals 12211

  // ok: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnCacheCluster(scope, 'SecureComputedMemcachedCluster', {
    cacheNodeType: 'cache.t3.micro',
    engine: 'memcached',
    numCacheNodes: 2,
    cacheSubnetGroupName: subnetGroup.ref,
    port: computedPort, // Using computed value that equals non-default Memcached port
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Redis serverless cache with non-default port
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'SecureServerlessRedisSubnetGroup', {
    description: 'Subnet group for Redis serverless cache',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  // ok: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnServerlessCache(scope, 'SecureServerlessRedisCache', {
    engine: 'redis',
    serverlessCacheName: 'my-secure-serverless-redis',
    subnetIds: ['subnet-12345', 'subnet-67890'],
    port: 8379, // Using non-default port for Redis
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Redis cluster with port from environment variable
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'EnvVarSecureRedisSubnetGroup', {
    description: 'Subnet group for Redis cluster',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  // Using environment variable with a secure default
  const redisPort = process.env.REDIS_PORT || 8379; // Non-default port as fallback

  // ok: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnCacheCluster(scope, 'EnvVarSecureRedisCluster', {
    cacheNodeType: 'cache.t3.micro',
    engine: 'redis',
    numCacheNodes: 1,
    cacheSubnetGroupName: subnetGroup.ref,
    port: redisPort, // Using environment variable with secure default
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Memcached cluster with port from environment variable
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'EnvVarSecureMemcachedSubnetGroup', {
    description: 'Subnet group for Memcached cluster',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  // Using environment variable with a secure default
  const memcachedPort = process.env.MEMCACHED_PORT || 12345; // Non-default port as fallback

  // ok: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnCacheCluster(scope, 'EnvVarSecureMemcachedCluster', {
    cacheNodeType: 'cache.t3.micro',
    engine: 'memcached',
    numCacheNodes: 2,
    cacheSubnetGroupName: subnetGroup.ref,
    port: memcachedPort, // Using environment variable with secure default
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Redis cluster with port from configuration
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'ConfigSecureRedisSubnetGroup', {
    description: 'Subnet group for Redis cluster',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  // Simulating a configuration system
  const config = {
    redisPort: 9736 // Non-default port from config
  };

  // ok: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnCacheCluster(scope, 'ConfigSecureRedisCluster', {
    cacheNodeType: 'cache.t3.micro',
    engine: 'redis',
    numCacheNodes: 1,
    cacheSubnetGroupName: subnetGroup.ref,
    port: config.redisPort, // Using non-default port from configuration
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Memcached cluster with port from configuration
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'ConfigSecureMemcachedSubnetGroup', {
    description: 'Subnet group for Memcached cluster',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  // Simulating a configuration system
  const config = {
    memcachedPort: 22422 // Non-default port from config
  };

  // ok: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnCacheCluster(scope, 'ConfigSecureMemcachedCluster', {
    cacheNodeType: 'cache.t3.micro',
    engine: 'memcached',
    numCacheNodes: 2,
    cacheSubnetGroupName: subnetGroup.ref,
    port: config.memcachedPort, // Using non-default port from configuration
  });
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Redis replication group with port from function
  const subnetGroup = new elasticache.CfnSubnetGroup(scope, 'FunctionSecureRedisSubnetGroup', {
    description: 'Subnet group for Redis replication group',
    subnetIds: ['subnet-12345', 'subnet-67890'],
  });

  // Function that returns a secure port
  const getSecurePort = (engine: string): number => {
    if (engine === 'redis') {
      return 7654; // Non-default Redis port
    } else if (engine === 'memcached') {
      return 22345; // Non-default Memcached port
    }
    return 9999; // Default fallback
  };

  // ok: typescript_cdk_elasticache_cluster_usage_of_default_port
  new elasticache.CfnReplicationGroup(scope, 'FunctionSecureRedisReplicationGroup', {
    replicationGroupDescription: 'Redis replication group',
    cacheNodeType: 'cache.t3.micro',
    engine: 'redis',
    numCacheClusters: 2,
    cacheSubnetGroupName: subnetGroup.ref,
    port: getSecurePort('redis'), // Using function to get non-default port
  });
}
// {/fact}