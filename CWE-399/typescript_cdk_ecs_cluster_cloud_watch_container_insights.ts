import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';

// True Positive Examples (Vulnerable Code)

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating an ECS cluster with containerInsights explicitly set to false
  // ruleid: typescript_cdk_ecs_cluster_cloud_watch_container_insights
  const cluster = new ecs.Cluster(scope, 'MyCluster', {
    containerInsights: false,
    vpc: new ec2.Vpc(scope, 'MyVpc'),
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  
  // Creating an ECS cluster with containerInsights explicitly disabled
  // ruleid: typescript_cdk_ecs_cluster_cloud_watch_container_insights
  new ecs.Cluster(scope, 'ProductionCluster', {
    clusterName: 'production-cluster',
    containerInsights: false,
    vpc: vpc,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  const clusterProps: ecs.ClusterProps = {
    containerInsights: false,
    vpc: vpc,
  };
  
  // Using props object with containerInsights set to false
  // ruleid: typescript_cdk_ecs_cluster_cloud_watch_container_insights
  const cluster = new ecs.Cluster(scope, 'HighTrafficCluster', clusterProps);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  const enableInsights = false;
  
  // Using a variable to disable containerInsights
  // ruleid: typescript_cdk_ecs_cluster_cloud_watch_container_insights
  const cluster = new ecs.Cluster(scope, 'ApiCluster', {
    containerInsights: enableInsights,
    vpc: vpc,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_5(scope: Construct, env: string) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  
  // Conditionally disabling containerInsights based on environment
  if (env === 'dev') {
    // ruleid: typescript_cdk_ecs_cluster_cloud_watch_container_insights
    return new ecs.Cluster(scope, 'DevCluster', {
      containerInsights: false,
      vpc: vpc,
    });
  }
  return new ecs.Cluster(scope, 'ProdCluster', {
    containerInsights: true,
    vpc: vpc,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  
  // Creating multiple clusters with containerInsights disabled
  // ruleid: typescript_cdk_ecs_cluster_cloud_watch_container_insights
  const cluster1 = new ecs.Cluster(scope, 'Cluster1', {
    containerInsights: false,
    vpc: vpc,
  });
  
  // ruleid: typescript_cdk_ecs_cluster_cloud_watch_container_insights
  const cluster2 = new ecs.Cluster(scope, 'Cluster2', {
    containerInsights: false,
    vpc: vpc,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  const config = {
    insights: false,
  };
  
  // Using a configuration object to disable containerInsights
  // ruleid: typescript_cdk_ecs_cluster_cloud_watch_container_insights
  const cluster = new ecs.Cluster(scope, 'ConfigCluster', {
    containerInsights: config.insights,
    vpc: vpc,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  
  // Creating a cluster with containerInsights disabled and capacity providers
  // ruleid: typescript_cdk_ecs_cluster_cloud_watch_container_insights
  const cluster = new ecs.Cluster(scope, 'CapacityCluster', {
    containerInsights: false,
    vpc: vpc,
    enableFargateCapacityProviders: true,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  
  // Creating a cluster with containerInsights disabled and custom tags
  // ruleid: typescript_cdk_ecs_cluster_cloud_watch_container_insights
  const cluster = new ecs.Cluster(scope, 'TaggedCluster', {
    containerInsights: false,
    vpc: vpc,
  });
  
  cdk.Tags.of(cluster).add('Environment', 'Production');
  cdk.Tags.of(cluster).add('CostCenter', '12345');
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  
  function createCluster(name: string) {
    // Function that creates a cluster with containerInsights disabled
    // ruleid: typescript_cdk_ecs_cluster_cloud_watch_container_insights
    return new ecs.Cluster(scope, name, {
      containerInsights: false,
      vpc: vpc,
    });
  }
  
  const cluster = createCluster('HelperFunctionCluster');
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  
  // Creating a cluster with containerInsights disabled and adding a service
  // ruleid: typescript_cdk_ecs_cluster_cloud_watch_container_insights
  const cluster = new ecs.Cluster(scope, 'ServiceCluster', {
    containerInsights: false,
    vpc: vpc,
  });
  
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'TaskDef');
  new ecs.FargateService(scope, 'Service', {
    cluster: cluster,
    taskDefinition: taskDefinition,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  
  // Using a ternary operator to disable containerInsights
  const isProd = false;
  
  // ruleid: typescript_cdk_ecs_cluster_cloud_watch_container_insights
  const cluster = new ecs.Cluster(scope, 'TernaryCluster', {
    containerInsights: isProd ? true : false,
    vpc: vpc,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  
  // Creating a cluster with containerInsights disabled and default capacity
  // ruleid: typescript_cdk_ecs_cluster_cloud_watch_container_insights
  const cluster = new ecs.Cluster(scope, 'DefaultCapacityCluster', {
    containerInsights: false,
    vpc: vpc,
    defaultCloudMapNamespace: {
      name: 'service.local',
    },
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  
  // Creating a cluster with containerInsights disabled in a loop
  for (let i = 0; i < 3; i++) {
    // ruleid: typescript_cdk_ecs_cluster_cloud_watch_container_insights
    new ecs.Cluster(scope, `LoopCluster${i}`, {
      containerInsights: false,
      vpc: vpc,
    });
  }
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  
  // Creating a cluster with containerInsights disabled and custom IAM role
  const role = new iam.Role(scope, 'ClusterRole', {
    assumedBy: new iam.ServicePrincipal('ecs.amazonaws.com'),
  });
  
  // ruleid: typescript_cdk_ecs_cluster_cloud_watch_container_insights
  const cluster = new ecs.Cluster(scope, 'RoleCluster', {
    containerInsights: false,
    vpc: vpc,
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=object-presence@v1.0 defects=0}
function good_case_1(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  
  // Creating an ECS cluster with containerInsights explicitly enabled
  // ok: typescript_cdk_ecs_cluster_cloud_watch_container_insights
  const cluster = new ecs.Cluster(scope, 'MyCluster', {
    containerInsights: true,
    vpc: vpc,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_2(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  
  // Creating an ECS cluster with default containerInsights (which is enabled by default)
  // ok: typescript_cdk_ecs_cluster_cloud_watch_container_insights
  const cluster = new ecs.Cluster(scope, 'DefaultCluster', {
    vpc: vpc,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_3(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  const clusterProps: ecs.ClusterProps = {
    containerInsights: true,
    vpc: vpc,
  };
  
  // Using props object with containerInsights set to true
  // ok: typescript_cdk_ecs_cluster_cloud_watch_container_insights
  const cluster = new ecs.Cluster(scope, 'PropsCluster', clusterProps);
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_4(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  const enableInsights = true;
  
  // Using a variable to enable containerInsights
  // ok: typescript_cdk_ecs_cluster_cloud_watch_container_insights
  const cluster = new ecs.Cluster(scope, 'VarCluster', {
    containerInsights: enableInsights,
    vpc: vpc,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_5(scope: Construct, env: string) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  
  // Always enabling containerInsights regardless of environment
  if (env === 'dev') {
    // ok: typescript_cdk_ecs_cluster_cloud_watch_container_insights
    return new ecs.Cluster(scope, 'DevCluster', {
      containerInsights: true,
      vpc: vpc,
    });
  }
  // ok: typescript_cdk_ecs_cluster_cloud_watch_container_insights
  return new ecs.Cluster(scope, 'ProdCluster', {
    containerInsights: true,
    vpc: vpc,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_6(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  
  // Creating multiple clusters with containerInsights enabled
  // ok: typescript_cdk_ecs_cluster_cloud_watch_container_insights
  const cluster1 = new ecs.Cluster(scope, 'Cluster1', {
    containerInsights: true,
    vpc: vpc,
  });
  
  // ok: typescript_cdk_ecs_cluster_cloud_watch_container_insights
  const cluster2 = new ecs.Cluster(scope, 'Cluster2', {
    containerInsights: true,
    vpc: vpc,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_7(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  const config = {
    insights: true,
  };
  
  // Using a configuration object to enable containerInsights
  // ok: typescript_cdk_ecs_cluster_cloud_watch_container_insights
  const cluster = new ecs.Cluster(scope, 'ConfigCluster', {
    containerInsights: config.insights,
    vpc: vpc,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_8(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  
  // Creating a cluster with containerInsights enabled and capacity providers
  // ok: typescript_cdk_ecs_cluster_cloud_watch_container_insights
  const cluster = new ecs.Cluster(scope, 'CapacityCluster', {
    containerInsights: true,
    vpc: vpc,
    enableFargateCapacityProviders: true,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_9(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  
  // Creating a cluster with containerInsights enabled and custom tags
  // ok: typescript_cdk_ecs_cluster_cloud_watch_container_insights
  const cluster = new ecs.Cluster(scope, 'TaggedCluster', {
    containerInsights: true,
    vpc: vpc,
  });
  
  cdk.Tags.of(cluster).add('Environment', 'Production');
  cdk.Tags.of(cluster).add('CostCenter', '12345');
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_10(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  
  function createCluster(name: string) {
    // Function that creates a cluster with containerInsights enabled
    // ok: typescript_cdk_ecs_cluster_cloud_watch_container_insights
    return new ecs.Cluster(scope, name, {
      containerInsights: true,
      vpc: vpc,
    });
  }
  
  const cluster = createCluster('HelperFunctionCluster');
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_11(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  
  // Creating a cluster with containerInsights enabled and adding a service
  // ok: typescript_cdk_ecs_cluster_cloud_watch_container_insights
  const cluster = new ecs.Cluster(scope, 'ServiceCluster', {
    containerInsights: true,
    vpc: vpc,
  });
  
  const taskDefinition = new ecs.FargateTaskDefinition(scope, 'TaskDef');
  new ecs.FargateService(scope, 'Service', {
    cluster: cluster,
    taskDefinition: taskDefinition,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_12(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  
  // Using a ternary operator to enable containerInsights
  const isProd = true;
  
  // ok: typescript_cdk_ecs_cluster_cloud_watch_container_insights
  const cluster = new ecs.Cluster(scope, 'TernaryCluster', {
    containerInsights: isProd ? true : true, // Always true regardless of condition
    vpc: vpc,
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_13(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  
  // Creating a cluster with containerInsights enabled and default capacity
  // ok: typescript_cdk_ecs_cluster_cloud_watch_container_insights
  const cluster = new ecs.Cluster(scope, 'DefaultCapacityCluster', {
    containerInsights: true,
    vpc: vpc,
    defaultCloudMapNamespace: {
      name: 'service.local',
    },
  });
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_14(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  
  // Creating clusters with containerInsights enabled in a loop
  for (let i = 0; i < 3; i++) {
    // ok: typescript_cdk_ecs_cluster_cloud_watch_container_insights
    new ecs.Cluster(scope, `LoopCluster${i}`, {
      containerInsights: true,
      vpc: vpc,
    });
  }
}
// {/fact}

// {fact rule=object-presence@v1.0 defects=0}
function good_case_15(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'MyVpc');
  
  // Creating a cluster with containerInsights enabled and custom IAM role
  const role = new iam.Role(scope, 'ClusterRole', {
    assumedBy: new iam.ServicePrincipal('ecs.amazonaws.com'),
  });
  
  // ok: typescript_cdk_ecs_cluster_cloud_watch_container_insights
  const cluster = new ecs.Cluster(scope, 'RoleCluster', {
    containerInsights: true,
    vpc: vpc,
  });
}
// {/fact}