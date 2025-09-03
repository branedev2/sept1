import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as dax from 'aws-cdk-lib/aws-dax';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';

// True Positive Examples (Vulnerable Code)

// {fact rule=divided-by-zero@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating a DAX cluster without encryption
  // ruleid: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster1', {
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    sseSpecification: {
      sseEnabled: false
    }
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating a DAX cluster with explicitly disabled encryption
  const role = new iam.Role(scope, 'DaxRole', {
    assumedBy: new iam.ServicePrincipal('dax.amazonaws.com')
  });
  
  // ruleid: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster2', {
    iamRoleArn: role.roleArn,
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    sseSpecification: {
      sseEnabled: false
    },
    description: 'DAX cluster for production'
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Creating a DAX cluster with encryption disabled in a variable
  const sseConfig = {
    sseEnabled: false
  };
  
  // ruleid: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster3', {
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    sseSpecification: sseConfig
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=1}
function bad_case_4(scope: Construct, vpc: ec2.Vpc) {
  // Creating a DAX cluster with subnet group but no encryption
  const subnetGroup = new dax.CfnSubnetGroup(scope, 'DaxSubnetGroup', {
    subnetIds: vpc.privateSubnets.map(subnet => subnet.subnetId),
    description: 'Subnet group for DAX cluster'
  });
  
  // ruleid: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster4', {
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    subnetGroupName: subnetGroup.ref,
    sseSpecification: {
      sseEnabled: false
    }
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Creating a DAX cluster with encryption disabled and security groups
  const securityGroup = new ec2.SecurityGroup(scope, 'DaxSG', {
    vpc: new ec2.Vpc(scope, 'VPC'),
    description: 'Security group for DAX cluster'
  });
  
  // ruleid: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster5', {
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    securityGroupIds: [securityGroup.securityGroupId],
    sseSpecification: {
      sseEnabled: false
    }
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Creating a DAX cluster with encryption disabled and parameter group
  const parameterGroup = new dax.CfnParameterGroup(scope, 'DaxPG', {
    parameterNameValues: {
      'query-ttl-millis': '60000',
      'record-ttl-millis': '100000'
    },
    description: 'Parameter group for DAX cluster'
  });
  
  // ruleid: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster6', {
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    parameterGroupName: parameterGroup.ref,
    sseSpecification: {
      sseEnabled: false
    }
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Creating a DAX cluster with encryption disabled and availability zones
  // ruleid: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster7', {
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    availabilityZones: ['us-east-1a', 'us-east-1b', 'us-east-1c'],
    sseSpecification: {
      sseEnabled: false
    }
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Creating a DAX cluster with encryption disabled and notification topic
  // ruleid: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster8', {
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    notificationTopicArn: 'arn:aws:sns:us-east-1:123456789012:dax-notifications',
    sseSpecification: {
      sseEnabled: false
    }
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Creating a DAX cluster with encryption disabled and maintenance window
  // ruleid: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster9', {
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    preferredMaintenanceWindow: 'sun:05:00-sun:09:00',
    sseSpecification: {
      sseEnabled: false
    }
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating a DAX cluster with encryption disabled and tags
  // ruleid: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster10', {
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    tags: [
      { key: 'Environment', value: 'Production' },
      { key: 'Owner', value: 'DataTeam' }
    ],
    sseSpecification: {
      sseEnabled: false
    }
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Creating a DAX cluster with encryption disabled and cluster name
  // ruleid: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster11', {
    clusterName: 'production-dax-cluster',
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    sseSpecification: {
      sseEnabled: false
    }
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating a DAX cluster with encryption disabled and custom port
  // ruleid: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster12', {
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    port: 9111,
    sseSpecification: {
      sseEnabled: false
    }
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating a DAX cluster with encryption disabled in a conditional
  const isProduction = false;
  const sseConfig = {
    sseEnabled: isProduction ? true : false
  };
  
  // ruleid: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster13', {
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    sseSpecification: sseConfig
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating a DAX cluster with encryption disabled and auto discovery
  // ruleid: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster14', {
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    clusterEndpointEncryptionType: 'NONE',
    sseSpecification: {
      sseEnabled: false
    }
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating a DAX cluster with encryption disabled and DynamoDB table
  const table = new dynamodb.Table(scope, 'Table', {
    partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
    billingMode: dynamodb.BillingMode.PAY_PER_REQUEST
  });
  
  // ruleid: typescript_cdk_dax_missing_encryption
  const daxCluster = new dax.CfnCluster(scope, 'DaxCluster15', {
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    sseSpecification: {
      sseEnabled: false
    }
  });
  
  // Grant permissions to access the table
  table.grantReadWriteData(new iam.Role(scope, 'DaxAccessRole', {
    assumedBy: new iam.ServicePrincipal('dax.amazonaws.com')
  }));
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=divided-by-zero@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating a DAX cluster with encryption enabled
  // ok: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster1', {
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    sseSpecification: {
      sseEnabled: true
    }
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Creating a DAX cluster with explicitly enabled encryption
  const role = new iam.Role(scope, 'DaxRole', {
    assumedBy: new iam.ServicePrincipal('dax.amazonaws.com')
  });
  
  // ok: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster2', {
    iamRoleArn: role.roleArn,
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    sseSpecification: {
      sseEnabled: true
    },
    description: 'DAX cluster for production'
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Creating a DAX cluster with encryption enabled in a variable
  const sseConfig = {
    sseEnabled: true
  };
  
  // ok: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster3', {
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    sseSpecification: sseConfig
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=0}
function good_case_4(scope: Construct, vpc: ec2.Vpc) {
  // Creating a DAX cluster with subnet group and encryption
  const subnetGroup = new dax.CfnSubnetGroup(scope, 'DaxSubnetGroup', {
    subnetIds: vpc.privateSubnets.map(subnet => subnet.subnetId),
    description: 'Subnet group for DAX cluster'
  });
  
  // ok: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster4', {
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    subnetGroupName: subnetGroup.ref,
    sseSpecification: {
      sseEnabled: true
    }
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Creating a DAX cluster with encryption enabled and security groups
  const securityGroup = new ec2.SecurityGroup(scope, 'DaxSG', {
    vpc: new ec2.Vpc(scope, 'VPC'),
    description: 'Security group for DAX cluster'
  });
  
  // ok: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster5', {
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    securityGroupIds: [securityGroup.securityGroupId],
    sseSpecification: {
      sseEnabled: true
    }
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Creating a DAX cluster with encryption enabled and parameter group
  const parameterGroup = new dax.CfnParameterGroup(scope, 'DaxPG', {
    parameterNameValues: {
      'query-ttl-millis': '60000',
      'record-ttl-millis': '100000'
    },
    description: 'Parameter group for DAX cluster'
  });
  
  // ok: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster6', {
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    parameterGroupName: parameterGroup.ref,
    sseSpecification: {
      sseEnabled: true
    }
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Creating a DAX cluster with encryption enabled and availability zones
  // ok: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster7', {
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    availabilityZones: ['us-east-1a', 'us-east-1b', 'us-east-1c'],
    sseSpecification: {
      sseEnabled: true
    }
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Creating a DAX cluster with encryption enabled and notification topic
  // ok: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster8', {
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    notificationTopicArn: 'arn:aws:sns:us-east-1:123456789012:dax-notifications',
    sseSpecification: {
      sseEnabled: true
    }
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Creating a DAX cluster with encryption enabled and maintenance window
  // ok: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster9', {
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    preferredMaintenanceWindow: 'sun:05:00-sun:09:00',
    sseSpecification: {
      sseEnabled: true
    }
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Creating a DAX cluster with encryption enabled and tags
  // ok: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster10', {
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    tags: [
      { key: 'Environment', value: 'Production' },
      { key: 'Owner', value: 'DataTeam' }
    ],
    sseSpecification: {
      sseEnabled: true
    }
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Creating a DAX cluster with encryption enabled and cluster name
  // ok: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster11', {
    clusterName: 'production-dax-cluster',
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    sseSpecification: {
      sseEnabled: true
    }
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Creating a DAX cluster with encryption enabled and custom port
  // ok: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster12', {
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    port: 9111,
    sseSpecification: {
      sseEnabled: true
    }
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Creating a DAX cluster with encryption enabled in a conditional
  const isProduction = true;
  const sseConfig = {
    sseEnabled: isProduction ? true : false
  };
  
  // ok: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster13', {
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    sseSpecification: sseConfig
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Creating a DAX cluster with encryption enabled and auto discovery
  // ok: typescript_cdk_dax_missing_encryption
  new dax.CfnCluster(scope, 'DaxCluster14', {
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    clusterEndpointEncryptionType: 'TLS',
    sseSpecification: {
      sseEnabled: true
    }
  });
}
// {/fact}

// {fact rule=divided-by-zero@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Creating a DAX cluster with encryption enabled and DynamoDB table
  const table = new dynamodb.Table(scope, 'Table', {
    partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
    billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
    encryption: dynamodb.TableEncryption.AWS_MANAGED
  });
  
  // ok: typescript_cdk_dax_missing_encryption
  const daxCluster = new dax.CfnCluster(scope, 'DaxCluster15', {
    iamRoleArn: 'arn:aws:iam::123456789012:role/DaxRole',
    nodeType: 'dax.r4.large',
    replicationFactor: 3,
    sseSpecification: {
      sseEnabled: true
    }
  });
  
  // Grant permissions to access the table
  table.grantReadWriteData(new iam.Role(scope, 'DaxAccessRole', {
    assumedBy: new iam.ServicePrincipal('dax.amazonaws.com')
  }));
}
// {/fact}