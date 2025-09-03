import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as docdb from 'aws-cdk-lib/aws-docdb';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as kms from 'aws-cdk-lib/aws-kms';

// True Positives (Vulnerable Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_document_db_cluster_encryption_at_rest
  new docdb.DatabaseCluster(scope, 'DocDBCluster1', {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.unsafePlainText('password'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    vpc,
    // Missing storageEncrypted property
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_document_db_cluster_encryption_at_rest
  new docdb.DatabaseCluster(scope, 'DocDBCluster2', {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.unsafePlainText('password'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    vpc,
    storageEncrypted: false, // Explicitly disabled encryption
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const params = {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.unsafePlainText('password'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    vpc,
  };
  
  // ruleid: typescript_cdk_document_db_cluster_encryption_at_rest
  new docdb.DatabaseCluster(scope, 'DocDBCluster3', params);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  let encryptionEnabled = false;
  
  // ruleid: typescript_cdk_document_db_cluster_encryption_at_rest
  new docdb.DatabaseCluster(scope, 'DocDBCluster4', {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.unsafePlainText('password'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    vpc,
    storageEncrypted: encryptionEnabled, // Variable set to false
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const clusterParams = {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.unsafePlainText('password'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    vpc,
    storageEncrypted: false,
  };
  
  // ruleid: typescript_cdk_document_db_cluster_encryption_at_rest
  new docdb.DatabaseCluster(scope, 'DocDBCluster5', clusterParams);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  function createCluster() {
    // ruleid: typescript_cdk_document_db_cluster_encryption_at_rest
    return new docdb.DatabaseCluster(scope, 'DocDBCluster6', {
      masterUser: {
        username: 'admin',
        password: cdk.SecretValue.unsafePlainText('password'),
      },
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      vpc,
    });
  }
  
  createCluster();
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const shouldEncrypt = () => false;
  
  // ruleid: typescript_cdk_document_db_cluster_encryption_at_rest
  new docdb.DatabaseCluster(scope, 'DocDBCluster7', {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.unsafePlainText('password'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    vpc,
    storageEncrypted: shouldEncrypt(), // Function returns false
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const config = {
    encrypt: false,
    username: 'admin',
    password: 'password',
  };
  
  // ruleid: typescript_cdk_document_db_cluster_encryption_at_rest
  new docdb.DatabaseCluster(scope, 'DocDBCluster8', {
    masterUser: {
      username: config.username,
      password: cdk.SecretValue.unsafePlainText(config.password),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    vpc,
    storageEncrypted: config.encrypt, // Config value is false
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_document_db_cluster_encryption_at_rest
  const cluster = new docdb.DatabaseCluster(scope, 'DocDBCluster9', {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.unsafePlainText('password'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    vpc,
  });
  
  // Adding tags but not encryption
  cdk.Tags.of(cluster).add('Environment', 'Production');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const options = {
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    vpc,
  };
  
  // ruleid: typescript_cdk_document_db_cluster_encryption_at_rest
  new docdb.DatabaseCluster(scope, 'DocDBCluster10', {
    ...options,
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.unsafePlainText('password'),
    },
    // No encryption configuration in spread or directly
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const encryptionConfig = {
    // Empty object, no encryption settings
  };
  
  // ruleid: typescript_cdk_document_db_cluster_encryption_at_rest
  new docdb.DatabaseCluster(scope, 'DocDBCluster11', {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.unsafePlainText('password'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    vpc,
    ...encryptionConfig, // Empty object doesn't add encryption
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_document_db_cluster_encryption_at_rest
  const cluster = new docdb.DatabaseCluster(scope, 'DocDBCluster12', {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.unsafePlainText('password'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    vpc,
    // Missing encryption
  });
  
  // Adding a parameter group but not encryption
  cluster.addRotationSingleUser();
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const isProduction = false;
  
  // ruleid: typescript_cdk_document_db_cluster_encryption_at_rest
  new docdb.DatabaseCluster(scope, 'DocDBCluster13', {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.unsafePlainText('password'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    vpc,
    storageEncrypted: isProduction, // Variable is false
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_document_db_cluster_encryption_at_rest
  new docdb.DatabaseCluster(scope, 'DocDBCluster14', {
    masterUser: {
      username: 'admin',
      secretName: '/docdb/admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    vpc,
    // Using secret manager for password but missing encryption
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const clusterProps = new docdb.DatabaseClusterProps();
  clusterProps.vpc = vpc;
  clusterProps.instanceType = ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM);
  clusterProps.vpcSubnets = { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS };
  clusterProps.masterUser = {
    username: 'admin',
    password: cdk.SecretValue.unsafePlainText('password'),
  };
  // Not setting storageEncrypted property
  
  // ruleid: typescript_cdk_document_db_cluster_encryption_at_rest
  new docdb.DatabaseCluster(scope, 'DocDBCluster15', clusterProps);
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_document_db_cluster_encryption_at_rest
  new docdb.DatabaseCluster(scope, 'DocDBCluster1', {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.unsafePlainText('password'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    vpc,
    storageEncrypted: true, // Encryption enabled
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const key = new kms.Key(scope, 'DocDBKey');
  
  // ok: typescript_cdk_document_db_cluster_encryption_at_rest
  new docdb.DatabaseCluster(scope, 'DocDBCluster2', {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.unsafePlainText('password'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    vpc,
    storageEncrypted: true,
    kmsKey: key, // Using custom KMS key for encryption
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const params = {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.unsafePlainText('password'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    vpc,
    storageEncrypted: true, // Encryption enabled in params
  };
  
  // ok: typescript_cdk_document_db_cluster_encryption_at_rest
  new docdb.DatabaseCluster(scope, 'DocDBCluster3', params);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  let encryptionEnabled = true;
  
  // ok: typescript_cdk_document_db_cluster_encryption_at_rest
  new docdb.DatabaseCluster(scope, 'DocDBCluster4', {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.unsafePlainText('password'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    vpc,
    storageEncrypted: encryptionEnabled, // Variable set to true
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const clusterParams = {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.unsafePlainText('password'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    vpc,
    storageEncrypted: true,
  };
  
  // ok: typescript_cdk_document_db_cluster_encryption_at_rest
  new docdb.DatabaseCluster(scope, 'DocDBCluster5', clusterParams);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  function createCluster() {
    // ok: typescript_cdk_document_db_cluster_encryption_at_rest
    return new docdb.DatabaseCluster(scope, 'DocDBCluster6', {
      masterUser: {
        username: 'admin',
        password: cdk.SecretValue.unsafePlainText('password'),
      },
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      vpc,
      storageEncrypted: true, // Encryption enabled
    });
  }
  
  createCluster();
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const shouldEncrypt = () => true;
  
  // ok: typescript_cdk_document_db_cluster_encryption_at_rest
  new docdb.DatabaseCluster(scope, 'DocDBCluster7', {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.unsafePlainText('password'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    vpc,
    storageEncrypted: shouldEncrypt(), // Function returns true
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const key = new kms.Key(scope, 'DocDBKey');
  
  const config = {
    encrypt: true,
    username: 'admin',
    password: 'password',
  };
  
  // ok: typescript_cdk_document_db_cluster_encryption_at_rest
  new docdb.DatabaseCluster(scope, 'DocDBCluster8', {
    masterUser: {
      username: config.username,
      password: cdk.SecretValue.unsafePlainText(config.password),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    vpc,
    storageEncrypted: config.encrypt, // Config value is true
    kmsKey: key,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_document_db_cluster_encryption_at_rest
  const cluster = new docdb.DatabaseCluster(scope, 'DocDBCluster9', {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.unsafePlainText('password'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    vpc,
    storageEncrypted: true, // Encryption enabled
  });
  
  cdk.Tags.of(cluster).add('Environment', 'Production');
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const options = {
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    vpc,
    storageEncrypted: true, // Encryption in options
  };
  
  // ok: typescript_cdk_document_db_cluster_encryption_at_rest
  new docdb.DatabaseCluster(scope, 'DocDBCluster10', {
    ...options,
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.unsafePlainText('password'),
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const encryptionConfig = {
    storageEncrypted: true,
  };
  
  // ok: typescript_cdk_document_db_cluster_encryption_at_rest
  new docdb.DatabaseCluster(scope, 'DocDBCluster11', {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.unsafePlainText('password'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    vpc,
    ...encryptionConfig, // Object with encryption enabled
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const key = kms.Key.fromKeyArn(scope, 'ImportedKey', 'arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab');
  
  // ok: typescript_cdk_document_db_cluster_encryption_at_rest
  const cluster = new docdb.DatabaseCluster(scope, 'DocDBCluster12', {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.unsafePlainText('password'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    vpc,
    storageEncrypted: true, // Encryption enabled
    kmsKey: key, // Using imported KMS key
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const isProduction = true;
  
  // ok: typescript_cdk_document_db_cluster_encryption_at_rest
  new docdb.DatabaseCluster(scope, 'DocDBCluster13', {
    masterUser: {
      username: 'admin',
      password: cdk.SecretValue.unsafePlainText('password'),
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    vpc,
    storageEncrypted: isProduction, // Variable is true
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_document_db_cluster_encryption_at_rest
  new docdb.DatabaseCluster(scope, 'DocDBCluster14', {
    masterUser: {
      username: 'admin',
      secretName: '/docdb/admin',
    },
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    vpc,
    storageEncrypted: true, // Using secret manager for password and encryption enabled
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const clusterProps = new docdb.DatabaseClusterProps();
  clusterProps.vpc = vpc;
  clusterProps.instanceType = ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM);
  clusterProps.vpcSubnets = { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS };
  clusterProps.masterUser = {
    username: 'admin',
    password: cdk.SecretValue.unsafePlainText('password'),
  };
  clusterProps.storageEncrypted = true; // Setting storageEncrypted to true
  
  // ok: typescript_cdk_document_db_cluster_encryption_at_rest
  new docdb.DatabaseCluster(scope, 'DocDBCluster15', clusterProps);
}
// {/fact}