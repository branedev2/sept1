import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';

// True Positive Examples (Vulnerable Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_rds_missing_storage_encryption
  new rds.DatabaseInstance(stack, 'MyDatabase', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    storageEncrypted: false, // Explicitly setting encryption to false
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_rds_missing_storage_encryption
  new rds.DatabaseInstance(stack, 'DatabaseWithoutEncryption', {
    engine: rds.DatabaseInstanceEngine.postgres({
      version: rds.PostgresEngineVersion.VER_13_7
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    // No storageEncrypted property means it defaults to false
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  const dbSecurityGroup = new ec2.SecurityGroup(stack, 'DBSecurityGroup', { vpc });
  
  // ruleid: typescript_cdk_rds_missing_storage_encryption
  new rds.DatabaseCluster(stack, 'AuroraClusterUnencrypted', {
    engine: rds.DatabaseClusterEngine.auroraMysql({
      version: rds.AuroraMysqlEngineVersion.VER_3_02_0
    }),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
      securityGroups: [dbSecurityGroup],
    },
    storageEncrypted: false,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // Create a parameter group with custom settings
  const parameterGroup = new rds.ParameterGroup(stack, 'ParameterGroup', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28
    }),
    parameters: {
      'max_connections': '100',
      'character_set_server': 'utf8mb4',
    }
  });
  
  // ruleid: typescript_cdk_rds_missing_storage_encryption
  new rds.DatabaseInstance(stack, 'CustomParamDBUnencrypted', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    parameterGroup,
    storageEncrypted: false,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const secret = new secretsmanager.Secret(stack, 'DBCredentialsSecret', {
    secretName: 'db-credentials',
    generateSecretString: {
      secretStringTemplate: JSON.stringify({ username: 'admin' }),
      generateStringKey: 'password',
      excludePunctuation: true,
    },
  });
  
  // ruleid: typescript_cdk_rds_missing_storage_encryption
  new rds.DatabaseInstance(stack, 'SecretDBUnencrypted', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    credentials: rds.Credentials.fromSecret(secret),
    storageEncrypted: false,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_rds_missing_storage_encryption
  const dbInstance = new rds.DatabaseInstance(stack, 'ConfigurableDB', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    storageEncrypted: false,
    multiAz: true,
    allocatedStorage: 100,
    maxAllocatedStorage: 200,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_rds_missing_storage_encryption
  new rds.DatabaseCluster(stack, 'AuroraServerlessUnencrypted', {
    engine: rds.DatabaseClusterEngine.auroraMysql({
      version: rds.AuroraMysqlEngineVersion.VER_3_02_0
    }),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
    },
    serverlessV2MinCapacity: 0.5,
    serverlessV2MaxCapacity: 2,
    storageEncrypted: false,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_rds_missing_storage_encryption
  new rds.DatabaseInstance(stack, 'OracleDBUnencrypted', {
    engine: rds.DatabaseInstanceEngine.oracle({
      version: rds.OracleEngineVersion.VER_19_0_0_0_2021_04_R1
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
    licenseModel: rds.LicenseModel.LICENSE_INCLUDED,
    storageEncrypted: false,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  const isEncrypted = false;
  
  // ruleid: typescript_cdk_rds_missing_storage_encryption
  new rds.DatabaseInstance(stack, 'VariableEncryptionDB', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    storageEncrypted: isEncrypted, // Using a variable set to false
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_rds_missing_storage_encryption
  const dbCluster = new rds.DatabaseCluster(stack, 'AuroraPostgresUnencrypted', {
    engine: rds.DatabaseClusterEngine.auroraPostgres({
      version: rds.AuroraPostgresEngineVersion.VER_13_7
    }),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    storageEncrypted: false,
    backup: {
      retention: cdk.Duration.days(7),
      preferredWindow: '01:00-02:00',
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_rds_missing_storage_encryption
  new rds.DatabaseInstance(stack, 'SQLServerUnencrypted', {
    engine: rds.DatabaseInstanceEngine.sqlServerEe({
      version: rds.SqlServerEngineVersion.VER_15
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.XLARGE),
    licenseModel: rds.LicenseModel.LICENSE_INCLUDED,
    storageEncrypted: false,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // Create a subnet group
  const subnetGroup = new rds.SubnetGroup(stack, 'DBSubnetGroup', {
    vpc,
    description: 'Subnet group for the database',
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
  });
  
  // ruleid: typescript_cdk_rds_missing_storage_encryption
  new rds.DatabaseInstance(stack, 'CustomSubnetDBUnencrypted', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    subnetGroup,
    storageEncrypted: false,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const dbProps = {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    storageEncrypted: false,
  };
  
  // ruleid: typescript_cdk_rds_missing_storage_encryption
  new rds.DatabaseInstance(stack, 'PropObjectDBUnencrypted', dbProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ruleid: typescript_cdk_rds_missing_storage_encryption
  new rds.DatabaseInstance(stack, 'MariaDBUnencrypted', {
    engine: rds.DatabaseInstanceEngine.mariaDb({
      version: rds.MariaDbEngineVersion.VER_10_6_10
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    storageEncrypted: false,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const getEncryptionSetting = () => {
    // In a real scenario, this might be reading from a config file or parameter
    return false;
  };
  
  // ruleid: typescript_cdk_rds_missing_storage_encryption
  new rds.DatabaseInstance(stack, 'FunctionReturnDBUnencrypted', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    storageEncrypted: getEncryptionSetting(), // Function returns false
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_rds_missing_storage_encryption
  new rds.DatabaseInstance(stack, 'MySecureDatabase', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    storageEncrypted: true, // Explicitly enabling encryption
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  const isEncrypted = true;
  
  // ok: typescript_cdk_rds_missing_storage_encryption
  new rds.DatabaseInstance(stack, 'VariableEncryptedDB', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    storageEncrypted: isEncrypted, // Using a variable set to true
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  const dbSecurityGroup = new ec2.SecurityGroup(stack, 'DBSecurityGroup', { vpc });
  
  // ok: typescript_cdk_rds_missing_storage_encryption
  new rds.DatabaseCluster(stack, 'AuroraClusterEncrypted', {
    engine: rds.DatabaseClusterEngine.auroraMysql({
      version: rds.AuroraMysqlEngineVersion.VER_3_02_0
    }),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
      securityGroups: [dbSecurityGroup],
    },
    storageEncrypted: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // Create a parameter group with custom settings
  const parameterGroup = new rds.ParameterGroup(stack, 'ParameterGroup', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28
    }),
    parameters: {
      'max_connections': '100',
      'character_set_server': 'utf8mb4',
    }
  });
  
  // ok: typescript_cdk_rds_missing_storage_encryption
  new rds.DatabaseInstance(stack, 'CustomParamDBEncrypted', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    parameterGroup,
    storageEncrypted: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const secret = new secretsmanager.Secret(stack, 'DBCredentialsSecret', {
    secretName: 'db-credentials-secure',
    generateSecretString: {
      secretStringTemplate: JSON.stringify({ username: 'admin' }),
      generateStringKey: 'password',
      excludePunctuation: true,
    },
  });
  
  // ok: typescript_cdk_rds_missing_storage_encryption
  new rds.DatabaseInstance(stack, 'SecretDBEncrypted', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    credentials: rds.Credentials.fromSecret(secret),
    storageEncrypted: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_rds_missing_storage_encryption
  const dbInstance = new rds.DatabaseInstance(stack, 'ConfigurableDBEncrypted', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    storageEncrypted: true,
    multiAz: true,
    allocatedStorage: 100,
    maxAllocatedStorage: 200,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_rds_missing_storage_encryption
  new rds.DatabaseCluster(stack, 'AuroraServerlessEncrypted', {
    engine: rds.DatabaseClusterEngine.auroraMysql({
      version: rds.AuroraMysqlEngineVersion.VER_3_02_0
    }),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
    },
    serverlessV2MinCapacity: 0.5,
    serverlessV2MaxCapacity: 2,
    storageEncrypted: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_rds_missing_storage_encryption
  new rds.DatabaseInstance(stack, 'OracleDBEncrypted', {
    engine: rds.DatabaseInstanceEngine.oracle({
      version: rds.OracleEngineVersion.VER_19_0_0_0_2021_04_R1
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
    licenseModel: rds.LicenseModel.LICENSE_INCLUDED,
    storageEncrypted: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const getEncryptionSetting = () => {
    // In a real scenario, this might be reading from a config file or parameter
    return true;
  };
  
  // ok: typescript_cdk_rds_missing_storage_encryption
  new rds.DatabaseInstance(stack, 'FunctionReturnDBEncrypted', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    storageEncrypted: getEncryptionSetting(), // Function returns true
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_rds_missing_storage_encryption
  const dbCluster = new rds.DatabaseCluster(stack, 'AuroraPostgresEncrypted', {
    engine: rds.DatabaseClusterEngine.auroraPostgres({
      version: rds.AuroraPostgresEngineVersion.VER_13_7
    }),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    storageEncrypted: true,
    backup: {
      retention: cdk.Duration.days(7),
      preferredWindow: '01:00-02:00',
    },
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_rds_missing_storage_encryption
  new rds.DatabaseInstance(stack, 'SQLServerEncrypted', {
    engine: rds.DatabaseInstanceEngine.sqlServerEe({
      version: rds.SqlServerEngineVersion.VER_15
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.XLARGE),
    licenseModel: rds.LicenseModel.LICENSE_INCLUDED,
    storageEncrypted: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // Create a subnet group
  const subnetGroup = new rds.SubnetGroup(stack, 'DBSubnetGroupSecure', {
    vpc,
    description: 'Subnet group for the secure database',
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
  });
  
  // ok: typescript_cdk_rds_missing_storage_encryption
  new rds.DatabaseInstance(stack, 'CustomSubnetDBEncrypted', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    subnetGroup,
    storageEncrypted: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  const dbProps = {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    storageEncrypted: true,
  };
  
  // ok: typescript_cdk_rds_missing_storage_encryption
  new rds.DatabaseInstance(stack, 'PropObjectDBEncrypted', dbProps);
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_rds_missing_storage_encryption
  new rds.DatabaseInstance(stack, 'MariaDBEncrypted', {
    engine: rds.DatabaseInstanceEngine.mariaDb({
      version: rds.MariaDbEngineVersion.VER_10_6_10
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    storageEncrypted: true,
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15(stack: cdk.Stack) {
  const vpc = new ec2.Vpc(stack, 'VPC');
  
  // ok: typescript_cdk_rds_missing_storage_encryption
  new rds.DatabaseInstance(stack, 'DefaultEncryptionDB', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    // When not specified and using a KMS key, encryption is automatically enabled
    storageEncryptionKey: new cdk.aws_kms.Key(stack, 'DBEncryptionKey'),
  });
}
// {/fact}