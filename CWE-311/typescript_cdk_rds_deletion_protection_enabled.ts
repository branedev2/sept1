import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

class DatabaseStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
    
    // Create a VPC for our examples
    const vpc = new ec2.Vpc(this, 'VPC', {
      maxAzs: 2
    });
  }
}

// True Positives (Vulnerable Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating RDS instance without specifying deletion protection
  // ruleid: typescript_cdk_rds_deletion_protection_enabled
  const instance = new rds.DatabaseInstance(scope, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28
    }),
    vpc: new ec2.Vpc(scope, 'VPC'),
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    credentials: rds.Credentials.fromGeneratedSecret('admin')
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating RDS instance with deletion protection explicitly set to false
  // ruleid: typescript_cdk_rds_deletion_protection_enabled
  const instance = new rds.DatabaseInstance(scope, 'Database', {
    engine: rds.DatabaseInstanceEngine.postgres({
      version: rds.PostgresEngineVersion.VER_13_4
    }),
    vpc: new ec2.Vpc(scope, 'VPC'),
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    deletionProtection: false
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Creating Aurora cluster without deletion protection
  // ruleid: typescript_cdk_rds_deletion_protection_enabled
  const cluster = new rds.DatabaseCluster(scope, 'AuroraCluster', {
    engine: rds.DatabaseClusterEngine.auroraMysql({
      version: rds.AuroraMysqlEngineVersion.VER_3_02_0
    }),
    instanceProps: {
      vpc: new ec2.Vpc(scope, 'VPC'),
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    },
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin')
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Creating Aurora cluster with deletion protection explicitly set to false
  // ruleid: typescript_cdk_rds_deletion_protection_enabled
  const cluster = new rds.DatabaseCluster(scope, 'AuroraCluster', {
    engine: rds.DatabaseClusterEngine.auroraPostgres({
      version: rds.AuroraPostgresEngineVersion.VER_13_4
    }),
    instanceProps: {
      vpc: new ec2.Vpc(scope, 'VPC'),
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    deletionProtection: false
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Creating RDS instance with deletion protection set to false in production environment
  const isProd = process.env.ENV === 'production';
  
  // ruleid: typescript_cdk_rds_deletion_protection_enabled
  const instance = new rds.DatabaseInstance(scope, 'ProductionDatabase', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28
    }),
    vpc: new ec2.Vpc(scope, 'VPC'),
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    deletionProtection: false
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Creating RDS instance with deletion protection dynamically set to false
  const enableProtection = false;
  
  // ruleid: typescript_cdk_rds_deletion_protection_enabled
  const instance = new rds.DatabaseInstance(scope, 'Database', {
    engine: rds.DatabaseInstanceEngine.mariaDb({
      version: rds.MariaDbEngineVersion.VER_10_6_8
    }),
    vpc: new ec2.Vpc(scope, 'VPC'),
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    deletionProtection: enableProtection
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Creating serverless Aurora cluster without deletion protection
  // ruleid: typescript_cdk_rds_deletion_protection_enabled
  const cluster = new rds.ServerlessCluster(scope, 'ServerlessCluster', {
    engine: rds.DatabaseClusterEngine.AURORA_POSTGRESQL,
    vpc: new ec2.Vpc(scope, 'VPC'),
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    scaling: {
      autoPause: cdk.Duration.minutes(10),
      minCapacity: rds.AuroraCapacityUnit.ACU_2,
      maxCapacity: rds.AuroraCapacityUnit.ACU_16,
    }
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Creating serverless Aurora cluster with deletion protection explicitly set to false
  // ruleid: typescript_cdk_rds_deletion_protection_enabled
  const cluster = new rds.ServerlessCluster(scope, 'ServerlessCluster', {
    engine: rds.DatabaseClusterEngine.AURORA_MYSQL,
    vpc: new ec2.Vpc(scope, 'VPC'),
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    scaling: {
      autoPause: cdk.Duration.minutes(10),
      minCapacity: rds.AuroraCapacityUnit.ACU_2,
      maxCapacity: rds.AuroraCapacityUnit.ACU_16,
    },
    deletionProtection: false
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Creating RDS instance with conditional deletion protection that defaults to false
  const config = {
    enableDeletionProtection: false
  };
  
  // ruleid: typescript_cdk_rds_deletion_protection_enabled
  const instance = new rds.DatabaseInstance(scope, 'Database', {
    engine: rds.DatabaseInstanceEngine.oracle({
      version: rds.OracleEngineVersion.VER_19_0_0_0_2021_04_R1
    }),
    vpc: new ec2.Vpc(scope, 'VPC'),
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    deletionProtection: config.enableDeletionProtection
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating RDS instance with deletion protection based on environment variable that might be undefined
  const deletionProtection = process.env.ENABLE_DELETION_PROTECTION === 'true';
  
  // ruleid: typescript_cdk_rds_deletion_protection_enabled
  const instance = new rds.DatabaseInstance(scope, 'Database', {
    engine: rds.DatabaseInstanceEngine.sqlServerEe({
      version: rds.SqlServerEngineVersion.VER_15_00_4073_23_V1
    }),
    vpc: new ec2.Vpc(scope, 'VPC'),
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.XLARGE),
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    deletionProtection: deletionProtection
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  // Creating multiple RDS instances in a loop without deletion protection
  const dbNames = ['users', 'products', 'orders'];
  
  for (const name of dbNames) {
    // ruleid: typescript_cdk_rds_deletion_protection_enabled
    const instance = new rds.DatabaseInstance(scope, `Database-${name}`, {
      engine: rds.DatabaseInstanceEngine.mysql({
        version: rds.MysqlEngineVersion.VER_8_0_28
      }),
      vpc: new ec2.Vpc(scope, `VPC-${name}`),
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      credentials: rds.Credentials.fromGeneratedSecret('admin')
    });
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating an instance with deletion protection set to a variable that could be false
  const config = getConfig(); // Assume this returns an object with configuration
  
  // ruleid: typescript_cdk_rds_deletion_protection_enabled
  const instance = new rds.DatabaseInstance(scope, 'Database', {
    engine: rds.DatabaseInstanceEngine.postgres({
      version: rds.PostgresEngineVersion.VER_14_3
    }),
    vpc: new ec2.Vpc(scope, 'VPC'),
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    deletionProtection: config.deletionProtection // This could be false
  });
  
  function getConfig() {
    return {
      deletionProtection: false
    };
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating an Aurora Serverless v2 cluster without deletion protection
  // ruleid: typescript_cdk_rds_deletion_protection_enabled
  const cluster = new rds.DatabaseCluster(scope, 'AuroraServerlessV2', {
    engine: rds.DatabaseClusterEngine.auroraMysql({
      version: rds.AuroraMysqlEngineVersion.VER_3_02_0
    }),
    instanceProps: {
      vpc: new ec2.Vpc(scope, 'VPC'),
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.SERVERLESS, ec2.InstanceSize.STANDARD),
    },
    serverlessV2MinCapacity: 0.5,
    serverlessV2MaxCapacity: 16,
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin')
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating an RDS instance with deletion protection explicitly set to false in a nested object
  const dbConfig = {
    settings: {
      protection: false
    }
  };
  
  // ruleid: typescript_cdk_rds_deletion_protection_enabled
  const instance = new rds.DatabaseInstance(scope, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28
    }),
    vpc: new ec2.Vpc(scope, 'VPC'),
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    deletionProtection: dbConfig.settings.protection
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating an RDS instance with deletion protection set to a ternary that evaluates to false
  const isTestEnv = process.env.NODE_ENV === 'test';
  
  // ruleid: typescript_cdk_rds_deletion_protection_enabled
  const instance = new rds.DatabaseInstance(scope, 'Database', {
    engine: rds.DatabaseInstanceEngine.postgres({
      version: rds.PostgresEngineVersion.VER_14_3
    }),
    vpc: new ec2.Vpc(scope, 'VPC'),
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    deletionProtection: isTestEnv ? false : false // Always false
  });
}
// {/fact}

// True Negatives (Secure Code)

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating RDS instance with deletion protection explicitly set to true
  // ok: typescript_cdk_rds_deletion_protection_enabled
  const instance = new rds.DatabaseInstance(scope, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28
    }),
    vpc: new ec2.Vpc(scope, 'VPC'),
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    deletionProtection: true
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Creating Aurora cluster with deletion protection explicitly set to true
  // ok: typescript_cdk_rds_deletion_protection_enabled
  const cluster = new rds.DatabaseCluster(scope, 'AuroraCluster', {
    engine: rds.DatabaseClusterEngine.auroraMysql({
      version: rds.AuroraMysqlEngineVersion.VER_3_02_0
    }),
    instanceProps: {
      vpc: new ec2.Vpc(scope, 'VPC'),
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    },
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    deletionProtection: true
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Creating serverless Aurora cluster with deletion protection explicitly set to true
  // ok: typescript_cdk_rds_deletion_protection_enabled
  const cluster = new rds.ServerlessCluster(scope, 'ServerlessCluster', {
    engine: rds.DatabaseClusterEngine.AURORA_POSTGRESQL,
    vpc: new ec2.Vpc(scope, 'VPC'),
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    scaling: {
      autoPause: cdk.Duration.minutes(10),
      minCapacity: rds.AuroraCapacityUnit.ACU_2,
      maxCapacity: rds.AuroraCapacityUnit.ACU_16,
    },
    deletionProtection: true
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Creating RDS instance with deletion protection based on environment that defaults to true
  const isProd = process.env.ENV === 'production';
  
  // ok: typescript_cdk_rds_deletion_protection_enabled
  const instance = new rds.DatabaseInstance(scope, 'Database', {
    engine: rds.DatabaseInstanceEngine.postgres({
      version: rds.PostgresEngineVersion.VER_13_4
    }),
    vpc: new ec2.Vpc(scope, 'VPC'),
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    deletionProtection: isProd ? true : true // Always true
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Creating RDS instance with deletion protection dynamically set to true
  const enableProtection = true;
  
  // ok: typescript_cdk_rds_deletion_protection_enabled
  const instance = new rds.DatabaseInstance(scope, 'Database', {
    engine: rds.DatabaseInstanceEngine.mariaDb({
      version: rds.MariaDbEngineVersion.VER_10_6_8
    }),
    vpc: new ec2.Vpc(scope, 'VPC'),
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    deletionProtection: enableProtection
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Creating multiple RDS instances in a loop with deletion protection
  const dbNames = ['users', 'products', 'orders'];
  
  for (const name of dbNames) {
    // ok: typescript_cdk_rds_deletion_protection_enabled
    const instance = new rds.DatabaseInstance(scope, `Database-${name}`, {
      engine: rds.DatabaseInstanceEngine.mysql({
        version: rds.MysqlEngineVersion.VER_8_0_28
      }),
      vpc: new ec2.Vpc(scope, `VPC-${name}`),
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      credentials: rds.Credentials.fromGeneratedSecret('admin'),
      deletionProtection: true
    });
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Creating an instance with deletion protection set to a variable that is always true
  const config = getConfig(); // Assume this returns an object with configuration
  
  // ok: typescript_cdk_rds_deletion_protection_enabled
  const instance = new rds.DatabaseInstance(scope, 'Database', {
    engine: rds.DatabaseInstanceEngine.postgres({
      version: rds.PostgresEngineVersion.VER_14_3
    }),
    vpc: new ec2.Vpc(scope, 'VPC'),
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    deletionProtection: config.deletionProtection
  });
  
  function getConfig() {
    return {
      deletionProtection: true
    };
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Creating an Aurora Serverless v2 cluster with deletion protection
  // ok: typescript_cdk_rds_deletion_protection_enabled
  const cluster = new rds.DatabaseCluster(scope, 'AuroraServerlessV2', {
    engine: rds.DatabaseClusterEngine.auroraMysql({
      version: rds.AuroraMysqlEngineVersion.VER_3_02_0
    }),
    instanceProps: {
      vpc: new ec2.Vpc(scope, 'VPC'),
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.SERVERLESS, ec2.InstanceSize.STANDARD),
    },
    serverlessV2MinCapacity: 0.5,
    serverlessV2MaxCapacity: 16,
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    deletionProtection: true
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Creating an RDS instance with deletion protection explicitly set to true in a nested object
  const dbConfig = {
    settings: {
      protection: true
    }
  };
  
  // ok: typescript_cdk_rds_deletion_protection_enabled
  const instance = new rds.DatabaseInstance(scope, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28
    }),
    vpc: new ec2.Vpc(scope, 'VPC'),
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    deletionProtection: dbConfig.settings.protection
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Creating an RDS instance with deletion protection set to a ternary that evaluates to true
  const isTestEnv = process.env.NODE_ENV === 'test';
  
  // ok: typescript_cdk_rds_deletion_protection_enabled
  const instance = new rds.DatabaseInstance(scope, 'Database', {
    engine: rds.DatabaseInstanceEngine.postgres({
      version: rds.PostgresEngineVersion.VER_14_3
    }),
    vpc: new ec2.Vpc(scope, 'VPC'),
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    deletionProtection: isTestEnv ? true : true // Always true
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_11(scope: Construct) {
  // Creating an RDS instance with deletion protection based on environment variable with safe default
  const deletionProtection = process.env.DISABLE_DELETION_PROTECTION !== 'true';
  
  // ok: typescript_cdk_rds_deletion_protection_enabled
  const instance = new rds.DatabaseInstance(scope, 'Database', {
    engine: rds.DatabaseInstanceEngine.sqlServerEe({
      version: rds.SqlServerEngineVersion.VER_15_00_4073_23_V1
    }),
    vpc: new ec2.Vpc(scope, 'VPC'),
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.XLARGE),
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    deletionProtection: deletionProtection // Defaults to true unless explicitly disabled
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Creating an RDS instance with deletion protection using logical OR to ensure true
  const configValue = getConfigValue(); // This might return undefined or false
  
  // ok: typescript_cdk_rds_deletion_protection_enabled
  const instance = new rds.DatabaseInstance(scope, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28
    }),
    vpc: new ec2.Vpc(scope, 'VPC'),
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    deletionProtection: configValue || true // Will be true if configValue is falsy
  });
  
  function getConfigValue() {
    return undefined; // Could return any value
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Creating an RDS instance with deletion protection using a function that returns true
  // ok: typescript_cdk_rds_deletion_protection_enabled
  const instance = new rds.DatabaseInstance(scope, 'Database', {
    engine: rds.DatabaseInstanceEngine.postgres({
      version: rds.PostgresEngineVersion.VER_14_3
    }),
    vpc: new ec2.Vpc(scope, 'VPC'),
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    deletionProtection: getDeletionProtectionSetting()
  });
  
  function getDeletionProtectionSetting(): boolean {
    // Complex logic that always returns true for safety
    return true;
  }
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Creating an RDS instance with deletion protection using a constant
  const DELETION_PROTECTION = true;
  
  // ok: typescript_cdk_rds_deletion_protection_enabled
  const instance = new rds.DatabaseInstance(scope, 'Database', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28
    }),
    vpc: new ec2.Vpc(scope, 'VPC'),
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    deletionProtection: DELETION_PROTECTION
  });
}
// {/fact}

// {fact rule=aws-kms-reencryption@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Creating an RDS instance with deletion protection using boolean expression
  const isProd = process.env.ENV === 'production';
  const isStaging = process.env.ENV === 'staging';
  
  // ok: typescript_cdk_rds_deletion_protection_enabled
  const instance = new rds.DatabaseInstance(scope, 'Database', {
    engine: rds.DatabaseInstanceEngine.postgres({
      version: rds.PostgresEngineVersion.VER_14_3
    }),
    vpc: new ec2.Vpc(scope, 'VPC'),
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    deletionProtection: isProd || isStaging || true // Will be true regardless of environment
  });
}
// {/fact}