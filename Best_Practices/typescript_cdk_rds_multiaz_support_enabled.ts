import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

// TRUE POSITIVES (Vulnerable Cases)

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_1() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ruleid: typescript_cdk_rds_multiaz_support_enabled
  new rds.DatabaseInstance(stack, 'MyDatabase', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28,
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    multiAz: false,
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_2() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ruleid: typescript_cdk_rds_multiaz_support_enabled
  const db = new rds.DatabaseInstance(stack, 'PostgresDatabase', {
    engine: rds.DatabaseInstanceEngine.postgres({
      version: rds.PostgresEngineVersion.VER_13_7,
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    multiAz: false,
    credentials: rds.Credentials.fromGeneratedSecret('postgres'),
    databaseName: 'mydb',
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_3() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const multiAzSetting = false;
  
  // ruleid: typescript_cdk_rds_multiaz_support_enabled
  new rds.DatabaseInstance(stack, 'MariaDBInstance', {
    engine: rds.DatabaseInstanceEngine.mariaDb({
      version: rds.MariaDbEngineVersion.VER_10_6_10,
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    multiAz: multiAzSetting,
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_4() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const dbProps = {
    engine: rds.DatabaseInstanceEngine.sqlServerEe({
      version: rds.SqlServerEngineVersion.VER_15,
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
    multiAz: false,
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    licenseModel: rds.LicenseModel.LICENSE_INCLUDED,
  };
  
  // ruleid: typescript_cdk_rds_multiaz_support_enabled
  new rds.DatabaseInstance(stack, 'SqlServerInstance', dbProps);
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_5() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ruleid: typescript_cdk_rds_multiaz_support_enabled
  new rds.DatabaseInstance(stack, 'OracleInstance', {
    engine: rds.DatabaseInstanceEngine.oracleEe({
      version: rds.OracleEngineVersion.VER_19_0_0_0_2021_04_R1,
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.XLARGE),
    multiAz: false,
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    licenseModel: rds.LicenseModel.BRING_YOUR_OWN_LICENSE,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_6() {
  class DatabaseStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      // ruleid: typescript_cdk_rds_multiaz_support_enabled
      new rds.DatabaseInstance(this, 'Database', {
        engine: rds.DatabaseInstanceEngine.mysql({
          version: rds.MysqlEngineVersion.VER_8_0_28,
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
        multiAz: false,
        credentials: rds.Credentials.fromGeneratedSecret('admin'),
      });
    }
  }
  
  const app = new cdk.App();
  new DatabaseStack(app, 'DatabaseStack');
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_7() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const isProd = false;
  
  // ruleid: typescript_cdk_rds_multiaz_support_enabled
  new rds.DatabaseInstance(stack, 'ConditionalDatabase', {
    engine: rds.DatabaseInstanceEngine.postgres({
      version: rds.PostgresEngineVersion.VER_14_3,
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    multiAz: isProd ? true : false, // This evaluates to false
    credentials: rds.Credentials.fromGeneratedSecret('postgres'),
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_8() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ruleid: typescript_cdk_rds_multiaz_support_enabled
  const db = new rds.DatabaseInstance(stack, 'MySqlInstance', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28,
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    // multiAz is not specified, which defaults to false
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_9() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const dbConfig = {
    engine: rds.DatabaseInstanceEngine.postgres({
      version: rds.PostgresEngineVersion.VER_13_7,
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    multiAz: false,
    credentials: rds.Credentials.fromGeneratedSecret('postgres'),
    databaseName: 'productiondb',
    backupRetention: cdk.Duration.days(7),
    storageEncrypted: true,
  };
  
  // ruleid: typescript_cdk_rds_multiaz_support_enabled
  new rds.DatabaseInstance(stack, 'ProductionDatabase', dbConfig);
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_10() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ruleid: typescript_cdk_rds_multiaz_support_enabled
  new rds.DatabaseInstance(stack, 'MySqlInstance', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28,
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    multiAz: false,
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    storageType: rds.StorageType.GP2,
    allocatedStorage: 100,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_11() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ruleid: typescript_cdk_rds_multiaz_support_enabled
  new rds.DatabaseInstance(stack, 'PostgresInstance', {
    engine: rds.DatabaseInstanceEngine.postgres({
      version: rds.PostgresEngineVersion.VER_14_3,
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    multiAz: false,
    credentials: rds.Credentials.fromGeneratedSecret('postgres'),
    storageEncrypted: true,
    backupRetention: cdk.Duration.days(14),
    deletionProtection: true,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_12() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const securityGroup = new ec2.SecurityGroup(stack, 'DBSecurityGroup', {
    vpc,
    description: 'Allow database access',
  });
  
  // ruleid: typescript_cdk_rds_multiaz_support_enabled
  new rds.DatabaseInstance(stack, 'MySqlInstance', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28,
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    multiAz: false,
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    securityGroups: [securityGroup],
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_13() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const parameterGroup = new rds.ParameterGroup(stack, 'ParameterGroup', {
    engine: rds.DatabaseInstanceEngine.postgres({
      version: rds.PostgresEngineVersion.VER_13_7,
    }),
    parameters: {
      'max_connections': '100',
      'shared_buffers': '4GB',
    },
  });
  
  // ruleid: typescript_cdk_rds_multiaz_support_enabled
  new rds.DatabaseInstance(stack, 'PostgresInstance', {
    engine: rds.DatabaseInstanceEngine.postgres({
      version: rds.PostgresEngineVersion.VER_13_7,
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.LARGE),
    multiAz: false,
    credentials: rds.Credentials.fromGeneratedSecret('postgres'),
    parameterGroup: parameterGroup,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_14() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ruleid: typescript_cdk_rds_multiaz_support_enabled
  new rds.DatabaseInstance(stack, 'MySqlInstance', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28,
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.XLARGE),
    multiAz: false,
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    monitoringInterval: cdk.Duration.minutes(1),
    enablePerformanceInsights: true,
    performanceInsightRetention: rds.PerformanceInsightRetention.DEFAULT,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_15() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ruleid: typescript_cdk_rds_multiaz_support_enabled
  new rds.DatabaseInstance(stack, 'PostgresInstance', {
    engine: rds.DatabaseInstanceEngine.postgres({
      version: rds.PostgresEngineVersion.VER_14_3,
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.XLARGE),
    multiAz: false,
    credentials: rds.Credentials.fromGeneratedSecret('postgres'),
    autoMinorVersionUpgrade: true,
    preferredBackupWindow: '01:00-02:00',
    preferredMaintenanceWindow: 'Sun:03:00-Sun:04:00',
  });
}
// {/fact}

// TRUE NEGATIVES (Secure Cases)

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_1() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ok: typescript_cdk_rds_multiaz_support_enabled
  new rds.DatabaseInstance(stack, 'MyDatabase', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28,
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
    multiAz: true,
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_2() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ok: typescript_cdk_rds_multiaz_support_enabled
  const db = new rds.DatabaseInstance(stack, 'PostgresDatabase', {
    engine: rds.DatabaseInstanceEngine.postgres({
      version: rds.PostgresEngineVersion.VER_13_7,
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    multiAz: true,
    credentials: rds.Credentials.fromGeneratedSecret('postgres'),
    databaseName: 'mydb',
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_3() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const multiAzSetting = true;
  
  // ok: typescript_cdk_rds_multiaz_support_enabled
  new rds.DatabaseInstance(stack, 'MariaDBInstance', {
    engine: rds.DatabaseInstanceEngine.mariaDb({
      version: rds.MariaDbEngineVersion.VER_10_6_10,
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    multiAz: multiAzSetting,
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_4() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const dbProps = {
    engine: rds.DatabaseInstanceEngine.sqlServerEe({
      version: rds.SqlServerEngineVersion.VER_15,
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
    multiAz: true,
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    licenseModel: rds.LicenseModel.LICENSE_INCLUDED,
  };
  
  // ok: typescript_cdk_rds_multiaz_support_enabled
  new rds.DatabaseInstance(stack, 'SqlServerInstance', dbProps);
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_5() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ok: typescript_cdk_rds_multiaz_support_enabled
  new rds.DatabaseInstance(stack, 'OracleInstance', {
    engine: rds.DatabaseInstanceEngine.oracleEe({
      version: rds.OracleEngineVersion.VER_19_0_0_0_2021_04_R1,
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.XLARGE),
    multiAz: true,
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    licenseModel: rds.LicenseModel.BRING_YOUR_OWN_LICENSE,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_6() {
  class DatabaseStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
      super(scope, id, props);
      
      const vpc = new ec2.Vpc(this, 'VPC');
      
      // ok: typescript_cdk_rds_multiaz_support_enabled
      new rds.DatabaseInstance(this, 'Database', {
        engine: rds.DatabaseInstanceEngine.mysql({
          version: rds.MysqlEngineVersion.VER_8_0_28,
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
        multiAz: true,
        credentials: rds.Credentials.fromGeneratedSecret('admin'),
      });
    }
  }
  
  const app = new cdk.App();
  new DatabaseStack(app, 'DatabaseStack');
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_7() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const isProd = true;
  
  // ok: typescript_cdk_rds_multiaz_support_enabled
  new rds.DatabaseInstance(stack, 'ConditionalDatabase', {
    engine: rds.DatabaseInstanceEngine.postgres({
      version: rds.PostgresEngineVersion.VER_14_3,
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    multiAz: isProd ? true : false, // This evaluates to true
    credentials: rds.Credentials.fromGeneratedSecret('postgres'),
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_8() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ok: typescript_cdk_rds_multiaz_support_enabled
  new rds.DatabaseCluster(stack, 'AuroraCluster', {
    engine: rds.DatabaseClusterEngine.auroraMysql({
      version: rds.AuroraMysqlEngineVersion.VER_3_02_0,
    }),
    instances: 2,
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_9() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const dbConfig = {
    engine: rds.DatabaseInstanceEngine.postgres({
      version: rds.PostgresEngineVersion.VER_13_7,
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    multiAz: true,
    credentials: rds.Credentials.fromGeneratedSecret('postgres'),
    databaseName: 'productiondb',
    backupRetention: cdk.Duration.days(7),
    storageEncrypted: true,
  };
  
  // ok: typescript_cdk_rds_multiaz_support_enabled
  new rds.DatabaseInstance(stack, 'ProductionDatabase', dbConfig);
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_10() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ok: typescript_cdk_rds_multiaz_support_enabled
  new rds.DatabaseInstance(stack, 'MySqlInstance', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28,
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
    multiAz: true,
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    storageType: rds.StorageType.GP2,
    allocatedStorage: 100,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_11() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ok: typescript_cdk_rds_multiaz_support_enabled
  new rds.DatabaseCluster(stack, 'AuroraPostgresCluster', {
    engine: rds.DatabaseClusterEngine.auroraPostgres({
      version: rds.AuroraPostgresEngineVersion.VER_13_7,
    }),
    instances: 3,
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    credentials: rds.Credentials.fromGeneratedSecret('postgres'),
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_12() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const securityGroup = new ec2.SecurityGroup(stack, 'DBSecurityGroup', {
    vpc,
    description: 'Allow database access',
  });
  
  // ok: typescript_cdk_rds_multiaz_support_enabled
  new rds.DatabaseInstance(stack, 'MySqlInstance', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28,
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    multiAz: true,
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    securityGroups: [securityGroup],
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    },
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_13() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  const parameterGroup = new rds.ParameterGroup(stack, 'ParameterGroup', {
    engine: rds.DatabaseInstanceEngine.postgres({
      version: rds.PostgresEngineVersion.VER_13_7,
    }),
    parameters: {
      'max_connections': '100',
      'shared_buffers': '4GB',
    },
  });
  
  // ok: typescript_cdk_rds_multiaz_support_enabled
  new rds.DatabaseInstance(stack, 'PostgresInstance', {
    engine: rds.DatabaseInstanceEngine.postgres({
      version: rds.PostgresEngineVersion.VER_13_7,
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.LARGE),
    multiAz: true,
    credentials: rds.Credentials.fromGeneratedSecret('postgres'),
    parameterGroup: parameterGroup,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_14() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ok: typescript_cdk_rds_multiaz_support_enabled
  new rds.DatabaseInstance(stack, 'MySqlInstance', {
    engine: rds.DatabaseInstanceEngine.mysql({
      version: rds.MysqlEngineVersion.VER_8_0_28,
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.XLARGE),
    multiAz: true,
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    monitoringInterval: cdk.Duration.minutes(1),
    enablePerformanceInsights: true,
    performanceInsightRetention: rds.PerformanceInsightRetention.DEFAULT,
  });
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_15() {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'MyStack');
  const vpc = new ec2.Vpc(stack, 'MyVpc');
  
  // ok: typescript_cdk_rds_multiaz_support_enabled
  new rds.DatabaseInstance(stack, 'PostgresInstance', {
    engine: rds.DatabaseInstanceEngine.postgres({
      version: rds.PostgresEngineVersion.VER_14_3,
    }),
    vpc,
    instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.XLARGE),
    multiAz: true,
    credentials: rds.Credentials.fromGeneratedSecret('postgres'),
    autoMinorVersionUpgrade: true,
    preferredBackupWindow: '01:00-02:00',
    preferredMaintenanceWindow: 'Sun:03:00-Sun:04:00',
  });
}
// {/fact}