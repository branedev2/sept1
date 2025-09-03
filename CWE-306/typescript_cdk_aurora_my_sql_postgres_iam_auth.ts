import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

// True Positives (Vulnerable Code - IAM Authentication not enabled)

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.DatabaseCluster(scope, 'Database', {
    engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_3_02_0 }),
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      vpc,
    },
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.DatabaseCluster(scope, 'Database', {
    engine: rds.DatabaseClusterEngine.auroraPostgres({ version: rds.AuroraPostgresEngineVersion.VER_13_4 }),
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      vpc,
    },
    iamAuthentication: false,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.DatabaseCluster(scope, 'AuroraMySQLCluster', {
    engine: rds.DatabaseClusterEngine.auroraMysql({
      version: rds.AuroraMysqlEngineVersion.VER_2_10_2,
    }),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    },
    defaultDatabaseName: 'mydb',
    credentials: {
      username: 'admin',
    },
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.DatabaseCluster(scope, 'PostgresCluster', {
    engine: rds.DatabaseClusterEngine.auroraPostgres({
      version: rds.AuroraPostgresEngineVersion.VER_14_3,
    }),
    credentials: rds.Credentials.fromPassword('admin', cdk.SecretValue.unsafePlainText('password123')),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R6G, ec2.InstanceSize.LARGE),
    },
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const securityGroup = new ec2.SecurityGroup(scope, 'SecurityGroup', { vpc });
  
  // ruleid: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.DatabaseCluster(scope, 'AuroraCluster', {
    engine: rds.DatabaseClusterEngine.auroraMysql({
      version: rds.AuroraMysqlEngineVersion.VER_3_01_0,
    }),
    instanceProps: {
      vpc,
      securityGroups: [securityGroup],
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.LARGE),
    },
    credentials: rds.Credentials.fromSecret(new cdk.aws_secretsmanager.Secret(scope, 'DBSecret')),
    backup: {
      retention: cdk.Duration.days(7),
    },
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.DatabaseCluster(scope, 'AuroraCluster', {
    engine: rds.DatabaseClusterEngine.auroraPostgres({
      version: rds.AuroraPostgresEngineVersion.VER_12_9,
    }),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.XLARGE),
    },
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    storageEncrypted: true,
    deletionProtection: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const parameterGroup = new rds.ParameterGroup(scope, 'ParameterGroup', {
    engine: rds.DatabaseClusterEngine.auroraMysql({
      version: rds.AuroraMysqlEngineVersion.VER_2_11_1,
    }),
    parameters: {
      'max_connections': '1000',
      'innodb_buffer_pool_size': '1073741824',
    },
  });
  
  // ruleid: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.DatabaseCluster(scope, 'AuroraCluster', {
    engine: rds.DatabaseClusterEngine.auroraMysql({
      version: rds.AuroraMysqlEngineVersion.VER_2_11_1,
    }),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    parameterGroup,
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const writer = new rds.CfnDBInstance(scope, 'Writer', {
    engine: 'aurora-postgresql',
    dbClusterIdentifier: 'my-cluster',
    dbInstanceClass: 'db.r5.large',
    enableIamDatabaseAuthentication: false,
  });
  
  const cluster = new rds.CfnDBCluster(scope, 'Cluster', {
    engine: 'aurora-postgresql',
    engineVersion: '13.4',
    masterUsername: 'admin',
    masterUserPassword: 'password123',
    dbClusterIdentifier: 'my-cluster',
    enableIamDatabaseAuthentication: false,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.DatabaseCluster(scope, 'AuroraCluster', {
    engine: rds.DatabaseClusterEngine.auroraMysql({
      version: rds.AuroraMysqlEngineVersion.VER_3_02_0,
    }),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
      publiclyAccessible: false,
    },
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    port: 3306,
    storageEncrypted: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.DatabaseCluster(scope, 'AuroraCluster', {
    engine: rds.DatabaseClusterEngine.auroraPostgres({
      version: rds.AuroraPostgresEngineVersion.VER_11_13,
    }),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    backup: {
      retention: cdk.Duration.days(14),
    },
    cloudwatchLogsExports: ['postgresql'],
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_11(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.DatabaseCluster(scope, 'AuroraCluster', {
    engine: rds.DatabaseClusterEngine.auroraMysql({
      version: rds.AuroraMysqlEngineVersion.VER_2_10_2,
    }),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    },
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    removalPolicy: cdk.RemovalPolicy.SNAPSHOT,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const subnetGroup = new rds.SubnetGroup(scope, 'SubnetGroup', {
    vpc,
    description: 'Subnet group for Aurora cluster',
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
  });
  
  // ruleid: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.DatabaseCluster(scope, 'AuroraCluster', {
    engine: rds.DatabaseClusterEngine.auroraPostgres({
      version: rds.AuroraPostgresEngineVersion.VER_13_4,
    }),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    subnetGroup,
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.DatabaseCluster(scope, 'AuroraCluster', {
    engine: rds.DatabaseClusterEngine.auroraMysql({
      version: rds.AuroraMysqlEngineVersion.VER_3_01_0,
    }),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.XLARGE),
    },
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    monitoringInterval: cdk.Duration.minutes(1),
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.DatabaseCluster(scope, 'AuroraCluster', {
    engine: rds.DatabaseClusterEngine.auroraPostgres({
      version: rds.AuroraPostgresEngineVersion.VER_12_9,
    }),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
      autoMinorVersionUpgrade: true,
    },
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    preferredMaintenanceWindow: 'Sun:00:00-Sun:03:00',
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ruleid: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.CfnDBCluster(scope, 'AuroraCluster', {
    engine: 'aurora-mysql',
    engineVersion: '8.0.mysql_aurora.3.02.0',
    masterUsername: 'admin',
    masterUserPassword: 'password123',
    dbSubnetGroupName: 'my-subnet-group',
    vpcSecurityGroupIds: ['sg-12345'],
    port: 3306,
    backupRetentionPeriod: 7,
    storageEncrypted: true,
  });
}
// {/fact}

// True Negatives (Secure Code - IAM Authentication enabled)

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_1(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.DatabaseCluster(scope, 'Database', {
    engine: rds.DatabaseClusterEngine.auroraMysql({ version: rds.AuroraMysqlEngineVersion.VER_3_02_0 }),
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      vpc,
    },
    iamAuthentication: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_2(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.DatabaseCluster(scope, 'Database', {
    engine: rds.DatabaseClusterEngine.auroraPostgres({ version: rds.AuroraPostgresEngineVersion.VER_13_4 }),
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    instanceProps: {
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      vpc,
    },
    iamAuthentication: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_3(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.DatabaseCluster(scope, 'AuroraMySQLCluster', {
    engine: rds.DatabaseClusterEngine.auroraMysql({
      version: rds.AuroraMysqlEngineVersion.VER_2_10_2,
    }),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    },
    defaultDatabaseName: 'mydb',
    credentials: {
      username: 'admin',
    },
    iamAuthentication: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_4(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.DatabaseCluster(scope, 'PostgresCluster', {
    engine: rds.DatabaseClusterEngine.auroraPostgres({
      version: rds.AuroraPostgresEngineVersion.VER_14_3,
    }),
    credentials: rds.Credentials.fromPassword('admin', cdk.SecretValue.unsafePlainText('password123')),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R6G, ec2.InstanceSize.LARGE),
    },
    iamAuthentication: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_5(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  const securityGroup = new ec2.SecurityGroup(scope, 'SecurityGroup', { vpc });
  
  // ok: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.DatabaseCluster(scope, 'AuroraCluster', {
    engine: rds.DatabaseClusterEngine.auroraMysql({
      version: rds.AuroraMysqlEngineVersion.VER_3_01_0,
    }),
    instanceProps: {
      vpc,
      securityGroups: [securityGroup],
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.LARGE),
    },
    credentials: rds.Credentials.fromSecret(new cdk.aws_secretsmanager.Secret(scope, 'DBSecret')),
    backup: {
      retention: cdk.Duration.days(7),
    },
    iamAuthentication: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_6(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.DatabaseCluster(scope, 'AuroraCluster', {
    engine: rds.DatabaseClusterEngine.auroraPostgres({
      version: rds.AuroraPostgresEngineVersion.VER_12_9,
    }),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.XLARGE),
    },
    credentials: rds.Credentials.fromGeneratedSecret('clusteradmin'),
    storageEncrypted: true,
    deletionProtection: true,
    iamAuthentication: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_7(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const parameterGroup = new rds.ParameterGroup(scope, 'ParameterGroup', {
    engine: rds.DatabaseClusterEngine.auroraMysql({
      version: rds.AuroraMysqlEngineVersion.VER_2_11_1,
    }),
    parameters: {
      'max_connections': '1000',
      'innodb_buffer_pool_size': '1073741824',
    },
  });
  
  // ok: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.DatabaseCluster(scope, 'AuroraCluster', {
    engine: rds.DatabaseClusterEngine.auroraMysql({
      version: rds.AuroraMysqlEngineVersion.VER_2_11_1,
    }),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    parameterGroup,
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    iamAuthentication: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_8(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const writer = new rds.CfnDBInstance(scope, 'Writer', {
    engine: 'aurora-postgresql',
    dbClusterIdentifier: 'my-cluster',
    dbInstanceClass: 'db.r5.large',
    enableIamDatabaseAuthentication: true,
  });
  
  const cluster = new rds.CfnDBCluster(scope, 'Cluster', {
    engine: 'aurora-postgresql',
    engineVersion: '13.4',
    masterUsername: 'admin',
    masterUserPassword: 'password123',
    dbClusterIdentifier: 'my-cluster',
    enableIamDatabaseAuthentication: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_9(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.DatabaseCluster(scope, 'AuroraCluster', {
    engine: rds.DatabaseClusterEngine.auroraMysql({
      version: rds.AuroraMysqlEngineVersion.VER_3_02_0,
    }),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
      publiclyAccessible: false,
    },
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    port: 3306,
    storageEncrypted: true,
    iamAuthentication: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_10(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.DatabaseCluster(scope, 'AuroraCluster', {
    engine: rds.DatabaseClusterEngine.auroraPostgres({
      version: rds.AuroraPostgresEngineVersion.VER_11_13,
    }),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    backup: {
      retention: cdk.Duration.days(14),
    },
    cloudwatchLogsExports: ['postgresql'],
    iamAuthentication: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_11(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.DatabaseCluster(scope, 'AuroraCluster', {
    engine: rds.DatabaseClusterEngine.auroraMysql({
      version: rds.AuroraMysqlEngineVersion.VER_2_10_2,
    }),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
    },
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    removalPolicy: cdk.RemovalPolicy.SNAPSHOT,
    iamAuthentication: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_12(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  const subnetGroup = new rds.SubnetGroup(scope, 'SubnetGroup', {
    vpc,
    description: 'Subnet group for Aurora cluster',
    vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
  });
  
  // ok: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.DatabaseCluster(scope, 'AuroraCluster', {
    engine: rds.DatabaseClusterEngine.auroraPostgres({
      version: rds.AuroraPostgresEngineVersion.VER_13_4,
    }),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    },
    subnetGroup,
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    iamAuthentication: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_13(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.DatabaseCluster(scope, 'AuroraCluster', {
    engine: rds.DatabaseClusterEngine.auroraMysql({
      version: rds.AuroraMysqlEngineVersion.VER_3_01_0,
    }),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.XLARGE),
    },
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    monitoringInterval: cdk.Duration.minutes(1),
    iamAuthentication: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_14(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.DatabaseCluster(scope, 'AuroraCluster', {
    engine: rds.DatabaseClusterEngine.auroraPostgres({
      version: rds.AuroraPostgresEngineVersion.VER_12_9,
    }),
    instanceProps: {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
      autoMinorVersionUpgrade: true,
    },
    credentials: rds.Credentials.fromGeneratedSecret('admin'),
    preferredMaintenanceWindow: 'Sun:00:00-Sun:03:00',
    iamAuthentication: true,
  });
}
// {/fact}

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
function good_case_15(scope: Construct) {
  const vpc = new ec2.Vpc(scope, 'VPC');
  
  // ok: typescript_cdk_aurora_my_sql_postgres_iam_auth
  const cluster = new rds.CfnDBCluster(scope, 'AuroraCluster', {
    engine: 'aurora-mysql',
    engineVersion: '8.0.mysql_aurora.3.02.0',
    masterUsername: 'admin',
    masterUserPassword: 'password123',
    dbSubnetGroupName: 'my-subnet-group',
    vpcSecurityGroupIds: ['sg-12345'],
    port: 3306,
    backupRetentionPeriod: 7,
    storageEncrypted: true,
    enableIamDatabaseAuthentication: true,
  });
}
// {/fact}