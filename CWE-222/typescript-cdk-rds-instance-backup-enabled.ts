import * as cdk from 'aws-cdk-lib';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import { Construct } from 'constructs';

class ExampleStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Common setup for examples
    const vpc = new ec2.Vpc(this, 'VPC', {
      maxAzs: 2
    });

    // Bad Case 1: RDS instance without backup retention period specified
    const bad_case_1 = () => {
      // ruleid: typescript-cdk-rds-instance-backup-enabled
      new rds.DatabaseInstance(this, 'DatabaseWithoutBackup', {
        engine: rds.DatabaseInstanceEngine.mysql({
          version: rds.MysqlEngineVersion.VER_8_0_26
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
        databaseName: 'mydb',
        credentials: rds.Credentials.fromGeneratedSecret('admin')
      });
    };

    // Bad Case 2: RDS instance with backup retention period explicitly set to 0
    const bad_case_2 = () => {
      // ruleid: typescript-cdk-rds-instance-backup-enabled
      new rds.DatabaseInstance(this, 'DatabaseWithZeroBackup', {
        engine: rds.DatabaseInstanceEngine.postgres({
          version: rds.PostgresEngineVersion.VER_13_4
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
        databaseName: 'postgresdb',
        credentials: rds.Credentials.fromGeneratedSecret('postgres'),
        backupRetention: cdk.Duration.days(0)
      });
    };

    // Bad Case 3: RDS instance created with minimal configuration and no backup
    const bad_case_3 = () => {
      // ruleid: typescript-cdk-rds-instance-backup-enabled
      new rds.DatabaseInstance(this, 'MinimalDatabaseNoBackup', {
        engine: rds.DatabaseInstanceEngine.mariaDb({
          version: rds.MariaDbEngineVersion.VER_10_5
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
        credentials: rds.Credentials.fromGeneratedSecret('admin')
      });
    };

    // Bad Case 4: RDS instance with variable set to 0 for backup retention
    const bad_case_4 = () => {
      const backupDays = 0;
      // ruleid: typescript-cdk-rds-instance-backup-enabled
      new rds.DatabaseInstance(this, 'DatabaseWithVariableZeroBackup', {
        engine: rds.DatabaseInstanceEngine.mysql({
          version: rds.MysqlEngineVersion.VER_8_0_28
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
        databaseName: 'appdb',
        credentials: rds.Credentials.fromGeneratedSecret('dbadmin'),
        backupRetention: cdk.Duration.days(backupDays)
      });
    };

    // Bad Case 5: RDS instance with computed value that results in 0 backup days
    const bad_case_5 = () => {
      const configuredDays = 2;
      const reductionFactor = 2;
      // ruleid: typescript-cdk-rds-instance-backup-enabled
      new rds.DatabaseInstance(this, 'DatabaseWithComputedZeroBackup', {
        engine: rds.DatabaseInstanceEngine.postgres({
          version: rds.PostgresEngineVersion.VER_14_2
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
        databaseName: 'enterprisedb',
        credentials: rds.Credentials.fromGeneratedSecret('pgadmin'),
        backupRetention: cdk.Duration.days(configuredDays - reductionFactor)
      });
    };

    // Bad Case 6: RDS instance in production environment without backup
    const bad_case_6 = () => {
      // ruleid: typescript-cdk-rds-instance-backup-enabled
      new rds.DatabaseInstance(this, 'ProductionDatabaseNoBackup', {
        engine: rds.DatabaseInstanceEngine.mysql({
          version: rds.MysqlEngineVersion.VER_8_0_30
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.XLARGE),
        databaseName: 'production',
        credentials: rds.Credentials.fromGeneratedSecret('prodadmin'),
        storageEncrypted: true,
        multiAz: true
      });
    };

    // Bad Case 7: RDS instance with conditional backup that evaluates to 0
    const bad_case_7 = () => {
      const isDevEnvironment = true;
      const backupDays = isDevEnvironment ? 0 : 7;
      // ruleid: typescript-cdk-rds-instance-backup-enabled
      new rds.DatabaseInstance(this, 'ConditionalZeroBackupDatabase', {
        engine: rds.DatabaseInstanceEngine.postgres({
          version: rds.PostgresEngineVersion.VER_13_7
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
        databaseName: 'devdb',
        credentials: rds.Credentials.fromGeneratedSecret('devuser'),
        backupRetention: cdk.Duration.days(backupDays)
      });
    };

    // Bad Case 8: RDS instance with backup disabled via options
    const bad_case_8 = () => {
      const options = {
        enableBackup: false,
        backupDays: 0
      };
      // ruleid: typescript-cdk-rds-instance-backup-enabled
      new rds.DatabaseInstance(this, 'OptionsDisabledBackupDatabase', {
        engine: rds.DatabaseInstanceEngine.mysql({
          version: rds.MysqlEngineVersion.VER_5_7
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.SMALL),
        databaseName: 'legacydb',
        credentials: rds.Credentials.fromGeneratedSecret('dbuser'),
        backupRetention: cdk.Duration.days(options.backupDays)
      });
    };

    // Bad Case 9: RDS instance with backup explicitly disabled for testing
    const bad_case_9 = () => {
      // ruleid: typescript-cdk-rds-instance-backup-enabled
      new rds.DatabaseInstance(this, 'TestDatabaseNoBackup', {
        engine: rds.DatabaseInstanceEngine.mariaDb({
          version: rds.MariaDbEngineVersion.VER_10_6
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
        databaseName: 'testdb',
        credentials: rds.Credentials.fromGeneratedSecret('testuser'),
        backupRetention: cdk.Duration.days(0),
        deletionProtection: false
      });
    };

    // Bad Case 10: RDS instance with backup set to 0 in high availability setup
    const bad_case_10 = () => {
      // ruleid: typescript-cdk-rds-instance-backup-enabled
      new rds.DatabaseInstance(this, 'HighAvailabilityNoBackup', {
        engine: rds.DatabaseInstanceEngine.postgres({
          version: rds.PostgresEngineVersion.VER_14_3
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.M6G, ec2.InstanceSize.XLARGE),
        databaseName: 'hadb',
        credentials: rds.Credentials.fromGeneratedSecret('haadmin'),
        multiAz: true,
        storageEncrypted: true,
        backupRetention: cdk.Duration.days(0)
      });
    };

    // Bad Case 11: RDS instance with backup disabled in a function
    const bad_case_11 = () => {
      const createDatabase = (id: string, backupEnabled: boolean) => {
        // ruleid: typescript-cdk-rds-instance-backup-enabled
        return new rds.DatabaseInstance(this, id, {
          engine: rds.DatabaseInstanceEngine.mysql({
            version: rds.MysqlEngineVersion.VER_8_0_28
          }),
          vpc,
          instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
          databaseName: 'funcdb',
          credentials: rds.Credentials.fromGeneratedSecret('dbuser'),
          backupRetention: backupEnabled ? cdk.Duration.days(7) : cdk.Duration.days(0)
        });
      };
      
      createDatabase('FunctionCreatedDatabaseNoBackup', false);
    };

    // Bad Case 12: RDS instance with backup disabled in a loop
    const bad_case_12 = () => {
      const dbConfigs = [
        { id: 'DB1', name: 'db1', backupDays: 7 },
        { id: 'DB2', name: 'db2', backupDays: 0 },  // This one has no backup
      ];
      
      for (const config of dbConfigs) {
        if (config.id === 'DB2') {
          // ruleid: typescript-cdk-rds-instance-backup-enabled
          new rds.DatabaseInstance(this, config.id, {
            engine: rds.DatabaseInstanceEngine.mysql({
              version: rds.MysqlEngineVersion.VER_8_0_26
            }),
            vpc,
            instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
            databaseName: config.name,
            credentials: rds.Credentials.fromGeneratedSecret('admin'),
            backupRetention: cdk.Duration.days(config.backupDays)
          });
        }
      }
    };

    // Bad Case 13: RDS instance with backup disabled based on environment variable
    const bad_case_13 = () => {
      // Simulating an environment variable
      const envBackupDays = 0;
      
      // ruleid: typescript-cdk-rds-instance-backup-enabled
      new rds.DatabaseInstance(this, 'EnvVarDatabaseNoBackup', {
        engine: rds.DatabaseInstanceEngine.postgres({
          version: rds.PostgresEngineVersion.VER_13_4
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
        databaseName: 'envdb',
        credentials: rds.Credentials.fromGeneratedSecret('envuser'),
        backupRetention: cdk.Duration.days(envBackupDays)
      });
    };

    // Bad Case 14: RDS instance with backup disabled in a complex configuration
    const bad_case_14 = () => {
      const config = {
        database: {
          settings: {
            backup: {
              enabled: false,
              retentionDays: 0
            }
          }
        }
      };
      
      // ruleid: typescript-cdk-rds-instance-backup-enabled
      new rds.DatabaseInstance(this, 'ComplexConfigNoBackup', {
        engine: rds.DatabaseInstanceEngine.mysql({
          version: rds.MysqlEngineVersion.VER_8_0_28
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.LARGE),
        databaseName: 'complexdb',
        credentials: rds.Credentials.fromGeneratedSecret('complexadmin'),
        backupRetention: cdk.Duration.days(config.database.settings.backup.retentionDays)
      });
    };

    // Bad Case 15: RDS instance with backup disabled for a read replica
    const bad_case_15 = () => {
      const sourceDb = new rds.DatabaseInstance(this, 'SourceDatabase', {
        engine: rds.DatabaseInstanceEngine.mysql({
          version: rds.MysqlEngineVersion.VER_8_0_28
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
        databaseName: 'sourcedb',
        credentials: rds.Credentials.fromGeneratedSecret('sourceadmin'),
        backupRetention: cdk.Duration.days(7)
      });
      
      // ruleid: typescript-cdk-rds-instance-backup-enabled
      new rds.DatabaseInstanceReadReplica(this, 'ReadReplicaNoBackup', {
        sourceDatabaseInstance: sourceDb,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
        vpc,
        backupRetention: cdk.Duration.days(0)
      });
    };

    // Good Case 1: RDS instance with backup retention period set to 7 days
    const good_case_1 = () => {
      // ok: typescript-cdk-rds-instance-backup-enabled
      new rds.DatabaseInstance(this, 'DatabaseWithBackup', {
        engine: rds.DatabaseInstanceEngine.mysql({
          version: rds.MysqlEngineVersion.VER_8_0_26
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
        databaseName: 'mydb',
        credentials: rds.Credentials.fromGeneratedSecret('admin'),
        backupRetention: cdk.Duration.days(7)
      });
    };

    // Good Case 2: RDS instance with minimum recommended backup retention (1 day)
    const good_case_2 = () => {
      // ok: typescript-cdk-rds-instance-backup-enabled
      new rds.DatabaseInstance(this, 'DatabaseWithMinBackup', {
        engine: rds.DatabaseInstanceEngine.postgres({
          version: rds.PostgresEngineVersion.VER_13_4
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
        databaseName: 'postgresdb',
        credentials: rds.Credentials.fromGeneratedSecret('postgres'),
        backupRetention: cdk.Duration.days(1)
      });
    };

    // Good Case 3: RDS instance with variable backup retention period
    const good_case_3 = () => {
      const backupDays = 14;
      // ok: typescript-cdk-rds-instance-backup-enabled
      new rds.DatabaseInstance(this, 'DatabaseWithVariableBackup', {
        engine: rds.DatabaseInstanceEngine.mariaDb({
          version: rds.MariaDbEngineVersion.VER_10_5
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
        credentials: rds.Credentials.fromGeneratedSecret('admin'),
        backupRetention: cdk.Duration.days(backupDays)
      });
    };

    // Good Case 4: RDS instance with computed backup retention period
    const good_case_4 = () => {
      const baseDays = 7;
      const additionalDays = 3;
      // ok: typescript-cdk-rds-instance-backup-enabled
      new rds.DatabaseInstance(this, 'DatabaseWithComputedBackup', {
        engine: rds.DatabaseInstanceEngine.mysql({
          version: rds.MysqlEngineVersion.VER_8_0_28
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
        databaseName: 'appdb',
        credentials: rds.Credentials.fromGeneratedSecret('dbadmin'),
        backupRetention: cdk.Duration.days(baseDays + additionalDays)
      });
    };

    // Good Case 5: RDS instance with conditional backup that evaluates to a positive value
    const good_case_5 = () => {
      const isProduction = true;
      const backupDays = isProduction ? 30 : 7;
      // ok: typescript-cdk-rds-instance-backup-enabled
      new rds.DatabaseInstance(this, 'ConditionalBackupDatabase', {
        engine: rds.DatabaseInstanceEngine.postgres({
          version: rds.PostgresEngineVersion.VER_14_2
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
        databaseName: 'enterprisedb',
        credentials: rds.Credentials.fromGeneratedSecret('pgadmin'),
        backupRetention: cdk.Duration.days(backupDays)
      });
    };

    // Good Case 6: RDS instance with maximum backup retention period
    const good_case_6 = () => {
      // ok: typescript-cdk-rds-instance-backup-enabled
      new rds.DatabaseInstance(this, 'DatabaseWithMaxBackup', {
        engine: rds.DatabaseInstanceEngine.mysql({
          version: rds.MysqlEngineVersion.VER_8_0_30
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.XLARGE),
        databaseName: 'production',
        credentials: rds.Credentials.fromGeneratedSecret('prodadmin'),
        storageEncrypted: true,
        multiAz: true,
        backupRetention: cdk.Duration.days(35) // Maximum allowed by AWS
      });
    };

    // Good Case 7: RDS instance with backup enabled via options
    const good_case_7 = () => {
      const options = {
        enableBackup: true,
        backupDays: 14
      };
      // ok: typescript-cdk-rds-instance-backup-enabled
      new rds.DatabaseInstance(this, 'OptionsEnabledBackupDatabase', {
        engine: rds.DatabaseInstanceEngine.postgres({
          version: rds.PostgresEngineVersion.VER_13_7
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
        databaseName: 'devdb',
        credentials: rds.Credentials.fromGeneratedSecret('devuser'),
        backupRetention: cdk.Duration.days(options.backupDays)
      });
    };

    // Good Case 8: RDS instance with backup enabled in a function
    const good_case_8 = () => {
      const createDatabase = (id: string, backupDays: number) => {
        // ok: typescript-cdk-rds-instance-backup-enabled
        return new rds.DatabaseInstance(this, id, {
          engine: rds.DatabaseInstanceEngine.mysql({
            version: rds.MysqlEngineVersion.VER_5_7
          }),
          vpc,
          instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.SMALL),
          databaseName: 'funcdb',
          credentials: rds.Credentials.fromGeneratedSecret('dbuser'),
          backupRetention: cdk.Duration.days(backupDays)
        });
      };
      
      createDatabase('FunctionCreatedDatabaseWithBackup', 7);
    };

    // Good Case 9: RDS instance with backup enabled in a loop
    const good_case_9 = () => {
      const dbConfigs = [
        { id: 'DB1', name: 'db1', backupDays: 7 },
        { id: 'DB2', name: 'db2', backupDays: 14 }
      ];
      
      for (const config of dbConfigs) {
        // ok: typescript-cdk-rds-instance-backup-enabled
        new rds.DatabaseInstance(this, config.id, {
          engine: rds.DatabaseInstanceEngine.mariaDb({
            version: rds.MariaDbEngineVersion.VER_10_6
          }),
          vpc,
          instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
          databaseName: config.name,
          credentials: rds.Credentials.fromGeneratedSecret('loopuser'),
          backupRetention: cdk.Duration.days(config.backupDays)
        });
      }
    };

    // Good Case 10: RDS instance with backup enabled based on environment variable
    const good_case_10 = () => {
      // Simulating an environment variable
      const envBackupDays = 7;
      
      // ok: typescript-cdk-rds-instance-backup-enabled
      new rds.DatabaseInstance(this, 'EnvVarDatabaseWithBackup', {
        engine: rds.DatabaseInstanceEngine.postgres({
          version: rds.PostgresEngineVersion.VER_14_3
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.M6G, ec2.InstanceSize.XLARGE),
        databaseName: 'hadb',
        credentials: rds.Credentials.fromGeneratedSecret('haadmin'),
        multiAz: true,
        storageEncrypted: true,
        backupRetention: cdk.Duration.days(envBackupDays)
      });
    };

    // Good Case 11: RDS instance with backup enabled in a complex configuration
    const good_case_11 = () => {
      const config = {
        database: {
          settings: {
            backup: {
              enabled: true,
              retentionDays: 21
            }
          }
        }
      };
      
      // ok: typescript-cdk-rds-instance-backup-enabled
      new rds.DatabaseInstance(this, 'ComplexConfigWithBackup', {
        engine: rds.DatabaseInstanceEngine.mysql({
          version: rds.MysqlEngineVersion.VER_8_0_28
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.LARGE),
        databaseName: 'complexdb',
        credentials: rds.Credentials.fromGeneratedSecret('complexadmin'),
        backupRetention: cdk.Duration.days(config.database.settings.backup.retentionDays)
      });
    };

    // Good Case 12: RDS instance with backup enabled for a read replica
    const good_case_12 = () => {
      const sourceDb = new rds.DatabaseInstance(this, 'SourceDatabaseWithBackup', {
        engine: rds.DatabaseInstanceEngine.mysql({
          version: rds.MysqlEngineVersion.VER_8_0_28
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
        databaseName: 'sourcedb',
        credentials: rds.Credentials.fromGeneratedSecret('sourceadmin'),
        backupRetention: cdk.Duration.days(7)
      });
      
      // ok: typescript-cdk-rds-instance-backup-enabled
      new rds.DatabaseInstanceReadReplica(this, 'ReadReplicaWithBackup', {
        sourceDatabaseInstance: sourceDb,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
        vpc,
        backupRetention: cdk.Duration.days(3)
      });
    };

    // Good Case 13: RDS instance with backup enabled and point-in-time recovery
    const good_case_13 = () => {
      // ok: typescript-cdk-rds-instance-backup-enabled
      new rds.DatabaseInstance(this, 'DatabaseWithPITR', {
        engine: rds.DatabaseInstanceEngine.postgres({
          version: rds.PostgresEngineVersion.VER_13_4
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
        databaseName: 'pitrdb',
        credentials: rds.Credentials.fromGeneratedSecret('pitruser'),
        backupRetention: cdk.Duration.days(5),
        enablePerformanceInsights: true
      });
    };

    // Good Case 14: RDS instance with backup enabled and custom parameter group
    const good_case_14 = () => {
      const parameterGroup = new rds.ParameterGroup(this, 'CustomParameterGroup', {
        engine: rds.DatabaseInstanceEngine.mysql({
          version: rds.MysqlEngineVersion.VER_8_0_28
        })
      });
      
      // ok: typescript-cdk-rds-instance-backup-enabled
      new rds.DatabaseInstance(this, 'DatabaseWithCustomParams', {
        engine: rds.DatabaseInstanceEngine.mysql({
          version: rds.MysqlEngineVersion.VER_8_0_28
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
        databaseName: 'paramdb',
        credentials: rds.Credentials.fromGeneratedSecret('paramuser'),
        parameterGroup: parameterGroup,
        backupRetention: cdk.Duration.days(10)
      });
    };

    // Good Case 15: RDS instance with backup enabled and monitoring
    const good_case_15 = () => {
      // ok: typescript-cdk-rds-instance-backup-enabled
      new rds.DatabaseInstance(this, 'DatabaseWithMonitoring', {
        engine: rds.DatabaseInstanceEngine.mysql({
          version: rds.MysqlEngineVersion.VER_8_0_26
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.XLARGE),
        databaseName: 'monitordb',
        credentials: rds.Credentials.fromGeneratedSecret('monitoradmin'),
        monitoringInterval: cdk.Duration.minutes(1),
        enablePerformanceInsights: true,
        backupRetention: cdk.Duration.days(14)
      });
    };
  }
}

const app = new cdk.App();
new ExampleStack(app, 'RdsBackupExampleStack');