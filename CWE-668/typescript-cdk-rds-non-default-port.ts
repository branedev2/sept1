import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

class DatabaseStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Create a VPC for examples
    const vpc = new ec2.Vpc(this, 'VPC', {
      maxAzs: 2
    });

    // True Positive Examples (Vulnerable Code)

// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_1() {
      // ruleid: typescript-cdk-rds-non-default-port
      const instance = new rds.DatabaseInstance(this, 'MyDatabase1', {
        engine: rds.DatabaseInstanceEngine.mysql({
          version: rds.MysqlEngineVersion.VER_8_0_28
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
        // Using default MySQL port 3306 (not specified)
      });
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_2() {
      // ruleid: typescript-cdk-rds-non-default-port
      const instance = new rds.DatabaseInstance(this, 'MyDatabase2', {
        engine: rds.DatabaseInstanceEngine.postgres({
          version: rds.PostgresEngineVersion.VER_13_4
        }),
        vpc,
        port: 5432, // Explicitly using default PostgreSQL port
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      });
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_3() {
      // ruleid: typescript-cdk-rds-non-default-port
      const cluster = new rds.DatabaseCluster(this, 'AuroraCluster1', {
        engine: rds.DatabaseClusterEngine.auroraMysql({
          version: rds.AuroraMysqlEngineVersion.VER_3_02_0
        }),
        instanceProps: {
          vpc,
          instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
        },
        // Using default Aurora MySQL port 3306 (not specified)
      });
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_4() {
      // ruleid: typescript-cdk-rds-non-default-port
      const cluster = new rds.DatabaseCluster(this, 'AuroraCluster2', {
        engine: rds.DatabaseClusterEngine.auroraPostgres({
          version: rds.AuroraPostgresEngineVersion.VER_13_4
        }),
        instanceProps: {
          vpc,
          instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
        },
        port: 5432, // Explicitly using default PostgreSQL port
      });
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_5() {
      // ruleid: typescript-cdk-rds-non-default-port
      const instance = new rds.DatabaseInstance(this, 'SQLServerDB', {
        engine: rds.DatabaseInstanceEngine.sqlServerEe({
          version: rds.SqlServerEngineVersion.VER_15
        }),
        vpc,
        port: 1433, // Explicitly using default SQL Server port
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
      });
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_6() {
      // ruleid: typescript-cdk-rds-non-default-port
      const instance = new rds.DatabaseInstance(this, 'OracleDB', {
        engine: rds.DatabaseInstanceEngine.oracleEe({
          version: rds.OracleEngineVersion.VER_19_0_0_0_2021_04_R1
        }),
        vpc,
        port: 1521, // Explicitly using default Oracle port
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.XLARGE),
      });
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_7() {
      const dbConfig = {
        engine: rds.DatabaseInstanceEngine.mariaDb({
          version: rds.MariaDbEngineVersion.VER_10_5
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
      };
      
      // ruleid: typescript-cdk-rds-non-default-port
      const instance = new rds.DatabaseInstance(this, 'MariaDB', dbConfig);
      // Using default MariaDB port 3306 (not specified)
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_8() {
      const portNumber = 3306; // Default MySQL port
      
      // ruleid: typescript-cdk-rds-non-default-port
      const instance = new rds.DatabaseInstance(this, 'MySQLWithVariable', {
        engine: rds.DatabaseInstanceEngine.mysql({
          version: rds.MysqlEngineVersion.VER_8_0_28
        }),
        vpc,
        port: portNumber, // Using variable with default port
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      });
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_9() {
      const getDefaultPort = () => {
        return 5432; // Default PostgreSQL port
      };
      
      // ruleid: typescript-cdk-rds-non-default-port
      const instance = new rds.DatabaseInstance(this, 'PostgresWithFunction', {
        engine: rds.DatabaseInstanceEngine.postgres({
          version: rds.PostgresEngineVersion.VER_13_4
        }),
        vpc,
        port: getDefaultPort(), // Using function that returns default port
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      });
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_10() {
      const config = {
        port: 1433, // Default SQL Server port
        engine: rds.DatabaseInstanceEngine.sqlServerEe({
          version: rds.SqlServerEngineVersion.VER_15
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
      };
      
      // ruleid: typescript-cdk-rds-non-default-port
      const instance = new rds.DatabaseInstance(this, 'SQLServerWithConfig', config);
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_11() {
      const DEFAULT_PORTS = {
        mysql: 3306,
        postgres: 5432,
        sqlserver: 1433,
        oracle: 1521,
      };
      
      // ruleid: typescript-cdk-rds-non-default-port
      const cluster = new rds.DatabaseCluster(this, 'AuroraClusterWithMap', {
        engine: rds.DatabaseClusterEngine.auroraMysql({
          version: rds.AuroraMysqlEngineVersion.VER_3_02_0
        }),
        instanceProps: {
          vpc,
          instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
        },
        port: DEFAULT_PORTS.mysql, // Using map with default port
      });
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_12() {
      const params = {
        engineVersion: rds.PostgresEngineVersion.VER_13_4,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      };
      
      // ruleid: typescript-cdk-rds-non-default-port
      const instance = new rds.DatabaseInstance(this, 'PostgresWithParams', {
        engine: rds.DatabaseInstanceEngine.postgres({
          version: params.engineVersion
        }),
        vpc,
        instanceType: params.instanceType,
        // Using default PostgreSQL port 5432 (not specified)
      });
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_13() {
      const environment = 'dev';
      let port;
      
      if (environment === 'prod') {
        port = 5433; // Non-default port
      } else {
        port = 5432; // Default PostgreSQL port
      }
      
      // ruleid: typescript-cdk-rds-non-default-port
      const instance = new rds.DatabaseInstance(this, 'PostgresWithCondition', {
        engine: rds.DatabaseInstanceEngine.postgres({
          version: rds.PostgresEngineVersion.VER_13_4
        }),
        vpc,
        port: port, // Using conditional port that resolves to default
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      });
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_14() {
      const baseConfig = {
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      };
      
      // ruleid: typescript-cdk-rds-non-default-port
      const instance = new rds.DatabaseInstance(this, 'MySQLWithSpread', {
        engine: rds.DatabaseInstanceEngine.mysql({
          version: rds.MysqlEngineVersion.VER_8_0_28
        }),
        ...baseConfig,
        // Using default MySQL port 3306 (not specified)
      });
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
    function bad_case_15() {
      const serverlessConfig = {
        enableHttpEndpoint: true,
        autoPause: cdk.Duration.minutes(10),
      };
      
      // ruleid: typescript-cdk-rds-non-default-port
      const cluster = new rds.ServerlessCluster(this, 'AuroraServerless', {
        engine: rds.DatabaseClusterEngine.auroraMysql({
          version: rds.AuroraMysqlEngineVersion.VER_2_08_1
        }),
        vpc,
        scaling: serverlessConfig,
        // Using default Aurora MySQL port 3306 (not specified)
      });
    }
// {/fact}

    // True Negative Examples (Secure Code)

// {fact rule=code-injection@v1.0 defects=0}
    function good_case_1() {
      // ok: typescript-cdk-rds-non-default-port
      const instance = new rds.DatabaseInstance(this, 'SecureMySQL', {
        engine: rds.DatabaseInstanceEngine.mysql({
          version: rds.MysqlEngineVersion.VER_8_0_28
        }),
        vpc,
        port: 3307, // Non-default MySQL port
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      });
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
    function good_case_2() {
      // ok: typescript-cdk-rds-non-default-port
      const instance = new rds.DatabaseInstance(this, 'SecurePostgres', {
        engine: rds.DatabaseInstanceEngine.postgres({
          version: rds.PostgresEngineVersion.VER_13_4
        }),
        vpc,
        port: 5433, // Non-default PostgreSQL port
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      });
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
    function good_case_3() {
      // ok: typescript-cdk-rds-non-default-port
      const cluster = new rds.DatabaseCluster(this, 'SecureAuroraMySQL', {
        engine: rds.DatabaseClusterEngine.auroraMysql({
          version: rds.AuroraMysqlEngineVersion.VER_3_02_0
        }),
        instanceProps: {
          vpc,
          instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
        },
        port: 3307, // Non-default Aurora MySQL port
      });
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
    function good_case_4() {
      // ok: typescript-cdk-rds-non-default-port
      const cluster = new rds.DatabaseCluster(this, 'SecureAuroraPostgres', {
        engine: rds.DatabaseClusterEngine.auroraPostgres({
          version: rds.AuroraPostgresEngineVersion.VER_13_4
        }),
        instanceProps: {
          vpc,
          instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
        },
        port: 5433, // Non-default PostgreSQL port
      });
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
    function good_case_5() {
      // ok: typescript-cdk-rds-non-default-port
      const instance = new rds.DatabaseInstance(this, 'SecureSQLServer', {
        engine: rds.DatabaseInstanceEngine.sqlServerEe({
          version: rds.SqlServerEngineVersion.VER_15
        }),
        vpc,
        port: 1434, // Non-default SQL Server port
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
      });
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
    function good_case_6() {
      // ok: typescript-cdk-rds-non-default-port
      const instance = new rds.DatabaseInstance(this, 'SecureOracle', {
        engine: rds.DatabaseInstanceEngine.oracleEe({
          version: rds.OracleEngineVersion.VER_19_0_0_0_2021_04_R1
        }),
        vpc,
        port: 1522, // Non-default Oracle port
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.XLARGE),
      });
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
    function good_case_7() {
      const dbConfig = {
        engine: rds.DatabaseInstanceEngine.mariaDb({
          version: rds.MariaDbEngineVersion.VER_10_5
        }),
        vpc,
        port: 3307, // Non-default MariaDB port
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
      };
      
      // ok: typescript-cdk-rds-non-default-port
      const instance = new rds.DatabaseInstance(this, 'SecureMariaDB', dbConfig);
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
    function good_case_8() {
      const portNumber = 3307; // Non-default MySQL port
      
      // ok: typescript-cdk-rds-non-default-port
      const instance = new rds.DatabaseInstance(this, 'SecureMySQLWithVariable', {
        engine: rds.DatabaseInstanceEngine.mysql({
          version: rds.MysqlEngineVersion.VER_8_0_28
        }),
        vpc,
        port: portNumber, // Using variable with non-default port
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      });
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
    function good_case_9() {
      const getNonDefaultPort = () => {
        return 5433; // Non-default PostgreSQL port
      };
      
      // ok: typescript-cdk-rds-non-default-port
      const instance = new rds.DatabaseInstance(this, 'SecurePostgresWithFunction', {
        engine: rds.DatabaseInstanceEngine.postgres({
          version: rds.PostgresEngineVersion.VER_13_4
        }),
        vpc,
        port: getNonDefaultPort(), // Using function that returns non-default port
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      });
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
    function good_case_10() {
      const config = {
        port: 1434, // Non-default SQL Server port
        engine: rds.DatabaseInstanceEngine.sqlServerEe({
          version: rds.SqlServerEngineVersion.VER_15
        }),
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
      };
      
      // ok: typescript-cdk-rds-non-default-port
      const instance = new rds.DatabaseInstance(this, 'SecureSQLServerWithConfig', config);
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
    function good_case_11() {
      const SECURE_PORTS = {
        mysql: 3307,
        postgres: 5433,
        sqlserver: 1434,
        oracle: 1522,
      };
      
      // ok: typescript-cdk-rds-non-default-port
      const cluster = new rds.DatabaseCluster(this, 'SecureAuroraClusterWithMap', {
        engine: rds.DatabaseClusterEngine.auroraMysql({
          version: rds.AuroraMysqlEngineVersion.VER_3_02_0
        }),
        instanceProps: {
          vpc,
          instanceType: ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
        },
        port: SECURE_PORTS.mysql, // Using map with non-default port
      });
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
    function good_case_12() {
      const params = {
        engineVersion: rds.PostgresEngineVersion.VER_13_4,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
        port: 5433, // Non-default PostgreSQL port
      };
      
      // ok: typescript-cdk-rds-non-default-port
      const instance = new rds.DatabaseInstance(this, 'SecurePostgresWithParams', {
        engine: rds.DatabaseInstanceEngine.postgres({
          version: params.engineVersion
        }),
        vpc,
        instanceType: params.instanceType,
        port: params.port, // Using parameter with non-default port
      });
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
    function good_case_13() {
      const environment = 'dev';
      let port;
      
      if (environment === 'prod') {
        port = 3307; // Non-default port
      } else {
        port = 3308; // Another non-default port
      }
      
      // ok: typescript-cdk-rds-non-default-port
      const instance = new rds.DatabaseInstance(this, 'SecureMySQLWithCondition', {
        engine: rds.DatabaseInstanceEngine.mysql({
          version: rds.MysqlEngineVersion.VER_8_0_28
        }),
        vpc,
        port: port, // Using conditional port that resolves to non-default
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
      });
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
    function good_case_14() {
      const baseConfig = {
        vpc,
        instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
        port: 3307, // Non-default MySQL port
      };
      
      // ok: typescript-cdk-rds-non-default-port
      const instance = new rds.DatabaseInstance(this, 'SecureMySQLWithSpread', {
        engine: rds.DatabaseInstanceEngine.mysql({
          version: rds.MysqlEngineVersion.VER_8_0_28
        }),
        ...baseConfig,
      });
    }
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
    function good_case_15() {
      const serverlessConfig = {
        enableHttpEndpoint: true,
        autoPause: cdk.Duration.minutes(10),
      };
      
      // ok: typescript-cdk-rds-non-default-port
      const cluster = new rds.ServerlessCluster(this, 'SecureAuroraServerless', {
        engine: rds.DatabaseClusterEngine.auroraMysql({
          version: rds.AuroraMysqlEngineVersion.VER_2_08_1
        }),
        vpc,
        scaling: serverlessConfig,
        port: 3307, // Non-default Aurora MySQL port
      });
    }
// {/fact}

  }
}

const app = new cdk.App();
new DatabaseStack(app, 'DatabaseStack');