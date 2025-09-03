import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as quicksight from 'aws-cdk-lib/aws-quicksight';

// True Positive Examples (Vulnerable Code)

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_1(scope: Construct) {
  // Creating a MySQL data source without SSL enabled
  // ruleid: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'VulnerableMySQLDataSource', {
    awsAccountId: '123456789012',
    dataSourceId: 'mysql-data-source',
    name: 'MySQL Data Source',
    type: 'MYSQL',
    dataSourceParameters: {
      mySqlParameters: {
        host: 'mysql-database.example.com',
        port: 3306,
        database: 'mydb'
      }
    },
    credentials: {
      credentialPair: {
        username: 'admin',
        password: 'password123'
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_2(scope: Construct) {
  // Creating a PostgreSQL data source with SSL explicitly disabled
  // ruleid: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'PostgreSQLDataSourceNoSSL', {
    awsAccountId: '123456789012',
    dataSourceId: 'postgres-data-source',
    name: 'PostgreSQL Data Source',
    type: 'POSTGRESQL',
    dataSourceParameters: {
      postgreSqlParameters: {
        host: 'postgres-db.example.com',
        port: 5432,
        database: 'analytics',
        sslMode: 'disable'
      }
    },
    credentials: {
      credentialPair: {
        username: 'dbuser',
        password: 'dbpass'
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_3(scope: Construct) {
  // Creating an Amazon RDS data source without SSL configuration
  // ruleid: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'RDSDataSourceNoSSL', {
    awsAccountId: '123456789012',
    dataSourceId: 'rds-data-source',
    name: 'RDS Data Source',
    type: 'AMAZON_RDS',
    dataSourceParameters: {
      amazonRdsParameters: {
        instanceId: 'rds-instance-1',
        database: 'reporting'
      }
    },
    credentials: {
      credentialPair: {
        username: 'rdsuser',
        password: 'rdspassword'
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_4(scope: Construct) {
  // Creating a SQL Server data source without SSL
  // ruleid: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'SQLServerDataSourceNoSSL', {
    awsAccountId: '123456789012',
    dataSourceId: 'sqlserver-data-source',
    name: 'SQL Server Data Source',
    type: 'SQLSERVER',
    dataSourceParameters: {
      sqlServerParameters: {
        host: 'sqlserver.example.com',
        port: 1433,
        database: 'analytics'
      }
    },
    credentials: {
      credentialPair: {
        username: 'sa',
        password: 'sqlpass'
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_5(scope: Construct) {
  // Creating a MariaDB data source without SSL
  // ruleid: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'MariaDBDataSourceNoSSL', {
    awsAccountId: '123456789012',
    dataSourceId: 'mariadb-data-source',
    name: 'MariaDB Data Source',
    type: 'MARIADB',
    dataSourceParameters: {
      mariaDbParameters: {
        host: 'mariadb.example.com',
        port: 3306,
        database: 'reports'
      }
    },
    credentials: {
      credentialPair: {
        username: 'dbadmin',
        password: 'mariapass'
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_6(scope: Construct) {
  // Creating a Teradata data source without SSL
  // ruleid: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'TeradataDataSourceNoSSL', {
    awsAccountId: '123456789012',
    dataSourceId: 'teradata-data-source',
    name: 'Teradata Data Source',
    type: 'TERADATA',
    dataSourceParameters: {
      teradataParameters: {
        host: 'teradata.example.com',
        port: 1025,
        database: 'warehouse'
      }
    },
    credentials: {
      credentialPair: {
        username: 'tduser',
        password: 'tdpassword'
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_7(scope: Construct) {
  // Creating an Oracle data source without SSL
  // ruleid: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'OracleDataSourceNoSSL', {
    awsAccountId: '123456789012',
    dataSourceId: 'oracle-data-source',
    name: 'Oracle Data Source',
    type: 'ORACLE',
    dataSourceParameters: {
      oracleParameters: {
        host: 'oracle-db.example.com',
        port: 1521,
        database: 'ORCL'
      }
    },
    credentials: {
      credentialPair: {
        username: 'system',
        password: 'oraclepass'
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_8(scope: Construct) {
  // Creating a Presto data source without SSL
  // ruleid: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'PrestoDataSourceNoSSL', {
    awsAccountId: '123456789012',
    dataSourceId: 'presto-data-source',
    name: 'Presto Data Source',
    type: 'PRESTO',
    dataSourceParameters: {
      prestoParameters: {
        host: 'presto.example.com',
        port: 8889,
        catalog: 'hive'
      }
    },
    credentials: {
      credentialPair: {
        username: 'presto',
        password: 'prestopass'
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_9(scope: Construct) {
  // Creating a Snowflake data source without SSL
  // ruleid: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'SnowflakeDataSourceNoSSL', {
    awsAccountId: '123456789012',
    dataSourceId: 'snowflake-data-source',
    name: 'Snowflake Data Source',
    type: 'SNOWFLAKE',
    dataSourceParameters: {
      snowflakeParameters: {
        host: 'snowflake.example.com',
        database: 'SNOWFLAKE_SAMPLE_DATA',
        warehouse: 'COMPUTE_WH'
      }
    },
    credentials: {
      credentialPair: {
        username: 'snowuser',
        password: 'snowpass'
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_10(scope: Construct) {
  // Creating a Spark data source without SSL
  // ruleid: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'SparkDataSourceNoSSL', {
    awsAccountId: '123456789012',
    dataSourceId: 'spark-data-source',
    name: 'Spark Data Source',
    type: 'SPARK',
    dataSourceParameters: {
      sparkParameters: {
        host: 'spark.example.com',
        port: 10000
      }
    },
    credentials: {
      credentialPair: {
        username: 'spark',
        password: 'sparkpass'
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_11(scope: Construct, config: any) {
  // Creating a PostgreSQL data source with dynamic configuration but SSL disabled
  const host = config.dbHost || 'default-postgres.example.com';
  const port = config.dbPort || 5432;
  
  // ruleid: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'DynamicPostgreSQLNoSSL', {
    awsAccountId: '123456789012',
    dataSourceId: 'dynamic-postgres-source',
    name: 'Dynamic PostgreSQL Source',
    type: 'POSTGRESQL',
    dataSourceParameters: {
      postgreSqlParameters: {
        host: host,
        port: port,
        database: 'analytics',
        sslMode: 'prefer' // Not enforcing SSL
      }
    },
    credentials: {
      credentialPair: {
        username: config.username,
        password: config.password
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_12(scope: Construct) {
  // Creating a MySQL data source with connection parameters from a function but no SSL
  const getConnectionParams = () => {
    return {
      host: 'mysql-prod.example.com',
      port: 3306,
      database: 'customers'
    };
  };
  
  const params = getConnectionParams();
  
  // ruleid: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'FunctionParamsMySQLNoSSL', {
    awsAccountId: '123456789012',
    dataSourceId: 'function-mysql-source',
    name: 'Function Params MySQL Source',
    type: 'MYSQL',
    dataSourceParameters: {
      mySqlParameters: {
        host: params.host,
        port: params.port,
        database: params.database
      }
    },
    credentials: {
      credentialPair: {
        username: 'admin',
        password: 'securepass123'
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_13(scope: Construct) {
  // Creating an RDS Aurora data source without SSL
  // ruleid: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'AuroraDataSourceNoSSL', {
    awsAccountId: '123456789012',
    dataSourceId: 'aurora-data-source',
    name: 'Aurora Data Source',
    type: 'AURORA',
    dataSourceParameters: {
      auroraParameters: {
        host: 'aurora-cluster.cluster-xyz.us-east-1.rds.amazonaws.com',
        port: 3306,
        database: 'reporting'
      }
    },
    credentials: {
      credentialPair: {
        username: 'aurorauser',
        password: 'aurorapass'
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_14(scope: Construct) {
  // Creating a data source with conditional logic but still no SSL
  const isProd = process.env.ENVIRONMENT === 'production';
  const dbHost = isProd ? 'prod-db.example.com' : 'dev-db.example.com';
  
  // ruleid: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'ConditionalDataSourceNoSSL', {
    awsAccountId: '123456789012',
    dataSourceId: 'conditional-data-source',
    name: isProd ? 'Production Database' : 'Development Database',
    type: 'POSTGRESQL',
    dataSourceParameters: {
      postgreSqlParameters: {
        host: dbHost,
        port: 5432,
        database: isProd ? 'prod_analytics' : 'dev_analytics'
      }
    },
    credentials: {
      credentialPair: {
        username: isProd ? 'prod_user' : 'dev_user',
        password: isProd ? 'prod_password' : 'dev_password'
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=1}
function bad_case_15(scope: Construct) {
  // Creating a data source with SSL configuration but set to 'none'
  // ruleid: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'ExplicitNoSSLDataSource', {
    awsAccountId: '123456789012',
    dataSourceId: 'explicit-no-ssl-source',
    name: 'Explicitly No SSL Source',
    type: 'MYSQL',
    dataSourceParameters: {
      mySqlParameters: {
        host: 'mysql.example.com',
        port: 3306,
        database: 'reports',
        sslMode: 'none'
      }
    },
    credentials: {
      credentialPair: {
        username: 'reporter',
        password: 'reportpass'
      }
    }
  });
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_1(scope: Construct) {
  // Creating a MySQL data source with SSL enabled
  // ok: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'SecureMySQLDataSource', {
    awsAccountId: '123456789012',
    dataSourceId: 'mysql-data-source-ssl',
    name: 'MySQL Data Source with SSL',
    type: 'MYSQL',
    dataSourceParameters: {
      mySqlParameters: {
        host: 'mysql-database.example.com',
        port: 3306,
        database: 'mydb',
        sslMode: 'require'
      }
    },
    credentials: {
      credentialPair: {
        username: 'admin',
        password: 'password123'
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_2(scope: Construct) {
  // Creating a PostgreSQL data source with SSL explicitly enabled
  // ok: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'PostgreSQLDataSourceWithSSL', {
    awsAccountId: '123456789012',
    dataSourceId: 'postgres-data-source-ssl',
    name: 'PostgreSQL Data Source with SSL',
    type: 'POSTGRESQL',
    dataSourceParameters: {
      postgreSqlParameters: {
        host: 'postgres-db.example.com',
        port: 5432,
        database: 'analytics',
        sslMode: 'verify-full'
      }
    },
    credentials: {
      credentialPair: {
        username: 'dbuser',
        password: 'dbpass'
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_3(scope: Construct) {
  // Creating an Amazon RDS data source with SSL configuration
  // ok: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'RDSDataSourceWithSSL', {
    awsAccountId: '123456789012',
    dataSourceId: 'rds-data-source-ssl',
    name: 'RDS Data Source with SSL',
    type: 'AMAZON_RDS',
    dataSourceParameters: {
      amazonRdsParameters: {
        instanceId: 'rds-instance-1',
        database: 'reporting'
      }
    },
    sslProperties: {
      disableSsl: false
    },
    credentials: {
      credentialPair: {
        username: 'rdsuser',
        password: 'rdspassword'
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_4(scope: Construct) {
  // Creating a SQL Server data source with SSL enabled
  // ok: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'SQLServerDataSourceWithSSL', {
    awsAccountId: '123456789012',
    dataSourceId: 'sqlserver-data-source-ssl',
    name: 'SQL Server Data Source with SSL',
    type: 'SQLSERVER',
    dataSourceParameters: {
      sqlServerParameters: {
        host: 'sqlserver.example.com',
        port: 1433,
        database: 'analytics'
      }
    },
    sslProperties: {
      disableSsl: false
    },
    credentials: {
      credentialPair: {
        username: 'sa',
        password: 'sqlpass'
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_5(scope: Construct) {
  // Creating a MariaDB data source with SSL enabled
  // ok: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'MariaDBDataSourceWithSSL', {
    awsAccountId: '123456789012',
    dataSourceId: 'mariadb-data-source-ssl',
    name: 'MariaDB Data Source with SSL',
    type: 'MARIADB',
    dataSourceParameters: {
      mariaDbParameters: {
        host: 'mariadb.example.com',
        port: 3306,
        database: 'reports'
      }
    },
    sslProperties: {
      disableSsl: false
    },
    credentials: {
      credentialPair: {
        username: 'dbadmin',
        password: 'mariapass'
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_6(scope: Construct) {
  // Creating a Teradata data source with SSL enabled
  // ok: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'TeradataDataSourceWithSSL', {
    awsAccountId: '123456789012',
    dataSourceId: 'teradata-data-source-ssl',
    name: 'Teradata Data Source with SSL',
    type: 'TERADATA',
    dataSourceParameters: {
      teradataParameters: {
        host: 'teradata.example.com',
        port: 1025,
        database: 'warehouse'
      }
    },
    sslProperties: {
      disableSsl: false
    },
    credentials: {
      credentialPair: {
        username: 'tduser',
        password: 'tdpassword'
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_7(scope: Construct) {
  // Creating an Oracle data source with SSL enabled
  // ok: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'OracleDataSourceWithSSL', {
    awsAccountId: '123456789012',
    dataSourceId: 'oracle-data-source-ssl',
    name: 'Oracle Data Source with SSL',
    type: 'ORACLE',
    dataSourceParameters: {
      oracleParameters: {
        host: 'oracle-db.example.com',
        port: 1521,
        database: 'ORCL'
      }
    },
    sslProperties: {
      disableSsl: false
    },
    credentials: {
      credentialPair: {
        username: 'system',
        password: 'oraclepass'
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_8(scope: Construct) {
  // Creating a Presto data source with SSL enabled
  // ok: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'PrestoDataSourceWithSSL', {
    awsAccountId: '123456789012',
    dataSourceId: 'presto-data-source-ssl',
    name: 'Presto Data Source with SSL',
    type: 'PRESTO',
    dataSourceParameters: {
      prestoParameters: {
        host: 'presto.example.com',
        port: 8889,
        catalog: 'hive'
      }
    },
    sslProperties: {
      disableSsl: false
    },
    credentials: {
      credentialPair: {
        username: 'presto',
        password: 'prestopass'
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_9(scope: Construct) {
  // Creating a Snowflake data source with SSL enabled
  // ok: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'SnowflakeDataSourceWithSSL', {
    awsAccountId: '123456789012',
    dataSourceId: 'snowflake-data-source-ssl',
    name: 'Snowflake Data Source with SSL',
    type: 'SNOWFLAKE',
    dataSourceParameters: {
      snowflakeParameters: {
        host: 'snowflake.example.com',
        database: 'SNOWFLAKE_SAMPLE_DATA',
        warehouse: 'COMPUTE_WH'
      }
    },
    sslProperties: {
      disableSsl: false
    },
    credentials: {
      credentialPair: {
        username: 'snowuser',
        password: 'snowpass'
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_10(scope: Construct) {
  // Creating a Spark data source with SSL enabled
  // ok: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'SparkDataSourceWithSSL', {
    awsAccountId: '123456789012',
    dataSourceId: 'spark-data-source-ssl',
    name: 'Spark Data Source with SSL',
    type: 'SPARK',
    dataSourceParameters: {
      sparkParameters: {
        host: 'spark.example.com',
        port: 10000
      }
    },
    sslProperties: {
      disableSsl: false
    },
    credentials: {
      credentialPair: {
        username: 'spark',
        password: 'sparkpass'
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_11(scope: Construct, config: any) {
  // Creating a PostgreSQL data source with dynamic configuration and SSL enabled
  const host = config.dbHost || 'default-postgres.example.com';
  const port = config.dbPort || 5432;
  
  // ok: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'DynamicPostgreSQLWithSSL', {
    awsAccountId: '123456789012',
    dataSourceId: 'dynamic-postgres-source-ssl',
    name: 'Dynamic PostgreSQL Source with SSL',
    type: 'POSTGRESQL',
    dataSourceParameters: {
      postgreSqlParameters: {
        host: host,
        port: port,
        database: 'analytics',
        sslMode: 'verify-ca'
      }
    },
    credentials: {
      credentialPair: {
        username: config.username,
        password: config.password
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_12(scope: Construct) {
  // Creating a MySQL data source with connection parameters from a function and SSL enabled
  const getConnectionParams = () => {
    return {
      host: 'mysql-prod.example.com',
      port: 3306,
      database: 'customers',
      sslMode: 'require'
    };
  };
  
  const params = getConnectionParams();
  
  // ok: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'FunctionParamsMySQLWithSSL', {
    awsAccountId: '123456789012',
    dataSourceId: 'function-mysql-source-ssl',
    name: 'Function Params MySQL Source with SSL',
    type: 'MYSQL',
    dataSourceParameters: {
      mySqlParameters: {
        host: params.host,
        port: params.port,
        database: params.database,
        sslMode: params.sslMode
      }
    },
    credentials: {
      credentialPair: {
        username: 'admin',
        password: 'securepass123'
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_13(scope: Construct) {
  // Creating an RDS Aurora data source with SSL enabled
  // ok: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'AuroraDataSourceWithSSL', {
    awsAccountId: '123456789012',
    dataSourceId: 'aurora-data-source-ssl',
    name: 'Aurora Data Source with SSL',
    type: 'AURORA',
    dataSourceParameters: {
      auroraParameters: {
        host: 'aurora-cluster.cluster-xyz.us-east-1.rds.amazonaws.com',
        port: 3306,
        database: 'reporting'
      }
    },
    sslProperties: {
      disableSsl: false
    },
    credentials: {
      credentialPair: {
        username: 'aurorauser',
        password: 'aurorapass'
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_14(scope: Construct) {
  // Creating a data source with conditional logic and SSL enabled
  const isProd = process.env.ENVIRONMENT === 'production';
  const dbHost = isProd ? 'prod-db.example.com' : 'dev-db.example.com';
  
  // ok: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'ConditionalDataSourceWithSSL', {
    awsAccountId: '123456789012',
    dataSourceId: 'conditional-data-source-ssl',
    name: isProd ? 'Production Database with SSL' : 'Development Database with SSL',
    type: 'POSTGRESQL',
    dataSourceParameters: {
      postgreSqlParameters: {
        host: dbHost,
        port: 5432,
        database: isProd ? 'prod_analytics' : 'dev_analytics',
        sslMode: 'require'
      }
    },
    credentials: {
      credentialPair: {
        username: isProd ? 'prod_user' : 'dev_user',
        password: isProd ? 'prod_password' : 'dev_password'
      }
    }
  });
}
// {/fact}

// {fact rule=insecure-cookie@v1.0 defects=0}
function good_case_15(scope: Construct) {
  // Creating a MySQL data source with SSL mode set to verify-ca
  // ok: typescript-cdk-quicksight-ssl-connections
  new quicksight.CfnDataSource(scope, 'MySQLVerifyCADataSource', {
    awsAccountId: '123456789012',
    dataSourceId: 'mysql-verify-ca-source',
    name: 'MySQL Verify CA Source',
    type: 'MYSQL',
    dataSourceParameters: {
      mySqlParameters: {
        host: 'mysql.example.com',
        port: 3306,
        database: 'reports',
        sslMode: 'verify-ca'
      }
    },
    credentials: {
      credentialPair: {
        username: 'reporter',
        password: 'reportpass'
      }
    }
  });
}
// {/fact}