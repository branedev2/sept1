import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;

// JDBC libraries
import org.postgresql.ds.PGSimpleDataSource;
import com.mysql.cj.jdbc.MysqlDataSource;
import oracle.jdbc.pool.OracleDataSource;
import com.microsoft.sqlserver.jdbc.SQLServerDataSource;
import org.h2.jdbcx.JdbcDataSource;

// Connection pool libraries
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.apache.commons.dbcp2.BasicDataSource;
import com.mchange.v2.c3p0.ComboPooledDataSource;
import org.apache.tomcat.jdbc.pool.DataSource;
import org.apache.tomcat.jdbc.pool.PoolProperties;

// ORM libraries
import org.hibernate.cfg.Configuration;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.apache.ibatis.mapping.Environment;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;
import org.apache.ibatis.transaction.TransactionFactory;
import org.apache.ibatis.transaction.jdbc.JdbcTransactionFactory;

// Cloud libraries
import software.amazon.awssdk.services.rds.RdsClient;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import com.google.cloud.secretmanager.v1.SecretManagerServiceClient;
import com.google.cloud.secretmanager.v1.SecretVersionName;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;

// Security Issue: Hardcoded database credentials in code

// True Positive Examples (Vulnerable/Insecure Code)

public class HardcodedDatabasePasswordExamples {

// {fact rule=hardcoded-credentials@v1.0 defects=1}
    public static void bad_case_1() {
        // Standard JDBC connection with hardcoded credentials
        try {
            // ruleid: java-do-not-hardcode-database-password
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/mydb", "admin", "Password123!");
            System.out.println("Connected to MySQL database");
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_2() {
        // PostgreSQL DataSource with hardcoded credentials
        PGSimpleDataSource dataSource = new PGSimpleDataSource();
        dataSource.setServerName("localhost");
        dataSource.setDatabaseName("postgres_db");
        dataSource.setUser("postgres");
        // ruleid: java-do-not-hardcode-database-password
        dataSource.setPassword("secr3t_p@ssw0rd");
        
        try {
            Connection conn = dataSource.getConnection();
            System.out.println("Connected to PostgreSQL database");
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_3() {
        // Oracle DataSource with hardcoded credentials
        try {
            OracleDataSource dataSource = new OracleDataSource();
            dataSource.setURL("jdbc:oracle:thin:@localhost:1521:orcl");
            dataSource.setUser("system");
            // ruleid: java-do-not-hardcode-database-password
            dataSource.setPassword("0racl3_p@55w0rd");
            
            Connection conn = dataSource.getConnection();
            System.out.println("Connected to Oracle database");
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_4() {
        // SQL Server DataSource with hardcoded credentials
        SQLServerDataSource dataSource = new SQLServerDataSource();
        dataSource.setServerName("localhost");
        dataSource.setDatabaseName("master");
        dataSource.setUser("sa");
        // ruleid: java-do-not-hardcode-database-password
        dataSource.setPassword("SqlS3rv3r2023!");
        
        try {
            Connection conn = dataSource.getConnection();
            System.out.println("Connected to SQL Server database");
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_5() {
        // H2 Database with hardcoded credentials
        JdbcDataSource dataSource = new JdbcDataSource();
        dataSource.setURL("jdbc:h2:mem:testdb");
        dataSource.setUser("sa");
        // ruleid: java-do-not-hardcode-database-password
        dataSource.setPassword("h2_p@ssw0rd");
        
        try {
            Connection conn = dataSource.getConnection();
            System.out.println("Connected to H2 database");
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_6() {
        // HikariCP connection pool with hardcoded credentials
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl("jdbc:mysql://localhost:3306/mydb");
        config.setUsername("root");
        // ruleid: java-do-not-hardcode-database-password
        config.setPassword("h1k@r1_p@55w0rd");
        config.setMaximumPoolSize(10);
        
        try (HikariDataSource dataSource = new HikariDataSource(config)) {
            Connection conn = dataSource.getConnection();
            System.out.println("Connected using HikariCP");
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_7() {
        // Apache DBCP connection pool with hardcoded credentials
        BasicDataSource dataSource = new BasicDataSource();
        dataSource.setDriverClassName("com.mysql.cj.jdbc.Driver");
        dataSource.setUrl("jdbc:mysql://localhost:3306/mydb");
        dataSource.setUsername("dbcp_user");
        // ruleid: java-do-not-hardcode-database-password
        dataSource.setPassword("dbcp_p@ssw0rd!");
        dataSource.setInitialSize(5);
        
        try {
            Connection conn = dataSource.getConnection();
            System.out.println("Connected using Apache DBCP");
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_8() {
        // C3P0 connection pool with hardcoded credentials
        try {
            ComboPooledDataSource cpds = new ComboPooledDataSource();
            cpds.setDriverClass("com.mysql.cj.jdbc.Driver");
            cpds.setJdbcUrl("jdbc:mysql://localhost:3306/mydb");
            cpds.setUser("c3p0_user");
            // ruleid: java-do-not-hardcode-database-password
            cpds.setPassword("c3p0_s3cr3t");
            cpds.setMinPoolSize(5);
            cpds.setAcquireIncrement(5);
            cpds.setMaxPoolSize(20);
            
            Connection conn = cpds.getConnection();
            System.out.println("Connected using C3P0");
            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_9() {
        // Tomcat JDBC Pool with hardcoded credentials
        PoolProperties p = new PoolProperties();
        p.setUrl("jdbc:mysql://localhost:3306/mydb");
        p.setDriverClassName("com.mysql.cj.jdbc.Driver");
        p.setUsername("tomcat_user");
        // ruleid: java-do-not-hardcode-database-password
        p.setPassword("t0mc@t_p@55");
        p.setJmxEnabled(true);
        p.setTestWhileIdle(false);
        p.setTestOnBorrow(true);
        
        DataSource datasource = new DataSource();
        datasource.setPoolProperties(p);
        
        try {
            Connection conn = datasource.getConnection();
            System.out.println("Connected using Tomcat JDBC Pool");
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_10() {
        // Hibernate ORM with hardcoded credentials
        Configuration configuration = new Configuration();
        configuration.setProperty("hibernate.connection.driver_class", "com.mysql.cj.jdbc.Driver");
        configuration.setProperty("hibernate.connection.url", "jdbc:mysql://localhost:3306/mydb");
        configuration.setProperty("hibernate.connection.username", "hibernate_user");
        // ruleid: java-do-not-hardcode-database-password
        configuration.setProperty("hibernate.connection.password", "h1b3rn@t3_pwd");
        configuration.setProperty("hibernate.dialect", "org.hibernate.dialect.MySQLDialect");
        
        // Would normally build a SessionFactory here
        System.out.println("Hibernate configured with hardcoded password");
    }

    public static void bad_case_11() {
        // JPA/Persistence.xml equivalent in code with hardcoded credentials
        Map<String, String> properties = new HashMap<>();
        properties.put("javax.persistence.jdbc.driver", "com.mysql.cj.jdbc.Driver");
        properties.put("javax.persistence.jdbc.url", "jdbc:mysql://localhost:3306/mydb");
        properties.put("javax.persistence.jdbc.user", "jpa_user");
        // ruleid: java-do-not-hardcode-database-password
        properties.put("javax.persistence.jdbc.password", "jp@_p@55w0rd");
        
        // Would normally create EntityManagerFactory here
        System.out.println("JPA configured with hardcoded password");
    }

    public static void bad_case_12() {
        // Spring JDBC with hardcoded credentials
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("com.mysql.cj.jdbc.Driver");
        dataSource.setUrl("jdbc:mysql://localhost:3306/mydb");
        dataSource.setUsername("spring_user");
        // ruleid: java-do-not-hardcode-database-password
        dataSource.setPassword("spr1ng_s3cr3t!");
        
        // Would normally use this dataSource with JdbcTemplate
        System.out.println("Spring JDBC configured with hardcoded password");
    }

    public static void bad_case_13() {
        // MyBatis ORM with hardcoded credentials
        TransactionFactory transactionFactory = new JdbcTransactionFactory();
        
        javax.sql.DataSource dataSource = new org.apache.ibatis.datasource.pooled.PooledDataSource(
                "com.mysql.cj.jdbc.Driver",
                "jdbc:mysql://localhost:3306/mydb",
                "mybatis_user",
                // ruleid: java-do-not-hardcode-database-password
                "myb@t1s_p@55");
        
        Environment environment = new Environment("development", transactionFactory, dataSource);
        Configuration configuration = new Configuration(environment);
        
        // Would normally build SqlSessionFactory here
        System.out.println("MyBatis configured with hardcoded password");
    }

    public static void bad_case_14() {
        // Spring Boot DataSource builder with hardcoded credentials
        javax.sql.DataSource dataSource = DataSourceBuilder
                .create()
                .url("jdbc:mysql://localhost:3306/mydb")
                .username("springboot_user")
                // ruleid: java-do-not-hardcode-database-password
                .password("b00t_p@55w0rd!")
                .driverClassName("com.mysql.cj.jdbc.Driver")
                .build();
        
        System.out.println("Spring Boot DataSource configured with hardcoded password");
    }

    public static void bad_case_15() {
        // MySQL DataSource with hardcoded credentials
        MysqlDataSource dataSource = new MysqlDataSource();
        dataSource.setURL("jdbc:mysql://localhost:3306/mydb");
        dataSource.setUser("mysql_user");
        // ruleid: java-do-not-hardcode-database-password
        dataSource.setPassword("my5ql_p@55w0rd");
        
        try {
            Connection conn = dataSource.getConnection();
            System.out.println("Connected to MySQL database using MysqlDataSource");
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Safe/Secure Code)

    public static void good_case_1() {
        // Standard JDBC connection with credentials from environment variables
        try {
            String dbUrl = System.getenv("DB_URL");
            String dbUser = System.getenv("DB_USER");
            // ok: java-do-not-hardcode-database-password
            String dbPassword = System.getenv("DB_PASSWORD");
            
            Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPassword);
            System.out.println("Connected to database using environment variables");
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_2() {
        // PostgreSQL DataSource with credentials from properties file
        try {
            Properties props = new Properties();
            FileInputStream fis = new FileInputStream("database.properties");
            props.load(fis);
            fis.close();
            
            PGSimpleDataSource dataSource = new PGSimpleDataSource();
            dataSource.setServerName(props.getProperty("db.server"));
            dataSource.setDatabaseName(props.getProperty("db.name"));
            dataSource.setUser(props.getProperty("db.user"));
            // ok: java-do-not-hardcode-database-password
            dataSource.setPassword(props.getProperty("db.password"));
            
            Connection conn = dataSource.getConnection();
            System.out.println("Connected to PostgreSQL using properties file");
            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void good_case_3() {
        // Oracle DataSource with credentials from system properties
        try {
            OracleDataSource dataSource = new OracleDataSource();
            dataSource.setURL(System.getProperty("oracle.jdbc.url"));
            dataSource.setUser(System.getProperty("oracle.jdbc.user"));
            // ok: java-do-not-hardcode-database-password
            dataSource.setPassword(System.getProperty("oracle.jdbc.password"));
            
            Connection conn = dataSource.getConnection();
            System.out.println("Connected to Oracle using system properties");
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_4() {
        // SQL Server DataSource with credentials from user input (not recommended for production)
        try {
            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter database username: ");
            String username = scanner.nextLine();
            System.out.print("Enter database password: ");
            // ok: java-do-not-hardcode-database-password
            String password = scanner.nextLine();
            scanner.close();
            
            SQLServerDataSource dataSource = new SQLServerDataSource();
            dataSource.setServerName("localhost");
            dataSource.setDatabaseName("master");
            dataSource.setUser(username);
            dataSource.setPassword(password);
            
            Connection conn = dataSource.getConnection();
            System.out.println("Connected to SQL Server using user input");
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_5() {
        // H2 Database with credentials from encrypted file
        try {
            // Read encrypted password from file
            byte[] encryptedPassword = Files.readAllBytes(Paths.get("encrypted_password.bin"));
            
            // Decrypt password (simplified example)
            SecretKeySpec secretKey = new SecretKeySpec("MySecretKey12345".getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            // ok: java-do-not-hardcode-database-password
            String password = new String(cipher.doFinal(encryptedPassword));
            
            JdbcDataSource dataSource = new JdbcDataSource();
            dataSource.setURL("jdbc:h2:mem:testdb");
            dataSource.setUser("sa");
            dataSource.setPassword(password);
            
            Connection conn = dataSource.getConnection();
            System.out.println("Connected to H2 using decrypted password");
            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void good_case_6() {
        // HikariCP connection pool with credentials from JNDI
        try {
            HikariConfig config = new HikariConfig();
            config.setDataSourceJNDI("java:comp/env/jdbc/MyDatabase");
            
            // No password is set directly in the code
            // ok: java-do-not-hardcode-database-password
            HikariDataSource dataSource = new HikariDataSource(config);
            
            Connection conn = dataSource.getConnection();
            System.out.println("Connected using HikariCP with JNDI");
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_7() {
        // Apache DBCP connection pool with credentials from environment variables
        try {
            BasicDataSource dataSource = new BasicDataSource();
            dataSource.setDriverClassName("com.mysql.cj.jdbc.Driver");
            dataSource.setUrl(System.getenv("DBCP_DB_URL"));
            dataSource.setUsername(System.getenv("DBCP_DB_USER"));
            // ok: java-do-not-hardcode-database-password
            dataSource.setPassword(System.getenv("DBCP_DB_PASSWORD"));
            dataSource.setInitialSize(5);
            
            Connection conn = dataSource.getConnection();
            System.out.println("Connected using Apache DBCP with environment variables");
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_8() {
        // C3P0 connection pool with credentials from properties file
        try {
            Properties props = new Properties();
            props.load(new FileInputStream("c3p0.properties"));
            
            ComboPooledDataSource cpds = new ComboPooledDataSource();
            cpds.setDriverClass("com.mysql.cj.jdbc.Driver");
            cpds.setJdbcUrl(props.getProperty("c3p0.jdbcUrl"));
            cpds.setUser(props.getProperty("c3p0.user"));
            // ok: java-do-not-hardcode-database-password
            cpds.setPassword(props.getProperty("c3p0.password"));
            cpds.setMinPoolSize(5);
            cpds.setMaxPoolSize(20);
            
            Connection conn = cpds.getConnection();
            System.out.println("Connected using C3P0 with properties file");
            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void good_case_9() {
        // Tomcat JDBC Pool with credentials from JNDI
        try {
            javax.naming.Context ctx = new javax.naming.InitialContext();
            javax.sql.DataSource ds = (javax.sql.DataSource) ctx.lookup("java:comp/env/jdbc/MyDB");
            
            // No password is set directly in the code
            // ok: java-do-not-hardcode-database-password
            Connection conn = ds.getConnection();
            
            System.out.println("Connected using Tomcat JDBC Pool with JNDI");
            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void good_case_10() {
        // Hibernate ORM with credentials from environment variables
        Configuration configuration = new Configuration();
        configuration.setProperty("hibernate.connection.driver_class", "com.mysql.cj.jdbc.Driver");
        configuration.setProperty("hibernate.connection.url", System.getenv("HIBERNATE_DB_URL"));
        configuration.setProperty("hibernate.connection.username", System.getenv("HIBERNATE_DB_USER"));
        // ok: java-do-not-hardcode-database-password
        configuration.setProperty("hibernate.connection.password", System.getenv("HIBERNATE_DB_PASSWORD"));
        configuration.setProperty("hibernate.dialect", "org.hibernate.dialect.MySQLDialect");
        
        // Would normally build a SessionFactory here
        System.out.println("Hibernate configured with environment variables");
    }

    public static void good_case_11() {
        // JPA with credentials from external configuration
        try {
            // Load properties from a secure location
            Properties props = new Properties();
            try (InputStream input = Files.newInputStream(Paths.get("/secure/jpa.properties"))) {
                props.load(input);
            }
            
            Map<String, String> properties = new HashMap<>();
            properties.put("javax.persistence.jdbc.driver", "com.mysql.cj.jdbc.Driver");
            properties.put("javax.persistence.jdbc.url", props.getProperty("db.url"));
            properties.put("javax.persistence.jdbc.user", props.getProperty("db.user"));
            // ok: java-do-not-hardcode-database-password
            properties.put("javax.persistence.jdbc.password", props.getProperty("db.password"));
            
            // Would normally create EntityManagerFactory here
            System.out.println("JPA configured with external properties");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_12() {
        // Spring JDBC with credentials from AWS Secrets Manager
        try {
            // Retrieve secret from AWS Secrets Manager
            SecretsManagerClient secretsClient = SecretsManagerClient.create();
            GetSecretValueRequest getSecretValueRequest = GetSecretValueRequest.builder()
                    .secretId("database-credentials")
                    .build();
            String secret = secretsClient.getSecretValue(getSecretValueRequest).secretString();
            
            // Parse the secret JSON (simplified)
            // In real code, use a JSON parser
            String username = secret.split("\"username\":\"")[1].split("\"")[0];
            // ok: java-do-not-hardcode-database-password
            String password = secret.split("\"password\":\"")[1].split("\"")[0];
            
            DriverManagerDataSource dataSource = new DriverManagerDataSource();
            dataSource.setDriverClassName("com.mysql.cj.jdbc.Driver");
            dataSource.setUrl("jdbc:mysql://mydb.amazonaws.com:3306/mydb");
            dataSource.setUsername(username);
            dataSource.setPassword(password);
            
            System.out.println("Spring JDBC configured with AWS Secrets Manager");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void good_case_13() {
        // MyBatis ORM with credentials from Google Cloud Secret Manager
        try {
            // Access the secret
            String projectId = "my-project";
            String secretId = "database-password";
            String versionId = "latest";
            
            SecretManagerServiceClient client = SecretManagerServiceClient.create();
            SecretVersionName secretVersionName = SecretVersionName.of(projectId, secretId, versionId);
            
            // Access the secret version
            // ok: java-do-not-hardcode-database-password
            String password = client.accessSecretVersion(secretVersionName)
                    .getPayload().getData().toStringUtf8();
            
            // Get username from environment variable
            String username = System.getenv("DB_USERNAME");
            
            javax.sql.DataSource dataSource = new org.apache.ibatis.datasource.pooled.PooledDataSource(
                    "com.mysql.cj.jdbc.Driver",
                    "jdbc:mysql://localhost:3306/mydb",
                    username,
                    password);
            
            TransactionFactory transactionFactory = new JdbcTransactionFactory();
            Environment environment = new Environment("development", transactionFactory, dataSource);
            Configuration configuration = new Configuration(environment);
            
            System.out.println("MyBatis configured with Google Cloud Secret Manager");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void good_case_14() {
        // Spring Boot DataSource builder with credentials from Azure Key Vault
        try {
            // Create a secret client using Azure Key Vault
            String keyVaultUrl = "https://mykeyvault.vault.azure.net/";
            SecretClient secretClient = new SecretClient.builder()
                    .vaultUrl(keyVaultUrl)
                    .credential(new DefaultAzureCredentialBuilder().build())
                    .buildClient();
            
            // Get the secret from Azure Key Vault
            KeyVaultSecret retrievedSecret = secretClient.getSecret("database-password");
            // ok: java-do-not-hardcode-database-password
            String password = retrievedSecret.getValue();
            
            javax.sql.DataSource dataSource = DataSourceBuilder
                    .create()
                    .url("jdbc:mysql://localhost:3306/mydb")
                    .username(System.getenv("DB_USERNAME"))
                    .password(password)
                    .driverClassName("com.mysql.cj.jdbc.Driver")
                    .build();
            
            System.out.println("Spring Boot DataSource configured with Azure Key Vault");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void good_case_15() {
        // MySQL DataSource with credentials from Java KeyStore
        try {
            // Load the KeyStore
            char[] keyStorePassword = System.getenv("KEYSTORE_PASSWORD").toCharArray();
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream("/path/to/keystore.p12"), keyStorePassword);
            
            // Retrieve the database password from the KeyStore
            char[] passwordChars = ((KeyStore.SecretKeyEntry) keyStore.getEntry(
                    "db-password", 
                    new KeyStore.PasswordProtection(keyStorePassword)
            )).getSecretKey().getEncoded().toString().toCharArray();
            
            // ok: java-do-not-hardcode-database-password
            String password = new String(passwordChars);
            
            MysqlDataSource dataSource = new MysqlDataSource();
            dataSource.setURL("jdbc:mysql://localhost:3306/mydb");
            dataSource.setUser(System.getenv("DB_USER"));
            dataSource.setPassword(password);
            
            Connection conn = dataSource.getConnection();
            System.out.println("Connected to MySQL database using KeyStore for password");
            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}