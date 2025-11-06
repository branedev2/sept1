import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;
import java.io.FileInputStream;
import java.io.IOException;
import javax.sql.DataSource;
import org.apache.commons.dbcp2.BasicDataSource;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.SimpleDriverDataSource;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.hibernate.cfg.Configuration;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import com.mongodb.client.MongoDatabase;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;
import org.apache.tomcat.jdbc.pool.DataSourceFactory;
import org.apache.tomcat.jdbc.pool.PoolProperties;
import com.mchange.v2.c3p0.ComboPooledDataSource;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import com.datastax.driver.core.Cluster;
import com.datastax.driver.core.Session;
import org.neo4j.driver.AuthTokens;
import org.neo4j.driver.Driver;
import org.neo4j.driver.GraphDatabase;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.xpack.client.PreBuiltXPackTransportClient;
import com.couchbase.client.java.Bucket;
import com.couchbase.client.java.Cluster;
import com.couchbase.client.java.CouchbaseCluster;
import org.influxdb.InfluxDB;
import org.influxdb.InfluxDBFactory;
import com.aerospike.client.AerospikeClient;
import com.aerospike.client.policy.ClientPolicy;
import io.vertx.core.Vertx;
import io.vertx.mysqlclient.MySQLConnectOptions;
import io.vertx.mysqlclient.MySQLPool;
import io.vertx.sqlclient.PoolOptions;
import java.util.HashMap;
import java.util.Map;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultResponse;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import com.google.cloud.secretmanager.v1.SecretManagerServiceClient;
import com.google.cloud.secretmanager.v1.SecretVersionName;
import java.util.Scanner;

// Security Issue: Hardcoded Database Passwords in Java Applications

// True Positive Examples (Vulnerable/Insecure Code)
public class HardcodedDatabasePasswordExamples {

// {fact rule=hardcoded-credentials@v1.0 defects=1}
    public static void bad_case_1() {
        // Standard JDBC connection with hardcoded password
        try {
            String url = "jdbc:mysql://localhost:3306/mydb";
            String username = "admin";
            // ruleid: java-hardcoded-database-password
            String password = "s3cr3tP@ssw0rd";
            Connection connection = DriverManager.getConnection(url, username, password);
            // Use connection...
            connection.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_2() {
        // Apache DBCP2 connection pool with hardcoded password
        BasicDataSource dataSource = new BasicDataSource();
        dataSource.setDriverClassName("org.postgresql.Driver");
        dataSource.setUrl("jdbc:postgresql://localhost:5432/mydb");
        dataSource.setUsername("postgres");
        // ruleid: java-hardcoded-database-password
        dataSource.setPassword("Postgr3sP@ss!");
        try {
            Connection conn = dataSource.getConnection();
            // Use connection...
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_3() {
        // HikariCP connection pool with hardcoded password
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl("jdbc:oracle:thin:@localhost:1521:orcl");
        config.setUsername("system");
        // ruleid: java-hardcoded-database-password
        config.setPassword("0r@cl3Adm1n");
        config.addDataSourceProperty("cachePrepStmts", "true");
        config.addDataSourceProperty("prepStmtCacheSize", "250");
        
        try (HikariDataSource ds = new HikariDataSource(config)) {
            Connection conn = ds.getConnection();
            // Use connection...
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_4() {
        // Spring JDBC DriverManagerDataSource with hardcoded password
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("com.microsoft.sqlserver.jdbc.SQLServerDriver");
        dataSource.setUrl("jdbc:sqlserver://localhost:1433;databaseName=master");
        dataSource.setUsername("sa");
        // ruleid: java-hardcoded-database-password
        dataSource.setPassword("SQLs3rv3rP@ss!");
        
        try {
            Connection conn = dataSource.getConnection();
            // Use connection...
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_5() {
        // Spring Boot DataSourceBuilder with hardcoded password
        DataSource dataSource = DataSourceBuilder.create()
            .url("jdbc:h2:mem:testdb")
            .driverClassName("org.h2.Driver")
            .username("sa")
            // ruleid: java-hardcoded-database-password
            .password("h2P@ssw0rd")
            .build();
            
        try {
            Connection conn = dataSource.getConnection();
            // Use connection...
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_6() {
        // Hibernate configuration with hardcoded password
        Configuration configuration = new Configuration();
        configuration.setProperty("hibernate.connection.driver_class", "com.mysql.jdbc.Driver");
        configuration.setProperty("hibernate.connection.url", "jdbc:mysql://localhost:3306/hibernate_db");
        configuration.setProperty("hibernate.connection.username", "hibernate_user");
        // ruleid: java-hardcoded-database-password
        configuration.setProperty("hibernate.connection.password", "h1b3rn@t3P@ss");
        configuration.setProperty("hibernate.dialect", "org.hibernate.dialect.MySQLDialect");
        
        // Build session factory and use it...
    }

    public static void bad_case_7() {
        // MongoDB connection with hardcoded password
        String username = "mongodb_user";
        // ruleid: java-hardcoded-database-password
        String password = "m0ng0DbP@ss123";
        String connectionString = "mongodb://" + username + ":" + password + "@localhost:27017/admin";
        
        try (MongoClient mongoClient = new MongoClient(new MongoClientURI(connectionString))) {
            MongoDatabase database = mongoClient.getDatabase("mydb");
            // Use database...
        }
    }

    public static void bad_case_8() {
        // Redis connection with hardcoded password
        String host = "localhost";
        int port = 6379;
        // ruleid: java-hardcoded-database-password
        String password = "R3d1sP@ssw0rd!";
        
        JedisPoolConfig poolConfig = new JedisPoolConfig();
        try (JedisPool jedisPool = new JedisPool(poolConfig, host, port, 2000, password);
             Jedis jedis = jedisPool.getResource()) {
            // Use jedis...
        }
    }

    public static void bad_case_9() {
        // Tomcat JDBC connection pool with hardcoded password
        PoolProperties p = new PoolProperties();
        p.setUrl("jdbc:mysql://localhost:3306/mydb");
        p.setDriverClassName("com.mysql.jdbc.Driver");
        p.setUsername("tomcat_pool");
        // ruleid: java-hardcoded-database-password
        p.setPassword("t0mc@tP00lP@ss");
        p.setJmxEnabled(true);
        
        org.apache.tomcat.jdbc.pool.DataSource ds = new org.apache.tomcat.jdbc.pool.DataSource();
        ds.setPoolProperties(p);
        
        try {
            Connection conn = ds.getConnection();
            // Use connection...
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_10() {
        // C3P0 connection pool with hardcoded password
        ComboPooledDataSource cpds = new ComboPooledDataSource();
        try {
            cpds.setDriverClass("com.mysql.jdbc.Driver");
            cpds.setJdbcUrl("jdbc:mysql://localhost:3306/mydb");
            cpds.setUser("c3p0_user");
            // ruleid: java-hardcoded-database-password
            cpds.setPassword("c3p0P@ssw0rd!");
            cpds.setMinPoolSize(5);
            cpds.setAcquireIncrement(5);
            cpds.setMaxPoolSize(20);
            
            Connection conn = cpds.getConnection();
            // Use connection...
            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_11() {
        // Cassandra driver with hardcoded password
        Cluster cluster = Cluster.builder()
            .addContactPoint("127.0.0.1")
            .withCredentials("cassandra_user", 
            // ruleid: java-hardcoded-database-password
            "c@ss@ndr@P@ss")
            .build();
            
        Session session = cluster.connect("mykeyspace");
        // Use session...
        session.close();
        cluster.close();
    }

    public static void bad_case_12() {
        // Neo4j driver with hardcoded password
        // ruleid: java-hardcoded-database-password
        Driver driver = GraphDatabase.driver("bolt://localhost:7687", 
            AuthTokens.basic("neo4j", "n30$jP@ssw0rd"));
            
        // Use driver...
        driver.close();
    }

    public static void bad_case_13() {
        // Elasticsearch with hardcoded password
        Settings settings = Settings.builder()
            .put("cluster.name", "elasticsearch")
            .put("xpack.security.user", "elastic:
            // ruleid: java-hardcoded-database-password
            3l@st1cP@ss!")
            .build();
            
        try {
            TransportClient client = new PreBuiltXPackTransportClient(settings);
            // Use client...
            client.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_14() {
        // Couchbase with hardcoded password
        Cluster cluster = CouchbaseCluster.create("localhost");
        // ruleid: java-hardcoded-database-password
        Bucket bucket = cluster.openBucket("default", "c0uchb@s3P@ss");
        
        // Use bucket...
        bucket.close();
        cluster.disconnect();
    }

    public static void bad_case_15() {
        // Vert.x MySQL client with hardcoded password
        MySQLConnectOptions connectOptions = new MySQLConnectOptions()
            .setPort(3306)
            .setHost("localhost")
            .setDatabase("vertx_db")
            .setUser("vertx_user")
            // ruleid: java-hardcoded-database-password
            .setPassword("v3rtxP@ssw0rd");
            
        PoolOptions poolOptions = new PoolOptions().setMaxSize(5);
        MySQLPool client = MySQLPool.pool(Vertx.vertx(), connectOptions, poolOptions);
        
        // Use client...
    }

    // True Negative Examples (Safe/Secure Code)
    public static void good_case_1() {
        // Standard JDBC connection with password from properties file
        try {
            Properties props = new Properties();
            props.load(new FileInputStream("database.properties"));
            
            String url = props.getProperty("db.url");
            String username = props.getProperty("db.username");
            // ok: java-hardcoded-database-password
            String password = props.getProperty("db.password");
            
            Connection connection = DriverManager.getConnection(url, username, password);
            // Use connection...
            connection.close();
        } catch (SQLException | IOException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_2() {
        // Apache DBCP2 with password from environment variable
        BasicDataSource dataSource = new BasicDataSource();
        dataSource.setDriverClassName("org.postgresql.Driver");
        dataSource.setUrl("jdbc:postgresql://localhost:5432/mydb");
        dataSource.setUsername("postgres");
        // ok: java-hardcoded-database-password
        dataSource.setPassword(System.getenv("DB_PASSWORD"));
        
        try {
            Connection conn = dataSource.getConnection();
            // Use connection...
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_3() {
        // HikariCP with password from system property
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl("jdbc:oracle:thin:@localhost:1521:orcl");
        config.setUsername("system");
        // ok: java-hardcoded-database-password
        config.setPassword(System.getProperty("oracle.password"));
        config.addDataSourceProperty("cachePrepStmts", "true");
        
        try (HikariDataSource ds = new HikariDataSource(config)) {
            Connection conn = ds.getConnection();
            // Use connection...
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_4() {
        // Spring JDBC with password from external configuration
        try {
            org.apache.commons.configuration.Configuration config = new PropertiesConfiguration("app-config.properties");
            
            DriverManagerDataSource dataSource = new DriverManagerDataSource();
            dataSource.setDriverClassName("com.microsoft.sqlserver.jdbc.SQLServerDriver");
            dataSource.setUrl("jdbc:sqlserver://localhost:1433;databaseName=master");
            dataSource.setUsername("sa");
            // ok: java-hardcoded-database-password
            dataSource.setPassword(config.getString("sqlserver.password"));
            
            Connection conn = dataSource.getConnection();
            // Use connection...
            conn.close();
        } catch (SQLException | ConfigurationException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_5() {
        // Spring Boot DataSourceBuilder with password from environment
        // ok: java-hardcoded-database-password
        DataSource dataSource = DataSourceBuilder.create()
            .url("jdbc:h2:mem:testdb")
            .driverClassName("org.h2.Driver")
            .username("sa")
            .password(System.getenv("H2_PASSWORD"))
            .build();
            
        try {
            Connection conn = dataSource.getConnection();
            // Use connection...
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_6() {
        // Hibernate with password from properties file
        try {
            Properties hibernateProps = new Properties();
            hibernateProps.load(new FileInputStream("hibernate.properties"));
            
            Configuration configuration = new Configuration();
            configuration.setProperty("hibernate.connection.driver_class", "com.mysql.jdbc.Driver");
            configuration.setProperty("hibernate.connection.url", "jdbc:mysql://localhost:3306/hibernate_db");
            configuration.setProperty("hibernate.connection.username", "hibernate_user");
            // ok: java-hardcoded-database-password
            configuration.setProperty("hibernate.connection.password", hibernateProps.getProperty("hibernate.password"));
            configuration.setProperty("hibernate.dialect", "org.hibernate.dialect.MySQLDialect");
            
            // Build session factory and use it...
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_7() {
        // MongoDB with password from environment variable
        String username = "mongodb_user";
        // ok: java-hardcoded-database-password
        String password = System.getenv("MONGODB_PASSWORD");
        String connectionString = "mongodb://" + username + ":" + password + "@localhost:27017/admin";
        
        try (MongoClient mongoClient = new MongoClient(new MongoClientURI(connectionString))) {
            MongoDatabase database = mongoClient.getDatabase("mydb");
            // Use database...
        }
    }

    public static void good_case_8() {
        // Redis with password from properties file
        try {
            Properties redisProps = new Properties();
            redisProps.load(new FileInputStream("redis.properties"));
            
            String host = "localhost";
            int port = 6379;
            // ok: java-hardcoded-database-password
            String password = redisProps.getProperty("redis.password");
            
            JedisPoolConfig poolConfig = new JedisPoolConfig();
            try (JedisPool jedisPool = new JedisPool(poolConfig, host, port, 2000, password);
                 Jedis jedis = jedisPool.getResource()) {
                // Use jedis...
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_9() {
        // Tomcat JDBC connection pool with password from system property
        PoolProperties p = new PoolProperties();
        p.setUrl("jdbc:mysql://localhost:3306/mydb");
        p.setDriverClassName("com.mysql.jdbc.Driver");
        p.setUsername("tomcat_pool");
        // ok: java-hardcoded-database-password
        p.setPassword(System.getProperty("tomcat.pool.password"));
        p.setJmxEnabled(true);
        
        org.apache.tomcat.jdbc.pool.DataSource ds = new org.apache.tomcat.jdbc.pool.DataSource();
        ds.setPoolProperties(p);
        
        try {
            Connection conn = ds.getConnection();
            // Use connection...
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_10() {
        // C3P0 connection pool with password from environment variable
        ComboPooledDataSource cpds = new ComboPooledDataSource();
        try {
            cpds.setDriverClass("com.mysql.jdbc.Driver");
            cpds.setJdbcUrl("jdbc:mysql://localhost:3306/mydb");
            cpds.setUser("c3p0_user");
            // ok: java-hardcoded-database-password
            cpds.setPassword(System.getenv("C3P0_PASSWORD"));
            cpds.setMinPoolSize(5);
            cpds.setAcquireIncrement(5);
            cpds.setMaxPoolSize(20);
            
            Connection conn = cpds.getConnection();
            // Use connection...
            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void good_case_11() {
        // Cassandra driver with password from properties file
        try {
            Properties cassandraProps = new Properties();
            cassandraProps.load(new FileInputStream("cassandra.properties"));
            
            // ok: java-hardcoded-database-password
            Cluster cluster = Cluster.builder()
                .addContactPoint("127.0.0.1")
                .withCredentials("cassandra_user", cassandraProps.getProperty("cassandra.password"))
                .build();
                
            Session session = cluster.connect("mykeyspace");
            // Use session...
            session.close();
            cluster.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_12() {
        // Neo4j driver with password from environment variable
        // ok: java-hardcoded-database-password
        Driver driver = GraphDatabase.driver("bolt://localhost:7687", 
            AuthTokens.basic("neo4j", System.getenv("NEO4J_PASSWORD")));
            
        // Use driver...
        driver.close();
    }

    public static void good_case_13() {
        // Using Spring Vault to retrieve database password
        try {
            VaultEndpoint vaultEndpoint = new VaultEndpoint();
            vaultEndpoint.setHost("localhost");
            vaultEndpoint.setPort(8200);
            
            VaultTemplate vaultTemplate = new VaultTemplate(
                vaultEndpoint, 
                new TokenAuthentication(System.getenv("VAULT_TOKEN"))
            );
            
            // ok: java-hardcoded-database-password
            VaultResponse response = vaultTemplate.read("secret/database/credentials");
            String password = (String) response.getData().get("password");
            
            // Use password to connect to database
            String url = "jdbc:mysql://localhost:3306/mydb";
            String username = "admin";
            Connection connection = DriverManager.getConnection(url, username, password);
            // Use connection...
            connection.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void good_case_14() {
        // Using AWS Secrets Manager to retrieve database password
        try {
            SecretsManagerClient secretsClient = SecretsManagerClient.builder()
                .region(Region.US_EAST_1)
                .build();
                
            GetSecretValueRequest getSecretValueRequest = GetSecretValueRequest.builder()
                .secretId("database/credentials")
                .build();
                
            // ok: java-hardcoded-database-password
            GetSecretValueResponse getSecretValueResponse = secretsClient.getSecretValue(getSecretValueRequest);
            String password = getSecretValueResponse.secretString();
            
            // Use password to connect to database
            String url = "jdbc:postgresql://localhost:5432/mydb";
            String username = "postgres";
            Connection connection = DriverManager.getConnection(url, username, password);
            // Use connection...
            connection.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void good_case_15() {
        // Using user input for password (not hardcoded)
        try {
            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter database password: ");
            // ok: java-hardcoded-database-password
            String password = scanner.nextLine();
            scanner.close();
            
            String url = "jdbc:mysql://localhost:3306/mydb";
            String username = "admin";
            Connection connection = DriverManager.getConnection(url, username, password);
            // Use connection...
            connection.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        // Main method to demonstrate examples
        System.out.println("Database Password Security Examples");
    }
}
// {/fact}