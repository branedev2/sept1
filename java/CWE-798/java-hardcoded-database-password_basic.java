import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;
import java.io.FileInputStream;
import java.io.IOException;
import javax.sql.DataSource;
import org.apache.commons.dbcp2.BasicDataSource;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import com.mongodb.client.MongoDatabase;
import redis.clients.jedis.Jedis;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import java.util.HashMap;
import java.util.Map;
import org.neo4j.driver.AuthTokens;
import org.neo4j.driver.Driver;
import org.neo4j.driver.GraphDatabase;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.rds.AmazonRDSClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.beans.factory.annotation.Autowired;
import java.io.InputStream;

public class DatabaseConnectionExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=hardcoded-credentials@v1.0 defects=1}
    public void bad_case_1() {
        try {
            String url = "jdbc:mysql://localhost:3306/mydb";
            String username = "admin";
            // ruleid: java-hardcoded-database-password
            Connection conn = DriverManager.getConnection(url, username, "super_secret_password123");
            Statement stmt = conn.createStatement();
            stmt.executeQuery("SELECT * FROM users");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        try {
            // ruleid: java-hardcoded-database-password
            Connection conn = DriverManager.getConnection(
                "jdbc:postgresql://localhost:5432/mydb", 
                "postgres", 
                "postgres123!"
            );
            conn.createStatement().executeUpdate("CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY)");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() {
        BasicDataSource dataSource = new BasicDataSource();
        dataSource.setDriverClassName("com.mysql.jdbc.Driver");
        dataSource.setUrl("jdbc:mysql://localhost:3306/mydb");
        dataSource.setUsername("root");
        // ruleid: java-hardcoded-database-password
        dataSource.setPassword("root_password");
        
        try {
            Connection conn = dataSource.getConnection();
            conn.createStatement().execute("TRUNCATE TABLE logs");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        Properties props = new Properties();
        props.setProperty("user", "dbuser");
        // ruleid: java-hardcoded-database-password
        props.setProperty("password", "dbpass123");
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:oracle:thin:@localhost:1521:orcl", props);
            conn.setAutoCommit(false);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    @Configuration
    public class bad_case_5 {
        @Bean
        public DataSource dataSource() {
            DriverManagerDataSource dataSource = new DriverManagerDataSource();
            dataSource.setDriverClassName("com.mysql.jdbc.Driver");
            dataSource.setUrl("jdbc:mysql://production-server:3306/customer_data");
            dataSource.setUsername("app_user");
            // ruleid: java-hardcoded-database-password
            dataSource.setPassword("App_User_P@ssw0rd!");
            return dataSource;
        }
    }

    public void bad_case_6() {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl("jdbc:mysql://remote-db:3306/analytics");
        config.setUsername("analytics_user");
        // ruleid: java-hardcoded-database-password
        config.setPassword("4n4lyt1cs_us3r!");
        config.addDataSourceProperty("cachePrepStmts", "true");
        
        try (HikariDataSource ds = new HikariDataSource(config);
             Connection conn = ds.getConnection()) {
            conn.createStatement().execute("DELETE FROM temp_data WHERE created_at < NOW() - INTERVAL 7 DAY");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        // MongoDB connection with hardcoded password
        // ruleid: java-hardcoded-database-password
        MongoClientURI uri = new MongoClientURI("mongodb://admin:mongo_admin_pwd@localhost:27017/admin");
        try (MongoClient mongoClient = new MongoClient(uri)) {
            MongoDatabase database = mongoClient.getDatabase("customer_data");
            database.getCollection("orders").drop();
        }
    }

    public void bad_case_8() {
        // Redis connection with hardcoded password
        Jedis jedis = new Jedis("redis-server.example.com");
        // ruleid: java-hardcoded-database-password
        jedis.auth("redis_complex_password_123");
        jedis.select(2);
        jedis.set("session:active", "true");
        jedis.close();
    }

    public void bad_case_9() {
        Map<String, String> config = new HashMap<>();
        config.put("host", "cassandra.example.com");
        config.put("username", "cassandra_user");
        // ruleid: java-hardcoded-database-password
        config.put("password", "C@ss@ndra2023!");
        
        // Simulate Cassandra connection using the config map
        try {
            Class.forName("com.datastax.driver.core.Cluster");
            System.out.println("Connecting to Cassandra with credentials: " + config.get("username") + ":" + config.get("password"));
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10() {
        // Neo4j connection with hardcoded password
        // ruleid: java-hardcoded-database-password
        Driver driver = GraphDatabase.driver("bolt://neo4j.example.com:7687", 
                                           AuthTokens.basic("neo4j", "n3o4j_p@ssw0rd"));
        
        try (var session = driver.session()) {
            session.run("MATCH (n) RETURN count(n) as count");
        } finally {
            driver.close();
        }
    }

    public void bad_case_11() {
        try {
            String connectionString = "jdbc:sqlserver://mssql.example.com:1433;databaseName=customers";
            Properties connectionProps = new Properties();
            connectionProps.put("user", "sa");
            // ruleid: java-hardcoded-database-password
            connectionProps.put("password", "SQL_server_2019!");
            connectionProps.put("encrypt", "true");
            
            Connection conn = DriverManager.getConnection(connectionString, connectionProps);
            conn.setReadOnly(true);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12() {
        // AWS RDS connection with hardcoded credentials
        // ruleid: java-hardcoded-database-password
        BasicAWSCredentials awsCredentials = new BasicAWSCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        AmazonRDSClient rdsClient = new AmazonRDSClient(awsCredentials);
        rdsClient.setEndpoint("rds.us-west-2.amazonaws.com");
    }

    public void bad_case_13() {
        // Embedded database with hardcoded password
        try {
            Class.forName("org.h2.Driver");
            // ruleid: java-hardcoded-database-password
            Connection conn = DriverManager.getConnection("jdbc:h2:~/test", "sa", "h2_password");
            conn.createStatement().execute("CREATE TABLE IF NOT EXISTS audit_log (id INT AUTO_INCREMENT, action VARCHAR(255))");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        // Connection pool with hardcoded credentials in a more complex setup
        BasicDataSource ds = new BasicDataSource();
        ds.setDriverClassName("com.mysql.jdbc.Driver");
        ds.setUrl("jdbc:mysql://db-cluster.example.com:3306/inventory");
        ds.setUsername("inventory_app");
        // ruleid: java-hardcoded-database-password
        ds.setPassword("inv3nt0ry_4pp_2023");
        ds.setInitialSize(5);
        ds.setMaxTotal(20);
        
        try {
            Connection conn = ds.getConnection();
            conn.createStatement().executeQuery("SELECT * FROM products WHERE stock < 10");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        // Connection with multiple database parameters including password
        try {
            String url = "jdbc:mysql://analytics-db:3306/metrics?useSSL=true&serverTimezone=UTC";
            Properties props = new Properties();
            props.setProperty("user", "metrics_reader");
            // ruleid: java-hardcoded-database-password
            props.setProperty("password", "m3tr1cs_r34d3r!");
            props.setProperty("connectTimeout", "5000");
            
            Connection conn = DriverManager.getConnection(url, props);
            conn.createStatement().executeQuery("SELECT AVG(response_time) FROM api_calls WHERE date > CURDATE() - INTERVAL 7 DAY");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Secure Code)

    public void good_case_1() {
        try {
            String url = "jdbc:mysql://localhost:3306/mydb";
            String username = System.getenv("DB_USERNAME");
            // ok: java-hardcoded-database-password
            String password = System.getenv("DB_PASSWORD");
            Connection conn = DriverManager.getConnection(url, username, password);
            Statement stmt = conn.createStatement();
            stmt.executeQuery("SELECT * FROM users");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() {
        try {
            Properties props = new Properties();
            // ok: java-hardcoded-database-password
            try (FileInputStream fis = new FileInputStream("config/database.properties")) {
                props.load(fis);
            }
            Connection conn = DriverManager.getConnection(
                props.getProperty("db.url"), 
                props.getProperty("db.user"), 
                props.getProperty("db.password")
            );
            conn.createStatement().executeUpdate("CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY)");
        } catch (SQLException | IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        BasicDataSource dataSource = new BasicDataSource();
        dataSource.setDriverClassName("com.mysql.jdbc.Driver");
        dataSource.setUrl("jdbc:mysql://localhost:3306/mydb");
        dataSource.setUsername("root");
        // ok: java-hardcoded-database-password
        String password = System.getProperty("database.password");
        dataSource.setPassword(password);
        
        try {
            Connection conn = dataSource.getConnection();
            conn.createStatement().execute("TRUNCATE TABLE logs");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void good_case_4() {
        Properties props = new Properties();
        props.setProperty("user", "dbuser");
        
        // ok: java-hardcoded-database-password
        String password = getPasswordFromSecureStore("db_main");
        props.setProperty("password", password);
        
        try {
            Connection conn = DriverManager.getConnection("jdbc:oracle:thin:@localhost:1521:orcl", props);
            conn.setAutoCommit(false);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    private String getPasswordFromSecureStore(String key) {
        // This would retrieve password from a secure credential store
        // Implementation would vary based on the secure store being used
        return System.getenv(key + "_PASSWORD");
    }

    @Configuration
    public class good_case_5 {
        @Autowired
        private Environment env;
        
        @Bean
        public DataSource dataSource() {
            DriverManagerDataSource dataSource = new DriverManagerDataSource();
            dataSource.setDriverClassName("com.mysql.jdbc.Driver");
            dataSource.setUrl(env.getProperty("spring.datasource.url"));
            dataSource.setUsername(env.getProperty("spring.datasource.username"));
            // ok: java-hardcoded-database-password
            dataSource.setPassword(env.getProperty("spring.datasource.password"));
            return dataSource;
        }
    }

    public void good_case_6() {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl("jdbc:mysql://remote-db:3306/analytics");
        config.setUsername("analytics_user");
        
        // ok: java-hardcoded-database-password
        try {
            Properties secureProps = new Properties();
            try (InputStream input = getClass().getClassLoader().getResourceAsStream("secure.properties")) {
                secureProps.load(input);
                config.setPassword(secureProps.getProperty("analytics.db.password"));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        try (HikariDataSource ds = new HikariDataSource(config);
             Connection conn = ds.getConnection()) {
            conn.createStatement().execute("DELETE FROM temp_data WHERE created_at < NOW() - INTERVAL 7 DAY");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        // MongoDB connection with password from environment variable
        String username = "admin";
        // ok: java-hardcoded-database-password
        String password = System.getenv("MONGO_PASSWORD");
        MongoClientURI uri = new MongoClientURI("mongodb://" + username + ":" + password + "@localhost:27017/admin");
        try (MongoClient mongoClient = new MongoClient(uri)) {
            MongoDatabase database = mongoClient.getDatabase("customer_data");
            database.getCollection("orders").drop();
        }
    }

    public void good_case_8() {
        // Redis connection with password from system property
        Jedis jedis = new Jedis("redis-server.example.com");
        // ok: java-hardcoded-database-password
        String redisPassword = System.getProperty("redis.password", "");
        jedis.auth(redisPassword);
        jedis.select(2);
        jedis.set("session:active", "true");
        jedis.close();
    }

    public void good_case_9() {
        Map<String, String> config = new HashMap<>();
        config.put("host", "cassandra.example.com");
        config.put("username", "cassandra_user");
        
        // ok: java-hardcoded-database-password
        try {
            Properties props = new Properties();
            try (FileInputStream fis = new FileInputStream("/etc/app/secrets/cassandra.properties")) {
                props.load(fis);
                config.put("password", props.getProperty("cassandra.password"));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        // Simulate Cassandra connection using the config map
        try {
            Class.forName("com.datastax.driver.core.Cluster");
            System.out.println("Connecting to Cassandra with username: " + config.get("username"));
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    public void good_case_10() {
        // Neo4j connection with password from environment
        String username = "neo4j";
        // ok: java-hardcoded-database-password
        String password = System.getenv("NEO4J_PASSWORD");
        Driver driver = GraphDatabase.driver("bolt://neo4j.example.com:7687", 
                                           AuthTokens.basic(username, password));
        
        try (var session = driver.session()) {
            session.run("MATCH (n) RETURN count(n) as count");
        } finally {
            driver.close();
        }
    }

    @Configuration
    public class good_case_11 {
        @Value("${mssql.username}")
        private String username;
        
        @Value("${mssql.password}")
        private String password;
        
        @Bean
        public Connection sqlServerConnection() throws SQLException {
            String connectionString = "jdbc:sqlserver://mssql.example.com:1433;databaseName=customers";
            Properties connectionProps = new Properties();
            connectionProps.put("user", username);
            // ok: java-hardcoded-database-password
            connectionProps.put("password", password);
            connectionProps.put("encrypt", "true");
            
            return DriverManager.getConnection(connectionString, connectionProps);
        }
    }

    public void good_case_12() {
        // AWS RDS connection with credentials from environment variables
        // ok: java-hardcoded-database-password
        String accessKey = System.getenv("AWS_AC_REDACTED_TWILIO_ID_KEY_ID");
        String secretKey = System.getenv("AWS_SECRET_AC_REDACTED_TWILIO_ID_KEY");
        
        BasicAWSCredentials awsCredentials = new BasicAWSCredentials(accessKey, secretKey);
        AmazonRDSClient rdsClient = new AmazonRDSClient(awsCredentials);
        rdsClient.setEndpoint("rds.us-west-2.amazonaws.com");
    }

    public void good_case_13() {
        // Embedded database with password from properties file
        try {
            Properties props = new Properties();
            // ok: java-hardcoded-database-password
            try (InputStream input = getClass().getClassLoader().getResourceAsStream("database.properties")) {
                props.load(input);
            }
            
            Class.forName("org.h2.Driver");
            Connection conn = DriverManager.getConnection(
                props.getProperty("db.url"), 
                props.getProperty("db.user"), 
                props.getProperty("db.password")
            );
            conn.createStatement().execute("CREATE TABLE IF NOT EXISTS audit_log (id INT AUTO_INCREMENT, action VARCHAR(255))");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_14() {
        // Connection pool with credentials from environment variables
        BasicDataSource ds = new BasicDataSource();
        ds.setDriverClassName("com.mysql.jdbc.Driver");
        ds.setUrl(System.getProperty("inventory.db.url", "jdbc:mysql://db-cluster.example.com:3306/inventory"));
        ds.setUsername(System.getProperty("inventory.db.user", "inventory_app"));
        // ok: java-hardcoded-database-password
        ds.setPassword(System.getProperty("inventory.db.password"));
        ds.setInitialSize(5);
        ds.setMaxTotal(20);
        
        try {
            Connection conn = ds.getConnection();
            conn.createStatement().executeQuery("SELECT * FROM products WHERE stock < 10");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        // Connection with multiple database parameters including password from secure source
        try {
            String url = "jdbc:mysql://analytics-db:3306/metrics?useSSL=true&serverTimezone=UTC";
            Properties props = new Properties();
            props.setProperty("user", "metrics_reader");
            
            // ok: java-hardcoded-database-password
            String password = getPasswordFromVault("metrics_db");
            props.setProperty("password", password);
            props.setProperty("connectTimeout", "5000");
            
            Connection conn = DriverManager.getConnection(url, props);
            conn.createStatement().executeQuery("SELECT AVG(response_time) FROM api_calls WHERE date > CURDATE() - INTERVAL 7 DAY");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    private String getPasswordFromVault(String key) {
        // This would retrieve password from a secure vault like HashiCorp Vault
        // Implementation would vary based on the vault being used
        return System.getenv(key.toUpperCase() + "_PASSWORD");
    }
}
// {/fact}