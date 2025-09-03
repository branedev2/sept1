import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;
import java.io.FileInputStream;
import java.io.IOException;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import java.util.Base64;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import com.mongodb.client.MongoDatabase;
import redis.clients.jedis.Jedis;
import org.neo4j.driver.AuthTokens;
import org.neo4j.driver.Driver;
import org.neo4j.driver.GraphDatabase;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.amazonaws.services.secretsmanager.model.GetSecretValueRequest;
import com.amazonaws.services.secretsmanager.model.GetSecretValueResult;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultResponseSupport;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import java.net.URI;

public class DatabasePasswordExamples {

    // True Positives (Vulnerable Code)

// {fact rule=hardcoded-credentials@v1.0 defects=1}
    public void bad_case_1() {
        try {
            String url = "jdbc:mysql://localhost:3306/mydb";
            String username = "admin";
            // ruleid: java-do-not-hardcode-database-password
            String password = "p@ssw0rd123";
            Connection conn = DriverManager.getConnection(url, username, password);
            Statement stmt = conn.createStatement();
            stmt.executeQuery("SELECT * FROM users");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        try {
            // ruleid: java-do-not-hardcode-database-password
            Connection conn = DriverManager.getConnection(
                "jdbc:postgresql://localhost:5432/mydb", 
                "postgres", 
                "SuperSecretPassword123!"
            );
            conn.createStatement().executeUpdate("CREATE TABLE employees (id INT, name VARCHAR(100))");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() {
        try {
            Properties props = new Properties();
            props.setProperty("user", "dbadmin");
            // ruleid: java-do-not-hardcode-database-password
            props.setProperty("password", "dbadmin_123456");
            Connection conn = DriverManager.getConnection("jdbc:oracle:thin:@localhost:1521:orcl", props);
            conn.setAutoCommit(false);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        // MongoDB connection with hardcoded password
        // ruleid: java-do-not-hardcode-database-password
        String connectionString = "mongodb://admin:mongodb_password@localhost:27017/admin";
        MongoClientURI uri = new MongoClientURI(connectionString);
        MongoClient mongoClient = new MongoClient(uri);
        MongoDatabase database = mongoClient.getDatabase("mydb");
    }

    public void bad_case_5() {
        // Redis connection with hardcoded password
        Jedis jedis = new Jedis("localhost");
        // ruleid: java-do-not-hardcode-database-password
        jedis.auth("redis_secret_password");
        jedis.set("key", "value");
    }

    public void bad_case_6() {
        // Neo4j connection with hardcoded password
        // ruleid: java-do-not-hardcode-database-password
        Driver driver = GraphDatabase.driver("bolt://localhost:7687", 
                                            AuthTokens.basic("neo4j", "neo4j_password"));
        driver.close();
    }

    public void bad_case_7() {
        try {
            // Connection string with embedded password
            // ruleid: java-do-not-hardcode-database-password
            String connectionUrl = "jdbc:sqlserver://localhost:1433;databaseName=AdventureWorks;user=sa;password=mssql_p@ssw0rd";
            Connection conn = DriverManager.getConnection(connectionUrl);
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8() {
        try {
            // Connection with hardcoded password in a different format
            String url = "jdbc:mysql://localhost:3306/mydb?useSSL=false";
            Properties info = new Properties();
            info.put("user", "root");
            // ruleid: java-do-not-hardcode-database-password
            info.put("password", "mysql_root_password");
            Connection conn = DriverManager.getConnection(url, info);
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9() {
        // Hardcoded password in a connection pool configuration
        try {
            Class.forName("org.apache.commons.dbcp.BasicDataSource");
            org.apache.commons.dbcp.BasicDataSource dataSource = new org.apache.commons.dbcp.BasicDataSource();
            dataSource.setDriverClassName("com.mysql.jdbc.Driver");
            dataSource.setUrl("jdbc:mysql://localhost:3306/mydb");
            dataSource.setUsername("dbuser");
            // ruleid: java-do-not-hardcode-database-password
            dataSource.setPassword("dbcp_password_123");
            Connection conn = dataSource.getConnection();
            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10() {
        // Hardcoded password in a slightly obfuscated way
        final String DB_USER = "admin";
        // ruleid: java-do-not-hardcode-database-password
        final String DB_PASS = "admin" + "_" + "password" + "!" + "2023";
        try {
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/mydb", DB_USER, DB_PASS);
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        // Cassandra connection with hardcoded password
        try {
            com.datastax.driver.core.Cluster cluster = com.datastax.driver.core.Cluster.builder()
                .addContactPoint("127.0.0.1")
                // ruleid: java-do-not-hardcode-database-password
                .withCredentials("cassandra", "cassandra_password")
                .build();
            com.datastax.driver.core.Session session = cluster.connect("mykeyspace");
            session.close();
            cluster.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12() {
        // Couchbase connection with hardcoded password
        try {
            // ruleid: java-do-not-hardcode-database-password
            com.couchbase.client.java.Cluster cluster = com.couchbase.client.java.CouchbaseCluster.create("localhost");
            cluster.authenticate("Administrator", "couchbase_password");
            com.couchbase.client.java.Bucket bucket = cluster.openBucket("default");
            bucket.close();
            cluster.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        // HikariCP connection pool with hardcoded password
        try {
            com.zaxxer.hikari.HikariConfig config = new com.zaxxer.hikari.HikariConfig();
            config.setJdbcUrl("jdbc:mysql://localhost:3306/mydb");
            config.setUsername("hikari_user");
            // ruleid: java-do-not-hardcode-database-password
            config.setPassword("hikari_password_123");
            com.zaxxer.hikari.HikariDataSource dataSource = new com.zaxxer.hikari.HikariDataSource(config);
            Connection conn = dataSource.getConnection();
            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        // Elasticsearch connection with hardcoded password
        try {
            // ruleid: java-do-not-hardcode-database-password
            org.elasticsearch.client.RestHighLevelClient client = new org.elasticsearch.client.RestHighLevelClient(
                org.elasticsearch.client.RestClient.builder(
                    new org.apache.http.HttpHost("localhost", 9200, "http"))
                    .setHttpClientConfigCallback(httpClientBuilder -> 
                        httpClientBuilder.setDefaultCredentialsProvider(
                            new org.apache.http.impl.client.BasicCredentialsProvider() {{
                                setCredentials(
                                    org.apache.http.auth.AuthScope.ANY,
                                    new org.apache.http.auth.UsernamePasswordCredentials("elastic", "elastic_password")
                                );
                            }}
                        )
                    )
            );
            client.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        // InfluxDB connection with hardcoded password
        try {
            // ruleid: java-do-not-hardcode-database-password
            org.influxdb.InfluxDB influxDB = org.influxdb.InfluxDBFactory.connect(
                "http://localhost:8086", "admin", "influxdb_password");
            influxDB.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negatives (Secure Code)

    public void good_case_1() {
        try {
            String url = "jdbc:mysql://localhost:3306/mydb";
            String username = "admin";
            // ok: java-do-not-hardcode-database-password
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
            FileInputStream fis = new FileInputStream("config.properties");
            props.load(fis);
            // ok: java-do-not-hardcode-database-password
            Connection conn = DriverManager.getConnection(
                props.getProperty("db.url"), 
                props.getProperty("db.user"), 
                props.getProperty("db.password")
            );
            conn.createStatement().executeUpdate("CREATE TABLE employees (id INT, name VARCHAR(100))");
        } catch (SQLException | IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        try {
            Properties props = new Properties();
            props.setProperty("user", "dbadmin");
            // ok: java-do-not-hardcode-database-password
            String password = fetchPasswordFromSecureStore("db_main");
            props.setProperty("password", password);
            Connection conn = DriverManager.getConnection("jdbc:oracle:thin:@localhost:1521:orcl", props);
            conn.setAutoCommit(false);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private String fetchPasswordFromSecureStore(String key) {
        // This would be implemented to fetch from a secure credential store
        return System.getProperty(key + ".password");
    }

    public void good_case_4() {
        // MongoDB connection with password from environment variable
        // ok: java-do-not-hardcode-database-password
        String password = System.getenv("MONGO_PASSWORD");
        String connectionString = "mongodb://admin:" + password + "@localhost:27017/admin";
        MongoClientURI uri = new MongoClientURI(connectionString);
        MongoClient mongoClient = new MongoClient(uri);
        MongoDatabase database = mongoClient.getDatabase("mydb");
    }

    public void good_case_5() {
        // Redis connection with password from properties file
        try {
            Properties props = new Properties();
            props.load(new FileInputStream("redis.properties"));
            Jedis jedis = new Jedis("localhost");
            // ok: java-do-not-hardcode-database-password
            jedis.auth(props.getProperty("redis.password"));
            jedis.set("key", "value");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_6() {
        // Neo4j connection with password from secure storage
        // ok: java-do-not-hardcode-database-password
        String password = getPasswordFromSecureStorage("neo4j.password");
        Driver driver = GraphDatabase.driver("bolt://localhost:7687", 
                                            AuthTokens.basic("neo4j", password));
        driver.close();
    }

    private String getPasswordFromSecureStorage(String key) {
        // Implementation would retrieve from a secure credential store
        return System.getProperty(key);
    }

    public void good_case_7() {
        try {
            // Connection string with password from environment variable
            String user = "sa";
            // ok: java-do-not-hardcode-database-password
            String password = System.getenv("MSSQL_PASSWORD");
            String connectionUrl = "jdbc:sqlserver://localhost:1433;databaseName=AdventureWorks;user=" + 
                                   user + ";password=" + password;
            Connection conn = DriverManager.getConnection(connectionUrl);
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void good_case_8() {
        try {
            // Using AWS Secrets Manager to retrieve database credentials
            // ok: java-do-not-hardcode-database-password
            String secretName = "prod/db/password";
            AWSSecretsManager client = AWSSecretsManagerClientBuilder.standard()
                                        .withRegion("us-west-2")
                                        .build();
            
            GetSecretValueRequest getSecretValueRequest = new GetSecretValueRequest()
                                                        .withSecretId(secretName);
            GetSecretValueResult getSecretValueResult = client.getSecretValue(getSecretValueRequest);
            String secret = getSecretValueResult.getSecretString();
            
            // Parse the secret JSON and get the password
            // This is simplified - in real code you'd use a JSON parser
            String password = secret.split("\"password\":\"")[1].split("\"")[0];
            
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/mydb", "dbuser", password);
            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_9() {
        // Using HashiCorp Vault to retrieve database credentials
        try {
            // ok: java-do-not-hardcode-database-password
            VaultEndpoint vaultEndpoint = VaultEndpoint.create("vault.example.com", 8200);
            vaultEndpoint.setScheme("https");
            
            VaultOperations vaultOperations = new VaultTemplate(
                vaultEndpoint, 
                new TokenAuthentication(System.getenv("VAULT_TOKEN"))
            );
            
            VaultResponseSupport<Map<String, Object>> response = 
                vaultOperations.read("secret/database/credentials");
            
            String username = (String) response.getData().get("username");
            String password = (String) response.getData().get("password");
            
            Connection conn = DriverManager.getConnection(
                "jdbc:postgresql://localhost:5432/mydb", username, password);
            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_10() {
        // Using a secure configuration service
        try {
            // ok: java-do-not-hardcode-database-password
            ConfigurationService configService = ConfigurationService.getInstance();
            String dbUrl = configService.getProperty("database.url");
            String dbUser = configService.getProperty("database.user");
            String dbPassword = configService.getProperty("database.password");
            
            Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPassword);
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // Mock class for demonstration
    static class ConfigurationService {
        private static ConfigurationService instance;
        
        public static ConfigurationService getInstance() {
            if (instance == null) {
                instance = new ConfigurationService();
            }
            return instance;
        }
        
        public String getProperty(String key) {
            // In a real implementation, this would securely retrieve configuration
            return System.getProperty(key);
        }
    }

    public void good_case_11() {
        // Cassandra connection with password from environment variable
        try {
            // ok: java-do-not-hardcode-database-password
            String password = System.getenv("CASSANDRA_PASSWORD");
            com.datastax.driver.core.Cluster cluster = com.datastax.driver.core.Cluster.builder()
                .addContactPoint("127.0.0.1")
                .withCredentials("cassandra", password)
                .build();
            com.datastax.driver.core.Session session = cluster.connect("mykeyspace");
            session.close();
            cluster.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_12() {
        // Couchbase connection with password from properties file
        try {
            Properties props = new Properties();
            props.load(new FileInputStream("couchbase.properties"));
            
            // ok: java-do-not-hardcode-database-password
            String password = props.getProperty("couchbase.password");
            com.couchbase.client.java.Cluster cluster = com.couchbase.client.java.CouchbaseCluster.create("localhost");
            cluster.authenticate("Administrator", password);
            com.couchbase.client.java.Bucket bucket = cluster.openBucket("default");
            bucket.close();
            cluster.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        // HikariCP connection pool with encrypted password
        try {
            // ok: java-do-not-hardcode-database-password
            String encryptedPassword = System.getProperty("db.encrypted.password");
            String password = decryptPassword(encryptedPassword);
            
            com.zaxxer.hikari.HikariConfig config = new com.zaxxer.hikari.HikariConfig();
            config.setJdbcUrl("jdbc:mysql://localhost:3306/mydb");
            config.setUsername("hikari_user");
            config.setPassword(password);
            com.zaxxer.hikari.HikariDataSource dataSource = new com.zaxxer.hikari.HikariDataSource(config);
            Connection conn = dataSource.getConnection();
            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String decryptPassword(String encryptedPassword) {
        try {
            // This is a simplified example - real implementation would be more secure
            byte[] decodedKey = Base64.getDecoder().decode(System.getProperty("encryption.key"));
            SecretKeySpec keySpec = new SecretKeySpec(decodedKey, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword));
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public void good_case_14() {
        // Elasticsearch connection with password from system properties
        try {
            // ok: java-do-not-hardcode-database-password
            final String password = System.getProperty("elastic.password");
            org.elasticsearch.client.RestHighLevelClient client = new org.elasticsearch.client.RestHighLevelClient(
                org.elasticsearch.client.RestClient.builder(
                    new org.apache.http.HttpHost("localhost", 9200, "http"))
                    .setHttpClientConfigCallback(httpClientBuilder -> 
                        httpClientBuilder.setDefaultCredentialsProvider(
                            new org.apache.http.impl.client.BasicCredentialsProvider() {{
                                setCredentials(
                                    org.apache.http.auth.AuthScope.ANY,
                                    new org.apache.http.auth.UsernamePasswordCredentials("elastic", password)
                                );
                            }}
                        )
                    )
            );
            client.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        // InfluxDB connection with password from environment variable
        try {
            // ok: java-do-not-hardcode-database-password
            String password = System.getenv("INFLUXDB_PASSWORD");
            org.influxdb.InfluxDB influxDB = org.influxdb.InfluxDBFactory.connect(
                "http://localhost:8086", "admin", password);
            influxDB.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}