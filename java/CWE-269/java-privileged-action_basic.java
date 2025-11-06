import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Properties;
import javax.net.ssl.HttpsURLConnection;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.logging.Logger;

public class PrivilegedActionExamples {
    private static final Logger logger = Logger.getLogger(PrivilegedActionExamples.class.getName());

    // True Positives (Vulnerable Code)

// {fact rule=improper-privilege-management@v1.0 defects=1}
    public void bad_case_1() {
        // ruleid: java-privileged-action
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {
                // Too much code in privileged block
                try {
                    // Read system properties
                    String userHome = System.getProperty("user.home");
                    
                    // Create file
                    File file = new File(userHome + "/config.properties");
                    
                    // Read file contents
                    Properties props = new Properties();
                    FileInputStream fis = new FileInputStream(file);
                    props.load(fis);
                    fis.close();
                    
                    // Process properties
                    String dbUrl = props.getProperty("db.url");
                    String username = props.getProperty("db.username");
                    String password = props.getProperty("db.password");
                    
                    // Connect to database
                    Connection conn = DriverManager.getConnection(dbUrl, username, password);
                    // Do database operations
                    conn.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
                return null;
            }
        });
    }

    public void bad_case_2() {
        // ruleid: java-privileged-action
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {
                // Network operations in privileged block
                try {
                    URL url = new URL("https://api.example.com/data");
                    HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
                    conn.setRequestMethod("GET");
                    
                    // Read response
                    int responseCode = conn.getResponseCode();
                    if (responseCode == 200) {
                        // Process response
                        // ...
                    }
                    conn.disconnect();
                    
                    // Write to file
                    File outputFile = new File("/tmp/api_response.txt");
                    FileOutputStream fos = new FileOutputStream(outputFile);
                    fos.write("Response code: ".getBytes());
                    fos.write(String.valueOf(responseCode).getBytes());
                    fos.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
                return null;
            }
        });
    }

    public void bad_case_3() implements PrivilegedAction<Void> {
        // ruleid: java-privileged-action
        @Override
        public Void run() {
            // Large method with multiple operations
            try {
                // Read system configuration
                String configPath = System.getProperty("config.path");
                Properties systemConfig = new Properties();
                systemConfig.load(new FileInputStream(configPath));
                
                // Update configuration
                systemConfig.setProperty("last.run", String.valueOf(System.currentTimeMillis()));
                systemConfig.store(new FileOutputStream(configPath), "Updated configuration");
                
                // Create temporary files
                File tempDir = new File(System.getProperty("java.io.tmpdir"));
                File tempFile = File.createTempFile("app_", ".tmp", tempDir);
                tempFile.deleteOnExit();
                
                // Write data to temp file
                FileOutputStream fos = new FileOutputStream(tempFile);
                fos.write("Temporary data".getBytes());
                fos.close();
            } catch (IOException e) {
                logger.severe("Error in privileged action: " + e.getMessage());
            }
            return null;
        }
    }

    public void bad_case_4() {
        // ruleid: java-privileged-action
        PrivilegedAction<String> action = new PrivilegedAction<String>() {
            @Override
            public String run() {
                // Multiple system operations
                StringBuilder result = new StringBuilder();
                
                // Get all system properties
                Properties props = System.getProperties();
                for (String key : props.stringPropertyNames()) {
                    result.append(key).append("=").append(props.getProperty(key)).append("\n");
                }
                
                // Write to file
                try {
                    File file = new File("/tmp/system_properties.txt");
                    Files.write(file.toPath(), result.toString().getBytes());
                    
                    // Change file permissions
                    file.setReadable(true, false);
                    file.setWritable(true, true);
                } catch (IOException e) {
                    e.printStackTrace();
                }
                
                return result.toString();
            }
        };
        
        String properties = AccessController.doPrivileged(action);
    }

    public void bad_case_5() {
        // ruleid: java-privileged-action
        AccessController.doPrivileged(new PrivilegedExceptionAction<Void>() {
            @Override
            public Void run() throws Exception {
                // Multiple file operations
                Path sourcePath = Paths.get("/etc/config/app.properties");
                Path targetPath = Paths.get(System.getProperty("user.home") + "/app.properties");
                
                // Read source file
                byte[] data = Files.readAllBytes(sourcePath);
                
                // Process data
                String content = new String(data);
                content = content.replace("debug=false", "debug=true");
                
                // Write to target file
                Files.write(targetPath, content.getBytes());
                
                // Set file permissions
                Files.setPosixFilePermissions(targetPath, 
                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-r--r--"));
                
                return null;
            }
        });
    }

    public void bad_case_6() {
        // ruleid: java-privileged-action
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {
                // Database operations in privileged block
                Connection conn = null;
                try {
                    // Load driver
                    Class.forName("com.mysql.jdbc.Driver");
                    
                    // Connect to database
                    String url = "jdbc:mysql://localhost:3306/testdb";
                    conn = DriverManager.getConnection(url, "admin", "password");
                    
                    // Create table
                    conn.createStatement().execute(
                        "CREATE TABLE IF NOT EXISTS users (id INT, name VARCHAR(100))");
                    
                    // Insert data
                    conn.createStatement().execute(
                        "INSERT INTO users VALUES (1, 'admin')");
                    
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    try {
                        if (conn != null) conn.close();
                    } catch (SQLException e) {
                        e.printStackTrace();
                    }
                }
                return null;
            }
        });
    }

    public void bad_case_7() {
        // ruleid: java-privileged-action
        AccessController.doPrivileged(new PrivilegedAction<Boolean>() {
            public Boolean run() {
                // Multiple system modifications
                try {
                    // Set multiple system properties
                    System.setProperty("app.debug", "true");
                    System.setProperty("app.logLevel", "VERBOSE");
                    System.setProperty("app.tempDir", "/tmp/app_data");
                    
                    // Create directories
                    File tempDir = new File("/tmp/app_data");
                    if (!tempDir.exists()) {
                        tempDir.mkdirs();
                    }
                    
                    File logDir = new File("/var/log/myapp");
                    if (!logDir.exists()) {
                        logDir.mkdirs();
                    }
                    
                    // Set up logging
                    File logFile = new File(logDir, "app.log");
                    if (!logFile.exists()) {
                        logFile.createNewFile();
                    }
                    
                    return true;
                } catch (Exception e) {
                    e.printStackTrace();
                    return false;
                }
            }
        });
    }

    public void bad_case_8() {
        // ruleid: java-privileged-action
        AccessController.doPrivileged(new PrivilegedExceptionAction<String[]>() {
            @Override
            public String[] run() throws Exception {
                // File system traversal and operations
                File rootDir = new File("/etc/app/config");
                String[] configFiles = rootDir.list();
                
                // Process each file
                for (String fileName : configFiles) {
                    File file = new File(rootDir, fileName);
                    if (file.isFile() && fileName.endsWith(".properties")) {
                        // Read properties
                        Properties props = new Properties();
                        FileInputStream fis = new FileInputStream(file);
                        props.load(fis);
                        fis.close();
                        
                        // Update properties
                        props.setProperty("last.modified", String.valueOf(System.currentTimeMillis()));
                        
                        // Write back
                        FileOutputStream fos = new FileOutputStream(file);
                        props.store(fos, "Updated by system");
                        fos.close();
                    }
                }
                
                return configFiles;
            }
        });
    }

    public void bad_case_9() implements PrivilegedAction<Integer> {
        // ruleid: java-privileged-action
        @Override
        public Integer run() {
            int count = 0;
            try {
                // Complex file operations
                String baseDir = System.getProperty("user.home") + "/data";
                File dir = new File(baseDir);
                
                // Create directory if it doesn't exist
                if (!dir.exists()) {
                    dir.mkdirs();
                }
                
                // Create multiple files
                for (int i = 0; i < 10; i++) {
                    File file = new File(dir, "file_" + i + ".dat");
                    if (!file.exists()) {
                        file.createNewFile();
                        FileOutputStream fos = new FileOutputStream(file);
                        fos.write(("Data for file " + i).getBytes());
                        fos.close();
                        count++;
                    }
                }
                
                // Read system environment
                System.getenv().forEach((key, value) -> {
                    System.out.println(key + "=" + value);
                });
                
            } catch (IOException e) {
                e.printStackTrace();
            }
            return count;
        }
    }

    public void bad_case_10() {
        // ruleid: java-privileged-action
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {
                try {
                    // Network and file operations combined
                    URL url = new URL("https://example.com/api/config");
                    URLConnection conn = url.openConnection();
                    
                    // Read from network
                    byte[] buffer = new byte[8192];
                    int bytesRead;
                    StringBuilder response = new StringBuilder();
                    try (java.io.InputStream in = conn.getInputStream()) {
                        while ((bytesRead = in.read(buffer)) != -1) {
                            response.append(new String(buffer, 0, bytesRead));
                        }
                    }
                    
                    // Process response
                    String configData = response.toString();
                    String[] lines = configData.split("\n");
                    
                    // Write to multiple configuration files
                    for (String line : lines) {
                        if (line.contains("=")) {
                            String[] parts = line.split("=", 2);
                            String fileName = parts[0].trim() + ".config";
                            String content = parts[1].trim();
                            
                            // Write to file
                            File file = new File("/etc/app/config/" + fileName);
                            FileOutputStream fos = new FileOutputStream(file);
                            fos.write(content.getBytes());
                            fos.close();
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
                return null;
            }
        });
    }

    public void bad_case_11() {
        // ruleid: java-privileged-action
        AccessController.doPrivileged(new PrivilegedAction<Boolean>() {
            public Boolean run() {
                // System configuration and security operations
                try {
                    // Set security manager
                    if (System.getSecurityManager() == null) {
                        System.setSecurityManager(new SecurityManager());
                    }
                    
                    // Set system properties
                    System.setProperty("java.security.policy", "/path/to/policy.file");
                    System.setProperty("java.security.auth.login.config", "/path/to/login.config");
                    
                    // Create security directories
                    File securityDir = new File("/app/security");
                    if (!securityDir.exists()) {
                        securityDir.mkdirs();
                    }
                    
                    // Generate and store keys
                    java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("RSA");
                    keyGen.initialize(2048);
                    java.security.KeyPair pair = keyGen.generateKeyPair();
                    
                    // Store public key
                    try (FileOutputStream fos = new FileOutputStream("/app/security/public.key")) {
                        fos.write(pair.getPublic().getEncoded());
                    }
                    
                    // Store private key
                    try (FileOutputStream fos = new FileOutputStream("/app/security/private.key")) {
                        fos.write(pair.getPrivate().getEncoded());
                    }
                    
                    return true;
                } catch (Exception e) {
                    e.printStackTrace();
                    return false;
                }
            }
        });
    }

    public void bad_case_12() {
        // ruleid: java-privileged-action
        AccessController.doPrivileged(new PrivilegedExceptionAction<Void>() {
            @Override
            public Void run() throws Exception {
                // Complex system administration tasks
                Runtime runtime = Runtime.getRuntime();
                
                // Execute system commands
                Process process = runtime.exec("hostname");
                java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(process.getInputStream()));
                
                String hostname = reader.readLine();
                process.waitFor();
                
                // Write to system configuration
                File hostFile = new File("/etc/hosts.allow");
                if (hostFile.exists() && hostFile.canWrite()) {
                    FileOutputStream fos = new FileOutputStream(hostFile, true);
                    String entry = hostname + " ALL: ALLOW\n";
                    fos.write(entry.getBytes());
                    fos.close();
                }
                
                // Modify system users (simulated)
                File passwdFile = new File("/tmp/passwd");
                if (!passwdFile.exists()) {
                    passwdFile.createNewFile();
                }
                FileOutputStream fos = new FileOutputStream(passwdFile);
                fos.write(("user:x:1000:1000:User:/home/user:/bin/bash\n").getBytes());
                fos.close();
                
                return null;
            }
        });
    }

    public void bad_case_13() {
        // ruleid: java-privileged-action
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {
                // Multiple resource access operations
                try {
                    // Access classpath resources
                    ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
                    java.util.Enumeration<URL> resources = classLoader.getResources("META-INF/services/");
                    
                    while (resources.hasMoreElements()) {
                        URL url = resources.nextElement();
                        System.out.println("Found service: " + url);
                        
                        // Read service files
                        if ("file".equals(url.getProtocol())) {
                            File dir = new File(url.toURI());
                            File[] files = dir.listFiles();
                            if (files != null) {
                                for (File file : files) {
                                    // Read service implementation
                                    FileInputStream fis = new FileInputStream(file);
                                    byte[] data = new byte[(int) file.length()];
                                    fis.read(data);
                                    fis.close();
                                    
                                    // Process service data
                                    String serviceImpl = new String(data).trim();
                                    System.out.println("Service implementation: " + serviceImpl);
                                    
                                    // Try to load the class
                                    try {
                                        Class.forName(serviceImpl);
                                    } catch (ClassNotFoundException e) {
                                        e.printStackTrace();
                                    }
                                }
                            }
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
                return null;
            }
        });
    }

    public void bad_case_14() {
        // ruleid: java-privileged-action
        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            public Void run() {
                // JMX operations in privileged block
                try {
                    javax.management.MBeanServer mbs = java.lang.management.ManagementFactory.getPlatformMBeanServer();
                    
                    // Register custom MBean
                    Object mbean = new Object() {
                        private int count = 0;
                        
                        public int getCount() {
                            return count;
                        }
                        
                        public void setCount(int count) {
                            this.count = count;
                        }
                        
                        public void increment() {
                            count++;
                        }
                    };
                    
                    javax.management.ObjectName name = new javax.management.ObjectName("com.example:type=Counter");
                    mbs.registerMBean(mbean, name);
                    
                    // Get system information
                    java.lang.management.MemoryMXBean memoryBean = java.lang.management.ManagementFactory.getMemoryMXBean();
                    java.lang.management.OperatingSystemMXBean osBean = java.lang.management.ManagementFactory.getOperatingSystemMXBean();
                    
                    // Log system information
                    System.out.println("Heap memory usage: " + memoryBean.getHeapMemoryUsage());
                    System.out.println("OS: " + osBean.getName() + " " + osBean.getVersion());
                    System.out.println("Available processors: " + osBean.getAvailableProcessors());
                    
                } catch (Exception e) {
                    e.printStackTrace();
                }
                return null;
            }
        });
    }

    public void bad_case_15() implements PrivilegedAction<Void> {
        // ruleid: java-privileged-action
        @Override
        public Void run() {
            // Multiple system operations with error handling
            try {
                // Get user information
                String userName = System.getProperty("user.name");
                String userHome = System.getProperty("user.home");
                String osName = System.getProperty("os.name");
                
                // Create user-specific directories
                File dataDir = new File(userHome + "/app/data");
                File configDir = new File(userHome + "/app/config");
                File logsDir = new File(userHome + "/app/logs");
                
                dataDir.mkdirs();
                configDir.mkdirs();
                logsDir.mkdirs();
                
                // Create default configuration
                Properties defaultConfig = new Properties();
                defaultConfig.setProperty("user.name", userName);
                defaultConfig.setProperty("os.name", osName);
                defaultConfig.setProperty("app.version", "1.0.0");
                defaultConfig.setProperty("app.data.dir", dataDir.getAbsolutePath());
                defaultConfig.setProperty("app.logs.dir", logsDir.getAbsolutePath());
                
                // Save configuration
                File configFile = new File(configDir, "app.properties");
                FileOutputStream fos = new FileOutputStream(configFile);
                defaultConfig.store(fos, "Default application configuration");
                fos.close();
                
                // Create log file
                File logFile = new File(logsDir, "app.log");
                if (!logFile.exists()) {
                    logFile.createNewFile();
                }
                
                // Write initial log entry
                FileOutputStream logFos = new FileOutputStream(logFile, true);
                String logEntry = String.format("[%s] Application initialized for user %s on %s\n", 
                    new java.util.Date(), userName, osName);
                logFos.write(logEntry.getBytes());
                logFos.close();
                
            } catch (IOException e) {
                e.printStackTrace();
            }
            return null;
        }
    }

    // True Negatives (Safe Code)

    public void good_case_1() {
        // Minimal privileged action to get a system property
        String userHome = AccessController.doPrivileged(
            new PrivilegedAction<String>() {
                // ok: java-privileged-action
                public String run() {
                    return System.getProperty("user.home");
                }
            }
        );
        
        // Use the property outside privileged block
        try {
            File configFile = new File(userHome + "/config.properties");
            Properties props = new Properties();
            if (configFile.exists()) {
                FileInputStream fis = new FileInputStream(configFile);
                props.load(fis);
                fis.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() {
        try {
            // Only file reading is privileged
            final File file = new File("/etc/config/app.properties");
            
            byte[] data = AccessController.doPrivileged(
                new PrivilegedExceptionAction<byte[]>() {
                    // ok: java-privileged-action
                    public byte[] run() throws IOException {
                        return Files.readAllBytes(file.toPath());
                    }
                }
            );
            
            // Process data outside privileged block
            String content = new String(data);
            Properties props = new Properties();
            props.load(new java.io.ByteArrayInputStream(data));
            
            // Use properties
            String dbUrl = props.getProperty("db.url");
            String username = props.getProperty("db.username");
            String password = props.getProperty("db.password");
            
            // Database operations outside privileged block
            Connection conn = DriverManager.getConnection(dbUrl, username, password);
            // Do database operations
            conn.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        // Get system property in privileged block
        final String configPath = AccessController.doPrivileged(
            new PrivilegedAction<String>() {
                // ok: java-privileged-action
                public String run() {
                    return System.getProperty("config.path");
                }
            }
        );
        
        // File operations outside privileged block
        try {
            Properties systemConfig = new Properties();
            FileInputStream fis = new FileInputStream(configPath);
            systemConfig.load(fis);
            fis.close();
            
            // Update configuration
            systemConfig.setProperty("last.run", String.valueOf(System.currentTimeMillis()));
            
            FileOutputStream fos = new FileOutputStream(configPath);
            systemConfig.store(fos, "Updated configuration");
            fos.close();
        } catch (IOException e) {
            logger.severe("Error processing configuration: " + e.getMessage());
        }
    }

    public void good_case_4() {
        // Create temp file in privileged block
        final File tempFile = AccessController.doPrivileged(
            new PrivilegedAction<File>() {
                // ok: java-privileged-action
                public File run() {
                    try {
                        File tempDir = new File(System.getProperty("java.io.tmpdir"));
                        File file = File.createTempFile("app_", ".tmp", tempDir);
                        file.deleteOnExit();
                        return file;
                    } catch (IOException e) {
                        e.printStackTrace();
                        return null;
                    }
                }
            }
        );
        
        // Write data outside privileged block
        if (tempFile != null) {
            try {
                FileOutputStream fos = new FileOutputStream(tempFile);
                fos.write("Temporary data".getBytes());
                fos.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void good_case_5() {
        // Get specific system property in privileged block
        final String debugMode = AccessController.doPrivileged(
            new PrivilegedAction<String>() {
                // ok: java-privileged-action
                public String run() {
                    return System.getProperty("app.debug", "false");
                }
            }
        );
        
        // Use property outside privileged block
        if (Boolean.parseBoolean(debugMode)) {
            try {
                // Enable debug logging
                File logDir = new File("/var/log/myapp");
                if (!logDir.exists()) {
                    logDir.mkdirs();
                }
                
                File logFile = new File(logDir, "debug.log");
                FileOutputStream fos = new FileOutputStream(logFile, true);
                fos.write(("Debug enabled at " + new java.util.Date() + "\n").getBytes());
                fos.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void good_case_6() {
        try {
            // Get database connection parameters in privileged block
            final Properties dbProps = AccessController.doPrivileged(
                new PrivilegedExceptionAction<Properties>() {
                    // ok: java-privileged-action
                    public Properties run() throws IOException {
                        Properties props = new Properties();
                        props.load(new FileInputStream("/etc/app/database.properties"));
                        return props;
                    }
                }
            );
            
            // Database operations outside privileged block
            String url = dbProps.getProperty("db.url");
            String username = dbProps.getProperty("db.username");
            String password = dbProps.getProperty("db.password");
            
            // Connect to database
            Connection conn = DriverManager.getConnection(url, username, password);
            
            // Create table
            conn.createStatement().execute(
                "CREATE TABLE IF NOT EXISTS users (id INT, name VARCHAR(100))");
            
            // Insert data
            conn.createStatement().execute(
                "INSERT INTO users VALUES (1, 'admin')");
            
            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        // Get user home in privileged block
        final String userHome = AccessController.doPrivileged(
            new PrivilegedAction<String>() {
                // ok: java-privileged-action
                public String run() {
                    return System.getProperty("user.home");
                }
            }
        );
        
        // Create directories outside privileged block
        try {
            File dataDir = new File(userHome + "/app_data");
            if (!dataDir.exists()) {
                dataDir.mkdirs();
            }
            
            // Create configuration file
            File configFile = new File(dataDir, "config.properties");
            if (!configFile.exists()) {
                Properties props = new Properties();
                props.setProperty("app.version", "1.0");
                props.setProperty("app.name", "Example App");
                
                FileOutputStream fos = new FileOutputStream(configFile);
                props.store(fos, "Application Configuration");
                fos.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_8() {
        try {
            // Check if file exists in privileged block
            final boolean configExists = AccessController.doPrivileged(
                new PrivilegedAction<Boolean>() {
                    // ok: java-privileged-action
                    public Boolean run() {
                        File configFile = new File("/etc/app/config/main.properties");
                        return configFile.exists();
                    }
                }
            );
            
            // Create default config outside privileged block if needed
            if (!configExists) {
                File configDir = new File("/etc/app/config");
                if (!configDir.exists()) {
                    configDir.mkdirs();
                }
                
                File configFile = new File(configDir, "main.properties");
                Properties defaultProps = new Properties();
                defaultProps.setProperty("app.mode", "production");
                defaultProps.setProperty("app.maxConnections", "100");
                
                FileOutputStream fos = new FileOutputStream(configFile);
                defaultProps.store(fos, "Default Configuration");
                fos.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_9() {
        // Get temp directory in privileged block
        final String tempDir = AccessController.doPrivileged(
            new PrivilegedAction<String>() {
                // ok: java-privileged-action
                public String run() {
                    return System.getProperty("java.io.tmpdir");
                }
            }
        );
        
        // Create files outside privileged block
        try {
            File dir = new File(tempDir + "/app_temp");
            if (!dir.exists()) {
                dir.mkdirs();
            }
            
            // Create multiple files
            for (int i = 0; i < 5; i++) {
                File file = new File(dir, "file_" + i + ".dat");
                if (!file.exists()) {
                    file.createNewFile();
                    FileOutputStream fos = new FileOutputStream(file);
                    fos.write(("Data for file " + i).getBytes());
                    fos.close();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_10() {
        try {
            // Get system property in privileged block
            final String osName = AccessController.doPrivileged(
                new PrivilegedAction<String>() {
                    // ok: java-privileged-action
                    public String run() {
                        return System.getProperty("os.name");
                    }
                }
            );
            
            // Network operations outside privileged block
            URL url = new URL("https://example.com/api/stats");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            
            // Send OS info
            String data = "os=" + java.net.URLEncoder.encode(osName, "UTF-8");
            try (java.io.OutputStream out = conn.getOutputStream()) {
                out.write(data.getBytes());
            }
            
            // Read response
            int responseCode = conn.getResponseCode();
            System.out.println("Response code: " + responseCode);
            
            conn.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        // Get security policy location in privileged block
        final String policyPath = AccessController.doPrivileged(
            new PrivilegedAction<String>() {
                // ok: java-privileged-action
                public String run() {
                    return System.getProperty("java.security.policy");
                }
            }
        );
        
        // Security operations outside privileged block
        if (policyPath != null) {
            try {
                // Read policy file
                File policyFile = new File(policyPath);
                if (policyFile.exists()) {
                    byte[] policyData = Files.readAllBytes(policyFile.toPath());
                    String policyContent = new String(policyData);
                    
                    // Log policy information
                    System.out.println("Security policy loaded from: " + policyPath);
                    System.out.println("Policy size: " + policyData.length + " bytes");
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("No security policy specified");
        }
    }

    public void good_case_12() {
        // Get hostname in privileged block
        final String hostname = AccessController.doPrivileged(
            new PrivilegedExceptionAction<String>() {
                // ok: java-privileged-action
                @Override
                public String run() throws Exception {
                    Process process = Runtime.getRuntime().exec("hostname");
                    java.io.BufferedReader reader = new java.io.BufferedReader(
                        new java.io.InputStreamReader(process.getInputStream()));
                    String result = reader.readLine();
                    process.waitFor();
                    return result;
                }
            }
        );
        
        // Use hostname outside privileged block
        try {
            // Log hostname
            File logFile = new File("/tmp/hostname.log");
            FileOutputStream fos = new FileOutputStream(logFile);
            fos.write(("Current hostname: " + hostname + "\n").getBytes());
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        // Get class loader in privileged block
        final ClassLoader classLoader = AccessController.doPrivileged(
            new PrivilegedAction<ClassLoader>() {
                // ok: java-privileged-action
                public ClassLoader run() {
                    return Thread.currentThread().getContextClassLoader();
                }
            }
        );
        
        // Use class loader outside privileged block
        try {
            // Find resources
            java.util.Enumeration<URL> resources = classLoader.getResources("META-INF/services/");
            
            while (resources.hasMoreElements()) {
                URL url = resources.nextElement();
                System.out.println("Found service: " + url);
                
                // Process resources
                if ("file".equals(url.getProtocol())) {
                    File dir = new File(url.toURI());
                    File[] files = dir.listFiles();
                    if (files != null) {
                        for (File file : files) {
                            System.out.println("Service file: " + file.getName());
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_14() {
        // Get MBean server in privileged block
        final javax.management.MBeanServer mbs = AccessController.doPrivileged(
            new PrivilegedAction<javax.management.MBeanServer>() {
                // ok: java-privileged-action
                public javax.management.MBeanServer run() {
                    return java.lang.management.ManagementFactory.getPlatformMBeanServer();
                }
            }
        );
        
        // Use MBean server outside privileged block
        try {
            // Get memory information
            javax.management.ObjectName memoryName = new javax.management.ObjectName("java.lang:type=Memory");
            Object memoryUsage = mbs.getAttribute(memoryName, "HeapMemoryUsage");
            
            // Log memory information
            System.out.println("Memory usage: " + memoryUsage);
            
            // Get thread information
            javax.management.ObjectName threadName = new javax.management.ObjectName("java.lang:type=Threading");
            Integer threadCount = (Integer) mbs.getAttribute(threadName, "ThreadCount");
            
            System.out.println("Thread count: " + threadCount);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        // Get user information in privileged block
        final String[] userInfo = AccessController.doPrivileged(
            new PrivilegedAction<String[]>() {
                // ok: java-privileged-action
                public String[] run() {
                    return new String[] {
                        System.getProperty("user.name"),
                        System.getProperty("user.home"),
                        System.getProperty("os.name")
                    };
                }
            }
        );
        
        // Use user information outside privileged block
        String userName = userInfo[0];
        String userHome = userInfo[1];
        String osName = userInfo[2];
        
        try {
            // Create user-specific directories
            File dataDir = new File(userHome + "/app/data");
            File configDir = new File(userHome + "/app/config");
            File logsDir = new File(userHome + "/app/logs");
            
            dataDir.mkdirs();
            configDir.mkdirs();
            logsDir.mkdirs();
            
            // Create default configuration
            Properties defaultConfig = new Properties();
            defaultConfig.setProperty("user.name", userName);
            defaultConfig.setProperty("os.name", osName);
            defaultConfig.setProperty("app.version", "1.0.0");
            
            // Save configuration
            File configFile = new File(configDir, "app.properties");
            FileOutputStream fos = new FileOutputStream(configFile);
            defaultConfig.store(fos, "Default application configuration");
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
// {/fact}