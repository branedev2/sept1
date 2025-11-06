import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.logging.Logger;
import java.util.logging.Level;

public class FileMkdirExamples {
    private static final Logger logger = Logger.getLogger(FileMkdirExamples.class.getName());
    
    // True Positives (Vulnerable Code)
    
// {fact rule=missing-check-on-method-output@v1.0 defects=1}
    public void bad_case_1() {
        File directory = new File("/tmp/app_data");
        // ruleid: java-checkresultoffilemkdir
        directory.mkdir();
        // The result of mkdir() is not checked, which could lead to issues if directory creation fails
        File configFile = new File(directory, "config.txt");
        try {
            configFile.createNewFile();
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Failed to create config file", e);
        }
    }
    
    public void bad_case_2() {
        String userDataPath = System.getProperty("user.home") + "/app_data";
        File userDir = new File(userDataPath);
        // ruleid: java-checkresultoffilemkdir
        userDir.mkdir();
        // No check if directory was created successfully
        System.out.println("User directory created at: " + userDataPath);
    }
    
    public void bad_case_3() {
        try {
            File tempDir = new File("/var/tmp/app_logs");
            // ruleid: java-checkresultoffilemkdir
            tempDir.mkdir();
            // Proceeds without checking if directory creation was successful
            writeLogFile(tempDir);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_4() {
        File baseDir = new File("/opt/application");
        File configDir = new File(baseDir, "config");
        // ruleid: java-checkresultoffilemkdir
        configDir.mkdir();
        // No verification of directory creation
        saveConfiguration(configDir);
    }
    
    public void bad_case_5() {
        String path = "/usr/local/share/data";
        File dataDir = new File(path);
        // ruleid: java-checkresultoffilemkdir
        dataDir.mkdir();
        // Assumes directory was created without checking
        for (int i = 0; i < 5; i++) {
            File subDir = new File(dataDir, "partition_" + i);
            subDir.mkdir(); // Also unchecked, but we're focusing on the first occurrence
        }
    }
    
    public void bad_case_6() {
        File projectDir = new File("./project");
        // ruleid: java-checkresultoffilemkdir
        projectDir.mkdir();
        // Directory creation result not checked in a loop
        String[] subdirs = {"src", "test", "docs", "lib"};
        for (String dir : subdirs) {
            new File(projectDir, dir).mkdir(); // Also unchecked
        }
    }
    
    public void bad_case_7() {
        try {
            String timestamp = String.valueOf(System.currentTimeMillis());
            File backupDir = new File("/backups/" + timestamp);
            // ruleid: java-checkresultoffilemkdir
            backupDir.mkdir();
            // No check before proceeding with backup operation
            performBackup(backupDir);
        } catch (Exception e) {
            logger.severe("Backup failed: " + e.getMessage());
        }
    }
    
    public void bad_case_8() {
        File cacheDir = new File(System.getProperty("java.io.tmpdir"), "cache");
        // ruleid: java-checkresultoffilemkdir
        cacheDir.mkdir();
        // Proceeds with cache operations without checking if directory exists
        initializeCache(cacheDir);
    }
    
    public void bad_case_9() {
        String username = System.getProperty("user.name");
        File userProfileDir = new File("/var/users/" + username);
        // ruleid: java-checkresultoffilemkdir
        userProfileDir.mkdir();
        // No verification before writing user profile data
        try {
            Files.write(Paths.get(userProfileDir.getPath(), "profile.json"), 
                       "{\"name\":\"" + username + "\"}".getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_10() {
        File uploadDir = new File("/var/www/uploads");
        // ruleid: java-checkresultoffilemkdir
        uploadDir.mkdir();
        // Assumes directory creation succeeded in a conditional block
        if (uploadDir.exists()) {
            System.out.println("Upload directory is ready");
        } else {
            System.out.println("Failed to create upload directory");
        }
    }
    
    public void bad_case_11() {
        String dirPath = "/opt/app/data";
        File dataDir = new File(dirPath);
        // ruleid: java-checkresultoffilemkdir
        dataDir.mkdir();
        // Tries to use the directory without checking creation result
        try {
            if (dataDir.canWrite()) {
                System.out.println("Directory is writable");
            }
        } catch (SecurityException e) {
            System.err.println("Security exception: " + e.getMessage());
        }
    }
    
    public void bad_case_12() {
        File logsDir = new File("/var/log/myapp");
        // ruleid: java-checkresultoffilemkdir
        logsDir.mkdir();
        // No check before setting permissions
        try {
            logsDir.setReadable(true, false);
            logsDir.setWritable(true, true);
            logsDir.setExecutable(true, false);
        } catch (SecurityException e) {
            logger.log(Level.WARNING, "Failed to set permissions", e);
        }
    }
    
    public void bad_case_13() {
        try {
            File reportsDir = new File("./reports");
            // ruleid: java-checkresultoffilemkdir
            reportsDir.mkdir();
            // Proceeds with report generation without checking directory creation
            generateReports(reportsDir);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Report generation failed", e);
        }
    }
    
    public void bad_case_14() {
        String path = System.getProperty("user.home") + "/downloads";
        File downloadsDir = new File(path);
        // ruleid: java-checkresultoffilemkdir
        downloadsDir.mkdir();
        // No check before creating a file in the directory
        File downloadFile = new File(downloadsDir, "downloaded_file.zip");
        try {
            downloadFile.createNewFile();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public void bad_case_15() {
        File tempDir = new File(System.getProperty("java.io.tmpdir"), "temp_" + System.currentTimeMillis());
        // ruleid: java-checkresultoffilemkdir
        tempDir.mkdir();
        // Uses the directory without checking if it was created
        System.out.println("Temporary directory created at: " + tempDir.getAbsolutePath());
        // Attempt to use the directory
        File tempFile = new File(tempDir, "temp.dat");
    }
    
    // True Negatives (Safe Code)
    
    public void good_case_1() {
        File directory = new File("/tmp/app_data");
        // ok: java-checkresultoffilemkdir
        boolean created = directory.mkdir();
        if (created) {
            File configFile = new File(directory, "config.txt");
            try {
                configFile.createNewFile();
            } catch (IOException e) {
                logger.log(Level.SEVERE, "Failed to create config file", e);
            }
        } else {
            logger.log(Level.WARNING, "Failed to create directory: " + directory.getAbsolutePath());
        }
    }
    
    public void good_case_2() {
        String userDataPath = System.getProperty("user.home") + "/app_data";
        File userDir = new File(userDataPath);
        // ok: java-checkresultoffilemkdir
        if (userDir.mkdir()) {
            System.out.println("User directory created at: " + userDataPath);
        } else {
            System.out.println("Failed to create user directory at: " + userDataPath);
        }
    }
    
    public void good_case_3() {
        try {
            File tempDir = new File("/var/tmp/app_logs");
            // ok: java-checkresultoffilemkdir
            if (!tempDir.mkdir() && !tempDir.exists()) {
                throw new IOException("Failed to create directory: " + tempDir.getAbsolutePath());
            }
            writeLogFile(tempDir);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void good_case_4() {
        File baseDir = new File("/opt/application");
        File configDir = new File(baseDir, "config");
        // ok: java-checkresultoffilemkdir
        boolean dirCreated = configDir.mkdir();
        if (dirCreated || configDir.exists()) {
            saveConfiguration(configDir);
        } else {
            logger.log(Level.SEVERE, "Could not create or access config directory");
        }
    }
    
    public void good_case_5() {
        String path = "/usr/local/share/data";
        File dataDir = new File(path);
        // ok: java-checkresultoffilemkdir
        boolean success = dataDir.mkdir();
        if (success) {
            for (int i = 0; i < 5; i++) {
                File subDir = new File(dataDir, "partition_" + i);
                if (!subDir.mkdir()) {
                    logger.warning("Failed to create partition directory: " + i);
                }
            }
        } else {
            logger.severe("Failed to create data directory");
        }
    }
    
    public void good_case_6() {
        File projectDir = new File("./project");
        // ok: java-checkresultoffilemkdir
        if (projectDir.mkdir() || projectDir.exists()) {
            String[] subdirs = {"src", "test", "docs", "lib"};
            for (String dir : subdirs) {
                File subDir = new File(projectDir, dir);
                if (!subDir.mkdir() && !subDir.exists()) {
                    logger.warning("Failed to create subdirectory: " + dir);
                }
            }
        } else {
            logger.severe("Failed to create project directory");
        }
    }
    
    public void good_case_7() {
        try {
            String timestamp = String.valueOf(System.currentTimeMillis());
            File backupDir = new File("/backups/" + timestamp);
            // ok: java-checkresultoffilemkdir
            boolean created = backupDir.mkdir();
            if (created) {
                performBackup(backupDir);
            } else {
                logger.severe("Failed to create backup directory");
            }
        } catch (Exception e) {
            logger.severe("Backup failed: " + e.getMessage());
        }
    }
    
    public void good_case_8() {
        File cacheDir = new File(System.getProperty("java.io.tmpdir"), "cache");
        // ok: java-checkresultoffilemkdir
        if (cacheDir.mkdir() || cacheDir.exists()) {
            initializeCache(cacheDir);
        } else {
            logger.warning("Could not create cache directory, using in-memory cache instead");
            initializeInMemoryCache();
        }
    }
    
    public void good_case_9() {
        String username = System.getProperty("user.name");
        File userProfileDir = new File("/var/users/" + username);
        // ok: java-checkresultoffilemkdir
        boolean dirCreated = userProfileDir.mkdir();
        if (dirCreated || userProfileDir.exists()) {
            try {
                Files.write(Paths.get(userProfileDir.getPath(), "profile.json"), 
                           "{\"name\":\"" + username + "\"}".getBytes());
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            logger.severe("Failed to create user profile directory");
        }
    }
    
    public void good_case_10() {
        File uploadDir = new File("/var/www/uploads");
        // ok: java-checkresultoffilemkdir
        boolean created = uploadDir.mkdir();
        if (created) {
            System.out.println("Upload directory created successfully");
        } else if (uploadDir.exists()) {
            System.out.println("Upload directory already exists");
        } else {
            System.out.println("Failed to create upload directory");
        }
    }
    
    public void good_case_11() {
        String dirPath = "/opt/app/data";
        File dataDir = new File(dirPath);
        // ok: java-checkresultoffilemkdir
        boolean success = dataDir.mkdir();
        if (success) {
            try {
                if (dataDir.canWrite()) {
                    System.out.println("Directory is writable");
                }
            } catch (SecurityException e) {
                System.err.println("Security exception: " + e.getMessage());
            }
        } else {
            System.err.println("Failed to create directory: " + dirPath);
        }
    }
    
    public void good_case_12() {
        File logsDir = new File("/var/log/myapp");
        // ok: java-checkresultoffilemkdir
        if (logsDir.mkdir() || logsDir.exists()) {
            try {
                logsDir.setReadable(true, false);
                logsDir.setWritable(true, true);
                logsDir.setExecutable(true, false);
            } catch (SecurityException e) {
                logger.log(Level.WARNING, "Failed to set permissions", e);
            }
        } else {
            logger.log(Level.SEVERE, "Failed to create logs directory");
        }
    }
    
    public void good_case_13() {
        try {
            File reportsDir = new File("./reports");
            // ok: java-checkresultoffilemkdir
            boolean created = reportsDir.mkdir();
            if (created || reportsDir.exists()) {
                generateReports(reportsDir);
            } else {
                throw new IOException("Failed to create reports directory");
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Report generation failed", e);
        }
    }
    
    public void good_case_14() {
        String path = System.getProperty("user.home") + "/downloads";
        File downloadsDir = new File(path);
        // ok: java-checkresultoffilemkdir
        if (downloadsDir.mkdir() || downloadsDir.exists()) {
            File downloadFile = new File(downloadsDir, "downloaded_file.zip");
            try {
                downloadFile.createNewFile();
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            logger.severe("Failed to create downloads directory");
        }
    }
    
    public void good_case_15() {
        File tempDir = new File(System.getProperty("java.io.tmpdir"), "temp_" + System.currentTimeMillis());
        // ok: java-checkresultoffilemkdir
        boolean created = tempDir.mkdir();
        if (created) {
            System.out.println("Temporary directory created at: " + tempDir.getAbsolutePath());
            // Use the directory now that we know it was created
            File tempFile = new File(tempDir, "temp.dat");
        } else {
            System.err.println("Failed to create temporary directory");
        }
    }
    
    // Helper methods to support the examples
    
    private void writeLogFile(File directory) throws IOException {
        File logFile = new File(directory, "app.log");
        logFile.createNewFile();
        // Write log content
    }
    
    private void saveConfiguration(File configDir) {
        // Save configuration to the directory
        System.out.println("Saving configuration to: " + configDir.getAbsolutePath());
    }
    
    private void performBackup(File backupDir) {
        // Perform backup operation
        System.out.println("Backing up to: " + backupDir.getAbsolutePath());
    }
    
    private void initializeCache(File cacheDir) {
        // Initialize cache in the specified directory
        System.out.println("Initializing cache in: " + cacheDir.getAbsolutePath());
    }
    
    private void initializeInMemoryCache() {
        // Initialize in-memory cache as fallback
        System.out.println("Initializing in-memory cache");
    }
    
    private void generateReports(File reportsDir) {
        // Generate reports in the specified directory
        System.out.println("Generating reports in: " + reportsDir.getAbsolutePath());
    }
}
// {/fact}