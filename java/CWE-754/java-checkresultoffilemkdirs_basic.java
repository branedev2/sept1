import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.logging.Logger;

public class CheckResultOfFileMkdirs {
    private static final Logger logger = Logger.getLogger(CheckResultOfFileMkdirs.class.getName());

    // True Positives (Vulnerable Code)

// {fact rule=missing-check-on-method-output@v1.0 defects=1}
    public void bad_case_1() {
        File directory = new File("/tmp/myapp/logs");
        // ruleid: java-checkresultoffilemkdirs
        directory.mkdirs();
        File logFile = new File(directory, "app.log");
        try {
            logFile.createNewFile();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        String path = System.getProperty("user.home") + "/data/uploads";
        File uploadDir = new File(path);
        // ruleid: java-checkresultoffilemkdirs
        uploadDir.mkdirs();
        System.out.println("Upload directory prepared at: " + path);
    }

    public void bad_case_3() {
        try {
            File configDir = new File("/etc/myapp/config");
            // ruleid: java-checkresultoffilemkdirs
            configDir.mkdirs();
            writeConfigFile(configDir);
        } catch (Exception e) {
            System.err.println("Error writing config: " + e.getMessage());
        }
    }

    public void bad_case_4() {
        String timestamp = String.valueOf(System.currentTimeMillis());
        File backupDir = new File("/var/backups/" + timestamp);
        // ruleid: java-checkresultoffilemkdirs
        backupDir.mkdirs();
        performBackup(backupDir);
    }

    public void bad_case_5() {
        for (String userId : getUserIds()) {
            File userDir = new File("/home/app/users/" + userId);
            // ruleid: java-checkresultoffilemkdirs
            userDir.mkdirs();
            createUserFiles(userDir, userId);
        }
    }

    public void bad_case_6() {
        String projectName = getProjectName();
        File projectDir = new File("/var/www/html/" + projectName);
        // ruleid: java-checkresultoffilemkdirs
        projectDir.mkdirs();
        deployProject(projectDir);
    }

    public void bad_case_7() {
        try {
            String reportPath = "/tmp/reports/" + generateReportId();
            File reportDir = new File(reportPath);
            // ruleid: java-checkresultoffilemkdirs
            reportDir.mkdirs();
            generateReport(reportDir);
        } catch (Exception e) {
            logger.severe("Failed to generate report: " + e.getMessage());
        }
    }

    public void bad_case_8() {
        File tempDir = new File(System.getProperty("java.io.tmpdir") + "/app_temp");
        // ruleid: java-checkresultoffilemkdirs
        tempDir.mkdirs();
        processTempFiles(tempDir);
    }

    public void bad_case_9() {
        String cachePath = getCachePath();
        File cacheDir = new File(cachePath);
        // ruleid: java-checkresultoffilemkdirs
        cacheDir.mkdirs();
        initializeCache(cacheDir);
    }

    public void bad_case_10() {
        File logsDir = new File("./logs");
        // ruleid: java-checkresultoffilemkdirs
        logsDir.mkdirs();
        setupLogging(logsDir);
    }

    public void bad_case_11() {
        String outputPath = getOutputPath();
        if (outputPath != null) {
            File outputDir = new File(outputPath);
            // ruleid: java-checkresultoffilemkdirs
            outputDir.mkdirs();
            saveOutput(outputDir);
        }
    }

    public void bad_case_12() {
        try {
            String dataDir = System.getProperty("user.dir") + "/data";
            File directory = new File(dataDir);
            // ruleid: java-checkresultoffilemkdirs
            directory.mkdirs();
            storeData(directory);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        String sessionId = getSessionId();
        File sessionDir = new File("/tmp/sessions/" + sessionId);
        // ruleid: java-checkresultoffilemkdirs
        sessionDir.mkdirs();
        saveSessionData(sessionDir, sessionId);
    }

    public void bad_case_14() {
        for (int i = 0; i < 10; i++) {
            File partitionDir = new File("/data/partitions/part_" + i);
            // ruleid: java-checkresultoffilemkdirs
            partitionDir.mkdirs();
            processPartition(partitionDir, i);
        }
    }

    public void bad_case_15() {
        String username = getCurrentUsername();
        if (username != null && !username.isEmpty()) {
            File userHomeDir = new File("/home/" + username);
            // ruleid: java-checkresultoffilemkdirs
            userHomeDir.mkdirs();
            setupUserEnvironment(userHomeDir, username);
        }
    }

    // True Negatives (Safe Code)

    public void good_case_1() {
        File directory = new File("/tmp/myapp/logs");
        // ok: java-checkresultoffilemkdirs
        if (directory.mkdirs()) {
            File logFile = new File(directory, "app.log");
            try {
                logFile.createNewFile();
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            System.err.println("Failed to create log directory");
        }
    }

    public void good_case_2() {
        String path = System.getProperty("user.home") + "/data/uploads";
        File uploadDir = new File(path);
        // ok: java-checkresultoffilemkdirs
        boolean created = uploadDir.mkdirs();
        if (created || uploadDir.exists()) {
            System.out.println("Upload directory prepared at: " + path);
        } else {
            System.err.println("Could not create upload directory");
        }
    }

    public void good_case_3() {
        try {
            File configDir = new File("/etc/myapp/config");
            // ok: java-checkresultoffilemkdirs
            if (!configDir.mkdirs() && !configDir.exists()) {
                throw new IOException("Failed to create config directory");
            }
            writeConfigFile(configDir);
        } catch (Exception e) {
            System.err.println("Error writing config: " + e.getMessage());
        }
    }

    public void good_case_4() {
        String timestamp = String.valueOf(System.currentTimeMillis());
        File backupDir = new File("/var/backups/" + timestamp);
        // ok: java-checkresultoffilemkdirs
        boolean success = backupDir.mkdirs();
        if (success) {
            performBackup(backupDir);
        } else {
            logger.warning("Failed to create backup directory");
        }
    }

    public void good_case_5() {
        for (String userId : getUserIds()) {
            File userDir = new File("/home/app/users/" + userId);
            // ok: java-checkresultoffilemkdirs
            if (userDir.mkdirs() || userDir.exists()) {
                createUserFiles(userDir, userId);
            } else {
                logger.warning("Could not create directory for user: " + userId);
            }
        }
    }

    public void good_case_6() {
        String projectName = getProjectName();
        File projectDir = new File("/var/www/html/" + projectName);
        // ok: java-checkresultoffilemkdirs
        boolean dirCreated = projectDir.mkdirs();
        if (dirCreated || projectDir.isDirectory()) {
            deployProject(projectDir);
        } else {
            throw new RuntimeException("Failed to create project directory");
        }
    }

    public void good_case_7() {
        try {
            String reportPath = "/tmp/reports/" + generateReportId();
            File reportDir = new File(reportPath);
            // ok: java-checkresultoffilemkdirs
            if (!reportDir.mkdirs()) {
                if (!reportDir.exists()) {
                    throw new IOException("Could not create report directory");
                }
            }
            generateReport(reportDir);
        } catch (Exception e) {
            logger.severe("Failed to generate report: " + e.getMessage());
        }
    }

    public void good_case_8() {
        File tempDir = new File(System.getProperty("java.io.tmpdir") + "/app_temp");
        // ok: java-checkresultoffilemkdirs
        boolean result = tempDir.mkdirs();
        logger.info("Temp directory creation " + (result ? "successful" : "failed or already exists"));
        if (tempDir.isDirectory()) {
            processTempFiles(tempDir);
        }
    }

    public void good_case_9() {
        String cachePath = getCachePath();
        File cacheDir = new File(cachePath);
        // ok: java-checkresultoffilemkdirs
        boolean created = cacheDir.mkdirs();
        if (!created && !cacheDir.exists()) {
            logger.severe("Failed to create cache directory");
            return;
        }
        initializeCache(cacheDir);
    }

    public void good_case_10() {
        File logsDir = new File("./logs");
        // ok: java-checkresultoffilemkdirs
        if (logsDir.mkdirs() || logsDir.exists()) {
            setupLogging(logsDir);
        } else {
            logger.warning("Could not set up logging directory");
        }
    }

    public void good_case_11() {
        try {
            String outputPath = getOutputPath();
            if (outputPath != null) {
                File outputDir = new File(outputPath);
                // ok: java-checkresultoffilemkdirs
                boolean success = outputDir.mkdirs();
                if (!success && !outputDir.exists()) {
                    throw new IOException("Failed to create output directory");
                }
                saveOutput(outputDir);
            }
        } catch (IOException e) {
            logger.severe("Error creating output: " + e.getMessage());
        }
    }

    public void good_case_12() {
        try {
            String dataDir = System.getProperty("user.dir") + "/data";
            File directory = new File(dataDir);
            // ok: java-checkresultoffilemkdirs
            boolean created = directory.mkdirs();
            if (created || directory.isDirectory()) {
                storeData(directory);
            } else {
                logger.severe("Could not create data directory");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        String sessionId = getSessionId();
        File sessionDir = new File("/tmp/sessions/" + sessionId);
        // ok: java-checkresultoffilemkdirs
        boolean dirCreated = sessionDir.mkdirs();
        if (dirCreated) {
            logger.info("Created new session directory");
            saveSessionData(sessionDir, sessionId);
        } else if (sessionDir.exists()) {
            logger.info("Using existing session directory");
            saveSessionData(sessionDir, sessionId);
        } else {
            logger.severe("Failed to create session directory");
        }
    }

    public void good_case_14() {
        try {
            for (int i = 0; i < 10; i++) {
                File partitionDir = new File("/data/partitions/part_" + i);
                // ok: java-checkresultoffilemkdirs
                if (!partitionDir.mkdirs() && !partitionDir.exists()) {
                    throw new IOException("Failed to create partition directory: " + i);
                }
                processPartition(partitionDir, i);
            }
        } catch (IOException e) {
            logger.severe("Partition processing failed: " + e.getMessage());
        }
    }

    public void good_case_15() {
        String username = getCurrentUsername();
        if (username != null && !username.isEmpty()) {
            File userHomeDir = new File("/home/" + username);
            // ok: java-checkresultoffilemkdirs
            boolean success = userHomeDir.mkdirs();
            if (success) {
                setupUserEnvironment(userHomeDir, username);
            } else {
                if (userHomeDir.exists()) {
                    logger.info("User directory already exists, continuing setup");
                    setupUserEnvironment(userHomeDir, username);
                } else {
                    logger.severe("Failed to create user home directory");
                }
            }
        }
    }

    // Helper methods to make the examples work
    private void writeConfigFile(File configDir) {}
    private void performBackup(File backupDir) {}
    private String[] getUserIds() { return new String[]{"user1", "user2"}; }
    private void createUserFiles(File userDir, String userId) {}
    private String getProjectName() { return "project1"; }
    private void deployProject(File projectDir) {}
    private String generateReportId() { return "report_" + System.currentTimeMillis(); }
    private void generateReport(File reportDir) {}
    private void processTempFiles(File tempDir) {}
    private String getCachePath() { return "/tmp/cache"; }
    private void initializeCache(File cacheDir) {}
    private void setupLogging(File logsDir) {}
    private String getOutputPath() { return "/tmp/output"; }
    private void saveOutput(File outputDir) {}
    private void storeData(File directory) {}
    private String getSessionId() { return "session_" + System.currentTimeMillis(); }
    private void saveSessionData(File sessionDir, String sessionId) {}
    private void processPartition(File partitionDir, int partitionNumber) {}
    private String getCurrentUsername() { return "testuser"; }
    private void setupUserEnvironment(File userHomeDir, String username) {}
}
// {/fact}