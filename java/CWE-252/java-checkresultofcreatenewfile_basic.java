import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.logging.Logger;

public class CheckResultOfCreateNewFileExamples {
    private static final Logger logger = Logger.getLogger(CheckResultOfCreateNewFileExamples.class.getName());

    // True Positive Examples (Vulnerable Code)

// {fact rule=check-result-of-file-mkdir@v1.0 defects=1}
    public void bad_case_1() {
        try {
            File file = new File("important_data.txt");
            // ruleid: java-checkresultofcreatenewfile
            file.createNewFile();
            // No check of the return value, might silently fail if file exists
            writeDataToFile(file);
        } catch (IOException e) {
            logger.severe("Error creating file: " + e.getMessage());
        }
    }

    public void bad_case_2() {
        try {
            File configFile = new File("/etc/app/config.properties");
            // ruleid: java-checkresultofcreatenewfile
            configFile.createNewFile();
            // Proceeds without checking if file was actually created
            writeConfigData(configFile);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() {
        File logFile = new File("application.log");
        try {
            // ruleid: java-checkresultofcreatenewfile
            logFile.createNewFile();
            // Ignores whether the file was created or already existed
            appendToLog(logFile, "Application started");
        } catch (IOException e) {
            System.err.println("Failed to create log file: " + e.getMessage());
        }
    }

    public void bad_case_4() {
        try {
            String filename = generateUniqueFilename();
            File tempFile = new File(filename);
            // ruleid: java-checkresultofcreatenewfile
            tempFile.createNewFile();
            // No verification if file creation succeeded
            storeSensitiveData(tempFile);
        } catch (IOException e) {
            logger.warning("Exception occurred: " + e.getMessage());
        }
    }

    public void bad_case_5() {
        File dataDir = new File("data");
        if (!dataDir.exists()) {
            dataDir.mkdir();
        }
        
        try {
            File dataFile = new File(dataDir, "user_data.dat");
            // ruleid: java-checkresultofcreatenewfile
            dataFile.createNewFile();
            // No check if file was created successfully
            writeUserData(dataFile);
        } catch (IOException e) {
            logger.severe("Failed to create data file: " + e.getMessage());
        }
    }

    public void bad_case_6() {
        try {
            for (int i = 0; i < 10; i++) {
                File file = new File("batch_" + i + ".txt");
                // ruleid: java-checkresultofcreatenewfile
                file.createNewFile();
                // No verification in a loop
                processBatchFile(file, i);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        File file = null;
        try {
            file = File.createTempFile("temp", ".tmp");
            File permanentFile = new File("permanent_" + System.currentTimeMillis() + ".dat");
            // ruleid: java-checkresultofcreatenewfile
            permanentFile.createNewFile();
            // No check if permanent file was created
            copyData(file, permanentFile);
        } catch (IOException e) {
            logger.severe("Error in file operations: " + e.getMessage());
        }
    }

    public void bad_case_8() {
        try {
            String baseDir = System.getProperty("user.home");
            File customDir = new File(baseDir + "/app_data");
            customDir.mkdirs();
            
            File settingsFile = new File(customDir, "settings.json");
            // ruleid: java-checkresultofcreatenewfile
            settingsFile.createNewFile();
            // No verification of successful file creation
            saveSettings(settingsFile);
        } catch (IOException e) {
            logger.severe("Failed to initialize settings: " + e.getMessage());
        }
    }

    public void bad_case_9() {
        try {
            String timestamp = String.valueOf(System.currentTimeMillis());
            File backupFile = new File("backup_" + timestamp + ".bak");
            // ruleid: java-checkresultofcreatenewfile
            backupFile.createNewFile();
            // No check if backup file was created
            performBackup(backupFile);
        } catch (IOException e) {
            logger.warning("Backup operation failed: " + e.getMessage());
        }
    }

    public void bad_case_10() {
        File[] files = new File[3];
        files[0] = new File("data1.txt");
        files[1] = new File("data2.txt");
        files[2] = new File("data3.txt");
        
        try {
            for (File file : files) {
                // ruleid: java-checkresultofcreatenewfile
                file.createNewFile();
                // No check in array iteration
                writeToFile(file, "Data for " + file.getName());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        try {
            File lockFile = new File(".lock");
            // ruleid: java-checkresultofcreatenewfile
            lockFile.createNewFile();
            // No verification if lock was acquired
            performCriticalOperation();
            lockFile.delete();
        } catch (IOException e) {
            logger.severe("Failed to create lock: " + e.getMessage());
        }
    }

    public void bad_case_12() {
        try {
            String fileName = getUserInput();
            File userFile = new File(fileName);
            // ruleid: java-checkresultofcreatenewfile
            userFile.createNewFile();
            // No check with user-provided filename
            writeUserContent(userFile);
        } catch (IOException e) {
            System.err.println("Error with user file: " + e.getMessage());
        }
    }

    public void bad_case_13() {
        try {
            if (isAdminUser()) {
                File adminFile = new File("admin_settings.cfg");
                // ruleid: java-checkresultofcreatenewfile
                adminFile.createNewFile();
                // No check in conditional block
                writeAdminSettings(adminFile);
            }
        } catch (IOException e) {
            logger.severe("Admin settings error: " + e.getMessage());
        }
    }

    public void bad_case_14() {
        Thread fileCreator = new Thread(() -> {
            try {
                File threadFile = new File("thread_data.txt");
                // ruleid: java-checkresultofcreatenewfile
                threadFile.createNewFile();
                // No check in a separate thread
                writeThreadData(threadFile);
            } catch (IOException e) {
                logger.severe("Thread file error: " + e.getMessage());
            }
        });
        fileCreator.start();
    }

    public void bad_case_15() {
        try {
            File parentDir = new File("parent");
            parentDir.mkdir();
            
            File childFile = new File(parentDir, "child.txt");
            // ruleid: java-checkresultofcreatenewfile
            childFile.createNewFile();
            // No verification after parent directory creation
            writeNestedData(childFile);
        } catch (IOException e) {
            logger.severe("Nested file error: " + e.getMessage());
        }
    }

    // True Negative Examples (Secure Code)

    public void good_case_1() {
        try {
            File file = new File("important_data.txt");
            // ok: java-checkresultofcreatenewfile
            boolean created = file.createNewFile();
            if (created) {
                writeDataToFile(file);
            } else {
                logger.warning("File already exists, not overwriting");
            }
        } catch (IOException e) {
            logger.severe("Error creating file: " + e.getMessage());
        }
    }

    public void good_case_2() {
        try {
            File configFile = new File("/etc/app/config.properties");
            // ok: java-checkresultofcreatenewfile
            if (!configFile.exists()) {
                configFile.createNewFile();
                writeConfigData(configFile);
            } else {
                logger.info("Using existing config file");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        File logFile = new File("application.log");
        try {
            // ok: java-checkresultofcreatenewfile
            if (logFile.createNewFile()) {
                logger.info("Created new log file");
            } else {
                logger.info("Using existing log file");
            }
            appendToLog(logFile, "Application started");
        } catch (IOException e) {
            System.err.println("Failed to create log file: " + e.getMessage());
        }
    }

    public void good_case_4() {
        try {
            String filename = generateUniqueFilename();
            File tempFile = new File(filename);
            // ok: java-checkresultofcreatenewfile
            if (tempFile.exists() || !tempFile.createNewFile()) {
                logger.warning("Could not create a unique file");
                return;
            }
            storeSensitiveData(tempFile);
        } catch (IOException e) {
            logger.warning("Exception occurred: " + e.getMessage());
        }
    }

    public void good_case_5() {
        File dataDir = new File("data");
        if (!dataDir.exists()) {
            dataDir.mkdir();
        }
        
        try {
            File dataFile = new File(dataDir, "user_data.dat");
            // ok: java-checkresultofcreatenewfile
            boolean fileCreated = dataFile.createNewFile();
            if (fileCreated) {
                writeUserData(dataFile);
            } else {
                logger.info("User data file already exists");
                updateUserData(dataFile);
            }
        } catch (IOException e) {
            logger.severe("Failed to create data file: " + e.getMessage());
        }
    }

    public void good_case_6() {
        try {
            for (int i = 0; i < 10; i++) {
                File file = new File("batch_" + i + ".txt");
                // ok: java-checkresultofcreatenewfile
                boolean created = file.createNewFile();
                if (created) {
                    processBatchFile(file, i);
                } else {
                    logger.info("Batch file " + i + " already exists, skipping");
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        File file = null;
        try {
            file = File.createTempFile("temp", ".tmp");
            File permanentFile = new File("permanent_" + System.currentTimeMillis() + ".dat");
            // ok: java-checkresultofcreatenewfile
            if (permanentFile.createNewFile()) {
                copyData(file, permanentFile);
            } else {
                logger.warning("Could not create permanent file");
            }
        } catch (IOException e) {
            logger.severe("Error in file operations: " + e.getMessage());
        }
    }

    public void good_case_8() {
        try {
            String baseDir = System.getProperty("user.home");
            File customDir = new File(baseDir + "/app_data");
            customDir.mkdirs();
            
            File settingsFile = new File(customDir, "settings.json");
            // ok: java-checkresultofcreatenewfile
            if (!settingsFile.exists()) {
                if (settingsFile.createNewFile()) {
                    saveSettings(settingsFile);
                } else {
                    logger.warning("Failed to create settings file");
                }
            } else {
                loadExistingSettings(settingsFile);
            }
        } catch (IOException e) {
            logger.severe("Failed to initialize settings: " + e.getMessage());
        }
    }

    public void good_case_9() {
        try {
            String timestamp = String.valueOf(System.currentTimeMillis());
            File backupFile = new File("backup_" + timestamp + ".bak");
            // ok: java-checkresultofcreatenewfile
            boolean backupCreated = backupFile.createNewFile();
            if (backupCreated) {
                performBackup(backupFile);
            } else {
                logger.warning("Backup file already exists with timestamp: " + timestamp);
                generateAlternativeBackup();
            }
        } catch (IOException e) {
            logger.warning("Backup operation failed: " + e.getMessage());
        }
    }

    public void good_case_10() {
        File[] files = new File[3];
        files[0] = new File("data1.txt");
        files[1] = new File("data2.txt");
        files[2] = new File("data3.txt");
        
        try {
            for (File file : files) {
                // ok: java-checkresultofcreatenewfile
                if (file.createNewFile()) {
                    writeToFile(file, "Data for " + file.getName());
                } else {
                    logger.info("File " + file.getName() + " already exists");
                    appendToFile(file, "Additional data");
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        try {
            File lockFile = new File(".lock");
            // ok: java-checkresultofcreatenewfile
            boolean lockAcquired = lockFile.createNewFile();
            if (lockAcquired) {
                try {
                    performCriticalOperation();
                } finally {
                    lockFile.delete();
                }
            } else {
                logger.warning("Another process holds the lock, waiting...");
                waitForLockRelease();
            }
        } catch (IOException e) {
            logger.severe("Failed to create lock: " + e.getMessage());
        }
    }

    public void good_case_12() {
        try {
            String fileName = getUserInput();
            File userFile = new File(fileName);
            // ok: java-checkresultofcreatenewfile
            if (userFile.exists()) {
                logger.info("File already exists: " + fileName);
                handleExistingFile(userFile);
            } else if (userFile.createNewFile()) {
                writeUserContent(userFile);
            } else {
                logger.warning("Failed to create file: " + fileName);
            }
        } catch (IOException e) {
            System.err.println("Error with user file: " + e.getMessage());
        }
    }

    public void good_case_13() {
        try {
            if (isAdminUser()) {
                File adminFile = new File("admin_settings.cfg");
                // ok: java-checkresultofcreatenewfile
                boolean created = adminFile.createNewFile();
                if (created) {
                    writeAdminSettings(adminFile);
                    logger.info("Created new admin settings file");
                } else {
                    logger.info("Admin settings file already exists");
                    updateAdminSettings(adminFile);
                }
            }
        } catch (IOException e) {
            logger.severe("Admin settings error: " + e.getMessage());
        }
    }

    public void good_case_14() {
        Thread fileCreator = new Thread(() -> {
            try {
                File threadFile = new File("thread_data.txt");
                // ok: java-checkresultofcreatenewfile
                boolean success = threadFile.createNewFile();
                if (success) {
                    writeThreadData(threadFile);
                } else {
                    logger.info("Thread data file already exists");
                    synchronized(this) {
                        updateThreadData(threadFile);
                    }
                }
            } catch (IOException e) {
                logger.severe("Thread file error: " + e.getMessage());
            }
        });
        fileCreator.start();
    }

    public void good_case_15() {
        try {
            File parentDir = new File("parent");
            if (!parentDir.exists() && !parentDir.mkdir()) {
                logger.severe("Failed to create parent directory");
                return;
            }
            
            File childFile = new File(parentDir, "child.txt");
            // ok: java-checkresultofcreatenewfile
            if (childFile.exists() || childFile.createNewFile()) {
                writeNestedData(childFile);
            } else {
                logger.severe("Failed to create or access child file");
            }
        } catch (IOException e) {
            logger.severe("Nested file error: " + e.getMessage());
        }
    }

    // Helper methods (implementations not important for the examples)
    private void writeDataToFile(File file) {}
    private void writeConfigData(File file) {}
    private void appendToLog(File file, String message) {}
    private String generateUniqueFilename() { return "unique_" + System.currentTimeMillis(); }
    private void storeSensitiveData(File file) {}
    private void writeUserData(File file) {}
    private void updateUserData(File file) {}
    private void processBatchFile(File file, int batchNumber) {}
    private void copyData(File source, File destination) {}
    private void saveSettings(File file) {}
    private void loadExistingSettings(File file) {}
    private void performBackup(File file) {}
    private void generateAlternativeBackup() {}
    private void writeToFile(File file, String content) {}
    private void appendToFile(File file, String content) {}
    private void performCriticalOperation() {}
    private void waitForLockRelease() {}
    private String getUserInput() { return "user_input.txt"; }
    private void writeUserContent(File file) {}
    private void handleExistingFile(File file) {}
    private boolean isAdminUser() { return false; }
    private void writeAdminSettings(File file) {}
    private void updateAdminSettings(File file) {}
    private void writeThreadData(File file) {}
    private void updateThreadData(File file) {}
    private void writeNestedData(File file) {}
}
// {/fact}