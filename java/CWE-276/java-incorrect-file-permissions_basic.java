import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;

public class FilePermissionsExamples {

    // True Positives (Vulnerable Code)

// {fact rule=insecure-file-permissions@v1.0 defects=1}
    public void bad_case_1() {
        try {
            File tempFile = File.createTempFile("sensitive_data", ".tmp");
            
            // ruleid: java-incorrect-file-permissions
            tempFile.setReadable(true, false); // Makes file readable by everyone
            tempFile.setWritable(true, false); // Makes file writable by everyone
            
            // Write sensitive data
            FileOutputStream fos = new FileOutputStream(tempFile);
            fos.write("Secret API key: abc123xyz".getBytes());
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        try {
            Path configFile = Paths.get("/etc/app/config.properties");
            Set<PosixFilePermission> perms = new HashSet<>();
            perms.add(PosixFilePermission.OWNER_READ);
            perms.add(PosixFilePermission.OWNER_WRITE);
            perms.add(PosixFilePermission.GROUP_READ);
            perms.add(PosixFilePermission.GROUP_WRITE);
            perms.add(PosixFilePermission.OTHERS_READ);
            
            // ruleid: java-incorrect-file-permissions
            Files.setPosixFilePermissions(configFile, perms); // 664 permissions (too permissive)
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() {
        try {
            File logFile = new File("/var/log/app/audit.log");
            logFile.createNewFile();
            
            // ruleid: java-incorrect-file-permissions
            logFile.setReadable(true, false); // World-readable
            logFile.setWritable(true, false); // World-writable
            logFile.setExecutable(true, false); // World-executable
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        try {
            Path keyFile = Paths.get("/home/user/private_key.pem");
            
            // ruleid: java-incorrect-file-permissions
            Files.setPosixFilePermissions(keyFile, 
                PosixFilePermissions.fromString("rw-rw-rw-")); // 666 permissions
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5() {
        try {
            File passwordFile = new File("/etc/passwords.txt");
            passwordFile.createNewFile();
            
            // ruleid: java-incorrect-file-permissions
            passwordFile.setReadable(true, false); // Anyone can read
            
            FileOutputStream fos = new FileOutputStream(passwordFile);
            fos.write("admin:secretpass123".getBytes());
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6() {
        try {
            Path secretsDir = Paths.get("/opt/app/secrets");
            Files.createDirectories(secretsDir);
            
            // ruleid: java-incorrect-file-permissions
            Files.setPosixFilePermissions(secretsDir, 
                PosixFilePermissions.fromString("rwxrwxrwx")); // 777 permissions
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        try {
            File dbConfigFile = new File("/etc/app/database.conf");
            dbConfigFile.createNewFile();
            
            // ruleid: java-incorrect-file-permissions
            dbConfigFile.setWritable(true, false); // Anyone can write
            
            FileOutputStream fos = new FileOutputStream(dbConfigFile);
            fos.write("db_password=super_secret_password".getBytes());
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8() {
        try {
            Path tokenFile = Paths.get("/home/user/.tokens");
            
            Set<PosixFilePermission> perms = EnumSet.of(
                PosixFilePermission.OWNER_READ, 
                PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.GROUP_READ,
                PosixFilePermission.GROUP_WRITE,
                PosixFilePermission.OTHERS_READ
            );
            
            // ruleid: java-incorrect-file-permissions
            Files.setPosixFilePermissions(tokenFile, perms); // 664 permissions
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9() {
        try {
            File backupFile = File.createTempFile("backup_", ".zip");
            
            // ruleid: java-incorrect-file-permissions
            backupFile.setReadable(true, false); // World-readable
            
            // Write sensitive backup data
            FileOutputStream fos = new FileOutputStream(backupFile);
            fos.write("Sensitive backup data".getBytes());
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10() {
        try {
            Path sshConfig = Paths.get("/home/user/.ssh/config");
            
            // ruleid: java-incorrect-file-permissions
            Files.setPosixFilePermissions(sshConfig, 
                PosixFilePermissions.fromString("rw-r--r--")); // 644 permissions (too permissive for SSH config)
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        try {
            File credentialsFile = new File("/opt/app/credentials.json");
            credentialsFile.createNewFile();
            
            // ruleid: java-incorrect-file-permissions
            if (!credentialsFile.setReadable(false, false)) {
                System.err.println("Failed to remove world readable permission");
            }
            credentialsFile.setReadable(true, true); // Owner can read
            credentialsFile.setWritable(true, false); // Everyone can write
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12() {
        try {
            Path certificatePath = Paths.get("/etc/ssl/private/server.key");
            
            // ruleid: java-incorrect-file-permissions
            Files.setPosixFilePermissions(certificatePath, 
                PosixFilePermissions.fromString("rw-r--r--")); // 644 permissions (private key should be 600)
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        try {
            File userDataFile = new File("/var/app/user_data.db");
            userDataFile.createNewFile();
            
            // ruleid: java-incorrect-file-permissions
            userDataFile.setExecutable(true, false); // World-executable
            userDataFile.setReadable(true, false); // World-readable
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        try {
            Path configDir = Paths.get("/etc/app/config");
            Files.createDirectories(configDir);
            
            Set<PosixFilePermission> perms = new HashSet<>();
            // Add all permissions for everyone
            perms.add(PosixFilePermission.OWNER_READ);
            perms.add(PosixFilePermission.OWNER_WRITE);
            perms.add(PosixFilePermission.OWNER_EXECUTE);
            perms.add(PosixFilePermission.GROUP_READ);
            perms.add(PosixFilePermission.GROUP_WRITE);
            perms.add(PosixFilePermission.GROUP_EXECUTE);
            perms.add(PosixFilePermission.OTHERS_READ);
            perms.add(PosixFilePermission.OTHERS_WRITE);
            
            // ruleid: java-incorrect-file-permissions
            Files.setPosixFilePermissions(configDir, perms); // 776 permissions
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        try {
            File tempDir = new File("/tmp/app_data");
            tempDir.mkdir();
            
            // ruleid: java-incorrect-file-permissions
            tempDir.setReadable(true, false); // World-readable
            tempDir.setWritable(true, false); // World-writable
            tempDir.setExecutable(true, false); // World-executable
            
            // Create sensitive file in world-writable directory
            File sensitiveFile = new File(tempDir, "sensitive.dat");
            FileOutputStream fos = new FileOutputStream(sensitiveFile);
            fos.write("Sensitive data".getBytes());
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // True Negatives (Secure Code)

    public void good_case_1() {
        try {
            File tempFile = File.createTempFile("sensitive_data", ".tmp");
            
            // ok: java-incorrect-file-permissions
            tempFile.setReadable(false, false); // Remove world readable
            tempFile.setReadable(true, true);   // Only owner can read
            tempFile.setWritable(false, false); // Remove world writable
            tempFile.setWritable(true, true);   // Only owner can write
            
            // Write sensitive data
            FileOutputStream fos = new FileOutputStream(tempFile);
            fos.write("Secret API key: abc123xyz".getBytes());
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() {
        try {
            Path configFile = Paths.get("/etc/app/config.properties");
            
            // ok: java-incorrect-file-permissions
            Files.setPosixFilePermissions(configFile, 
                PosixFilePermissions.fromString("rw-------")); // 600 permissions (owner only)
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        try {
            File logFile = new File("/var/log/app/audit.log");
            logFile.createNewFile();
            
            // ok: java-incorrect-file-permissions
            logFile.setReadable(false, false);  // Remove world readable
            logFile.setReadable(true, true);    // Only owner can read
            logFile.setWritable(false, false);  // Remove world writable
            logFile.setWritable(true, true);    // Only owner can write
            logFile.setExecutable(false, false); // Remove world executable
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_4() {
        try {
            Path keyFile = Paths.get("/home/user/private_key.pem");
            
            // ok: java-incorrect-file-permissions
            Files.setPosixFilePermissions(keyFile, 
                PosixFilePermissions.fromString("rw-------")); // 600 permissions
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_5() {
        try {
            File passwordFile = new File("/etc/passwords.txt");
            passwordFile.createNewFile();
            
            // ok: java-incorrect-file-permissions
            passwordFile.setReadable(false, false); // Remove world readable
            passwordFile.setReadable(true, true);   // Only owner can read
            passwordFile.setWritable(false, false); // Remove world writable
            passwordFile.setWritable(true, true);   // Only owner can write
            
            FileOutputStream fos = new FileOutputStream(passwordFile);
            fos.write("admin:secretpass123".getBytes());
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_6() {
        try {
            Path secretsDir = Paths.get("/opt/app/secrets");
            Files.createDirectories(secretsDir);
            
            // ok: java-incorrect-file-permissions
            Files.setPosixFilePermissions(secretsDir, 
                PosixFilePermissions.fromString("rwx------")); // 700 permissions
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        try {
            File dbConfigFile = new File("/etc/app/database.conf");
            dbConfigFile.createNewFile();
            
            // ok: java-incorrect-file-permissions
            dbConfigFile.setReadable(false, false); // Remove world readable
            dbConfigFile.setReadable(true, true);   // Only owner can read
            dbConfigFile.setWritable(false, false); // Remove world writable
            dbConfigFile.setWritable(true, true);   // Only owner can write
            
            FileOutputStream fos = new FileOutputStream(dbConfigFile);
            fos.write("db_password=super_secret_password".getBytes());
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_8() {
        try {
            Path tokenFile = Paths.get("/home/user/.tokens");
            
            // ok: java-incorrect-file-permissions
            Files.setPosixFilePermissions(tokenFile, 
                EnumSet.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE
                )); // 600 permissions
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_9() {
        try {
            File backupFile = File.createTempFile("backup_", ".zip");
            
            // ok: java-incorrect-file-permissions
            backupFile.setReadable(false, false); // Remove world readable
            backupFile.setReadable(true, true);   // Only owner can read
            backupFile.setWritable(false, false); // Remove world writable
            backupFile.setWritable(true, true);   // Only owner can write
            
            // Write sensitive backup data
            FileOutputStream fos = new FileOutputStream(backupFile);
            fos.write("Sensitive backup data".getBytes());
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_10() {
        try {
            Path sshConfig = Paths.get("/home/user/.ssh/config");
            
            // ok: java-incorrect-file-permissions
            Files.setPosixFilePermissions(sshConfig, 
                PosixFilePermissions.fromString("rw-------")); // 600 permissions
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        try {
            File credentialsFile = new File("/opt/app/credentials.json");
            credentialsFile.createNewFile();
            
            // ok: java-incorrect-file-permissions
            credentialsFile.setReadable(false, false); // Remove world readable
            credentialsFile.setReadable(true, true);   // Only owner can read
            credentialsFile.setWritable(false, false); // Remove world writable
            credentialsFile.setWritable(true, true);   // Only owner can write
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_12() {
        try {
            Path certificatePath = Paths.get("/etc/ssl/private/server.key");
            
            // ok: java-incorrect-file-permissions
            Files.setPosixFilePermissions(certificatePath, 
                PosixFilePermissions.fromString("rw-------")); // 600 permissions
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        try {
            File userDataFile = new File("/var/app/user_data.db");
            userDataFile.createNewFile();
            
            // ok: java-incorrect-file-permissions
            userDataFile.setReadable(false, false); // Remove world readable
            userDataFile.setReadable(true, true);   // Only owner can read
            userDataFile.setWritable(false, false); // Remove world writable
            userDataFile.setWritable(true, true);   // Only owner can write
            userDataFile.setExecutable(false, false); // Remove all executable
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_14() {
        try {
            Path configDir = Paths.get("/etc/app/config");
            Files.createDirectories(configDir);
            
            // ok: java-incorrect-file-permissions
            Files.setPosixFilePermissions(configDir, 
                PosixFilePermissions.fromString("rwx------")); // 700 permissions
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        try {
            File tempDir = new File("/tmp/app_data");
            tempDir.mkdir();
            
            // ok: java-incorrect-file-permissions
            tempDir.setReadable(false, false);  // Remove world readable
            tempDir.setReadable(true, true);    // Only owner can read
            tempDir.setWritable(false, false);  // Remove world writable
            tempDir.setWritable(true, true);    // Only owner can write
            tempDir.setExecutable(false, false); // Remove world executable
            tempDir.setExecutable(true, true);   // Only owner can execute
            
            // Create sensitive file in secure directory
            File sensitiveFile = new File(tempDir, "sensitive.dat");
            FileOutputStream fos = new FileOutputStream(sensitiveFile);
            fos.write("Sensitive data".getBytes());
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
// {/fact}