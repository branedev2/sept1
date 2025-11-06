import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;

public class FilePermissionsTest {

    // True Positive Examples (Vulnerable Code)

// {fact rule=insecure-file-permissions@v1.0 defects=1}
    public void bad_case_1() throws IOException {
        Path path = Paths.get("/tmp/sensitive_data.txt");
        Set<PosixFilePermission> perms = new HashSet<>();
        perms.add(PosixFilePermission.OWNER_READ);
        perms.add(PosixFilePermission.OWNER_WRITE);
        perms.add(PosixFilePermission.GROUP_READ);
        perms.add(PosixFilePermission.GROUP_WRITE);
        perms.add(PosixFilePermission.OTHERS_READ);
        perms.add(PosixFilePermission.OTHERS_WRITE); // Too permissive
        // ruleid: java-incorrect-file-permissions
        Files.setPosixFilePermissions(path, perms);
    }

    public void bad_case_2() throws IOException {
        Path configFile = Paths.get("/etc/app/config.properties");
        Set<PosixFilePermission> permissions = EnumSet.allOf(PosixFilePermission.class); // All permissions for everyone
        // ruleid: java-incorrect-file-permissions
        Files.setPosixFilePermissions(configFile, permissions);
    }

    public void bad_case_3() throws IOException {
        Path keyFile = Paths.get("/home/user/private_key.pem");
        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-rw-rw-"); // Read-write for all
        // ruleid: java-incorrect-file-permissions
        Files.setPosixFilePermissions(keyFile, perms);
    }

    public void bad_case_4() throws IOException {
        Path logFile = Paths.get("/var/log/app.log");
        // World-writable log file
        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-rw-rw-");
        // ruleid: java-incorrect-file-permissions
        Files.setPosixFilePermissions(logFile, perms);
    }

    public void bad_case_5() throws IOException {
        Path secretsDir = Paths.get("/opt/app/secrets");
        // Everyone can read, write, and execute in secrets directory
        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rwxrwxrwx");
        // ruleid: java-incorrect-file-permissions
        Files.setPosixFilePermissions(secretsDir, perms);
    }

    public void bad_case_6() throws IOException {
        String fileName = "/etc/passwd.backup";
        Path path = Paths.get(fileName);
        Set<PosixFilePermission> perms = new HashSet<>();
        // Add all permissions for everyone
        for (PosixFilePermission permission : PosixFilePermission.values()) {
            perms.add(permission);
        }
        // ruleid: java-incorrect-file-permissions
        Files.setPosixFilePermissions(path, perms);
    }

    public void bad_case_7() throws IOException {
        Path tempFile = Files.createTempFile("sensitive", ".data");
        Set<PosixFilePermission> perms = new HashSet<>();
        perms.add(PosixFilePermission.OWNER_READ);
        perms.add(PosixFilePermission.OWNER_WRITE);
        perms.add(PosixFilePermission.GROUP_READ);
        perms.add(PosixFilePermission.GROUP_WRITE);
        perms.add(PosixFilePermission.OTHERS_READ);
        // ruleid: java-incorrect-file-permissions
        Files.setPosixFilePermissions(tempFile, perms);
    }

    public void bad_case_8() throws IOException {
        Path dbConfigFile = Paths.get("/opt/app/database.conf");
        // Using octal representation (777 in this case)
        File file = dbConfigFile.toFile();
        // ruleid: java-incorrect-file-permissions
        boolean success = file.setReadable(true, false); // Readable by all
        success &= file.setWritable(true, false); // Writable by all
        success &= file.setExecutable(true, false); // Executable by all
    }

    public void bad_case_9() throws IOException {
        Path credentialsFile = Paths.get("/home/user/.credentials");
        // Group and others can read sensitive credentials
        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("r--r--r--");
        // ruleid: java-incorrect-file-permissions
        Files.setPosixFilePermissions(credentialsFile, perms);
    }

    public void bad_case_10() throws IOException {
        Path scriptFile = Paths.get("/opt/app/scripts/backup.sh");
        // Everyone can modify the script
        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rwxrwxrwx");
        // ruleid: java-incorrect-file-permissions
        Files.setPosixFilePermissions(scriptFile, perms);
    }

    public void bad_case_11() throws IOException {
        Path configDir = Paths.get("/etc/app/config");
        // Others can write to config directory
        Set<PosixFilePermission> perms = new HashSet<>();
        perms.add(PosixFilePermission.OWNER_READ);
        perms.add(PosixFilePermission.OWNER_WRITE);
        perms.add(PosixFilePermission.OWNER_EXECUTE);
        perms.add(PosixFilePermission.GROUP_READ);
        perms.add(PosixFilePermission.OTHERS_READ);
        perms.add(PosixFilePermission.OTHERS_WRITE); // Allowing others to write
        // ruleid: java-incorrect-file-permissions
        Files.setPosixFilePermissions(configDir, perms);
    }

    public void bad_case_12() throws IOException {
        Path userDataFile = Paths.get("/var/data/users.db");
        File file = userDataFile.toFile();
        // ruleid: java-incorrect-file-permissions
        file.setReadable(true, false); // Readable by everyone
        file.setWritable(true, true); // Writable only by owner
    }

    public void bad_case_13() throws IOException {
        Path keyStore = Paths.get("/opt/app/security/keystore.jks");
        // Group members can write to keystore
        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-rw----");
        // ruleid: java-incorrect-file-permissions
        Files.setPosixFilePermissions(keyStore, perms);
    }

    public void bad_case_14() throws IOException {
        Path tempDir = Files.createTempDirectory("app_data");
        // World-writable temporary directory
        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rwxrwxrwx");
        // ruleid: java-incorrect-file-permissions
        Files.setPosixFilePermissions(tempDir, perms);
    }

    public void bad_case_15() throws IOException {
        Path apiTokenFile = Paths.get("/home/user/.api_tokens");
        // Creating a file with default permissions, which might be too permissive
        Files.createFile(apiTokenFile);
        // Not setting any specific permissions, relying on umask
        // ruleid: java-incorrect-file-permissions
        // The absence of explicit permission setting is the issue here
    }

    // True Negative Examples (Secure Code)

    public void good_case_1() throws IOException {
        Path path = Paths.get("/tmp/sensitive_data.txt");
        Set<PosixFilePermission> perms = new HashSet<>();
        perms.add(PosixFilePermission.OWNER_READ);
        perms.add(PosixFilePermission.OWNER_WRITE);
        // ok: java-incorrect-file-permissions
        Files.setPosixFilePermissions(path, perms);
    }

    public void good_case_2() throws IOException {
        Path configFile = Paths.get("/etc/app/config.properties");
        // Only owner can read and write
        Set<PosixFilePermission> permissions = EnumSet.of(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE
        );
        // ok: java-incorrect-file-permissions
        Files.setPosixFilePermissions(configFile, permissions);
    }

    public void good_case_3() throws IOException {
        Path keyFile = Paths.get("/home/user/private_key.pem");
        // Private key should be readable only by owner
        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("r--------");
        // ok: java-incorrect-file-permissions
        Files.setPosixFilePermissions(keyFile, perms);
    }

    public void good_case_4() throws IOException {
        Path logFile = Paths.get("/var/log/app.log");
        // Owner can read/write, group can read
        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-r-----");
        // ok: java-incorrect-file-permissions
        Files.setPosixFilePermissions(logFile, perms);
    }

    public void good_case_5() throws IOException {
        Path secretsDir = Paths.get("/opt/app/secrets");
        // Only owner has full access to secrets directory
        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rwx------");
        // ok: java-incorrect-file-permissions
        Files.setPosixFilePermissions(secretsDir, perms);
    }

    public void good_case_6() throws IOException {
        String fileName = "/etc/passwd.backup";
        Path path = Paths.get(fileName);
        // Secure permissions for sensitive file
        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
        // ok: java-incorrect-file-permissions
        Files.setPosixFilePermissions(path, perms);
    }

    public void good_case_7() throws IOException {
        Path tempFile = Files.createTempFile("sensitive", ".data");
        // Restrict permissions on temporary file with sensitive data
        Set<PosixFilePermission> perms = EnumSet.of(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE
        );
        // ok: java-incorrect-file-permissions
        Files.setPosixFilePermissions(tempFile, perms);
    }

    public void good_case_8() throws IOException {
        Path dbConfigFile = Paths.get("/opt/app/database.conf");
        File file = dbConfigFile.toFile();
        // ok: java-incorrect-file-permissions
        boolean success = file.setReadable(true, true); // Readable only by owner
        success &= file.setWritable(true, true); // Writable only by owner
        success &= file.setExecutable(false); // Not executable
    }

    public void good_case_9() throws IOException {
        Path credentialsFile = Paths.get("/home/user/.credentials");
        // Only owner can read credentials
        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("r--------");
        // ok: java-incorrect-file-permissions
        Files.setPosixFilePermissions(credentialsFile, perms);
    }

    public void good_case_10() throws IOException {
        Path scriptFile = Paths.get("/opt/app/scripts/backup.sh");
        // Owner can read/write/execute, group can read/execute
        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rwxr-x---");
        // ok: java-incorrect-file-permissions
        Files.setPosixFilePermissions(scriptFile, perms);
    }

    public void good_case_11() throws IOException {
        Path configDir = Paths.get("/etc/app/config");
        // Secure permissions for config directory
        Set<PosixFilePermission> perms = new HashSet<>();
        perms.add(PosixFilePermission.OWNER_READ);
        perms.add(PosixFilePermission.OWNER_WRITE);
        perms.add(PosixFilePermission.OWNER_EXECUTE);
        perms.add(PosixFilePermission.GROUP_READ);
        perms.add(PosixFilePermission.GROUP_EXECUTE);
        // ok: java-incorrect-file-permissions
        Files.setPosixFilePermissions(configDir, perms);
    }

    public void good_case_12() throws IOException {
        Path userDataFile = Paths.get("/var/data/users.db");
        // Set appropriate permissions based on security requirements
        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-r-----");
        // ok: java-incorrect-file-permissions
        Files.setPosixFilePermissions(userDataFile, perms);
    }

    public void good_case_13() throws IOException {
        Path keyStore = Paths.get("/opt/app/security/keystore.jks");
        // Only owner can access keystore
        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
        // ok: java-incorrect-file-permissions
        Files.setPosixFilePermissions(keyStore, perms);
    }

    public void good_case_14() throws IOException {
        Path tempDir = Files.createTempDirectory("app_data");
        // Secure temporary directory permissions
        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rwx------");
        // ok: java-incorrect-file-permissions
        Files.setPosixFilePermissions(tempDir, perms);
    }

    public void good_case_15() throws IOException {
        Path apiTokenFile = Paths.get("/home/user/.api_tokens");
        // Create file with explicit secure permissions
        Files.createFile(apiTokenFile);
        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
        // ok: java-incorrect-file-permissions
        Files.setPosixFilePermissions(apiTokenFile, perms);
    }
}
// {/fact}