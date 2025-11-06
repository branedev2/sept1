import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.zip.CRC32;
import java.util.zip.Checksum;
import javax.xml.bind.DatatypeConverter;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.util.encoders.Hex;

public class ChecksumExamples {

    // True Positives (Vulnerable Code)

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public static String bad_case_1() {
        try {
            File file = new File("important_file.txt");
            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            fis.close();
            
            // ruleid: java-insecure-hashing-for-checksum
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hashBytes = md.digest(data);
            
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    public static String bad_case_2() {
        try {
            byte[] fileContent = Files.readAllBytes(Paths.get("config.xml"));
            
            // ruleid: java-insecure-hashing-for-checksum
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            byte[] checksum = digest.digest(fileContent);
            
            return DatatypeConverter.printHexBinary(checksum).toLowerCase();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String bad_case_3() {
        try {
            File file = new File("firmware_update.bin");
            
            // ruleid: java-insecure-hashing-for-checksum
            return DigestUtils.md5Hex(new FileInputStream(file));
        } catch (IOException e) {
            return null;
        }
    }

    public static String bad_case_4() {
        try {
            byte[] fileData = Files.readAllBytes(Paths.get("sensitive_document.pdf"));
            
            // ruleid: java-insecure-hashing-for-checksum
            return DigestUtils.sha1Hex(fileData);
        } catch (IOException e) {
            return null;
        }
    }

    public static byte[] bad_case_5() {
        try {
            byte[] fileContent = Files.readAllBytes(Paths.get("database_backup.sql"));
            
            // ruleid: java-insecure-hashing-for-checksum
            MD5Digest digest = new MD5Digest();
            digest.update(fileContent, 0, fileContent.length);
            byte[] result = new byte[digest.getDigestSize()];
            digest.doFinal(result, 0);
            
            return result;
        } catch (IOException e) {
            return null;
        }
    }

    public static String bad_case_6() {
        try {
            FileInputStream fis = new FileInputStream("user_data.csv");
            byte[] data = fis.readAllBytes();
            fis.close();
            
            // ruleid: java-insecure-hashing-for-checksum
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(data);
            byte[] digest = md.digest();
            
            return new String(Hex.encode(digest));
        } catch (Exception e) {
            return null;
        }
    }

    public static String bad_case_7() {
        try {
            byte[] fileBytes = Files.readAllBytes(Paths.get("system_image.iso"));
            
            // ruleid: java-insecure-hashing-for-checksum
            MessageDigest md = MessageDigest.getInstance("SHA1");
            byte[] hashBytes = md.digest(fileBytes);
            
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    public static String bad_case_8() {
        try {
            File file = new File("financial_report.xlsx");
            FileInputStream fis = new FileInputStream(file);
            
            // ruleid: java-insecure-hashing-for-checksum
            String checksum = org.apache.commons.codec.digest.DigestUtils.md5Hex(fis);
            fis.close();
            
            return checksum;
        } catch (IOException e) {
            return null;
        }
    }

    public static String bad_case_9() {
        try {
            byte[] fileData = Files.readAllBytes(Paths.get("application.jar"));
            
            // ruleid: java-insecure-hashing-for-checksum
            MessageDigest md = MessageDigest.getInstance("MD2");
            byte[] hash = md.digest(fileData);
            
            return javax.xml.bind.DatatypeConverter.printHexBinary(hash);
        } catch (Exception e) {
            return null;
        }
    }

    public static String bad_case_10() {
        try {
            // Calculate checksum for a downloaded file
            byte[] downloadedFile = Files.readAllBytes(Paths.get("downloaded_update.zip"));
            
            // ruleid: java-insecure-hashing-for-checksum
            MessageDigest md = MessageDigest.getInstance("SHA1");
            md.update(downloadedFile);
            byte[] digest = md.digest();
            
            StringBuilder hexString = new StringBuilder();
            for (byte b : digest) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();
        } catch (Exception e) {
            return null;
        }
    }

    public static String bad_case_11() {
        try {
            // Verify integrity of a configuration file
            File configFile = new File("app_config.json");
            FileInputStream fis = new FileInputStream(configFile);
            byte[] data = new byte[(int) configFile.length()];
            fis.read(data);
            fis.close();
            
            // ruleid: java-insecure-hashing-for-checksum
            return DigestUtils.md5Hex(data);
        } catch (IOException e) {
            return null;
        }
    }

    public static String bad_case_12() {
        try {
            byte[] fileContent = Files.readAllBytes(Paths.get("customer_data.csv"));
            
            // ruleid: java-insecure-hashing-for-checksum
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] hashBytes = md.digest(fileContent);
            
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    public static String bad_case_13() {
        try {
            // Generate checksum for a log file
            byte[] logFile = Files.readAllBytes(Paths.get("system.log"));
            
            // ruleid: java-insecure-hashing-for-checksum
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(logFile);
            
            return DatatypeConverter.printHexBinary(digest);
        } catch (Exception e) {
            return null;
        }
    }

    public static String bad_case_14() {
        try {
            // Calculate checksum for a backup file
            File backupFile = new File("backup.tar.gz");
            FileInputStream fis = new FileInputStream(backupFile);
            
            // ruleid: java-insecure-hashing-for-checksum
            String checksum = DigestUtils.sha1Hex(fis);
            fis.close();
            
            return checksum;
        } catch (IOException e) {
            return null;
        }
    }

    public static byte[] bad_case_15() {
        try {
            byte[] fileData = Files.readAllBytes(Paths.get("firmware.bin"));
            
            // ruleid: java-insecure-hashing-for-checksum
            org.bouncycastle.crypto.digests.SHA1Digest digest = new org.bouncycastle.crypto.digests.SHA1Digest();
            digest.update(fileData, 0, fileData.length);
            byte[] result = new byte[digest.getDigestSize()];
            digest.doFinal(result, 0);
            
            return result;
        } catch (IOException e) {
            return null;
        }
    }

    // True Negatives (Secure Code)

    public static String good_case_1() {
        try {
            File file = new File("important_file.txt");
            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            fis.close();
            
            // ok: java-insecure-hashing-for-checksum
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(data);
            
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    public static String good_case_2() {
        try {
            byte[] fileContent = Files.readAllBytes(Paths.get("config.xml"));
            
            // ok: java-insecure-hashing-for-checksum
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            byte[] checksum = digest.digest(fileContent);
            
            return DatatypeConverter.printHexBinary(checksum).toLowerCase();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String good_case_3() {
        try {
            File file = new File("firmware_update.bin");
            
            // ok: java-insecure-hashing-for-checksum
            return DigestUtils.sha256Hex(new FileInputStream(file));
        } catch (IOException e) {
            return null;
        }
    }

    public static String good_case_4() {
        try {
            byte[] fileData = Files.readAllBytes(Paths.get("sensitive_document.pdf"));
            
            // ok: java-insecure-hashing-for-checksum
            return DigestUtils.sha384Hex(fileData);
        } catch (IOException e) {
            return null;
        }
    }

    public static byte[] good_case_5() {
        try {
            byte[] fileContent = Files.readAllBytes(Paths.get("database_backup.sql"));
            
            // ok: java-insecure-hashing-for-checksum
            SHA256Digest digest = new SHA256Digest();
            digest.update(fileContent, 0, fileContent.length);
            byte[] result = new byte[digest.getDigestSize()];
            digest.doFinal(result, 0);
            
            return result;
        } catch (IOException e) {
            return null;
        }
    }

    public static String good_case_6() {
        try {
            FileInputStream fis = new FileInputStream("user_data.csv");
            byte[] data = fis.readAllBytes();
            fis.close();
            
            // ok: java-insecure-hashing-for-checksum
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            md.update(data);
            byte[] digest = md.digest();
            
            return new String(Hex.encode(digest));
        } catch (Exception e) {
            return null;
        }
    }

    public static String good_case_7() {
        try {
            byte[] fileBytes = Files.readAllBytes(Paths.get("system_image.iso"));
            
            // ok: java-insecure-hashing-for-checksum
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(fileBytes);
            
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    public static String good_case_8() {
        try {
            File file = new File("financial_report.xlsx");
            FileInputStream fis = new FileInputStream(file);
            
            // ok: java-insecure-hashing-for-checksum
            String checksum = org.apache.commons.codec.digest.DigestUtils.sha512Hex(fis);
            fis.close();
            
            return checksum;
        } catch (IOException e) {
            return null;
        }
    }

    public static String good_case_9() {
        try {
            byte[] fileData = Files.readAllBytes(Paths.get("application.jar"));
            
            // ok: java-insecure-hashing-for-checksum
            MessageDigest md = MessageDigest.getInstance("SHA3-256");
            byte[] hash = md.digest(fileData);
            
            return javax.xml.bind.DatatypeConverter.printHexBinary(hash);
        } catch (Exception e) {
            return null;
        }
    }

    public static long good_case_10() {
        try {
            // Using CRC32 for error detection, not for security purposes
            byte[] fileData = Files.readAllBytes(Paths.get("data.bin"));
            
            // ok: java-insecure-hashing-for-checksum
            Checksum crc32 = new CRC32();
            crc32.update(fileData, 0, fileData.length);
            
            return crc32.getValue();
        } catch (IOException e) {
            return -1;
        }
    }

    public static String good_case_11() {
        try {
            // Verify integrity of a configuration file
            File configFile = new File("app_config.json");
            FileInputStream fis = new FileInputStream(configFile);
            byte[] data = new byte[(int) configFile.length()];
            fis.read(data);
            fis.close();
            
            // ok: java-insecure-hashing-for-checksum
            return DigestUtils.sha384Hex(data);
        } catch (IOException e) {
            return null;
        }
    }

    public static String good_case_12() {
        try {
            byte[] fileContent = Files.readAllBytes(Paths.get("customer_data.csv"));
            
            // ok: java-insecure-hashing-for-checksum
            MessageDigest md = MessageDigest.getInstance("SHA-224");
            byte[] hashBytes = md.digest(fileContent);
            
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    public static String good_case_13() {
        try {
            // Generate checksum for a log file
            byte[] logFile = Files.readAllBytes(Paths.get("system.log"));
            
            // ok: java-insecure-hashing-for-checksum
            MessageDigest md = MessageDigest.getInstance("SHA-512/256");
            byte[] digest = md.digest(logFile);
            
            return DatatypeConverter.printHexBinary(digest);
        } catch (Exception e) {
            return null;
        }
    }

    public static String good_case_14() {
        try {
            // Calculate checksum for a backup file
            File backupFile = new File("backup.tar.gz");
            FileInputStream fis = new FileInputStream(backupFile);
            
            // ok: java-insecure-hashing-for-checksum
            String checksum = DigestUtils.sha3_256Hex(fis);
            fis.close();
            
            return checksum;
        } catch (IOException e) {
            return null;
        }
    }

    public static byte[] good_case_15() {
        try {
            byte[] fileData = Files.readAllBytes(Paths.get("firmware.bin"));
            
            // ok: java-insecure-hashing-for-checksum
            org.bouncycastle.crypto.digests.SHA512Digest digest = new org.bouncycastle.crypto.digests.SHA512Digest();
            digest.update(fileData, 0, fileData.length);
            byte[] result = new byte[digest.getDigestSize()];
            digest.doFinal(result, 0);
            
            return result;
        } catch (IOException e) {
            return null;
        }
    }
}
// {/fact}