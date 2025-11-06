import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;
import java.util.zip.CRC32;
import java.util.zip.Checksum;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;

public class InsecureHexValueExamples {

    // True Positives (Vulnerable Code)

// {fact rule=nan-injection@v1.0 defects=1}
    public void bad_case_1() {
        try {
            String password = "secretPassword123";
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));
            
            StringBuilder hexString = new StringBuilder();
            for (byte hashByte : hashBytes) {
                // ruleid: java-insecure-hex-value
                String hex = Integer.toHexString(0xff & hashByte);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            
            System.out.println("Password hash: " + hexString.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() {
        try {
            String data = "sensitive data";
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(data.getBytes());
            
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                // ruleid: java-insecure-hex-value
                sb.append(Integer.toHexString((b & 0xff)));
            }
            
            String hashValue = sb.toString();
            System.out.println("MD5 hash: " + hashValue);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() {
        String input = "user input";
        CRC32 crc = new CRC32();
        crc.update(input.getBytes());
        long checksum = crc.getValue();
        
        // ruleid: java-insecure-hex-value
        String hexChecksum = Long.toHexString(checksum);
        
        System.out.println("CRC32 checksum: " + hexChecksum);
    }

    public void bad_case_4() {
        try {
            String userId = "user123";
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            byte[] hash = digest.digest(userId.getBytes(StandardCharsets.UTF_8));
            
            StringBuilder hexHash = new StringBuilder();
            for (byte b : hash) {
                // ruleid: java-insecure-hex-value
                hexHash.append(Integer.toHexString(0xff & b));
            }
            
            String token = hexHash.toString();
            System.out.println("Authentication token: " + token);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5() {
        String filename = "document.pdf";
        int hashCode = filename.hashCode();
        
        // ruleid: java-insecure-hex-value
        String hexHash = Integer.toHexString(hashCode);
        
        String uniqueFilename = hexHash + "_" + filename;
        System.out.println("Unique filename: " + uniqueFilename);
    }

    public void bad_case_6() {
        try {
            String sessionId = UUID.randomUUID().toString();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(sessionId.getBytes());
            
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                // ruleid: java-insecure-hex-value
                String hex = Integer.toHexString(b & 0xff);
                if (hex.length() == 1) sb.append('0');
                sb.append(hex);
            }
            
            System.out.println("Session token: " + sb.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        int colorValue = 0xFF5733;
        
        // ruleid: java-insecure-hex-value
        String hexColor = "#" + Integer.toHexString(colorValue);
        
        System.out.println("Color code: " + hexColor);
    }

    public void bad_case_8() {
        try {
            String email = "user@example.com";
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(email.getBytes());
            
            StringBuilder hexString = new StringBuilder();
            for (int i = 0; i < digest.length; i++) {
                // ruleid: java-insecure-hex-value
                hexString.append(Integer.toHexString(0xFF & digest[i]));
            }
            
            String emailHash = hexString.toString();
            System.out.println("Email hash for Gravatar: " + emailHash);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9() {
        byte[] data = "Random data for checksum".getBytes();
        int checksum = 0;
        
        for (byte b : data) {
            checksum = (checksum + (b & 0xFF)) % 0xFFFF;
        }
        
        // ruleid: java-insecure-hex-value
        String hexChecksum = Integer.toHexString(checksum);
        
        System.out.println("Simple checksum: " + hexChecksum);
    }

    public void bad_case_10() {
        try {
            String text = "Text to be hashed";
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            byte[] digest = md.digest(text.getBytes());
            
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                // ruleid: java-insecure-hex-value
                sb.append(Integer.toHexString((b & 0xff)));
            }
            
            System.out.println("SHA-512 hash: " + sb.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        int ipAddress = 0xC0A80001; // 192.168.0.1
        
        // ruleid: java-insecure-hex-value
        String hexIp = Integer.toHexString(ipAddress);
        
        System.out.println("IP in hex: " + hexIp);
    }

    public void bad_case_12() {
        try {
            String input = "data to hash";
            MessageDigest md = MessageDigest.getInstance("SHA-384");
            byte[] hashBytes = md.digest(input.getBytes());
            
            StringBuilder result = new StringBuilder();
            for (byte b : hashBytes) {
                // ruleid: java-insecure-hex-value
                result.append(Integer.toHexString((b & 0xff) + 0x100).substring(1));
            }
            
            System.out.println("SHA-384 hash: " + result.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() {
        long timestamp = System.currentTimeMillis();
        
        // ruleid: java-insecure-hex-value
        String hexTimestamp = Long.toHexString(timestamp);
        
        String uniqueId = "session_" + hexTimestamp;
        System.out.println("Unique session ID: " + uniqueId);
    }

    public void bad_case_14() {
        try {
            String data = "sensitive information";
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] digest = md.digest(data.getBytes());
            
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                // ruleid: java-insecure-hex-value
                String hex = Integer.toHexString(b & 0xff);
                if (hex.length() < 2) {
                    sb.append("0");
                }
                sb.append(hex);
            }
            
            System.out.println("Data fingerprint: " + sb.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() {
        String text = "Example text";
        int hash = 0;
        
        for (char c : text.toCharArray()) {
            hash = 31 * hash + c;
        }
        
        // ruleid: java-insecure-hex-value
        String hexHash = Integer.toHexString(hash);
        
        System.out.println("Simple string hash: " + hexHash);
    }

    // True Negatives (Secure Code)

    public void good_case_1() {
        try {
            String password = "secretPassword123";
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));
            
            StringBuilder hexString = new StringBuilder();
            for (byte hashByte : hashBytes) {
                // ok: java-insecure-hex-value
                String hex = String.format("%02x", hashByte & 0xff);
                hexString.append(hex);
            }
            
            System.out.println("Password hash: " + hexString.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() {
        try {
            String data = "sensitive data";
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(data.getBytes());
            
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                // ok: java-insecure-hex-value
                sb.append(String.format("%02x", b & 0xff));
            }
            
            String hashValue = sb.toString();
            System.out.println("MD5 hash: " + hashValue);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() {
        String input = "user input";
        CRC32 crc = new CRC32();
        crc.update(input.getBytes());
        long checksum = crc.getValue();
        
        // ok: java-insecure-hex-value
        String hexChecksum = String.format("%08x", checksum);
        
        System.out.println("CRC32 checksum: " + hexChecksum);
    }

    public void good_case_4() {
        try {
            String userId = "user123";
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            byte[] hash = digest.digest(userId.getBytes(StandardCharsets.UTF_8));
            
            // ok: java-insecure-hex-value
            String token = new BigInteger(1, hash).toString(16);
            
            System.out.println("Authentication token: " + token);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_5() {
        String filename = "document.pdf";
        int hashCode = filename.hashCode();
        
        // ok: java-insecure-hex-value
        String hexHash = String.format("%08x", hashCode);
        
        String uniqueFilename = hexHash + "_" + filename;
        System.out.println("Unique filename: " + uniqueFilename);
    }

    public void good_case_6() {
        try {
            String sessionId = UUID.randomUUID().toString();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(sessionId.getBytes());
            
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                // ok: java-insecure-hex-value
                sb.append(String.format("%02x", b & 0xff));
            }
            
            System.out.println("Session token: " + sb.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() {
        int colorValue = 0xFF5733;
        
        // ok: java-insecure-hex-value
        String hexColor = String.format("#%06x", colorValue);
        
        System.out.println("Color code: " + hexColor);
    }

    public void good_case_8() {
        try {
            String email = "user@example.com";
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(email.getBytes());
            
            StringBuilder hexString = new StringBuilder();
            for (int i = 0; i < digest.length; i++) {
                // ok: java-insecure-hex-value
                hexString.append(String.format("%02x", 0xFF & digest[i]));
            }
            
            String emailHash = hexString.toString();
            System.out.println("Email hash for Gravatar: " + emailHash);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_9() {
        byte[] data = "Random data for checksum".getBytes();
        int checksum = 0;
        
        for (byte b : data) {
            checksum = (checksum + (b & 0xFF)) % 0xFFFF;
        }
        
        // ok: java-insecure-hex-value
        String hexChecksum = String.format("%04x", checksum);
        
        System.out.println("Simple checksum: " + hexChecksum);
    }

    public void good_case_10() {
        try {
            String text = "Text to be hashed";
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            byte[] digest = md.digest(text.getBytes());
            
            // ok: java-insecure-hex-value
            StringBuilder sb = new StringBuilder(2 * digest.length);
            for (byte b : digest) {
                sb.append(String.format("%02x", b & 0xff));
            }
            
            System.out.println("SHA-512 hash: " + sb.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() {
        int ipAddress = 0xC0A80001; // 192.168.0.1
        
        // ok: java-insecure-hex-value
        String hexIp = String.format("%08x", ipAddress);
        
        System.out.println("IP in hex: " + hexIp);
    }

    public void good_case_12() {
        try {
            String input = "data to hash";
            MessageDigest md = MessageDigest.getInstance("SHA-384");
            byte[] hashBytes = md.digest(input.getBytes());
            
            // ok: java-insecure-hex-value
            StringBuilder result = new StringBuilder();
            for (byte b : hashBytes) {
                result.append(String.format("%02x", b & 0xff));
            }
            
            System.out.println("SHA-384 hash: " + result.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        long timestamp = System.currentTimeMillis();
        
        // ok: java-insecure-hex-value
        String hexTimestamp = String.format("%016x", timestamp);
        
        String uniqueId = "session_" + hexTimestamp;
        System.out.println("Unique session ID: " + uniqueId);
    }

    public void good_case_14() {
        try {
            String data = "sensitive information";
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] digest = md.digest(data.getBytes());
            
            // ok: java-insecure-hex-value
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02x", b & 0xff));
            }
            
            System.out.println("Data fingerprint: " + sb.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        String text = "Example text";
        int hash = 0;
        
        for (char c : text.toCharArray()) {
            hash = 31 * hash + c;
        }
        
        // ok: java-insecure-hex-value
        String hexHash = String.format("%08x", hash);
        
        System.out.println("Simple string hash: " + hexHash);
    }
}
// {/fact}