import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

public class CipherUpdateAADTestCases {

    // True Positives (Vulnerable Code)

// {fact rule=cipher-update-aad@v1.0 defects=1}
    public byte[] bad_case_1(byte[] plaintext, byte[] aad) throws Exception {
        // Initializing cipher with GCM mode
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        // First updating with plaintext, then with AAD - incorrect order
        // ruleid: java-cipherupdateaad
        cipher.update(plaintext);
        cipher.updateAAD(aad);
        
        return cipher.doFinal();
    }

    public byte[] bad_case_2(byte[] plaintext, byte[] aad1, byte[] aad2) throws Exception {
        // Using GCM mode with multiple updates in wrong order
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        cipher.updateAAD(aad1);
        // ruleid: java-cipherupdateaad
        cipher.update(plaintext, 0, plaintext.length / 2);
        cipher.updateAAD(aad2);
        
        return cipher.doFinal(plaintext, plaintext.length / 2, plaintext.length - plaintext.length / 2);
    }

    public byte[] bad_case_3(byte[] plaintext, byte[] aad) throws Exception {
        // Using CCM mode with incorrect order
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        // ruleid: java-cipherupdateaad
        byte[] firstPart = cipher.update(plaintext, 0, 10);
        cipher.updateAAD(aad);
        
        byte[] secondPart = cipher.doFinal(plaintext, 10, plaintext.length - 10);
        return concatenate(firstPart, secondPart);
    }

    public byte[] bad_case_4(byte[] plaintext, byte[] aad) throws Exception {
        // Interleaving update and updateAAD calls
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        cipher.updateAAD(aad, 0, 5);
        // ruleid: java-cipherupdateaad
        cipher.update(plaintext, 0, 10);
        cipher.updateAAD(aad, 5, aad.length - 5);
        
        return cipher.doFinal(plaintext, 10, plaintext.length - 10);
    }

    public byte[] bad_case_5(byte[] plaintext, byte[] aad) throws Exception {
        // Using ByteBuffer with incorrect order
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        ByteBuffer ptBuffer = ByteBuffer.wrap(plaintext);
        ByteBuffer aadBuffer = ByteBuffer.wrap(aad);
        
        // ruleid: java-cipherupdateaad
        cipher.update(ptBuffer);
        cipher.updateAAD(aadBuffer);
        
        return cipher.doFinal();
    }

    public byte[] bad_case_6(byte[] plaintext, byte[] aad) throws Exception {
        // Using try-with-resources with incorrect order
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        try {
            // ruleid: java-cipherupdateaad
            cipher.update(plaintext);
            cipher.updateAAD(aad);
            return cipher.doFinal();
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public byte[] bad_case_7(byte[] plaintext, byte[] aad) throws Exception {
        // Using conditional logic with incorrect order
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        if (plaintext.length > 0) {
            // ruleid: java-cipherupdateaad
            cipher.update(plaintext, 0, plaintext.length / 2);
        }
        
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        
        return cipher.doFinal(plaintext, plaintext.length / 2, plaintext.length - plaintext.length / 2);
    }

    public byte[] bad_case_8(byte[] plaintext, byte[] aad1, byte[] aad2) throws Exception {
        // Using loop with incorrect order
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        // ruleid: java-cipherupdateaad
        for (int i = 0; i < plaintext.length; i += 10) {
            int len = Math.min(10, plaintext.length - i);
            cipher.update(plaintext, i, len);
        }
        
        cipher.updateAAD(aad1);
        cipher.updateAAD(aad2);
        
        return cipher.doFinal();
    }

    public byte[] bad_case_9(byte[] plaintext, byte[] aad) throws Exception {
        // Using switch statement with incorrect order
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        int mode = 1;
        switch (mode) {
            case 1:
                // ruleid: java-cipherupdateaad
                cipher.update(plaintext, 0, 10);
                break;
            case 2:
                cipher.updateAAD(new byte[0]);
                break;
        }
        
        cipher.updateAAD(aad);
        return cipher.doFinal(plaintext, 10, plaintext.length - 10);
    }

    public byte[] bad_case_10(byte[] plaintext, byte[] aad) throws Exception {
        // Using method chaining with incorrect order
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        processData(cipher, plaintext);
        // ruleid: java-cipherupdateaad
        cipher.updateAAD(aad);
        
        return cipher.doFinal();
    }
    
    private void processData(Cipher cipher, byte[] data) throws Exception {
        cipher.update(data);
    }

    public byte[] bad_case_11(byte[] plaintext, byte[] aad) throws Exception {
        // Using nested blocks with incorrect order
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        {
            // ruleid: java-cipherupdateaad
            cipher.update(plaintext, 0, plaintext.length / 2);
        }
        
        {
            cipher.updateAAD(aad);
        }
        
        return cipher.doFinal(plaintext, plaintext.length / 2, plaintext.length - plaintext.length / 2);
    }

    public byte[] bad_case_12(byte[] plaintext, byte[] aad) throws Exception {
        // Using exception handling with incorrect order
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        try {
            // ruleid: java-cipherupdateaad
            cipher.update(plaintext);
        } catch (Exception e) {
            // Handle exception
        }
        
        try {
            cipher.updateAAD(aad);
        } catch (Exception e) {
            // Handle exception
        }
        
        return cipher.doFinal();
    }

    public byte[] bad_case_13(byte[] plaintext, byte[] aad) throws Exception {
        // Using ternary operator with incorrect order
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        boolean shouldUpdate = true;
        
        // ruleid: java-cipherupdateaad
        byte[] firstPart = shouldUpdate ? cipher.update(plaintext, 0, 10) : new byte[0];
        
        boolean shouldAddAAD = true;
        if (shouldAddAAD) {
            cipher.updateAAD(aad);
        }
        
        return concatenate(firstPart, cipher.doFinal(plaintext, 10, plaintext.length - 10));
    }

    public byte[] bad_case_14(byte[] plaintext, byte[] aad) throws Exception {
        // Using multiple ciphers with incorrect order
        Cipher cipher1 = Cipher.getInstance("AES/GCM/NoPadding");
        Cipher cipher2 = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        
        cipher1.init(Cipher.ENCRYPT_MODE, key, spec);
        cipher2.init(Cipher.ENCRYPT_MODE, key, spec);
        
        // ruleid: java-cipherupdateaad
        cipher1.update(plaintext);
        cipher1.updateAAD(aad);
        
        return cipher1.doFinal();
    }

    public byte[] bad_case_15(byte[] plaintext, byte[] aad) throws Exception {
        // Using array of ciphers with incorrect order
        Cipher[] ciphers = new Cipher[2];
        ciphers[0] = Cipher.getInstance("AES/GCM/NoPadding");
        ciphers[1] = Cipher.getInstance("AES/CCM/NoPadding");
        
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        
        ciphers[0].init(Cipher.ENCRYPT_MODE, key, spec);
        
        // ruleid: java-cipherupdateaad
        ciphers[0].update(plaintext, 0, 10);
        ciphers[0].updateAAD(aad);
        
        return ciphers[0].doFinal(plaintext, 10, plaintext.length - 10);
    }

    // True Negatives (Secure Code)

    public byte[] good_case_1(byte[] plaintext, byte[] aad) throws Exception {
        // Correct order: first updateAAD, then update
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        // ok: java-cipherupdateaad
        cipher.updateAAD(aad);
        cipher.update(plaintext);
        
        return cipher.doFinal();
    }

    public byte[] good_case_2(byte[] plaintext, byte[] aad1, byte[] aad2) throws Exception {
        // Correct order with multiple AAD updates before any plaintext update
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        // ok: java-cipherupdateaad
        cipher.updateAAD(aad1);
        cipher.updateAAD(aad2);
        cipher.update(plaintext);
        
        return cipher.doFinal();
    }

    public byte[] good_case_3(byte[] plaintext, byte[] aad) throws Exception {
        // Correct order with CCM mode
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        // ok: java-cipherupdateaad
        cipher.updateAAD(aad);
        byte[] firstPart = cipher.update(plaintext, 0, 10);
        
        byte[] secondPart = cipher.doFinal(plaintext, 10, plaintext.length - 10);
        return concatenate(firstPart, secondPart);
    }

    public byte[] good_case_4(byte[] plaintext, byte[] aad) throws Exception {
        // Correct order with partial AAD updates
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        // ok: java-cipherupdateaad
        cipher.updateAAD(aad, 0, 5);
        cipher.updateAAD(aad, 5, aad.length - 5);
        cipher.update(plaintext, 0, 10);
        
        return cipher.doFinal(plaintext, 10, plaintext.length - 10);
    }

    public byte[] good_case_5(byte[] plaintext, byte[] aad) throws Exception {
        // Correct order using ByteBuffer
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        ByteBuffer ptBuffer = ByteBuffer.wrap(plaintext);
        ByteBuffer aadBuffer = ByteBuffer.wrap(aad);
        
        // ok: java-cipherupdateaad
        cipher.updateAAD(aadBuffer);
        cipher.update(ptBuffer);
        
        return cipher.doFinal();
    }

    public byte[] good_case_6(byte[] plaintext, byte[] aad) throws Exception {
        // Correct order using try-with-resources
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        try {
            // ok: java-cipherupdateaad
            cipher.updateAAD(aad);
            cipher.update(plaintext);
            return cipher.doFinal();
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public byte[] good_case_7(byte[] plaintext, byte[] aad) throws Exception {
        // Correct order with conditional logic
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        if (aad != null) {
            // ok: java-cipherupdateaad
            cipher.updateAAD(aad);
        }
        
        if (plaintext.length > 0) {
            cipher.update(plaintext, 0, plaintext.length / 2);
        }
        
        return cipher.doFinal(plaintext, plaintext.length / 2, plaintext.length - plaintext.length / 2);
    }

    public byte[] good_case_8(byte[] plaintext, byte[] aad1, byte[] aad2) throws Exception {
        // Correct order with loops
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        // ok: java-cipherupdateaad
        cipher.updateAAD(aad1);
        cipher.updateAAD(aad2);
        
        for (int i = 0; i < plaintext.length; i += 10) {
            int len = Math.min(10, plaintext.length - i);
            cipher.update(plaintext, i, len);
        }
        
        return cipher.doFinal();
    }

    public byte[] good_case_9(byte[] plaintext, byte[] aad) throws Exception {
        // Correct order with switch statement
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        int mode = 1;
        switch (mode) {
            case 1:
                // ok: java-cipherupdateaad
                cipher.updateAAD(aad);
                break;
            case 2:
                cipher.updateAAD(new byte[0]);
                break;
        }
        
        cipher.update(plaintext, 0, 10);
        return cipher.doFinal(plaintext, 10, plaintext.length - 10);
    }

    public byte[] good_case_10(byte[] plaintext, byte[] aad) throws Exception {
        // Correct order with method chaining
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        // ok: java-cipherupdateaad
        cipher.updateAAD(aad);
        processData(cipher, plaintext);
        
        return cipher.doFinal();
    }

    public byte[] good_case_11(byte[] plaintext, byte[] aad) throws Exception {
        // Correct order with nested blocks
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        {
            // ok: java-cipherupdateaad
            cipher.updateAAD(aad);
        }
        
        {
            cipher.update(plaintext, 0, plaintext.length / 2);
        }
        
        return cipher.doFinal(plaintext, plaintext.length / 2, plaintext.length - plaintext.length / 2);
    }

    public byte[] good_case_12(byte[] plaintext, byte[] aad) throws Exception {
        // Correct order with exception handling
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        try {
            // ok: java-cipherupdateaad
            cipher.updateAAD(aad);
        } catch (Exception e) {
            // Handle exception
        }
        
        try {
            cipher.update(plaintext);
        } catch (Exception e) {
            // Handle exception
        }
        
        return cipher.doFinal();
    }

    public byte[] good_case_13(byte[] plaintext, byte[] aad) throws Exception {
        // Correct order with ternary operator
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        boolean shouldAddAAD = true;
        
        // ok: java-cipherupdateaad
        if (shouldAddAAD) {
            cipher.updateAAD(aad);
        }
        
        boolean shouldUpdate = true;
        byte[] firstPart = shouldUpdate ? cipher.update(plaintext, 0, 10) : new byte[0];
        
        return concatenate(firstPart, cipher.doFinal(plaintext, 10, plaintext.length - 10));
    }

    public byte[] good_case_14(byte[] plaintext, byte[] aad) throws Exception {
        // Correct order with multiple ciphers
        Cipher cipher1 = Cipher.getInstance("AES/GCM/NoPadding");
        Cipher cipher2 = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        
        cipher1.init(Cipher.ENCRYPT_MODE, key, spec);
        cipher2.init(Cipher.ENCRYPT_MODE, key, spec);
        
        // ok: java-cipherupdateaad
        cipher1.updateAAD(aad);
        cipher1.update(plaintext);
        
        return cipher1.doFinal();
    }

    public byte[] good_case_15(byte[] plaintext, byte[] aad) throws Exception {
        // Direct doFinal without update (no AAD order issue)
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        
        // ok: java-cipherupdateaad
        cipher.updateAAD(aad);
        
        // No update call, directly using doFinal with the plaintext
        return cipher.doFinal(plaintext);
    }

    // Helper method to concatenate byte arrays
    private byte[] concatenate(byte[] a, byte[] b) {
        if (a == null || a.length == 0) return b;
        if (b == null || b.length == 0) return a;
        
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}
// {/fact}