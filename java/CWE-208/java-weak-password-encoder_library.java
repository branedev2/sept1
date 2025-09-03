import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import java.security.spec.InvalidKeySpecException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.mindrot.jbcrypt.BCrypt;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.Crypt;
import com.google.common.hash.Hashing;
import java.nio.charset.StandardCharsets;
import org.jasypt.util.password.BasicPasswordEncryptor;
import org.jasypt.util.password.StrongPasswordEncryptor;
import org.jasypt.digest.StandardStringDigester;
import org.jasypt.util.password.ConfigurablePasswordEncryptor;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.bouncycastle.crypto.generators.SCrypt;
import org.passay.PasswordGenerator;
import org.passay.CharacterRule;
import org.passay.EnglishCharacterData;
import at.favre.lib.crypto.bcrypt.BCrypt.Version;
import at.favre.lib.crypto.bcrypt.BCrypt.Hasher;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import de.mkammerer.argon2.Argon2Factory.Argon2Types;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.http.ResponseEntity;
import spark.Request;
import spark.Response;
import spark.Spark;
import io.javalin.Javalin;
import io.javalin.http.Context;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.Base64;

// Security Issue: Weak Password Encoding/Hashing Algorithms

// True Positive Examples (Vulnerable/Insecure Code)
public class WeakPasswordEncoderExamples {

// {fact rule=cryptographic-key-generator@v1.0 defects=1}
    public static void bad_case_1(HttpServletRequest request) {
        String password = request.getParameter("password");
        
        // ruleid: java-weak-password-encoder
        PasswordEncoder encoder = NoOpPasswordEncoder.getInstance();
        String hashedPassword = encoder.encode(password);
        
        System.out.println("Hashed password: " + hashedPassword);
    }

    public static void bad_case_2(HttpServletRequest request) {
        String password = request.getParameter("password");
        try {
            // ruleid: java-weak-password-encoder
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hashedBytes = md.digest(password.getBytes());
            
            StringBuilder sb = new StringBuilder();
            for (byte b : hashedBytes) {
                sb.append(String.format("%02x", b));
            }
            String hashedPassword = sb.toString();
            
            System.out.println("MD5 hashed password: " + hashedPassword);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_3(HttpServletRequest request) {
        String password = request.getParameter("password");
        
        // ruleid: java-weak-password-encoder
        String hashedPassword = DigestUtils.sha1Hex(password);
        
        System.out.println("SHA-1 hashed password: " + hashedPassword);
    }

    public static void bad_case_4(HttpServletRequest request) {
        String password = request.getParameter("password");
        String username = request.getParameter("username");
        
        // ruleid: java-weak-password-encoder
        Md5Hash hash = new Md5Hash(password, username, 1);
        String hashedPassword = hash.toHex();
        
        System.out.println("Apache Shiro MD5 hashed password: " + hashedPassword);
    }

    public static void bad_case_5(HttpServletRequest request) {
        String password = request.getParameter("password");
        
        // ruleid: java-weak-password-encoder
        BasicPasswordEncryptor encryptor = new BasicPasswordEncryptor();
        String hashedPassword = encryptor.encryptPassword(password);
        
        System.out.println("Jasypt Basic hashed password: " + hashedPassword);
    }

    public static void bad_case_6(HttpServletRequest request) {
        String password = request.getParameter("password");
        
        // ruleid: java-weak-password-encoder
        String hashedPassword = Hashing.sha1().hashString(password, StandardCharsets.UTF_8).toString();
        
        System.out.println("Guava SHA-1 hashed password: " + hashedPassword);
    }

    public static void bad_case_7(HttpServletRequest request) {
        String password = request.getParameter("password");
        
        // ruleid: java-weak-password-encoder
        StandardStringDigester digester = new StandardStringDigester();
        digester.setAlgorithm("MD5");
        digester.setIterations(1);
        String hashedPassword = digester.digest(password);
        
        System.out.println("Jasypt MD5 Digester hashed password: " + hashedPassword);
    }

    public static void bad_case_8(HttpServletRequest request) {
        String password = request.getParameter("password");
        
        // ruleid: java-weak-password-encoder
        ConfigurablePasswordEncryptor encryptor = new ConfigurablePasswordEncryptor();
        encryptor.setAlgorithm("SHA-1");
        encryptor.setPlainDigest(true);
        String hashedPassword = encryptor.encryptPassword(password);
        
        System.out.println("Jasypt SHA-1 hashed password: " + hashedPassword);
    }

    public static void bad_case_9(HttpServletRequest request) {
        String password = request.getParameter("password");
        
        try {
            // ruleid: java-weak-password-encoder
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] hashedBytes = md.digest(password.getBytes());
            String hashedPassword = Base64.getEncoder().encodeToString(hashedBytes);
            
            System.out.println("SHA-1 Base64 hashed password: " + hashedPassword);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_10(Request request) {
        String password = request.queryParams("password");
        
        // ruleid: java-weak-password-encoder
        String hashedPassword = DigestUtils.md5Hex(password);
        
        System.out.println("Apache Commons Codec MD5 hashed password: " + hashedPassword);
    }

    public static void bad_case_11(Context ctx) {
        String password = ctx.formParam("password");
        
        // ruleid: java-weak-password-encoder
        SimpleHash hash = new SimpleHash("SHA-1", password);
        String hashedPassword = hash.toHex();
        
        System.out.println("Apache Shiro SHA-1 hashed password: " + hashedPassword);
    }

    public static void bad_case_12(HttpExchange exchange) throws IOException {
        String query = exchange.getRequestURI().getQuery();
        String password = query.substring(query.indexOf("password=") + 9);
        
        try {
            // ruleid: java-weak-password-encoder
            MessageDigest md = MessageDigest.getInstance("SHA-224");
            byte[] hashedBytes = md.digest(password.getBytes());
            
            StringBuilder sb = new StringBuilder();
            for (byte b : hashedBytes) {
                sb.append(String.format("%02x", b));
            }
            String hashedPassword = sb.toString();
            
            System.out.println("SHA-224 hashed password: " + hashedPassword);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static void bad_case_13(HttpServletRequest request) {
        String password = request.getParameter("password");
        
        // ruleid: java-weak-password-encoder
        StandardPasswordEncoder encoder = new StandardPasswordEncoder();
        String hashedPassword = encoder.encode(password);
        
        System.out.println("Spring Security Standard (SHA-256) hashed password: " + hashedPassword);
    }

    public static void bad_case_14(HttpServletRequest request) {
        String password = request.getParameter("password");
        String salt = request.getParameter("salt");
        
        // ruleid: java-weak-password-encoder
        String hashedPassword = Crypt.crypt(password, salt);
        
        System.out.println("Apache Commons Codec Crypt hashed password: " + hashedPassword);
    }

    public static void bad_case_15(HttpServletRequest request) {
        String password = request.getParameter("password");
        
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        // ruleid: java-weak-password-encoder
        encoders.put("md5", new org.springframework.security.crypto.password.MessageDigestPasswordEncoder("MD5"));
        DelegatingPasswordEncoder delegatingEncoder = new DelegatingPasswordEncoder("md5", encoders);
        
        String hashedPassword = delegatingEncoder.encode(password);
        System.out.println("Spring Security MD5 Delegating hashed password: " + hashedPassword);
    }

    // True Negative Examples (Safe/Secure Code)
    public static void good_case_1(HttpServletRequest request) {
        String password = request.getParameter("password");
        
        // ok: java-weak-password-encoder
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
        String hashedPassword = encoder.encode(password);
        
        System.out.println("BCrypt hashed password: " + hashedPassword);
    }

    public static void good_case_2(HttpServletRequest request) {
        String password = request.getParameter("password");
        
        // ok: java-weak-password-encoder
        String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt(12));
        
        System.out.println("JBCrypt hashed password: " + hashedPassword);
    }

    public static void good_case_3(HttpServletRequest request) {
        String password = request.getParameter("password");
        
        try {
            // ok: java-weak-password-encoder
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), 
                                            "randomsalt".getBytes(), 
                                            65536, 
                                            256);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = skf.generateSecret(spec).getEncoded();
            
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            String hashedPassword = sb.toString();
            
            System.out.println("PBKDF2 hashed password: " + hashedPassword);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    public static void good_case_4(HttpServletRequest request) {
        String password = request.getParameter("password");
        
        // ok: java-weak-password-encoder
        Pbkdf2PasswordEncoder encoder = new Pbkdf2PasswordEncoder("secret", 8, 185000, 256);
        String hashedPassword = encoder.encode(password);
        
        System.out.println("Spring Security PBKDF2 hashed password: " + hashedPassword);
    }

    public static void good_case_5(HttpServletRequest request) {
        String password = request.getParameter("password");
        
        // ok: java-weak-password-encoder
        SCryptPasswordEncoder encoder = new SCryptPasswordEncoder();
        String hashedPassword = encoder.encode(password);
        
        System.out.println("Spring Security SCrypt hashed password: " + hashedPassword);
    }

    public static void good_case_6(HttpServletRequest request) {
        String password = request.getParameter("password");
        
        // ok: java-weak-password-encoder
        Argon2PasswordEncoder encoder = new Argon2PasswordEncoder();
        String hashedPassword = encoder.encode(password);
        
        System.out.println("Spring Security Argon2 hashed password: " + hashedPassword);
    }

    public static void good_case_7(HttpServletRequest request) {
        String password = request.getParameter("password");
        
        // ok: java-weak-password-encoder
        StrongPasswordEncryptor encryptor = new StrongPasswordEncryptor();
        String hashedPassword = encryptor.encryptPassword(password);
        
        System.out.println("Jasypt Strong hashed password: " + hashedPassword);
    }

    public static void good_case_8(HttpServletRequest request) {
        String password = request.getParameter("password");
        String salt = request.getParameter("username");
        
        // ok: java-weak-password-encoder
        Sha256Hash hash = new Sha256Hash(password, salt, 10000);
        String hashedPassword = hash.toHex();
        
        System.out.println("Apache Shiro SHA-256 hashed password: " + hashedPassword);
    }

    public static void good_case_9(Request request) {
        String password = request.queryParams("password");
        
        // ok: java-weak-password-encoder
        byte[] salt = new byte[16];
        java.security.SecureRandom.getInstanceStrong().nextBytes(salt);
        byte[] hashedBytes = SCrypt.generate(password.getBytes(), salt, 16384, 8, 1, 32);
        String hashedPassword = Base64.getEncoder().encodeToString(hashedBytes);
        
        System.out.println("Bouncy Castle SCrypt hashed password: " + hashedPassword);
    }

    public static void good_case_10(Context ctx) {
        String password = ctx.formParam("password");
        
        // ok: java-weak-password-encoder
        Argon2 argon2 = Argon2Factory.create(Argon2Types.ARGON2id);
        String hashedPassword = argon2.hash(4, 65536, 1, password.toCharArray());
        
        System.out.println("Argon2 hashed password: " + hashedPassword);
    }

    public static void good_case_11(HttpExchange exchange) throws IOException {
        String query = exchange.getRequestURI().getQuery();
        String password = query.substring(query.indexOf("password=") + 9);
        
        // ok: java-weak-password-encoder
        Hasher hasher = at.favre.lib.crypto.bcrypt.BCrypt.withDefaults();
        String hashedPassword = hasher.hashToString(12, password.toCharArray());
        
        System.out.println("Favre BCrypt hashed password: " + hashedPassword);
    }

    public static void good_case_12(HttpServletRequest request) {
        String password = request.getParameter("password");
        
        // ok: java-weak-password-encoder
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        String hashedPassword = encoder.encode(password);
        
        System.out.println("Spring Security Default Delegating hashed password: " + hashedPassword);
    }

    public static void good_case_13(HttpServletRequest request) {
        String password = request.getParameter("password");
        
        // ok: java-weak-password-encoder
        byte[] salt = new byte[16];
        java.security.SecureRandom.getInstanceStrong().nextBytes(salt);
        String hashedPassword = OpenBSDBCrypt.generate("2b", salt, password.getBytes(), 12);
        
        System.out.println("Bouncy Castle OpenBSD BCrypt hashed password: " + hashedPassword);
    }

    public static void good_case_14(HttpServletRequest request) {
        String password = request.getParameter("password");
        
        // ok: java-weak-password-encoder
        StandardStringDigester digester = new StandardStringDigester();
        digester.setAlgorithm("SHA-256");
        digester.setIterations(10000);
        digester.setSaltSizeBytes(16);
        String hashedPassword = digester.digest(password);
        
        System.out.println("Jasypt SHA-256 Digester hashed password: " + hashedPassword);
    }

    public static void good_case_15(HttpServletRequest request) {
        String password = request.getParameter("password");
        
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        // ok: java-weak-password-encoder
        encoders.put("bcrypt", new BCryptPasswordEncoder(12));
        encoders.put("pbkdf2", new Pbkdf2PasswordEncoder());
        DelegatingPasswordEncoder delegatingEncoder = new DelegatingPasswordEncoder("bcrypt", encoders);
        
        String hashedPassword = delegatingEncoder.encode(password);
        System.out.println("Spring Security Strong Delegating hashed password: " + hashedPassword);
    }
}
// {/fact}