import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class InheritableThreadLocalExamples {

    // True Positives (Vulnerable Code)

// {fact rule=thread-safety-violation@v1.0 defects=1}
    public void bad_case_1() {
        // ruleid: java-inheritable-thread-local
        InheritableThreadLocal<String> passwordStorage = new InheritableThreadLocal<>();
        passwordStorage.set("sensitive_password");
        
        Thread childThread = new Thread(() -> {
            // Child thread can access the password
            String password = passwordStorage.get();
            System.out.println("Password accessed in child thread: " + password);
        });
        childThread.start();
    }

    public void bad_case_2() {
        // ruleid: java-inheritable-thread-local
        InheritableThreadLocal<SecretKey> secretKeyStorage = new InheritableThreadLocal<SecretKey>() {
            @Override
            protected SecretKey initialValue() {
                try {
                    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                    keyGen.init(256);
                    return keyGen.generateKey();
                } catch (Exception e) {
                    return null;
                }
            }
        };
        
        new Thread(() -> {
            SecretKey key = secretKeyStorage.get();
            System.out.println("Secret key accessed in child thread");
        }).start();
    }

    public void bad_case_3() {
        // ruleid: java-inheritable-thread-local
        InheritableThreadLocal<Map<String, String>> userCredentials = new InheritableThreadLocal<>();
        Map<String, String> credentials = new HashMap<>();
        credentials.put("username", "admin");
        credentials.put("password", "secret123");
        userCredentials.set(credentials);
        
        ExecutorService executor = Executors.newSingleThreadExecutor();
        executor.submit(() -> {
            Map<String, String> creds = userCredentials.get();
            System.out.println("Credentials accessed: " + creds);
        });
        executor.shutdown();
    }

    public void bad_case_4() {
        // ruleid: java-inheritable-thread-local
        final InheritableThreadLocal<byte[]> sessionTokens = new InheritableThreadLocal<>();
        sessionTokens.set(new SecureRandom().generateSeed(16));
        
        Runnable task = () -> {
            byte[] token = sessionTokens.get();
            System.out.println("Token accessed: " + Base64.getEncoder().encodeToString(token));
        };
        new Thread(task).start();
    }

    public void bad_case_5() {
        class SensitiveData {
            private String apiKey;
            public SensitiveData(String key) { this.apiKey = key; }
            public String getApiKey() { return apiKey; }
        }
        
        // ruleid: java-inheritable-thread-local
        InheritableThreadLocal<SensitiveData> apiKeyStorage = new InheritableThreadLocal<>();
        apiKeyStorage.set(new SensitiveData("api_secret_key_12345"));
        
        Thread thread = new Thread(() -> {
            SensitiveData data = apiKeyStorage.get();
            System.out.println("API Key: " + data.getApiKey());
        });
        thread.start();
    }

    public void bad_case_6() {
        // ruleid: java-inheritable-thread-local
        final InheritableThreadLocal<String[]> databaseCredentials = new InheritableThreadLocal<>();
        databaseCredentials.set(new String[]{"jdbc:mysql://localhost:3306/db", "root", "password"});
        
        ExecutorService executor = Executors.newFixedThreadPool(5);
        for (int i = 0; i < 5; i++) {
            executor.execute(() -> {
                String[] credentials = databaseCredentials.get();
                System.out.println("Database URL: " + credentials[0]);
            });
        }
        executor.shutdown();
    }

    public void bad_case_7() {
        // ruleid: java-inheritable-thread-local
        InheritableThreadLocal<Integer> sensitiveUserIds = new InheritableThreadLocal<Integer>() {
            @Override
            protected Integer initialValue() {
                return 12345; // Admin user ID
            }
        };
        
        Thread childThread = new Thread(() -> {
            Integer userId = sensitiveUserIds.get();
            System.out.println("Operating with user ID: " + userId);
        });
        childThread.start();
    }

    public void bad_case_8() {
        // ruleid: java-inheritable-thread-local
        InheritableThreadLocal<Boolean> adminPrivileges = new InheritableThreadLocal<>();
        adminPrivileges.set(true);
        
        Runnable task = () -> {
            if (adminPrivileges.get()) {
                System.out.println("Executing with admin privileges");
            }
        };
        new Thread(task).start();
    }

    public void bad_case_9() {
        class AuthToken {
            private String token;
            public AuthToken(String t) { token = t; }
            public String getToken() { return token; }
        }
        
        // ruleid: java-inheritable-thread-local
        InheritableThreadLocal<AuthToken> authTokenStorage = new InheritableThreadLocal<>();
        authTokenStorage.set(new AuthToken("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
        
        ExecutorService service = Executors.newCachedThreadPool();
        service.submit(() -> {
            AuthToken token = authTokenStorage.get();
            System.out.println("Using auth token: " + token.getToken());
        });
        service.shutdown();
    }

    public void bad_case_10() {
        // ruleid: java-inheritable-thread-local
        InheritableThreadLocal<Long> sessionExpiryTime = new InheritableThreadLocal<>();
        sessionExpiryTime.set(System.currentTimeMillis() + 3600000); // 1 hour from now
        
        Thread thread = new Thread(() -> {
            Long expiry = sessionExpiryTime.get();
            if (System.currentTimeMillis() < expiry) {
                System.out.println("Session is valid");
            }
        });
        thread.start();
    }

    public void bad_case_11() {
        // ruleid: java-inheritable-thread-local
        InheritableThreadLocal<StringBuilder> sqlQueryBuilder = new InheritableThreadLocal<>();
        sqlQueryBuilder.set(new StringBuilder("SELECT * FROM users WHERE role='admin'"));
        
        Thread thread = new Thread(() -> {
            StringBuilder query = sqlQueryBuilder.get();
            System.out.println("Executing query: " + query.toString());
        });
        thread.start();
    }

    public void bad_case_12() {
        // ruleid: java-inheritable-thread-local
        InheritableThreadLocal<Map<String, Object>> userContext = new InheritableThreadLocal<>();
        Map<String, Object> context = new HashMap<>();
        context.put("userId", 1001);
        context.put("isAdmin", true);
        context.put("sessionToken", "abc123xyz");
        userContext.set(context);
        
        ExecutorService executor = Executors.newSingleThreadExecutor();
        executor.submit(() -> {
            Map<String, Object> ctx = userContext.get();
            System.out.println("User context: " + ctx);
        });
        executor.shutdown();
    }

    public void bad_case_13() {
        class EncryptionKey {
            private byte[] keyData;
            public EncryptionKey(byte[] data) { this.keyData = data; }
            public byte[] getKeyData() { return keyData; }
        }
        
        // ruleid: java-inheritable-thread-local
        InheritableThreadLocal<EncryptionKey> encryptionKeyStorage = new InheritableThreadLocal<>();
        encryptionKeyStorage.set(new EncryptionKey(new SecureRandom().generateSeed(32)));
        
        Thread thread = new Thread(() -> {
            EncryptionKey key = encryptionKeyStorage.get();
            System.out.println("Using encryption key for operation");
        });
        thread.start();
    }

    public void bad_case_14() {
        // ruleid: java-inheritable-thread-local
        InheritableThreadLocal<String> oauthTokenStorage = new InheritableThreadLocal<String>() {
            @Override
            protected String initialValue() {
                return "oauth2_access_token_value";
            }
        };
        
        ExecutorService executor = Executors.newFixedThreadPool(3);
        for (int i = 0; i < 3; i++) {
            executor.execute(() -> {
                String token = oauthTokenStorage.get();
                System.out.println("Making API call with OAuth token");
            });
        }
        executor.shutdown();
    }

    public void bad_case_15() {
        // ruleid: java-inheritable-thread-local
        InheritableThreadLocal<String[]> sshCredentials = new InheritableThreadLocal<>();
        sshCredentials.set(new String[]{"username", "private_key_data"});
        
        Thread thread = new Thread(() -> {
            String[] creds = sshCredentials.get();
            System.out.println("Connecting to SSH with username: " + creds[0]);
        });
        thread.start();
    }

    // True Negatives (Safe Code)

    public void good_case_1() {
        // ok: java-inheritable-thread-local
        ThreadLocal<String> passwordStorage = new ThreadLocal<>();
        passwordStorage.set("sensitive_password");
        
        Thread childThread = new Thread(() -> {
            // Child thread cannot access the password
            String password = passwordStorage.get(); // Will be null
            System.out.println("Password in child thread: " + password);
        });
        childThread.start();
    }

    public void good_case_2() {
        // ok: java-inheritable-thread-local
        ThreadLocal<SecretKey> secretKeyStorage = new ThreadLocal<SecretKey>() {
            @Override
            protected SecretKey initialValue() {
                try {
                    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                    keyGen.init(256);
                    return keyGen.generateKey();
                } catch (Exception e) {
                    return null;
                }
            }
        };
        
        new Thread(() -> {
            SecretKey key = secretKeyStorage.get(); // Will be a new key, not parent's
            System.out.println("Secret key in child thread is different");
        }).start();
    }

    public void good_case_3() {
        // ok: java-inheritable-thread-local
        ThreadLocal<Map<String, String>> userCredentials = new ThreadLocal<>();
        Map<String, String> credentials = new HashMap<>();
        credentials.put("username", "admin");
        credentials.put("password", "secret123");
        userCredentials.set(credentials);
        
        ExecutorService executor = Executors.newSingleThreadExecutor();
        executor.submit(() -> {
            Map<String, String> creds = userCredentials.get(); // Will be null
            System.out.println("Credentials in child thread: " + creds);
        });
        executor.shutdown();
    }

    public void good_case_4() {
        // Using a secure approach to pass data to child threads
        final byte[] sessionToken = new SecureRandom().generateSeed(16);
        
        // ok: java-inheritable-thread-local
        Runnable task = () -> {
            // Explicitly passing the token as a parameter
            processToken(sessionToken);
        };
        new Thread(task).start();
    }
    
    private void processToken(byte[] token) {
        System.out.println("Token processed: " + Base64.getEncoder().encodeToString(token));
    }

    public void good_case_5() {
        class SensitiveData {
            private String apiKey;
            public SensitiveData(String key) { this.apiKey = key; }
            public String getApiKey() { return apiKey; }
        }
        
        // ok: java-inheritable-thread-local
        ThreadLocal<SensitiveData> apiKeyStorage = new ThreadLocal<>();
        apiKeyStorage.set(new SensitiveData("api_secret_key_12345"));
        
        // Pass only what's needed to the child thread
        final String apiKeyForThread = apiKeyStorage.get().getApiKey();
        Thread thread = new Thread(() -> {
            // Using explicitly passed data instead of ThreadLocal
            System.out.println("API Key: " + apiKeyForThread);
        });
        thread.start();
    }

    public void good_case_6() {
        // ok: java-inheritable-thread-local
        final String dbUrl = "jdbc:mysql://localhost:3306/db";
        final String username = "root";
        final String password = "password";
        
        ExecutorService executor = Executors.newFixedThreadPool(5);
        for (int i = 0; i < 5; i++) {
            executor.execute(() -> {
                // Using a connection pool or explicitly passing connection parameters
                System.out.println("Connecting to database: " + dbUrl);
                // createConnection(dbUrl, username, password);
            });
        }
        executor.shutdown();
    }

    public void good_case_7() {
        // ok: java-inheritable-thread-local
        final Integer adminUserId = 12345;
        
        Thread childThread = new Thread(() -> {
            // Explicitly passing the user ID as a final variable
            System.out.println("Operating with user ID: " + adminUserId);
        });
        childThread.start();
    }

    public void good_case_8() {
        // ok: java-inheritable-thread-local
        final boolean hasAdminPrivileges = true;
        
        Runnable task = () -> {
            // Using explicitly passed variable
            if (hasAdminPrivileges) {
                System.out.println("Executing with admin privileges");
            }
        };
        new Thread(task).start();
    }

    public void good_case_9() {
        class AuthToken {
            private String token;
            public AuthToken(String t) { token = t; }
            public String getToken() { return token; }
        }
        
        // ok: java-inheritable-thread-local
        final AuthToken authToken = new AuthToken("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
        
        ExecutorService service = Executors.newCachedThreadPool();
        service.submit(() -> {
            // Using explicitly passed token
            System.out.println("Using auth token: " + authToken.getToken());
        });
        service.shutdown();
    }

    public void good_case_10() {
        // ok: java-inheritable-thread-local
        final long sessionExpiry = System.currentTimeMillis() + 3600000; // 1 hour from now
        
        Thread thread = new Thread(() -> {
            // Using explicitly passed expiry time
            if (System.currentTimeMillis() < sessionExpiry) {
                System.out.println("Session is valid");
            }
        });
        thread.start();
    }

    public void good_case_11() {
        // ok: java-inheritable-thread-local
        final String sqlQuery = "SELECT * FROM users WHERE role='admin'";
        
        Thread thread = new Thread(() -> {
            // Using explicitly passed query
            System.out.println("Executing query: " + sqlQuery);
        });
        thread.start();
    }

    public void good_case_12() {
        // ok: java-inheritable-thread-local
        Map<String, Object> context = new HashMap<>();
        context.put("userId", 1001);
        context.put("isAdmin", true);
        context.put("sessionToken", "abc123xyz");
        
        // Create an immutable copy for thread safety
        final Map<String, Object> immutableContext = new HashMap<>(context);
        
        ExecutorService executor = Executors.newSingleThreadExecutor();
        executor.submit(() -> {
            // Using explicitly passed context
            System.out.println("User context: " + immutableContext);
        });
        executor.shutdown();
    }

    public void good_case_13() {
        class EncryptionKey {
            private byte[] keyData;
            public EncryptionKey(byte[] data) { this.keyData = data; }
            public byte[] getKeyData() { return keyData; }
        }
        
        // ok: java-inheritable-thread-local
        final EncryptionKey encryptionKey = new EncryptionKey(new SecureRandom().generateSeed(32));
        
        Thread thread = new Thread(() -> {
            // Using explicitly passed key
            System.out.println("Using encryption key for operation");
        });
        thread.start();
    }

    public void good_case_14() {
        // ok: java-inheritable-thread-local
        final String oauthToken = "oauth2_access_token_value";
        
        ExecutorService executor = Executors.newFixedThreadPool(3);
        for (int i = 0; i < 3; i++) {
            executor.execute(() -> {
                // Using explicitly passed token
                System.out.println("Making API call with OAuth token: " + oauthToken);
            });
        }
        executor.shutdown();
    }

    public void good_case_15() {
        // ok: java-inheritable-thread-local
        class SecureCredentialProvider {
            public String getUsername() { return "username"; }
            public String getPrivateKey() { return "private_key_data"; }
        }
        
        final SecureCredentialProvider credProvider = new SecureCredentialProvider();
        
        Thread thread = new Thread(() -> {
            // Using a secure credential provider instead of ThreadLocal
            System.out.println("Connecting to SSH with username: " + credProvider.getUsername());
        });
        thread.start();
    }
}
// {/fact}