import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;
import redis.clients.jedis.exceptions.JedisConnectionException;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.io.Serializable;
import java.util.List;
import java.util.ArrayList;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.ListOperations;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import java.time.Duration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

public class RedisDataLossExamples {

    // True Positives (Vulnerable Code)

// {fact rule=resource-leak@v1.0 defects=1}
    public void bad_case_1() {
        Jedis jedis = null;
        try {
            jedis = new Jedis("localhost");
            String key = "user:profile:1001";
            // ruleid: java-cache-data-loss-from-redis
            jedis.set(key, null); // Attempting to store null value directly
        } finally {
            if (jedis != null) {
                jedis.close();
            }
        }
    }

    public void bad_case_2() {
        JedisPool pool = new JedisPool(new JedisPoolConfig(), "localhost");
        Jedis jedis = null;
        try {
            jedis = pool.getResource();
            String userId = "1002";
            String userProfile = fetchUserProfile(userId);
            // ruleid: java-cache-data-loss-from-redis
            jedis.set("user:" + userId, userProfile); // No validation if userProfile is null
        } finally {
            if (jedis != null) {
                jedis.close();
            }
            pool.close();
        }
    }

    private String fetchUserProfile(String userId) {
        // This could return null in some cases
        return null;
    }

    public void bad_case_3(RedisTemplate<String, Object> redisTemplate) {
        String key = "product:inventory:1003";
        Integer quantity = getProductQuantity(); // Could be null
        ValueOperations<String, Object> ops = redisTemplate.opsForValue();
        // ruleid: java-cache-data-loss-from-redis
        ops.set(key, quantity); // No null check before storing
    }

    private Integer getProductQuantity() {
        // This could return null
        return null;
    }

    public void bad_case_4() {
        Jedis jedis = new Jedis("localhost");
        Map<String, String> userMap = new HashMap<>();
        userMap.put("name", "John");
        userMap.put("email", null); // Null email
        // ruleid: java-cache-data-loss-from-redis
        jedis.hmset("user:1004", userMap); // Map contains null value
        jedis.close();
    }

    public void bad_case_5(RedisTemplate<String, String> redisTemplate) {
        HashOperations<String, Object, Object> hashOps = redisTemplate.opsForHash();
        String key = "session:1005";
        String sessionData = retrieveSessionData();
        // ruleid: java-cache-data-loss-from-redis
        hashOps.put(key, "data", sessionData); // No validation if sessionData is null
    }

    private String retrieveSessionData() {
        // Could return null
        return null;
    }

    public void bad_case_6() {
        JedisPool pool = new JedisPool(new JedisPoolConfig(), "localhost");
        Jedis jedis = pool.getResource();
        try {
            String[] values = new String[]{"value1", null, "value3"};
            // ruleid: java-cache-data-loss-from-redis
            jedis.rpush("list:1006", values); // Array contains null value
        } finally {
            jedis.close();
            pool.close();
        }
    }

    public void bad_case_7(RedisTemplate<String, List<String>> redisTemplate) {
        ListOperations<String, List<String>> listOps = redisTemplate.opsForList();
        List<String> dataList = generateDataList();
        // ruleid: java-cache-data-loss-from-redis
        listOps.rightPushAll("list:1007", dataList); // No check if dataList is null
    }

    private List<String> generateDataList() {
        // Could return null
        return null;
    }

    public void bad_case_8() {
        Jedis jedis = new Jedis("localhost");
        String key = "config:1008";
        String value = getConfigValue();
        try {
            // ruleid: java-cache-data-loss-from-redis
            jedis.setex(key, 3600, value); // No validation if value is null
        } finally {
            jedis.close();
        }
    }

    private String getConfigValue() {
        // Could return null
        return null;
    }

    public void bad_case_9(RedisTemplate<String, Object> redisTemplate) {
        String key = "cache:1009";
        Object value = fetchCachedObject();
        ValueOperations<String, Object> ops = redisTemplate.opsForValue();
        // ruleid: java-cache-data-loss-from-redis
        ops.set(key, value, 1, TimeUnit.HOURS); // No check if value is null
    }

    private Object fetchCachedObject() {
        // Could return null
        return null;
    }

    public void bad_case_10() {
        JedisPool pool = new JedisPool(new JedisPoolConfig(), "localhost");
        Jedis jedis = null;
        try {
            jedis = pool.getResource();
            Map<String, String> hash = new HashMap<>();
            hash.put("field1", "value1");
            String nullableValue = getNullableValue();
            hash.put("field2", nullableValue); // Could be null
            // ruleid: java-cache-data-loss-from-redis
            jedis.hmset("hash:1010", hash); // No validation of map values
        } finally {
            if (jedis != null) {
                jedis.close();
            }
            pool.close();
        }
    }

    private String getNullableValue() {
        // Could return null
        return null;
    }

    @Service
    public class BadCacheService11 {
        private final RedisTemplate<String, Object> redisTemplate;

        public BadCacheService11(RedisTemplate<String, Object> redisTemplate) {
            this.redisTemplate = redisTemplate;
        }

        public void cacheUserData(String userId) {
            Map<String, Object> userData = getUserData(userId);
            HashOperations<String, String, Object> hashOps = redisTemplate.opsForHash();
            // ruleid: java-cache-data-loss-from-redis
            hashOps.putAll("user:" + userId, userData); // No validation if userData is null or contains null values
        }

        private Map<String, Object> getUserData(String userId) {
            // Could return null or map with null values
            return null;
        }
    }

    public void bad_case_12() {
        Jedis jedis = new Jedis("localhost");
        try {
            String key = "transaction:1012";
            String transactionData = getTransactionData();
            // ruleid: java-cache-data-loss-from-redis
            jedis.set(key, transactionData); // No validation if transactionData is null
            jedis.expire(key, 3600);
        } finally {
            jedis.close();
        }
    }

    private String getTransactionData() {
        // Could return null
        return null;
    }

    public void bad_case_13(RedisTemplate<String, String> redisTemplate) {
        String key = "notification:1013";
        String message = getNotificationMessage();
        ValueOperations<String, String> ops = redisTemplate.opsForValue();
        // ruleid: java-cache-data-loss-from-redis
        if (key != null) { // Only checking key, not value
            ops.set(key, message, 30, TimeUnit.MINUTES);
        }
    }

    private String getNotificationMessage() {
        // Could return null
        return null;
    }

    public void bad_case_14() {
        JedisPool pool = new JedisPool(new JedisPoolConfig(), "localhost");
        Jedis jedis = null;
        try {
            jedis = pool.getResource();
            String[] fields = {"field1", "field2", "field3"};
            String[] values = getFieldValues(); // Could be null or contain null values
            // ruleid: java-cache-data-loss-from-redis
            for (int i = 0; i < fields.length; i++) {
                jedis.hset("hash:1014", fields[i], values[i]); // No validation if values[i] is null
            }
        } finally {
            if (jedis != null) {
                jedis.close();
            }
            pool.close();
        }
    }

    private String[] getFieldValues() {
        // Could return array with null values
        return new String[]{"value1", null, "value3"};
    }

    public void bad_case_15(RedisTemplate<String, List<String>> redisTemplate) {
        String key = "logs:1015";
        List<String> logEntries = getLogEntries();
        ListOperations<String, List<String>> listOps = redisTemplate.opsForList();
        // ruleid: java-cache-data-loss-from-redis
        for (String entry : logEntries) { // No null check on logEntries
            listOps.rightPush(key, entry); // No validation if entry is null
        }
    }

    private List<String> getLogEntries() {
        // Could return list with null entries
        List<String> logs = new ArrayList<>();
        logs.add("log1");
        logs.add(null);
        logs.add("log3");
        return logs;
    }

    // True Negatives (Safe Code)

    public void good_case_1() {
        Jedis jedis = null;
        try {
            jedis = new Jedis("localhost");
            String key = "user:profile:2001";
            String value = getUserProfile();
            // ok: java-cache-data-loss-from-redis
            if (value != null) {
                jedis.set(key, value); // Properly checking for null before storing
            }
        } finally {
            if (jedis != null) {
                jedis.close();
            }
        }
    }

    private String getUserProfile() {
        // Could return null
        return "profile data";
    }

    public void good_case_2() {
        JedisPool pool = new JedisPool(new JedisPoolConfig(), "localhost");
        Jedis jedis = null;
        try {
            jedis = pool.getResource();
            String userId = "2002";
            String userProfile = fetchUserProfileSafe(userId);
            // ok: java-cache-data-loss-from-redis
            if (userProfile != null) {
                jedis.set("user:" + userId, userProfile);
            } else {
                // Handle null case, e.g., log warning or use default value
                jedis.set("user:" + userId, "{}"); // Default empty JSON
            }
        } finally {
            if (jedis != null) {
                jedis.close();
            }
            pool.close();
        }
    }

    private String fetchUserProfileSafe(String userId) {
        // This could return null in some cases
        return "user profile data";
    }

    public void good_case_3(RedisTemplate<String, Object> redisTemplate) {
        String key = "product:inventory:2003";
        Integer quantity = getProductQuantitySafe();
        ValueOperations<String, Object> ops = redisTemplate.opsForValue();
        // ok: java-cache-data-loss-from-redis
        if (quantity != null) {
            ops.set(key, quantity);
        } else {
            ops.set(key, 0); // Default value when quantity is null
        }
    }

    private Integer getProductQuantitySafe() {
        // This could return null
        return 100;
    }

    public void good_case_4() {
        Jedis jedis = new Jedis("localhost");
        Map<String, String> userMap = new HashMap<>();
        userMap.put("name", "John");
        
        String email = getUserEmail();
        // ok: java-cache-data-loss-from-redis
        userMap.put("email", email != null ? email : ""); // Handling null email
        
        jedis.hmset("user:2004", userMap);
        jedis.close();
    }

    private String getUserEmail() {
        // Could return null
        return "john@example.com";
    }

    public void good_case_5(RedisTemplate<String, String> redisTemplate) {
        HashOperations<String, Object, Object> hashOps = redisTemplate.opsForHash();
        String key = "session:2005";
        String sessionData = retrieveSessionDataSafe();
        // ok: java-cache-data-loss-from-redis
        hashOps.put(key, "data", sessionData != null ? sessionData : "{}"); // Handling null
    }

    private String retrieveSessionDataSafe() {
        // Could return null
        return "session data";
    }

    public void good_case_6() {
        JedisPool pool = new JedisPool(new JedisPoolConfig(), "localhost");
        Jedis jedis = pool.getResource();
        try {
            String[] rawValues = new String[]{"value1", null, "value3"};
            List<String> validValues = new ArrayList<>();
            
            // ok: java-cache-data-loss-from-redis
            for (String value : rawValues) {
                if (value != null) {
                    validValues.add(value);
                }
            }
            
            jedis.rpush("list:2006", validValues.toArray(new String[0]));
        } finally {
            jedis.close();
            pool.close();
        }
    }

    public void good_case_7(RedisTemplate<String, List<String>> redisTemplate) {
        ListOperations<String, List<String>> listOps = redisTemplate.opsForList();
        List<String> dataList = generateDataListSafe();
        // ok: java-cache-data-loss-from-redis
        if (dataList != null && !dataList.isEmpty()) {
            listOps.rightPushAll("list:2007", dataList);
        }
    }

    private List<String> generateDataListSafe() {
        List<String> list = new ArrayList<>();
        list.add("item1");
        list.add("item2");
        return list;
    }

    public void good_case_8() {
        Jedis jedis = new Jedis("localhost");
        String key = "config:2008";
        String value = getConfigValueSafe();
        try {
            // ok: java-cache-data-loss-from-redis
            if (value != null) {
                jedis.setex(key, 3600, value);
            } else {
                jedis.setex(key, 3600, "default_config");
            }
        } finally {
            jedis.close();
        }
    }

    private String getConfigValueSafe() {
        // Could return null
        return "config value";
    }

    public void good_case_9(RedisTemplate<String, Object> redisTemplate) {
        String key = "cache:2009";
        Object value = fetchCachedObjectSafe();
        ValueOperations<String, Object> ops = redisTemplate.opsForValue();
        // ok: java-cache-data-loss-from-redis
        if (value != null) {
            ops.set(key, value, 1, TimeUnit.HOURS);
        }
    }

    private Object fetchCachedObjectSafe() {
        // Could return null
        return new Object();
    }

    public void good_case_10() {
        JedisPool pool = new JedisPool(new JedisPoolConfig(), "localhost");
        Jedis jedis = null;
        try {
            jedis = pool.getResource();
            Map<String, String> hash = new HashMap<>();
            hash.put("field1", "value1");
            
            String nullableValue = getNullableValueSafe();
            // ok: java-cache-data-loss-from-redis
            if (nullableValue != null) {
                hash.put("field2", nullableValue);
            } else {
                hash.put("field2", ""); // Default empty string
            }
            
            jedis.hmset("hash:2010", hash);
        } finally {
            if (jedis != null) {
                jedis.close();
            }
            pool.close();
        }
    }

    private String getNullableValueSafe() {
        // Could return null
        return "safe value";
    }

    @Service
    public class GoodCacheService11 {
        private final RedisTemplate<String, Object> redisTemplate;

        public GoodCacheService11(RedisTemplate<String, Object> redisTemplate) {
            this.redisTemplate = redisTemplate;
        }

        public void cacheUserData(String userId) {
            Map<String, Object> userData = getUserDataSafe(userId);
            HashOperations<String, String, Object> hashOps = redisTemplate.opsForHash();
            
            // ok: java-cache-data-loss-from-redis
            if (userData != null) {
                // Remove any null values from the map
                userData.entrySet().removeIf(entry -> entry.getValue() == null);
                if (!userData.isEmpty()) {
                    hashOps.putAll("user:" + userId, userData);
                }
            }
        }

        private Map<String, Object> getUserDataSafe(String userId) {
            Map<String, Object> data = new HashMap<>();
            data.put("name", "User " + userId);
            data.put("email", "user" + userId + "@example.com");
            return data;
        }
    }

    public void good_case_12() {
        Jedis jedis = new Jedis("localhost");
        try {
            String key = "transaction:2012";
            String transactionData = getTransactionDataSafe();
            // ok: java-cache-data-loss-from-redis
            if (transactionData != null) {
                jedis.set(key, transactionData);
                jedis.expire(key, 3600);
            } else {
                // Log error or handle the null case appropriately
                System.err.println("Transaction data was null, not caching");
            }
        } finally {
            jedis.close();
        }
    }

    private String getTransactionDataSafe() {
        // Could return null
        return "transaction data";
    }

    public void good_case_13(RedisTemplate<String, String> redisTemplate) {
        String key = "notification:2013";
        String message = getNotificationMessageSafe();
        ValueOperations<String, String> ops = redisTemplate.opsForValue();
        // ok: java-cache-data-loss-from-redis
        if (key != null && message != null) { // Checking both key and value
            ops.set(key, message, 30, TimeUnit.MINUTES);
        }
    }

    private String getNotificationMessageSafe() {
        // Could return null
        return "notification message";
    }

    public void good_case_14() {
        JedisPool pool = new JedisPool(new JedisPoolConfig(), "localhost");
        Jedis jedis = null;
        try {
            jedis = pool.getResource();
            String[] fields = {"field1", "field2", "field3"};
            String[] values = getFieldValuesSafe();
            
            // ok: java-cache-data-loss-from-redis
            if (values != null && values.length == fields.length) {
                for (int i = 0; i < fields.length; i++) {
                    if (values[i] != null) {
                        jedis.hset("hash:2014", fields[i], values[i]);
                    } else {
                        jedis.hset("hash:2014", fields[i], ""); // Default value
                    }
                }
            }
        } finally {
            if (jedis != null) {
                jedis.close();
            }
            pool.close();
        }
    }

    private String[] getFieldValuesSafe() {
        return new String[]{"value1", "value2", "value3"};
    }

    public void good_case_15(RedisTemplate<String, String> redisTemplate) {
        String key = "logs:2015";
        List<String> logEntries = getLogEntriesSafe();
        ListOperations<String, String> listOps = redisTemplate.opsForList();
        
        // ok: java-cache-data-loss-from-redis
        if (logEntries != null) {
            for (String entry : logEntries) {
                if (entry != null) {
                    listOps.rightPush(key, entry);
                }
            }
        }
    }

    private List<String> getLogEntriesSafe() {
        List<String> logs = new ArrayList<>();
        logs.add("log1");
        logs.add("log2");
        logs.add("log3");
        return logs;
    }

    // Helper methods
    @Configuration
    public class RedisConfig {
        @Bean
        public JedisConnectionFactory jedisConnectionFactory() {
            return new JedisConnectionFactory();
        }
        
        @Bean
        public RedisTemplate<String, Object> redisTemplate() {
            RedisTemplate<String, Object> template = new RedisTemplate<>();
            template.setConnectionFactory(jedisConnectionFactory());
            template.setKeySerializer(new StringRedisSerializer());
            template.setValueSerializer(new GenericJackson2JsonRedisSerializer());
            template.setHashKeySerializer(new StringRedisSerializer());
            template.setHashValueSerializer(new GenericJackson2JsonRedisSerializer());
            return template;
        }
        
        @Bean
        public RedisCacheManager cacheManager(RedisConnectionFactory connectionFactory) {
            RedisCacheConfiguration config = RedisCacheConfiguration.defaultCacheConfig()
                .entryTtl(Duration.ofMinutes(10))
                .disableCachingNullValues(); // Important for preventing null values in cache
                
            return RedisCacheManager.builder(connectionFactory)
                .cacheDefaults(config)
                .build();
        }
    }
}
// {/fact}