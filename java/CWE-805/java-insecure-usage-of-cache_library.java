import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.cache.Cache;
import org.apache.commons.cache.CacheFactory;
import org.ehcache.CacheManager;
import org.ehcache.config.builders.CacheConfigurationBuilder;
import org.infinispan.cache.impl.CacheImpl;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import com.google.common.cache.CacheBuilder;
import com.hazelcast.cache.ICache;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import net.sf.ehcache.Element;
import redis.clients.jedis.Jedis;
import org.redisson.api.RMapCache;
import org.redisson.api.RedissonClient;
import org.springframework.data.redis.core.RedisTemplate;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.jboss.cache.Cache;
import org.apache.ignite.IgniteCache;
import org.apache.ignite.Ignition;
import javax.cache.CacheManager;
import javax.cache.Caching;
import org.mapdb.DB;
import org.mapdb.DBMaker;

// Security Issue: Insecure usage of StringByteConverter with Cache can lead to buffer access length errors

// Custom StringByteConverter class for demonstration purposes
class StringByteConverter {
    public byte[] convert(String input) {
        return input.getBytes();
    }
}

// Custom BufferedCache class for demonstration purposes
class BufferedCache {
    private Map<String, byte[]> cache = new HashMap<>();
    
    public void put(String key, byte[] value, int maxSize) {
        if (value.length <= maxSize) {
            cache.put(key, value);
        }
    }
    
    public byte[] get(String key) {
        return cache.get(key);
    }
}

// True Positive Examples (Vulnerable/Insecure Code)
class VulnerableExamples {
    
// {fact rule=incorrect-buffer-length-access@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        // Apache Commons Cache with StringByteConverter
        String userInput = request.getParameter("data");
        StringByteConverter converter = new StringByteConverter();
        Cache cache = CacheFactory.getInstance().createCache();
        
        // ruleid: java-insecure-usage-of-cache
        cache.put("key", converter.convert(userInput));
    }
    
    public void bad_case_2(HttpServletRequest request) {
        // EhCache with StringByteConverter
        String userInput = request.getParameter("data");
        StringByteConverter converter = new StringByteConverter();
        net.sf.ehcache.Cache cache = new net.sf.ehcache.CacheManager().getCache("myCache");
        
        // ruleid: java-insecure-usage-of-cache
        cache.put(new Element("key", converter.convert(userInput)));
    }
    
    public void bad_case_3(HttpServletRequest request) {
        // Google Guava Cache with StringByteConverter
        String userInput = request.getHeader("X-Custom-Data");
        StringByteConverter converter = new StringByteConverter();
        com.google.common.cache.Cache<String, byte[]> cache = CacheBuilder.newBuilder().build();
        
        // ruleid: java-insecure-usage-of-cache
        cache.put("key", converter.convert(userInput));
    }
    
    public void bad_case_4(HttpServletRequest request) {
        // Hazelcast Cache with StringByteConverter
        String userInput = request.getParameter("content");
        StringByteConverter converter = new StringByteConverter();
        HazelcastInstance hazelcastInstance = Hazelcast.newHazelcastInstance();
        ICache<String, byte[]> cache = hazelcastInstance.getCacheManager().getCache("myCache");
        
        // ruleid: java-insecure-usage-of-cache
        cache.put("key", converter.convert(userInput));
    }
    
    public void bad_case_5(HttpServletRequest request) {
        // Redis with StringByteConverter using Jedis
        String userInput = request.getParameter("text");
        StringByteConverter converter = new StringByteConverter();
        Jedis jedis = new Jedis("localhost");
        
        // ruleid: java-insecure-usage-of-cache
        jedis.set("key".getBytes(), converter.convert(userInput));
    }
    
    public void bad_case_6(HttpServletRequest request) {
        // Redisson Cache with StringByteConverter
        String userInput = request.getParameter("message");
        StringByteConverter converter = new StringByteConverter();
        RedissonClient redisson = null; // Initialization would happen in real code
        RMapCache<String, byte[]> cache = redisson.getMapCache("myCache");
        
        // ruleid: java-insecure-usage-of-cache
        cache.put("key", converter.convert(userInput));
    }
    
    public void bad_case_7(HttpServletRequest request) {
        // Spring Redis Template with StringByteConverter
        String userInput = request.getParameter("payload");
        StringByteConverter converter = new StringByteConverter();
        RedisTemplate<String, byte[]> redisTemplate = new RedisTemplate<>();
        
        // ruleid: java-insecure-usage-of-cache
        redisTemplate.opsForValue().set("key", converter.convert(userInput));
    }
    
    public void bad_case_8(HttpServletRequest request) {
        // Caffeine Cache with StringByteConverter
        String userInput = request.getParameter("input");
        StringByteConverter converter = new StringByteConverter();
        com.github.benmanes.caffeine.cache.Cache<String, byte[]> cache = Caffeine.newBuilder().build();
        
        // ruleid: java-insecure-usage-of-cache
        cache.put("key", converter.convert(userInput));
    }
    
    public void bad_case_9(HttpServletRequest request) {
        // JBoss Cache with StringByteConverter
        String userInput = request.getParameter("data");
        StringByteConverter converter = new StringByteConverter();
        org.jboss.cache.Cache cache = new org.jboss.cache.CacheFactory().createCache();
        
        // ruleid: java-insecure-usage-of-cache
        cache.put("/node/key", converter.convert(userInput));
    }
    
    public void bad_case_10(HttpServletRequest request) {
        // Apache Ignite Cache with StringByteConverter
        String userInput = request.getParameter("content");
        StringByteConverter converter = new StringByteConverter();
        IgniteCache<String, byte[]> cache = Ignition.ignite().getOrCreateCache("myCache");
        
        // ruleid: java-insecure-usage-of-cache
        cache.put("key", converter.convert(userInput));
    }
    
    public void bad_case_11(HttpServletRequest request) {
        // JSR-107 JCache with StringByteConverter
        String userInput = request.getParameter("text");
        StringByteConverter converter = new StringByteConverter();
        javax.cache.Cache<String, byte[]> cache = Caching.getCachingProvider()
            .getCacheManager().getCache("myCache");
        
        // ruleid: java-insecure-usage-of-cache
        cache.put("key", converter.convert(userInput));
    }
    
    public void bad_case_12(HttpServletRequest request) {
        // MapDB with StringByteConverter
        String userInput = request.getParameter("data");
        StringByteConverter converter = new StringByteConverter();
        DB db = DBMaker.memoryDB().make();
        Map<String, byte[]> cache = db.hashMap("cache").createOrOpen();
        
        // ruleid: java-insecure-usage-of-cache
        cache.put("key", converter.convert(userInput));
    }
    
    public void bad_case_13(HttpServletRequest request) {
        // Infinispan Cache with StringByteConverter
        String userInput = request.getParameter("content");
        StringByteConverter converter = new StringByteConverter();
        CacheImpl<String, byte[]> cache = new CacheImpl<>("myCache");
        
        // ruleid: java-insecure-usage-of-cache
        cache.put("key", converter.convert(userInput));
    }
    
    @RestController
    public class BadCacheController {
        @PostMapping("/bad_case_14")
        public void bad_case_14(@RequestBody String userInput) {
            // Spring Cacheable with StringByteConverter
            StringByteConverter converter = new StringByteConverter();
            Map<String, byte[]> cache = new ConcurrentHashMap<>();
            
            // ruleid: java-insecure-usage-of-cache
            cache.put("key", converter.convert(userInput));
        }
        
        @GetMapping("/bad_case_15")
        public void bad_case_15(HttpServletRequest request) {
            // Custom Cache with StringByteConverter
            String userInput = request.getQueryString();
            StringByteConverter converter = new StringByteConverter();
            Map<String, byte[]> cache = new HashMap<>();
            
            // ruleid: java-insecure-usage-of-cache
            cache.put("key", converter.convert(userInput));
        }
    }
}
// {/fact}

// True Negative Examples (Safe/Secure Code)
class SecureExamples {
    
// {fact rule=incorrect-buffer-length-access@v1.0 defects=0}
    public void good_case_1(HttpServletRequest request) {
        // Apache Commons Cache with BufferedCache
        String userInput = request.getParameter("data");
        StringByteConverter converter = new StringByteConverter();
        BufferedCache cache = new BufferedCache();
        
        // ok: java-insecure-usage-of-cache
        cache.put("key", converter.convert(userInput), 1024); // Using size limit
    }
    
    public void good_case_2(HttpServletRequest request) {
        // EhCache with ByteBuffer and boundary check
        String userInput = request.getParameter("data");
        net.sf.ehcache.Cache cache = new net.sf.ehcache.CacheManager().getCache("myCache");
        
        byte[] bytes = userInput.getBytes();
        ByteBuffer buffer = ByteBuffer.allocate(1024); // Fixed size buffer
        
        // ok: java-insecure-usage-of-cache
        if (bytes.length <= buffer.capacity()) {
            buffer.put(bytes);
            cache.put(new Element("key", buffer.array()));
        }
    }
    
    public void good_case_3(HttpServletRequest request) {
        // Google Guava Cache with length validation
        String userInput = request.getHeader("X-Custom-Data");
        com.google.common.cache.Cache<String, byte[]> cache = CacheBuilder.newBuilder().build();
        
        byte[] bytes = userInput.getBytes();
        // ok: java-insecure-usage-of-cache
        if (bytes.length <= 2048) { // Validate length before caching
            cache.put("key", bytes);
        }
    }
    
    public void good_case_4(HttpServletRequest request) {
        // Hazelcast Cache with safe byte array handling
        String userInput = request.getParameter("content");
        HazelcastInstance hazelcastInstance = Hazelcast.newHazelcastInstance();
        ICache<String, byte[]> cache = hazelcastInstance.getCacheManager().getCache("myCache");
        
        byte[] bytes = userInput.getBytes();
        byte[] safeCopy = new byte[Math.min(bytes.length, 1024)]; // Ensure max size
        
        // ok: java-insecure-usage-of-cache
        System.arraycopy(bytes, 0, safeCopy, 0, safeCopy.length);
        cache.put("key", safeCopy);
    }
    
    public void good_case_5(HttpServletRequest request) {
        // Redis with ByteBuffer and boundary check using Jedis
        String userInput = request.getParameter("text");
        Jedis jedis = new Jedis("localhost");
        
        ByteBuffer buffer = ByteBuffer.allocate(1024); // Fixed size buffer
        byte[] bytes = userInput.getBytes();
        
        // ok: java-insecure-usage-of-cache
        if (bytes.length <= buffer.capacity()) {
            buffer.put(bytes);
            jedis.set("key".getBytes(), buffer.array());
        }
    }
    
    public void good_case_6(HttpServletRequest request) {
        // Redisson Cache with truncation if needed
        String userInput = request.getParameter("message");
        RedissonClient redisson = null; // Initialization would happen in real code
        RMapCache<String, String> cache = redisson.getMapCache("myCache");
        
        // ok: java-insecure-usage-of-cache
        if (userInput.length() > 1024) {
            cache.put("key", userInput.substring(0, 1024)); // Truncate to safe length
        } else {
            cache.put("key", userInput);
        }
    }
    
    public void good_case_7(HttpServletRequest request) {
        // Spring Redis Template with safe byte handling
        String userInput = request.getParameter("payload");
        RedisTemplate<String, byte[]> redisTemplate = new RedisTemplate<>();
        
        byte[] bytes = userInput.getBytes();
        int maxSize = 2048;
        
        // ok: java-insecure-usage-of-cache
        if (bytes.length <= maxSize) {
            redisTemplate.opsForValue().set("key", bytes);
        } else {
            byte[] truncated = new byte[maxSize];
            System.arraycopy(bytes, 0, truncated, 0, maxSize);
            redisTemplate.opsForValue().set("key", truncated);
        }
    }
    
    public void good_case_8(HttpServletRequest request) {
        // Caffeine Cache with ByteBuffer for safety
        String userInput = request.getParameter("input");
        com.github.benmanes.caffeine.cache.Cache<String, ByteBuffer> cache = Caffeine.newBuilder().build();
        
        // ok: java-insecure-usage-of-cache
        ByteBuffer safeBuffer = ByteBuffer.allocate(1024); // Fixed size buffer
        safeBuffer.put(userInput.getBytes(), 0, Math.min(userInput.getBytes().length, safeBuffer.capacity()));
        cache.put("key", safeBuffer);
    }
    
    public void good_case_9(HttpServletRequest request) {
        // JBoss Cache with length validation
        String userInput = request.getParameter("data");
        org.jboss.cache.Cache cache = new org.jboss.cache.CacheFactory().createCache();
        
        // ok: java-insecure-usage-of-cache
        if (userInput.length() <= 1024) {
            cache.put("/node/key", userInput); // Store as string instead of byte[]
        } else {
            cache.put("/node/key", userInput.substring(0, 1024)); // Truncate if too long
        }
    }
    
    public void good_case_10(HttpServletRequest request) {
        // Apache Ignite Cache with safe byte array handling
        String userInput = request.getParameter("content");
        IgniteCache<String, byte[]> cache = Ignition.ignite().getOrCreateCache("myCache");
        
        byte[] bytes = userInput.getBytes();
        int maxSize = 2048;
        
        // ok: java-insecure-usage-of-cache
        if (bytes.length <= maxSize) {
            cache.put("key", bytes);
        } else {
            byte[] truncated = new byte[maxSize];
            System.arraycopy(bytes, 0, truncated, 0, maxSize);
            cache.put("key", truncated);
        }
    }
    
    public void good_case_11(HttpServletRequest request) {
        // JSR-107 JCache with ByteBuffer for safety
        String userInput = request.getParameter("text");
        javax.cache.Cache<String, ByteBuffer> cache = Caching.getCachingProvider()
            .getCacheManager().getCache("myCache");
        
        // ok: java-insecure-usage-of-cache
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        byte[] bytes = userInput.getBytes();
        buffer.put(bytes, 0, Math.min(bytes.length, buffer.capacity()));
        cache.put("key", buffer);
    }
    
    public void good_case_12(HttpServletRequest request) {
        // MapDB with length validation
        String userInput = request.getParameter("data");
        DB db = DBMaker.memoryDB().make();
        Map<String, byte[]> cache = db.hashMap("cache").createOrOpen();
        
        byte[] bytes = userInput.getBytes();
        int maxSize = 1024;
        
        // ok: java-insecure-usage-of-cache
        if (bytes.length <= maxSize) {
            cache.put("key", bytes);
        } else {
            // Log warning or handle oversized input appropriately
            byte[] truncated = new byte[maxSize];
            System.arraycopy(bytes, 0, truncated, 0, maxSize);
            cache.put("key", truncated);
        }
    }
    
    public void good_case_13(HttpServletRequest request) {
        // Infinispan Cache with safe byte array handling
        String userInput = request.getParameter("content");
        CacheImpl<String, ByteBuffer> cache = new CacheImpl<>("myCache");
        
        // ok: java-insecure-usage-of-cache
        ByteBuffer buffer = ByteBuffer.allocate(2048); // Fixed size buffer
        buffer.put(userInput.getBytes(), 0, Math.min(userInput.getBytes().length, buffer.capacity()));
        cache.put("key", buffer);
    }
    
    @RestController
    public class GoodCacheController {
        @PostMapping("/good_case_14")
        public void good_case_14(@RequestBody String userInput) {
            // Spring Cacheable with ByteBuffer
            Map<String, ByteBuffer> cache = new ConcurrentHashMap<>();
            
            // ok: java-insecure-usage-of-cache
            ByteBuffer buffer = ByteBuffer.allocate(1024);
            byte[] bytes = userInput.getBytes();
            buffer.put(bytes, 0, Math.min(bytes.length, buffer.capacity()));
            cache.put("key", buffer);
        }
        
        @GetMapping("/good_case_15")
        public void good_case_15(HttpServletRequest request) {
            // Custom Cache with length validation
            String userInput = request.getQueryString();
            Map<String, String> cache = new HashMap<>();
            
            // ok: java-insecure-usage-of-cache
            if (userInput != null && userInput.length() <= 2048) {
                cache.put("key", userInput);
            } else if (userInput != null) {
                cache.put("key", userInput.substring(0, 2048)); // Truncate if too long
            }
        }
    }
}
// {/fact}