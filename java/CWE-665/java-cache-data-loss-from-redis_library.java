import java.util.*;
import java.io.*;
import java.net.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;
import org.springframework.data.redis.core.*;
import org.springframework.data.redis.connection.*;
import redis.clients.jedis.*;
import io.lettuce.core.*;
import io.lettuce.core.api.*;
import io.lettuce.core.api.sync.*;
import redisson.*;
import redisson.api.*;
import com.lambdaworks.redis.*;
import org.redisson.*;
import org.redisson.api.*;
import org.redisson.config.*;
import org.springframework.cache.annotation.*;
import org.springframework.cache.*;
import javax.servlet.http.*;
import org.apache.commons.pool2.impl.*;
import com.google.gson.*;
import org.springframework.web.context.request.*;
import org.springframework.beans.factory.annotation.*;
import com.fasterxml.jackson.databind.*;
import org.springframework.data.redis.serializer.*;
import org.springframework.data.redis.cache.*;
import org.springframework.boot.autoconfigure.cache.*;
import org.springframework.context.annotation.*;

// Security Issue: Cache data loss from Redis due to uninitialized or improperly validated variables

// True Positive Examples (Vulnerable/Insecure Code)

@RestController
public class RedisVulnerabilityExamples {

    // Example 1: Using Spring Data Redis with uninitialized template
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;
    
// {fact rule=improper-initialization@v1.0 defects=1}
    @GetMapping("/bad1")
    public void bad_case_1(HttpServletRequest request) {
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        
        RedisTemplate<String, Object> localTemplate = null; // Uninitialized template
        
        try {
            // ruleid: java-cache-data-loss-from-redis
            localTemplate.opsForValue().set(key, value);
        } catch (Exception e) {
            System.out.println("Redis operation failed: " + e.getMessage());
        }
    }
    
    // Example 2: Using Jedis with uninitialized connection
    @GetMapping("/bad2")
    public void bad_case_2(HttpServletRequest request) {
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        
        Jedis jedis = null; // Uninitialized Jedis client
        
        try {
            // ruleid: java-cache-data-loss-from-redis
            jedis.set(key, value);
            jedis.close();
        } catch (Exception e) {
            System.out.println("Jedis operation failed: " + e.getMessage());
        }
    }
    
    // Example 3: Using Lettuce with uninitialized connection
    @GetMapping("/bad3")
    public void bad_case_3(HttpServletRequest request) {
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        
        RedisClient redisClient = null; // Uninitialized client
        StatefulRedisConnection<String, String> connection = null;
        
        try {
            // ruleid: java-cache-data-loss-from-redis
            connection = redisClient.connect();
            RedisCommands<String, String> commands = connection.sync();
            commands.set(key, value);
        } finally {
            if (connection != null) {
                connection.close();
            }
        }
    }
    
    // Example 4: Using Redisson with uninitialized client
    @GetMapping("/bad4")
    public void bad_case_4(HttpServletRequest request) {
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        
        RedissonClient redisson = null; // Uninitialized client
        
        try {
            RBucket<String> bucket = null;
            // ruleid: java-cache-data-loss-from-redis
            bucket = redisson.getBucket(key);
            bucket.set(value);
        } catch (Exception e) {
            System.out.println("Redisson operation failed: " + e.getMessage());
        }
    }
    
    // Example 5: Using Spring Cache with uninitialized cache manager
    @GetMapping("/bad5")
    public void bad_case_5(HttpServletRequest request) {
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        
        CacheManager cacheManager = null; // Uninitialized cache manager
        
        try {
            // ruleid: java-cache-data-loss-from-redis
            Cache cache = cacheManager.getCache("userCache");
            cache.put(key, value);
        } catch (Exception e) {
            System.out.println("Cache operation failed: " + e.getMessage());
        }
    }
    
    // Example 6: Using Spring Data Redis with improperly validated key
    @Autowired
    private StringRedisTemplate stringRedisTemplate;
    
    @GetMapping("/bad6")
    public void bad_case_6(HttpServletRequest request) {
        String key = request.getParameter("key"); // Could be null or empty
        String value = request.getParameter("value");
        
        // ruleid: java-cache-data-loss-from-redis
        stringRedisTemplate.opsForValue().set(key, value);
    }
    
    // Example 7: Using Jedis pool with uninitialized pool
    @GetMapping("/bad7")
    public void bad_case_7(HttpServletRequest request) {
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        
        JedisPool jedisPool = null; // Uninitialized pool
        
        try (Jedis jedis = jedisPool.getResource()) {
            // ruleid: java-cache-data-loss-from-redis
            jedis.set(key, value);
        } catch (Exception e) {
            System.out.println("Jedis pool operation failed: " + e.getMessage());
        }
    }
    
    // Example 8: Using Redis Cluster with uninitialized cluster
    @GetMapping("/bad8")
    public void bad_case_8(HttpServletRequest request) {
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        
        JedisCluster jedisCluster = null; // Uninitialized cluster
        
        try {
            // ruleid: java-cache-data-loss-from-redis
            jedisCluster.set(key, value);
        } catch (Exception e) {
            System.out.println("Jedis cluster operation failed: " + e.getMessage());
        }
    }
    
    // Example 9: Using Lettuce with improperly validated connection
    @GetMapping("/bad9")
    public void bad_case_9(HttpServletRequest request) {
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        
        RedisClient redisClient = RedisClient.create("redis://localhost:6379");
        StatefulRedisConnection<String, String> connection = null; // Not initialized
        
        try {
            // ruleid: java-cache-data-loss-from-redis
            RedisCommands<String, String> commands = connection.sync();
            commands.set(key, value);
        } finally {
            if (connection != null) {
                connection.close();
            }
            redisClient.shutdown();
        }
    }
    
    // Example 10: Using Spring Data Redis Hash operations with uninitialized template
    @GetMapping("/bad10")
    public void bad_case_10(HttpServletRequest request) {
        String key = request.getParameter("key");
        String field = request.getParameter("field");
        String value = request.getParameter("value");
        
        RedisTemplate<String, Object> localTemplate = null; // Uninitialized template
        
        try {
            // ruleid: java-cache-data-loss-from-redis
            localTemplate.opsForHash().put(key, field, value);
        } catch (Exception e) {
            System.out.println("Redis hash operation failed: " + e.getMessage());
        }
    }
    
    // Example 11: Using Redisson Map with uninitialized client
    @GetMapping("/bad11")
    public void bad_case_11(HttpServletRequest request) {
        String mapName = request.getParameter("mapName");
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        
        RedissonClient redisson = null; // Uninitialized client
        
        try {
            // ruleid: java-cache-data-loss-from-redis
            RMap<String, String> map = redisson.getMap(mapName);
            map.put(key, value);
        } catch (Exception e) {
            System.out.println("Redisson map operation failed: " + e.getMessage());
        }
    }
    
    // Example 12: Using Spring Data Redis List operations with uninitialized template
    @GetMapping("/bad12")
    public void bad_case_12(HttpServletRequest request) {
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        
        RedisTemplate<String, Object> localTemplate = null; // Uninitialized template
        
        try {
            // ruleid: java-cache-data-loss-from-redis
            localTemplate.opsForList().rightPush(key, value);
        } catch (Exception e) {
            System.out.println("Redis list operation failed: " + e.getMessage());
        }
    }
    
    // Example 13: Using Spring Data Redis Set operations with uninitialized template
    @GetMapping("/bad13")
    public void bad_case_13(HttpServletRequest request) {
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        
        RedisTemplate<String, Object> localTemplate = null; // Uninitialized template
        
        try {
            // ruleid: java-cache-data-loss-from-redis
            localTemplate.opsForSet().add(key, value);
        } catch (Exception e) {
            System.out.println("Redis set operation failed: " + e.getMessage());
        }
    }
    
    // Example 14: Using Spring Data Redis ZSet operations with uninitialized template
    @GetMapping("/bad14")
    public void bad_case_14(HttpServletRequest request) {
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        double score = Double.parseDouble(request.getParameter("score"));
        
        RedisTemplate<String, Object> localTemplate = null; // Uninitialized template
        
        try {
            // ruleid: java-cache-data-loss-from-redis
            localTemplate.opsForZSet().add(key, value, score);
        } catch (Exception e) {
            System.out.println("Redis zset operation failed: " + e.getMessage());
        }
    }
    
    // Example 15: Using Spring Data Redis with uninitialized serializer
    @GetMapping("/bad15")
    public void bad_case_15(HttpServletRequest request) {
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(new JedisConnectionFactory());
        
        // Serializer not set
        
        try {
            // ruleid: java-cache-data-loss-from-redis
            template.afterPropertiesSet();
            template.opsForValue().set(key, value);
        } catch (Exception e) {
            System.out.println("Redis operation failed: " + e.getMessage());
        }
    }
    
    // True Negative Examples (Safe/Secure Code)
    
    // Example 1: Using Spring Data Redis with properly initialized template
    @Autowired
    private RedisTemplate<String, Object> safeRedisTemplate;
    
    @GetMapping("/good1")
    public void good_case_1(HttpServletRequest request) {
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        
        if (key != null && !key.isEmpty() && value != null) {
            try {
                // ok: java-cache-data-loss-from-redis
                safeRedisTemplate.opsForValue().set(key, value);
            } catch (Exception e) {
                System.out.println("Redis operation failed: " + e.getMessage());
            }
        }
    }
    
    // Example 2: Using Jedis with properly initialized connection
    @GetMapping("/good2")
    public void good_case_2(HttpServletRequest request) {
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        
        if (key != null && !key.isEmpty() && value != null) {
            try (Jedis jedis = new Jedis("localhost", 6379)) {
                // ok: java-cache-data-loss-from-redis
                jedis.set(key, value);
            } catch (Exception e) {
                System.out.println("Jedis operation failed: " + e.getMessage());
            }
        }
    }
    
    // Example 3: Using Lettuce with properly initialized connection
    @GetMapping("/good3")
    public void good_case_3(HttpServletRequest request) {
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        
        if (key != null && !key.isEmpty() && value != null) {
            RedisClient redisClient = RedisClient.create("redis://localhost:6379");
            StatefulRedisConnection<String, String> connection = null;
            
            try {
                connection = redisClient.connect();
                RedisCommands<String, String> commands = connection.sync();
                // ok: java-cache-data-loss-from-redis
                commands.set(key, value);
            } catch (Exception e) {
                System.out.println("Lettuce operation failed: " + e.getMessage());
            } finally {
                if (connection != null) {
                    connection.close();
                }
                redisClient.shutdown();
            }
        }
    }
    
    // Example 4: Using Redisson with properly initialized client
    @GetMapping("/good4")
    public void good_case_4(HttpServletRequest request) {
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        
        if (key != null && !key.isEmpty() && value != null) {
            Config config = new Config();
            config.useSingleServer().setAddress("redis://localhost:6379");
            RedissonClient redisson = Redisson.create(config);
            
            try {
                // ok: java-cache-data-loss-from-redis
                RBucket<String> bucket = redisson.getBucket(key);
                bucket.set(value);
            } catch (Exception e) {
                System.out.println("Redisson operation failed: " + e.getMessage());
            } finally {
                redisson.shutdown();
            }
        }
    }
    
    // Example 5: Using Spring Cache with properly initialized cache manager
    @Autowired
    private CacheManager safeCacheManager;
    
    @GetMapping("/good5")
    public void good_case_5(HttpServletRequest request) {
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        
        if (key != null && !key.isEmpty() && value != null) {
            try {
                // ok: java-cache-data-loss-from-redis
                Cache cache = safeCacheManager.getCache("userCache");
                if (cache != null) {
                    cache.put(key, value);
                }
            } catch (Exception e) {
                System.out.println("Cache operation failed: " + e.getMessage());
            }
        }
    }
    
    // Example 6: Using Spring Data Redis with validated key
    @Autowired
    private StringRedisTemplate safeStringRedisTemplate;
    
    @GetMapping("/good6")
    public void good_case_6(HttpServletRequest request) {
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        
        if (key != null && !key.isEmpty() && value != null) {
            // ok: java-cache-data-loss-from-redis
            safeStringRedisTemplate.opsForValue().set(key, value);
        }
    }
    
    // Example 7: Using Jedis pool with properly initialized pool
    @GetMapping("/good7")
    public void good_case_7(HttpServletRequest request) {
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        
        if (key != null && !key.isEmpty() && value != null) {
            JedisPoolConfig poolConfig = new JedisPoolConfig();
            JedisPool jedisPool = new JedisPool(poolConfig, "localhost", 6379);
            
            try (Jedis jedis = jedisPool.getResource()) {
                // ok: java-cache-data-loss-from-redis
                jedis.set(key, value);
            } catch (Exception e) {
                System.out.println("Jedis pool operation failed: " + e.getMessage());
            } finally {
                jedisPool.close();
            }
        }
    }
    
    // Example 8: Using Redis Cluster with properly initialized cluster
    @GetMapping("/good8")
    public void good_case_8(HttpServletRequest request) {
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        
        if (key != null && !key.isEmpty() && value != null) {
            Set<HostAndPort> nodes = new HashSet<>();
            nodes.add(new HostAndPort("localhost", 7000));
            nodes.add(new HostAndPort("localhost", 7001));
            
            try (JedisCluster jedisCluster = new JedisCluster(nodes)) {
                // ok: java-cache-data-loss-from-redis
                jedisCluster.set(key, value);
            } catch (Exception e) {
                System.out.println("Jedis cluster operation failed: " + e.getMessage());
            }
        }
    }
    
    // Example 9: Using Lettuce with properly validated connection
    @GetMapping("/good9")
    public void good_case_9(HttpServletRequest request) {
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        
        if (key != null && !key.isEmpty() && value != null) {
            RedisClient redisClient = RedisClient.create("redis://localhost:6379");
            StatefulRedisConnection<String, String> connection = null;
            
            try {
                connection = redisClient.connect();
                if (connection != null) {
                    RedisCommands<String, String> commands = connection.sync();
                    // ok: java-cache-data-loss-from-redis
                    commands.set(key, value);
                }
            } catch (Exception e) {
                System.out.println("Lettuce operation failed: " + e.getMessage());
            } finally {
                if (connection != null) {
                    connection.close();
                }
                redisClient.shutdown();
            }
        }
    }
    
    // Example 10: Using Spring Data Redis Hash operations with properly initialized template
    @Autowired
    private RedisTemplate<String, Object> hashRedisTemplate;
    
    @GetMapping("/good10")
    public void good_case_10(HttpServletRequest request) {
        String key = request.getParameter("key");
        String field = request.getParameter("field");
        String value = request.getParameter("value");
        
        if (key != null && !key.isEmpty() && field != null && !field.isEmpty() && value != null) {
            try {
                // ok: java-cache-data-loss-from-redis
                hashRedisTemplate.opsForHash().put(key, field, value);
            } catch (Exception e) {
                System.out.println("Redis hash operation failed: " + e.getMessage());
            }
        }
    }
    
    // Example 11: Using Redisson Map with properly initialized client
    @GetMapping("/good11")
    public void good_case_11(HttpServletRequest request) {
        String mapName = request.getParameter("mapName");
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        
        if (mapName != null && !mapName.isEmpty() && key != null && !key.isEmpty() && value != null) {
            Config config = new Config();
            config.useSingleServer().setAddress("redis://localhost:6379");
            RedissonClient redisson = Redisson.create(config);
            
            try {
                // ok: java-cache-data-loss-from-redis
                RMap<String, String> map = redisson.getMap(mapName);
                map.put(key, value);
            } catch (Exception e) {
                System.out.println("Redisson map operation failed: " + e.getMessage());
            } finally {
                redisson.shutdown();
            }
        }
    }
    
    // Example 12: Using Spring Data Redis List operations with properly initialized template
    @Autowired
    private RedisTemplate<String, Object> listRedisTemplate;
    
    @GetMapping("/good12")
    public void good_case_12(HttpServletRequest request) {
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        
        if (key != null && !key.isEmpty() && value != null) {
            try {
                // ok: java-cache-data-loss-from-redis
                listRedisTemplate.opsForList().rightPush(key, value);
            } catch (Exception e) {
                System.out.println("Redis list operation failed: " + e.getMessage());
            }
        }
    }
    
    // Example 13: Using Spring Data Redis Set operations with properly initialized template
    @Autowired
    private RedisTemplate<String, Object> setRedisTemplate;
    
    @GetMapping("/good13")
    public void good_case_13(HttpServletRequest request) {
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        
        if (key != null && !key.isEmpty() && value != null) {
            try {
                // ok: java-cache-data-loss-from-redis
                setRedisTemplate.opsForSet().add(key, value);
            } catch (Exception e) {
                System.out.println("Redis set operation failed: " + e.getMessage());
            }
        }
    }
    
    // Example 14: Using Spring Data Redis ZSet operations with properly initialized template
    @Autowired
    private RedisTemplate<String, Object> zsetRedisTemplate;
    
    @GetMapping("/good14")
    public void good_case_14(HttpServletRequest request) {
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        String scoreStr = request.getParameter("score");
        
        if (key != null && !key.isEmpty() && value != null && scoreStr != null) {
            try {
                double score = Double.parseDouble(scoreStr);
                // ok: java-cache-data-loss-from-redis
                zsetRedisTemplate.opsForZSet().add(key, value, score);
            } catch (NumberFormatException e) {
                System.out.println("Invalid score format: " + e.getMessage());
            } catch (Exception e) {
                System.out.println("Redis zset operation failed: " + e.getMessage());
            }
        }
    }
    
    // Example 15: Using Spring Data Redis with properly initialized serializer
    @GetMapping("/good15")
    public void good_case_15(HttpServletRequest request) {
        String key = request.getParameter("key");
        String value = request.getParameter("value");
        
        if (key != null && !key.isEmpty() && value != null) {
            RedisTemplate<String, Object> template = new RedisTemplate<>();
            template.setConnectionFactory(new JedisConnectionFactory());
            template.setKeySerializer(new StringRedisSerializer());
            template.setValueSerializer(new GenericJackson2JsonRedisSerializer());
            
            try {
                // ok: java-cache-data-loss-from-redis
                template.afterPropertiesSet();
                template.opsForValue().set(key, value);
            } catch (Exception e) {
                System.out.println("Redis operation failed: " + e.getMessage());
            }
        }
    }
}
// {/fact}