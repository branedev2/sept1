import org.crac.Context
import org.crac.Core
import org.crac.Resource
import com.amazonaws.services.lambda.runtime.LambdaLogger
import com.amazonaws.services.lambda.runtime.LambdaRuntime
import java.sql.Connection
import java.sql.DriverManager
import java.util.concurrent.Executors
import java.util.concurrent.ExecutorService
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicReference
import java.io.Closeable
import java.net.HttpURLConnection
import java.net.URL
import javax.sql.DataSource
import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import software.amazon.awssdk.services.s3.S3Client
import software.amazon.awssdk.services.dynamodb.DynamoDbClient
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials
import software.amazon.awssdk.regions.Region
import redis.clients.jedis.Jedis
import redis.clients.jedis.JedisPool
import redis.clients.jedis.JedisPoolConfig

// True Positives (Vulnerable Code)

// {fact rule=missing-release-of-memory@v1.0 defects=1}
fun bad_case_1() {
    val handler = object : Resource {
        override fun beforeCheckpoint(context: Context) {
            println("Preparing for checkpoint")
        }

        override fun afterRestore(context: Context) {
            println("Restored from checkpoint")
        }
    }

    // ruleid: kotlin-lambda-snapstart-runtime-hooks
    Core.getGlobalContext().register(handler)
}
// {/fact}

// {fact rule=missing-release-of-memory@v1.0 defects=1}
fun bad_case_2() {
    fun setupDatabase() {
        val dbResource = object : Resource {
            private var connection: Connection? = null
            
            override fun beforeCheckpoint(context: Context) {
                connection?.close()
            }
            
            override fun afterRestore(context: Context) {
                connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/db", "user", "pass")
            }
        }
        
        // ruleid: kotlin-lambda-snapstart-runtime-hooks
        Core.getGlobalContext().register(dbResource)
    }
    
    setupDatabase()
}
// {/fact}

// {fact rule=missing-release-of-memory@v1.0 defects=1}
fun bad_case_3() {
    val executorService = Executors.newFixedThreadPool(10)
    
    val lambda = {
        val resource = object : Resource {
            override fun beforeCheckpoint(context: Context) {
                println("Shutting down executor service")
                executorService.shutdown()
            }
            
            override fun afterRestore(context: Context) {
                println("Executor service restored")
            }
        }
        
        // ruleid: kotlin-lambda-snapstart-runtime-hooks
        Core.getGlobalContext().register(resource)
    }
    
    lambda()
}
// {/fact}

// {fact rule=missing-release-of-memory@v1.0 defects=1}
fun bad_case_4() {
    class Handler {
        fun initialize() {
            val logger = LambdaRuntime.getLogger()
            
            val cacheResource = object : Resource {
                private val cache = ConcurrentHashMap<String, String>()
                
                override fun beforeCheckpoint(context: Context) {
                    logger.log("Clearing cache before checkpoint")
                    cache.clear()
                }
                
                override fun afterRestore(context: Context) {
                    logger.log("Cache restored")
                }
            }
            
            // ruleid: kotlin-lambda-snapstart-runtime-hooks
            Core.getGlobalContext().register(cacheResource)
        }
    }
    
    Handler().initialize()
}
// {/fact}

// {fact rule=missing-release-of-memory@v1.0 defects=1}
fun bad_case_5() {
    fun registerS3Client() {
        val s3Client = S3Client.builder()
            .region(Region.US_EAST_1)
            .build()
        
        val s3Resource = object : Resource {
            override fun beforeCheckpoint(context: Context) {
                s3Client.close()
            }
            
            override fun afterRestore(context: Context) {
                // Re-initialize if needed
            }
        }
        
        // ruleid: kotlin-lambda-snapstart-runtime-hooks
        Core.getGlobalContext().register(s3Resource)
    }
    
    registerS3Client()
}
// {/fact}

// {fact rule=missing-release-of-memory@v1.0 defects=1}
fun bad_case_6() {
    val initializeConnections = { connectionCount: Int ->
        val connectionPool = mutableListOf<Connection>()
        
        val poolResource = object : Resource {
            override fun beforeCheckpoint(context: Context) {
                connectionPool.forEach { it.close() }
                connectionPool.clear()
            }
            
            override fun afterRestore(context: Context) {
                repeat(connectionCount) {
                    connectionPool.add(DriverManager.getConnection("jdbc:mysql://localhost:3306/db", "user", "pass"))
                }
            }
        }
        
        // ruleid: kotlin-lambda-snapstart-runtime-hooks
        Core.getGlobalContext().register(poolResource)
    }
    
    initializeConnections(5)
}
// {/fact}

// {fact rule=missing-release-of-memory@v1.0 defects=1}
fun bad_case_7() {
    class ConnectionManager {
        fun setupConnectionPool() {
            val hikariConfig = HikariConfig()
            hikariConfig.jdbcUrl = "jdbc:mysql://localhost:3306/db"
            hikariConfig.username = "user"
            hikariConfig.password = "password"
            
            val dataSource = HikariDataSource(hikariConfig)
            
            val localResource = object : Resource {
                override fun beforeCheckpoint(context: Context) {
                    dataSource.close()
                }
                
                override fun afterRestore(context: Context) {
                    // Reinitialize if needed
                }
            }
            
            // ruleid: kotlin-lambda-snapstart-runtime-hooks
            Core.getGlobalContext().register(localResource)
        }
    }
    
    ConnectionManager().setupConnectionPool()
}
// {/fact}

// {fact rule=missing-release-of-memory@v1.0 defects=1}
fun bad_case_8() {
    val dynamoDbClient = DynamoDbClient.builder()
        .region(Region.US_EAST_1)
        .build()
    
    fun registerDynamoDbHooks() {
        val dynamoResource = object : Resource {
            override fun beforeCheckpoint(context: Context) {
                dynamoDbClient.close()
            }
            
            override fun afterRestore(context: Context) {
                // Client will be recreated when needed
            }
        }
        
        // ruleid: kotlin-lambda-snapstart-runtime-hooks
        Core.getGlobalContext().register(dynamoResource)
    }
    
    registerDynamoDbHooks()
}
// {/fact}

// {fact rule=missing-release-of-memory@v1.0 defects=1}
fun bad_case_9() {
    val jedisPool = JedisPool(JedisPoolConfig(), "localhost")
    
    val setupRedis = {
        val redisResource = object : Resource {
            override fun beforeCheckpoint(context: Context) {
                jedisPool.close()
            }
            
            override fun afterRestore(context: Context) {
                // Pool will be recreated when needed
            }
        }
        
        // ruleid: kotlin-lambda-snapstart-runtime-hooks
        Core.getGlobalContext().register(redisResource)
    }
    
    setupRedis()
}
// {/fact}

// {fact rule=missing-release-of-memory@v1.0 defects=1}
fun bad_case_10() {
    class HttpClientManager {
        private val connections = mutableListOf<HttpURLConnection>()
        
        fun registerCleanupHooks() {
            val httpResource = object : Resource {
                override fun beforeCheckpoint(context: Context) {
                    connections.forEach { it.disconnect() }
                    connections.clear()
                }
                
                override fun afterRestore(context: Context) {
                    // Connections will be recreated when needed
                }
            }
            
            // ruleid: kotlin-lambda-snapstart-runtime-hooks
            Core.getGlobalContext().register(httpResource)
        }
    }
    
    HttpClientManager().registerCleanupHooks()
}
// {/fact}

// {fact rule=missing-release-of-memory@v1.0 defects=1}
fun bad_case_11() {
    val tempFiles = mutableListOf<String>()
    
    fun setupFileCleanup() {
        val fileResource = object : Resource {
            override fun beforeCheckpoint(context: Context) {
                tempFiles.forEach { java.io.File(it).delete() }
                tempFiles.clear()
            }
            
            override fun afterRestore(context: Context) {
                // Temp files will be recreated when needed
            }
        }
        
        // ruleid: kotlin-lambda-snapstart-runtime-hooks
        Core.getGlobalContext().register(fileResource)
    }
    
    setupFileCleanup()
}
// {/fact}

// {fact rule=missing-release-of-memory@v1.0 defects=1}
fun bad_case_12() {
    val atomicRef = AtomicReference<Closeable>()
    
    fun initializeResource() {
        val resource = object : Resource {
            override fun beforeCheckpoint(context: Context) {
                atomicRef.get()?.close()
                atomicRef.set(null)
            }
            
            override fun afterRestore(context: Context) {
                // Resource will be recreated when needed
            }
        }
        
        // ruleid: kotlin-lambda-snapstart-runtime-hooks
        Core.getGlobalContext().register(resource)
    }
    
    initializeResource()
}
// {/fact}

// {fact rule=missing-release-of-memory@v1.0 defects=1}
fun bad_case_13() {
    class ResourceManager {
        fun registerShutdownHook() {
            val executor = Executors.newSingleThreadExecutor()
            
            val executorResource = object : Resource {
                override fun beforeCheckpoint(context: Context) {
                    executor.shutdown()
                }
                
                override fun afterRestore(context: Context) {
                    // Executor will be recreated when needed
                }
            }
            
            // ruleid: kotlin-lambda-snapstart-runtime-hooks
            Core.getGlobalContext().register(executorResource)
        }
    }
    
    ResourceManager().registerShutdownHook()
}
// {/fact}

// {fact rule=missing-release-of-memory@v1.0 defects=1}
fun bad_case_14() {
    fun setupCacheManager() {
        val cache = mutableMapOf<String, Any>()
        
        val cacheResource = object : Resource {
            override fun beforeCheckpoint(context: Context) {
                cache.clear()
            }
            
            override fun afterRestore(context: Context) {
                // Cache will be populated when needed
            }
        }
        
        // ruleid: kotlin-lambda-snapstart-runtime-hooks
        Core.getGlobalContext().register(cacheResource)
    }
    
    setupCacheManager()
}
// {/fact}

// {fact rule=missing-release-of-memory@v1.0 defects=1}
fun bad_case_15() {
    val initializeResources = { config: Map<String, String> ->
        val resources = mutableListOf<AutoCloseable>()
        
        val resourceManager = object : Resource {
            override fun beforeCheckpoint(context: Context) {
                resources.forEach { it.close() }
                resources.clear()
            }
            
            override fun afterRestore(context: Context) {
                // Resources will be recreated when needed
            }
        }
        
        // ruleid: kotlin-lambda-snapstart-runtime-hooks
        Core.getGlobalContext().register(resourceManager)
    }
    
    initializeResources(mapOf("key" to "value"))
}
// {/fact}

// True Negatives (Safe Code)

// Class-level instantiation of the resource
class DatabaseResource : Resource {
    private var connection: Connection? = null
    
    override fun beforeCheckpoint(context: Context) {
        connection?.close()
    }
    
    override fun afterRestore(context: Context) {
        connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/db", "user", "pass")
    }
}

// {fact rule=missing-release-of-memory@v1.0 defects=0}
fun good_case_1() {
    val dbResource = DatabaseResource()
    
    // ok: kotlin-lambda-snapstart-runtime-hooks
    Core.getGlobalContext().register(dbResource)
}
// {/fact}

// Class-level instantiation of the resource
class ExecutorServiceResource(private val executorService: ExecutorService) : Resource {
    override fun beforeCheckpoint(context: Context) {
        executorService.shutdown()
    }
    
    override fun afterRestore(context: Context) {
        // Executor service will be recreated when needed
    }
}

// {fact rule=missing-release-of-memory@v1.0 defects=0}
fun good_case_2() {
    val executorService = Executors.newFixedThreadPool(10)
    val executorResource = ExecutorServiceResource(executorService)
    
    // ok: kotlin-lambda-snapstart-runtime-hooks
    Core.getGlobalContext().register(executorResource)
}
// {/fact}

// Class-level instantiation of the resource
class CacheResource : Resource {
    private val cache = ConcurrentHashMap<String, String>()
    
    override fun beforeCheckpoint(context: Context) {
        cache.clear()
    }
    
    override fun afterRestore(context: Context) {
        // Cache will be populated when needed
    }
}

// {fact rule=missing-release-of-memory@v1.0 defects=0}
fun good_case_3() {
    val cacheResource = CacheResource()
    
    // ok: kotlin-lambda-snapstart-runtime-hooks
    Core.getGlobalContext().register(cacheResource)
}
// {/fact}

// Class-level instantiation of the resource
class S3ClientResource(private val s3Client: S3Client) : Resource {
    override fun beforeCheckpoint(context: Context) {
        s3Client.close()
    }
    
    override fun afterRestore(context: Context) {
        // S3 client will be recreated when needed
    }
}

// {fact rule=missing-release-of-memory@v1.0 defects=0}
fun good_case_4() {
    val s3Client = S3Client.builder()
        .region(Region.US_EAST_1)
        .build()
    
    val s3Resource = S3ClientResource(s3Client)
    
    // ok: kotlin-lambda-snapstart-runtime-hooks
    Core.getGlobalContext().register(s3Resource)
}
// {/fact}

// Class-level instantiation of the resource
class ConnectionPoolResource(private val connectionCount: Int) : Resource {
    private val connectionPool = mutableListOf<Connection>()
    
    override fun beforeCheckpoint(context: Context) {
        connectionPool.forEach { it.close() }
        connectionPool.clear()
    }
    
    override fun afterRestore(context: Context) {
        repeat(connectionCount) {
            connectionPool.add(DriverManager.getConnection("jdbc:mysql://localhost:3306/db", "user", "pass"))
        }
    }
}

// {fact rule=missing-release-of-memory@v1.0 defects=0}
fun good_case_5() {
    val poolResource = ConnectionPoolResource(5)
    
    // ok: kotlin-lambda-snapstart-runtime-hooks
    Core.getGlobalContext().register(poolResource)
}
// {/fact}

// Class-level instantiation of the resource
class DataSourceResource(private val dataSource: DataSource) : Resource {
    override fun beforeCheckpoint(context: Context) {
        if (dataSource is HikariDataSource) {
            dataSource.close()
        }
    }
    
    override fun afterRestore(context: Context) {
        // DataSource will be recreated when needed
    }
}

// {fact rule=missing-release-of-memory@v1.0 defects=0}
fun good_case_6() {
    val hikariConfig = HikariConfig()
    hikariConfig.jdbcUrl = "jdbc:mysql://localhost:3306/db"
    hikariConfig.username = "user"
    hikariConfig.password = "password"
    
    val dataSource = HikariDataSource(hikariConfig)
    val dataSourceResource = DataSourceResource(dataSource)
    
    // ok: kotlin-lambda-snapstart-runtime-hooks
    Core.getGlobalContext().register(dataSourceResource)
}
// {/fact}

// Class-level instantiation of the resource
class DynamoDbResource(private val dynamoDbClient: DynamoDbClient) : Resource {
    override fun beforeCheckpoint(context: Context) {
        dynamoDbClient.close()
    }
    
    override fun afterRestore(context: Context) {
        // DynamoDB client will be recreated when needed
    }
}

// {fact rule=missing-release-of-memory@v1.0 defects=0}
fun good_case_7() {
    val dynamoDbClient = DynamoDbClient.builder()
        .region(Region.US_EAST_1)
        .build()
    
    val dynamoResource = DynamoDbResource(dynamoDbClient)
    
    // ok: kotlin-lambda-snapstart-runtime-hooks
    Core.getGlobalContext().register(dynamoResource)
}
// {/fact}

// Class-level instantiation of the resource
class RedisPoolResource(private val jedisPool: JedisPool) : Resource {
    override fun beforeCheckpoint(context: Context) {
        jedisPool.close()
    }
    
    override fun afterRestore(context: Context) {
        // Redis pool will be recreated when needed
    }
}

// {fact rule=missing-release-of-memory@v1.0 defects=0}
fun good_case_8() {
    val jedisPool = JedisPool(JedisPoolConfig(), "localhost")
    val redisResource = RedisPoolResource(jedisPool)
    
    // ok: kotlin-lambda-snapstart-runtime-hooks
    Core.getGlobalContext().register(redisResource)
}
// {/fact}

// Class-level instantiation of the resource
class HttpConnectionResource : Resource {
    private val connections = mutableListOf<HttpURLConnection>()
    
    fun addConnection(connection: HttpURLConnection) {
        connections.add(connection)
    }
    
    override fun beforeCheckpoint(context: Context) {
        connections.forEach { it.disconnect() }
        connections.clear()
    }
    
    override fun afterRestore(context: Context) {
        // Connections will be recreated when needed
    }
}

// {fact rule=missing-release-of-memory@v1.0 defects=0}
fun good_case_9() {
    val httpResource = HttpConnectionResource()
    
    // ok: kotlin-lambda-snapstart-runtime-hooks
    Core.getGlobalContext().register(httpResource)
}
// {/fact}

// Class-level instantiation of the resource
class TempFileResource : Resource {
    private val tempFiles = mutableListOf<String>()
    
    fun addTempFile(path: String) {
        tempFiles.add(path)
    }
    
    override fun beforeCheckpoint(context: Context) {
        tempFiles.forEach { java.io.File(it).delete() }
        tempFiles.clear()
    }
    
    override fun afterRestore(context: Context) {
        // Temp files will be recreated when needed
    }
}

// {fact rule=missing-release-of-memory@v1.0 defects=0}
fun good_case_10() {
    val fileResource = TempFileResource()
    
    // ok: kotlin-lambda-snapstart-runtime-hooks
    Core.getGlobalContext().register(fileResource)
}
// {/fact}

// Class-level instantiation of the resource
class CloseableResource(private val atomicRef: AtomicReference<Closeable>) : Resource {
    override fun beforeCheckpoint(context: Context) {
        atomicRef.get()?.close()
        atomicRef.set(null)
    }
    
    override fun afterRestore(context: Context) {
        // Resource will be recreated when needed
    }
}

// {fact rule=missing-release-of-memory@v1.0 defects=0}
fun good_case_11() {
    val atomicRef = AtomicReference<Closeable>()
    val resource = CloseableResource(atomicRef)
    
    // ok: kotlin-lambda-snapstart-runtime-hooks
    Core.getGlobalContext().register(resource)
}
// {/fact}

// Class-level instantiation of the resource
class ExecutorShutdownResource(private val executor: ExecutorService) : Resource {
    override fun beforeCheckpoint(context: Context) {
        executor.shutdown()
    }
    
    override fun afterRestore(context: Context) {
        // Executor will be recreated when needed
    }
}

// {fact rule=missing-release-of-memory@v1.0 defects=0}
fun good_case_12() {
    val executor = Executors.newSingleThreadExecutor()
    val executorResource = ExecutorShutdownResource(executor)
    
    // ok: kotlin-lambda-snapstart-runtime-hooks
    Core.getGlobalContext().register(executorResource)
}
// {/fact}

// Class-level instantiation of the resource
class CacheManagerResource : Resource {
    private val cache = mutableMapOf<String, Any>()
    
    override fun beforeCheckpoint(context: Context) {
        cache.clear()
    }
    
    override fun afterRestore(context: Context) {
        // Cache will be populated when needed
    }
}

// {fact rule=missing-release-of-memory@v1.0 defects=0}
fun good_case_13() {
    val cacheManager = CacheManagerResource()
    
    // ok: kotlin-lambda-snapstart-runtime-hooks
    Core.getGlobalContext().register(cacheManager)
}
// {/fact}

// Class-level instantiation of the resource
class ResourceManagerResource : Resource {
    private val resources = mutableListOf<AutoCloseable>()
    
    fun addResource(resource: AutoCloseable) {
        resources.add(resource)
    }
    
    override fun beforeCheckpoint(context: Context) {
        resources.forEach { it.close() }
        resources.clear()
    }
    
    override fun afterRestore(context: Context) {
        // Resources will be recreated when needed
    }
}

// {fact rule=missing-release-of-memory@v1.0 defects=0}
fun good_case_14() {
    val resourceManager = ResourceManagerResource()
    
    // ok: kotlin-lambda-snapstart-runtime-hooks
    Core.getGlobalContext().register(resourceManager)
}
// {/fact}

// Using a singleton pattern for class-level instantiation
object GlobalResourceManager : Resource {
    private val resources = mutableListOf<AutoCloseable>()
    
    fun addResource(resource: AutoCloseable) {
        resources.add(resource)
    }
    
    override fun beforeCheckpoint(context: Context) {
        resources.forEach { it.close() }
        resources.clear()
    }
    
    override fun afterRestore(context: Context) {
        // Resources will be recreated when needed
    }
}

// {fact rule=missing-release-of-memory@v1.0 defects=0}
fun good_case_15() {
    // ok: kotlin-lambda-snapstart-runtime-hooks
    Core.getGlobalContext().register(GlobalResourceManager)
}
// {/fact}