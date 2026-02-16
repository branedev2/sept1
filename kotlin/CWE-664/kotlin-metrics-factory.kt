package com.example.metrics

import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import io.micrometer.prometheus.PrometheusConfig
import io.micrometer.prometheus.PrometheusMeterRegistry
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Scope
import org.springframework.stereotype.Component
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import javax.inject.Singleton
import kotlin.concurrent.thread

// Custom MetricsFactory class for examples
class MetricsFactory(private val appName: String) {
    private val registry = SimpleMeterRegistry()
    
    fun createCounter(name: String): Any {
        return registry.counter(name, "app", appName)
    }
    
    fun createGauge(name: String): Any {
        return registry.gauge(name, 0.0)
    }
}

// True Positive Examples (Vulnerable Code)

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_1() {
    class MetricsService {
        // ruleid: kotlin-metrics-factory
        fun getMetricsFactory(): MetricsFactory {
            return MetricsFactory("app1")
        }
        
        fun recordMetric(name: String) {
            val factory = getMetricsFactory()
            factory.createCounter(name)
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_2() {
    class RequestHandler {
        // ruleid: kotlin-metrics-factory
        private fun createMetricsFactory(): MetricsFactory {
            return MetricsFactory("app2")
        }
        
        fun handleRequest() {
            val metricsFactory = createMetricsFactory()
            metricsFactory.createCounter("request_count")
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_3() {
    class MetricsManager {
        // ruleid: kotlin-metrics-factory
        fun provideMetricsFactory(): MetricsFactory {
            val appName = "app3"
            return MetricsFactory(appName)
        }
    }
    
    val manager = MetricsManager()
    val factory1 = manager.provideMetricsFactory()
    val factory2 = manager.provideMetricsFactory() // Creates another instance
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_4() {
    @RestController
    class MetricsController {
        // ruleid: kotlin-metrics-factory
        private fun getMetricsFactory(): MetricsFactory {
            return MetricsFactory("web-app")
        }
        
        @GetMapping("/metrics")
        fun getMetrics(): String {
            val factory = getMetricsFactory() // New instance on each request
            factory.createCounter("api_calls")
            return "Metrics recorded"
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_5() {
    class Worker(private val name: String) {
        // ruleid: kotlin-metrics-factory
        fun initMetrics(): MetricsFactory {
            return MetricsFactory("worker-$name")
        }
        
        fun doWork() {
            val metrics = initMetrics() // New instance each time
            metrics.createCounter("work_done")
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_6() {
    @Configuration
    class AppConfig {
        // ruleid: kotlin-metrics-factory
        @Bean
        fun metricsFactory(): MetricsFactory {
            return MetricsFactory("configuredApp")
        }
    }
    // Without proper scope, Spring will create a new instance for each injection
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_7() {
    class MetricsUtil {
        companion object {
            // ruleid: kotlin-metrics-factory
            fun createMetricsFactory(appId: String): MetricsFactory {
                return MetricsFactory(appId)
            }
        }
    }
    
    fun processRequest() {
        val factory = MetricsUtil.createMetricsFactory("app7") // New instance each call
        factory.createGauge("processing_time")
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_8() {
    class DataProcessor {
        // ruleid: kotlin-metrics-factory
        fun getMetrics(jobId: String): MetricsFactory {
            return MetricsFactory("processor-$jobId")
        }
        
        fun process(data: List<String>, jobId: String) {
            val metrics = getMetrics(jobId) // New instance for each job
            metrics.createCounter("processed_items")
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_9() {
    class AsyncTask {
        // ruleid: kotlin-metrics-factory
        fun setupMetrics(): MetricsFactory {
            return MetricsFactory("async-task")
        }
        
        fun execute() {
            thread {
                val metrics = setupMetrics() // New instance in each thread
                metrics.createCounter("task_executed")
            }
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_10() {
    class MetricsProvider {
        // ruleid: kotlin-metrics-factory
        fun factoryFor(component: String): MetricsFactory {
            return MetricsFactory(component)
        }
    }
    
    val provider = MetricsProvider()
    val factory1 = provider.factoryFor("component1")
    val factory2 = provider.factoryFor("component2") // Multiple instances
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_11() {
    class UserService {
        // ruleid: kotlin-metrics-factory
        private fun metricsFactory(): MetricsFactory {
            val appName = System.getProperty("app.name", "user-service")
            return MetricsFactory(appName)
        }
        
        fun createUser(username: String) {
            val metrics = metricsFactory() // New instance each time
            metrics.createCounter("user_created")
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_12() {
    @Component
    class MetricsComponent {
        // ruleid: kotlin-metrics-factory
        fun createFactory(): MetricsFactory {
            return MetricsFactory("component-metrics")
        }
        
        fun recordEvent(eventName: String) {
            val factory = createFactory() // New instance each time
            factory.createCounter(eventName)
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_13() {
    class PrometheusMetricsFactory(appName: String) : MetricsFactory(appName) {
        // Additional Prometheus-specific methods
    }
    
    class PrometheusReporter {
        // ruleid: kotlin-metrics-factory
        fun getFactory(): PrometheusMetricsFactory {
            return PrometheusMetricsFactory("prometheus-app")
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_14() {
    class RequestProcessor {
        // ruleid: kotlin-metrics-factory
        fun newMetricsFactory(): MetricsFactory {
            val env = System.getenv("APP_ENV") ?: "dev"
            return MetricsFactory("app-$env")
        }
        
        fun handleRequest(id: String) {
            val metrics = newMetricsFactory() // Creates new instance
            metrics.createCounter("request.$id")
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=1}
fun bad_case_15() {
    abstract class BaseService {
        // ruleid: kotlin-metrics-factory
        protected fun createMetricsFactory(): MetricsFactory {
            return MetricsFactory("base-service")
        }
    }
    
    class ConcreteService : BaseService() {
        fun doOperation() {
            val metrics = createMetricsFactory() // Inherits non-singleton pattern
            metrics.createGauge("operation_gauge")
        }
    }
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_1() {
    class MetricsService {
        // Singleton instance
        companion object {
            private val metricsFactory = MetricsFactory("app1")
        }
        
        // ok: kotlin-metrics-factory
        fun getMetricsFactory(): MetricsFactory {
            return companion.metricsFactory
        }
        
        fun recordMetric(name: String) {
            val factory = getMetricsFactory()
            factory.createCounter(name)
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_2() {
    class RequestHandler {
        companion object {
            private val metricsFactory = MetricsFactory("app2")
        }
        
        // ok: kotlin-metrics-factory
        private fun getMetricsFactory(): MetricsFactory {
            return companion.metricsFactory
        }
        
        fun handleRequest() {
            val metricsFactory = getMetricsFactory()
            metricsFactory.createCounter("request_count")
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_3() {
    object MetricsManager {
        private val metricsFactory = MetricsFactory("app3")
        
        // ok: kotlin-metrics-factory
        fun provideMetricsFactory(): MetricsFactory {
            return metricsFactory
        }
    }
    
    val factory1 = MetricsManager.provideMetricsFactory()
    val factory2 = MetricsManager.provideMetricsFactory() // Same instance
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_4() {
    @RestController
    class MetricsController {
        private val metricsFactory = MetricsFactory("web-app")
        
        // ok: kotlin-metrics-factory
        private fun getMetricsFactory(): MetricsFactory {
            return metricsFactory
        }
        
        @GetMapping("/metrics")
        fun getMetrics(): String {
            val factory = getMetricsFactory() // Same instance for all requests
            factory.createCounter("api_calls")
            return "Metrics recorded"
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_5() {
    class Worker(private val name: String) {
        private val metricsFactory = MetricsFactory("worker-$name")
        
        // ok: kotlin-metrics-factory
        fun getMetrics(): MetricsFactory {
            return metricsFactory
        }
        
        fun doWork() {
            val metrics = getMetrics() // Same instance each time
            metrics.createCounter("work_done")
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_6() {
    @Configuration
    class AppConfig {
        // ok: kotlin-metrics-factory
        @Bean
        @Singleton
        fun metricsFactory(): MetricsFactory {
            return MetricsFactory("configuredApp")
        }
    }
    // With @Singleton, Spring will create only one instance
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_7() {
    class MetricsUtil {
        companion object {
            private val factories = mutableMapOf<String, MetricsFactory>()
            
            // ok: kotlin-metrics-factory
            fun getMetricsFactory(appId: String): MetricsFactory {
                return factories.getOrPut(appId) { MetricsFactory(appId) }
            }
        }
    }
    
    fun processRequest() {
        val factory = MetricsUtil.getMetricsFactory("app7") // Reuses instance
        factory.createGauge("processing_time")
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_8() {
    class DataProcessor {
        private val metricsCache = mutableMapOf<String, MetricsFactory>()
        
        // ok: kotlin-metrics-factory
        fun getMetrics(jobId: String): MetricsFactory {
            return metricsCache.getOrPut(jobId) { MetricsFactory("processor-$jobId") }
        }
        
        fun process(data: List<String>, jobId: String) {
            val metrics = getMetrics(jobId) // Reuses instance for same job
            metrics.createCounter("processed_items")
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_9() {
    object AsyncTaskMetrics {
        private val metricsFactory = MetricsFactory("async-task")
        
        // ok: kotlin-metrics-factory
        fun getMetricsFactory(): MetricsFactory {
            return metricsFactory
        }
    }
    
    class AsyncTask {
        fun execute() {
            thread {
                val metrics = AsyncTaskMetrics.getMetricsFactory() // Same instance across threads
                metrics.createCounter("task_executed")
            }
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_10() {
    class MetricsProvider {
        private val factories = mutableMapOf<String, MetricsFactory>()
        
        // ok: kotlin-metrics-factory
        fun factoryFor(component: String): MetricsFactory {
            return factories.getOrPut(component) { MetricsFactory(component) }
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_11() {
    @Component
    class UserService {
        private val metricsFactory: MetricsFactory
        
        init {
            val appName = System.getProperty("app.name", "user-service")
            metricsFactory = MetricsFactory(appName)
        }
        
        // ok: kotlin-metrics-factory
        private fun getMetricsFactory(): MetricsFactory {
            return metricsFactory
        }
        
        fun createUser(username: String) {
            val metrics = getMetricsFactory() // Same instance each time
            metrics.createCounter("user_created")
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_12() {
    @Component
    class MetricsComponent {
        private val factory = MetricsFactory("component-metrics")
        
        // ok: kotlin-metrics-factory
        fun getFactory(): MetricsFactory {
            return factory
        }
        
        fun recordEvent(eventName: String) {
            val factory = getFactory() // Same instance each time
            factory.createCounter(eventName)
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_13() {
    class PrometheusMetricsFactory private constructor(appName: String) : MetricsFactory(appName) {
        companion object {
            private val instance = PrometheusMetricsFactory("prometheus-app")
        }
        
        // ok: kotlin-metrics-factory
        fun getInstance(): PrometheusMetricsFactory {
            return instance
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_14() {
    @Component
    class RequestProcessor {
        private val metricsFactory: MetricsFactory
        
        init {
            val env = System.getenv("APP_ENV") ?: "dev"
            metricsFactory = MetricsFactory("app-$env")
        }
        
        // ok: kotlin-metrics-factory
        fun getMetricsFactory(): MetricsFactory {
            return metricsFactory
        }
        
        fun handleRequest(id: String) {
            val metrics = getMetricsFactory() // Returns singleton instance
            metrics.createCounter("request.$id")
        }
    }
}
// {/fact}

// {fact rule=resource-leak@v1.0 defects=0}
fun good_case_15() {
    abstract class BaseService {
        protected val metricsFactory = MetricsFactory("base-service")
        
        // ok: kotlin-metrics-factory
        protected fun getMetricsFactory(): MetricsFactory {
            return metricsFactory
        }
    }
    
    class ConcreteService : BaseService() {
        fun doOperation() {
            val metrics = getMetricsFactory() // Uses singleton from parent
            metrics.createGauge("operation_gauge")
        }
    }
}
// {/fact}