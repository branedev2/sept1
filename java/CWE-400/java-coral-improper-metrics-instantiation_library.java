import com.codahale.metrics.MetricRegistry;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.prometheus.client.CollectorRegistry;
import com.netflix.spectator.api.Registry;
import com.netflix.spectator.api.DefaultRegistry;
import org.springframework.metrics.instrument.MeterRegistry as SpringMeterRegistry;
import org.springframework.metrics.instrument.simple.SimpleMeterRegistry as SpringSimpleMeterRegistry;
import com.uber.m3.tally.Scope;
import com.uber.m3.tally.RootScopeBuilder;
import io.dropwizard.metrics5.MetricRegistry as Dropwizard5MetricRegistry;
import com.google.monitoring.metrics.MetricRegistry as GoogleMetricRegistry;
import io.opencensus.stats.StatsRecorder;
import io.opencensus.stats.Stats;
import com.amazonaws.metrics.MetricRegistry as AWSMetricRegistry;
import com.amazonaws.metrics.AwsSdkMetrics;
import org.apache.kafka.common.metrics.Metrics;
import org.apache.kafka.common.metrics.MetricConfig;
import com.microsoft.applicationinsights.TelemetryClient;
import io.opentelemetry.api.metrics.MeterProvider;
import io.opentelemetry.sdk.metrics.SdkMeterProvider;
import com.newrelic.api.agent.NewRelic;
import com.datadog.metrics.MetricRegistry as DatadogMetricRegistry;
import org.elasticsearch.metrics.ElasticsearchMetrics;
import org.apache.logging.log4j.metrics.MetricsFactory;
import org.apache.logging.log4j.metrics.impl.DefaultMetricsFactory;
import org.apache.commons.metrics.MetricsFactory as CommonsMetricsFactory;
import org.apache.commons.metrics.impl.DefaultMetricsFactory as CommonsDefaultMetricsFactory;
import com.github.rollingmetrics.histogram.HistogramFactory;
import com.github.rollingmetrics.counter.CounterFactory;
import com.github.rollingmetrics.gauge.GaugeFactory;
import com.github.rollingmetrics.timer.TimerFactory;
import org.apache.skywalking.apm.toolkit.meter.MeterFactory;
import org.apache.skywalking.apm.toolkit.meter.MetricsFactory as SkywalkingMetricsFactory;
import org.apache.dubbo.metrics.MetricsFactory as DubboMetricsFactory;
import org.apache.dubbo.metrics.DefaultMetricsFactory as DubboDefaultMetricsFactory;
import org.apache.pulsar.metrics.MetricsFactory as PulsarMetricsFactory;
import org.apache.pulsar.metrics.impl.DefaultMetricsFactory as PulsarDefaultMetricsFactory;

// Security Issue: Improper instantiation of MetricsFactory objects without singleton pattern can lead to resource exhaustion

// True Positive Examples (Vulnerable/Insecure Code)

public class ImproperMetricsInstantiationExamples {

    // Bad case 1: Dropwizard Metrics - Creating new registry instances for each request
// {fact rule=resource-leak@v1.0 defects=1}
    public MetricRegistry bad_case_1() {
        // ruleid: java-coral-improper-metrics-instantiation
        return new MetricRegistry();
    }

    // Bad case 2: Micrometer - Creating new registry instances without singleton pattern
    public MeterRegistry bad_case_2() {
        // ruleid: java-coral-improper-metrics-instantiation
        return new SimpleMeterRegistry();
    }

    // Bad case 3: Prometheus - Creating new registry instances
    public CollectorRegistry bad_case_3() {
        // ruleid: java-coral-improper-metrics-instantiation
        return new CollectorRegistry();
    }

    // Bad case 4: Netflix Spectator - Creating new registry instances
    public Registry bad_case_4() {
        // ruleid: java-coral-improper-metrics-instantiation
        return new DefaultRegistry();
    }

    // Bad case 5: Spring Metrics - Creating new registry instances
    public SpringMeterRegistry bad_case_5() {
        // ruleid: java-coral-improper-metrics-instantiation
        return new SpringSimpleMeterRegistry();
    }

    // Bad case 6: Uber M3 - Creating new scope instances
    public Scope bad_case_6() {
        // ruleid: java-coral-improper-metrics-instantiation
        return new RootScopeBuilder().build();
    }

    // Bad case 7: Dropwizard Metrics 5 - Creating new registry instances
    public Dropwizard5MetricRegistry bad_case_7() {
        // ruleid: java-coral-improper-metrics-instantiation
        return new Dropwizard5MetricRegistry();
    }

    // Bad case 8: Google Metrics - Creating new registry instances
    public GoogleMetricRegistry bad_case_8() {
        // ruleid: java-coral-improper-metrics-instantiation
        return new GoogleMetricRegistry();
    }

    // Bad case 9: OpenCensus - Creating new stats recorder instances
    public StatsRecorder bad_case_9() {
        // ruleid: java-coral-improper-metrics-instantiation
        return Stats.getStatsRecorder();
    }

    // Bad case 10: AWS SDK Metrics - Creating new registry instances
    public AWSMetricRegistry bad_case_10() {
        // ruleid: java-coral-improper-metrics-instantiation
        return new AWSMetricRegistry();
    }

    // Bad case 11: Kafka Metrics - Creating new metrics instances
    public Metrics bad_case_11() {
        // ruleid: java-coral-improper-metrics-instantiation
        return new Metrics(new MetricConfig(), null, null);
    }

    // Bad case 12: Application Insights - Creating new telemetry client instances
    public TelemetryClient bad_case_12() {
        // ruleid: java-coral-improper-metrics-instantiation
        return new TelemetryClient();
    }

    // Bad case 13: OpenTelemetry - Creating new meter provider instances
    public MeterProvider bad_case_13() {
        // ruleid: java-coral-improper-metrics-instantiation
        return SdkMeterProvider.builder().build();
    }

    // Bad case 14: Log4j Metrics - Creating new metrics factory instances
    public MetricsFactory bad_case_14() {
        // ruleid: java-coral-improper-metrics-instantiation
        return new DefaultMetricsFactory();
    }

    // Bad case 15: Commons Metrics - Creating new metrics factory instances
    public CommonsMetricsFactory bad_case_15() {
        // ruleid: java-coral-improper-metrics-instantiation
        return new CommonsDefaultMetricsFactory();
    }

    // True Negative Examples (Safe/Secure Code)

    // Good case 1: Dropwizard Metrics - Using singleton pattern
    private static final MetricRegistry METRIC_REGISTRY = new MetricRegistry();
    
    public MetricRegistry good_case_1() {
        // ok: java-coral-improper-metrics-instantiation
        return METRIC_REGISTRY;
    }

    // Good case 2: Micrometer - Using singleton pattern
    private static final MeterRegistry METER_REGISTRY = new SimpleMeterRegistry();
    
    public MeterRegistry good_case_2() {
        // ok: java-coral-improper-metrics-instantiation
        return METER_REGISTRY;
    }

    // Good case 3: Prometheus - Using singleton pattern
    private static final CollectorRegistry COLLECTOR_REGISTRY = CollectorRegistry.defaultRegistry;
    
    public CollectorRegistry good_case_3() {
        // ok: java-coral-improper-metrics-instantiation
        return COLLECTOR_REGISTRY;
    }

    // Good case 4: Netflix Spectator - Using singleton pattern
    private static final Registry SPECTATOR_REGISTRY = new DefaultRegistry();
    
    public Registry good_case_4() {
        // ok: java-coral-improper-metrics-instantiation
        return SPECTATOR_REGISTRY;
    }

    // Good case 5: Spring Metrics - Using singleton pattern
    private static final SpringMeterRegistry SPRING_METER_REGISTRY = new SpringSimpleMeterRegistry();
    
    public SpringMeterRegistry good_case_5() {
        // ok: java-coral-improper-metrics-instantiation
        return SPRING_METER_REGISTRY;
    }

    // Good case 6: Uber M3 - Using singleton pattern
    private static final Scope M3_SCOPE = new RootScopeBuilder().build();
    
    public Scope good_case_6() {
        // ok: java-coral-improper-metrics-instantiation
        return M3_SCOPE;
    }

    // Good case 7: Dropwizard Metrics 5 - Using singleton pattern
    private static final Dropwizard5MetricRegistry DW5_METRIC_REGISTRY = new Dropwizard5MetricRegistry();
    
    public Dropwizard5MetricRegistry good_case_7() {
        // ok: java-coral-improper-metrics-instantiation
        return DW5_METRIC_REGISTRY;
    }

    // Good case 8: Google Metrics - Using singleton pattern
    private static final GoogleMetricRegistry GOOGLE_METRIC_REGISTRY = new GoogleMetricRegistry();
    
    public GoogleMetricRegistry good_case_8() {
        // ok: java-coral-improper-metrics-instantiation
        return GOOGLE_METRIC_REGISTRY;
    }

    // Good case 9: OpenCensus - Using singleton pattern
    private static final StatsRecorder STATS_RECORDER = Stats.getStatsRecorder();
    
    public StatsRecorder good_case_9() {
        // ok: java-coral-improper-metrics-instantiation
        return STATS_RECORDER;
    }

    // Good case 10: AWS SDK Metrics - Using singleton pattern
    private static final AWSMetricRegistry AWS_METRIC_REGISTRY = AwsSdkMetrics.getRegistry();
    
    public AWSMetricRegistry good_case_10() {
        // ok: java-coral-improper-metrics-instantiation
        return AWS_METRIC_REGISTRY;
    }

    // Good case 11: Kafka Metrics - Using singleton pattern
    private static final Metrics KAFKA_METRICS = new Metrics(new MetricConfig(), null, null);
    
    public Metrics good_case_11() {
        // ok: java-coral-improper-metrics-instantiation
        return KAFKA_METRICS;
    }

    // Good case 12: Application Insights - Using singleton pattern
    private static final TelemetryClient TELEMETRY_CLIENT = new TelemetryClient();
    
    public TelemetryClient good_case_12() {
        // ok: java-coral-improper-metrics-instantiation
        return TELEMETRY_CLIENT;
    }

    // Good case 13: OpenTelemetry - Using singleton pattern
    private static final MeterProvider METER_PROVIDER = SdkMeterProvider.builder().build();
    
    public MeterProvider good_case_13() {
        // ok: java-coral-improper-metrics-instantiation
        return METER_PROVIDER;
    }

    // Good case 14: Log4j Metrics - Using singleton pattern
    private static final MetricsFactory LOG4J_METRICS_FAC_REDACTED_TWILIO_ID = new DefaultMetricsFactory();
    
    public MetricsFactory good_case_14() {
        // ok: java-coral-improper-metrics-instantiation
        return LOG4J_METRICS_FAC_REDACTED_TWILIO_ID;
    }

    // Good case 15: Commons Metrics - Using singleton pattern
    private static final CommonsMetricsFactory COMMONS_METRICS_FAC_REDACTED_TWILIO_ID = new CommonsDefaultMetricsFactory();
    
    public CommonsMetricsFactory good_case_15() {
        // ok: java-coral-improper-metrics-instantiation
        return COMMONS_METRICS_FAC_REDACTED_TWILIO_ID;
    }
}
// {/fact}