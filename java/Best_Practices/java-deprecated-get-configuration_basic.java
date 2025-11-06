package com.example.awsconfig;

import com.amazonaws.services.appconfig.AmazonAppConfig;
import com.amazonaws.services.appconfig.AmazonAppConfigClient;
import com.amazonaws.services.appconfig.AmazonAppConfigClientBuilder;
import com.amazonaws.services.appconfig.model.GetConfigurationRequest;
import com.amazonaws.services.appconfig.model.GetConfigurationResult;
import com.amazonaws.services.appconfigdata.AmazonAppConfigData;
import com.amazonaws.services.appconfigdata.AmazonAppConfigDataClient;
import com.amazonaws.services.appconfigdata.AmazonAppConfigDataClientBuilder;
import com.amazonaws.services.appconfigdata.model.GetLatestConfigurationRequest;
import com.amazonaws.services.appconfigdata.model.GetLatestConfigurationResult;
import com.amazonaws.services.appconfigdata.model.StartConfigurationSessionRequest;
import com.amazonaws.services.appconfigdata.model.StartConfigurationSessionResult;
import java.nio.ByteBuffer;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import software.amazon.awssdk.services.appconfig.AppConfigClient;
import software.amazon.awssdk.services.appconfig.model.GetConfigurationResponse;
import software.amazon.awssdk.services.appconfigdata.AppConfigDataClient;
import software.amazon.awssdk.services.appconfigdata.model.StartConfigurationSessionResponse;

public class AppConfigExamples {

    // True Positives (Vulnerable Code)

// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_1() {
        AmazonAppConfig appConfig = AmazonAppConfigClient.builder().build();
        
        // ruleid: java-deprecated-get-configuration
        GetConfigurationResult result = appConfig.getConfiguration(
            new GetConfigurationRequest()
                .withApplication("MyApp")
                .withEnvironment("Production")
                .withConfiguration("MyConfig")
                .withClientId("MyClientId"));
        
        String configData = new String(result.getContent().array());
        System.out.println("Config: " + configData);
    }

    public void bad_case_2() {
        AmazonAppConfig appConfig = AmazonAppConfigClientBuilder.standard().build();
        GetConfigurationRequest request = new GetConfigurationRequest()
            .withApplication("MyApp")
            .withEnvironment("Staging")
            .withConfiguration("FeatureFlags")
            .withClientId("Client123");
        
        // ruleid: java-deprecated-get-configuration
        GetConfigurationResult result = appConfig.getConfiguration(request);
        
        processConfiguration(result);
    }

    public void bad_case_3() {
        AmazonAppConfig client = AmazonAppConfigClient.builder().build();
        String application = "ServiceApp";
        String environment = "Development";
        String configuration = "APISettings";
        String clientId = "DevClient";
        
        // ruleid: java-deprecated-get-configuration
        GetConfigurationResult config = client.getConfiguration(
            new GetConfigurationRequest()
                .withApplication(application)
                .withEnvironment(environment)
                .withConfiguration(configuration)
                .withClientId(clientId));
                
        if (config.getConfigurationVersion() != null) {
            System.out.println("Version: " + config.getConfigurationVersion());
        }
    }

    public void bad_case_4() {
        class ConfigFetcher {
            private final AmazonAppConfig appConfigClient;
            
            public ConfigFetcher() {
                this.appConfigClient = AmazonAppConfigClient.builder().build();
            }
            
            public String fetchConfig(String app, String env, String config) {
                // ruleid: java-deprecated-get-configuration
                GetConfigurationResult result = appConfigClient.getConfiguration(
                    new GetConfigurationRequest()
                        .withApplication(app)
                        .withEnvironment(env)
                        .withConfiguration(config)
                        .withClientId("ConfigFetcher"));
                
                return new String(result.getContent().array());
            }
        }
        
        ConfigFetcher fetcher = new ConfigFetcher();
        String configData = fetcher.fetchConfig("WebApp", "Production", "DatabaseSettings");
        System.out.println(configData);
    }

    public void bad_case_5() {
        AmazonAppConfig appConfig = AmazonAppConfigClient.builder().build();
        
        for (String environment : new String[]{"Dev", "Test", "Prod"}) {
            // ruleid: java-deprecated-get-configuration
            GetConfigurationResult result = appConfig.getConfiguration(
                new GetConfigurationRequest()
                    .withApplication("MultiEnvApp")
                    .withEnvironment(environment)
                    .withConfiguration("AppSettings")
                    .withClientId("EnvClient-" + environment));
            
            System.out.println("Config for " + environment + ": " + 
                new String(result.getContent().array()));
        }
    }

    public void bad_case_6() {
        try {
            AmazonAppConfig appConfig = AmazonAppConfigClient.builder().build();
            
            // ruleid: java-deprecated-get-configuration
            GetConfigurationResult result = appConfig.getConfiguration(
                new GetConfigurationRequest()
                    .withApplication("ErrorHandlingApp")
                    .withEnvironment("Production")
                    .withConfiguration("ErrorConfig")
                    .withClientId("ErrorClient"));
                    
            System.out.println("Config loaded successfully");
        } catch (Exception e) {
            System.err.println("Failed to load configuration: " + e.getMessage());
        }
    }

    public void bad_case_7() {
        AmazonAppConfig appConfig = AmazonAppConfigClient.builder().build();
        String clientId = "DynamicClient-" + System.currentTimeMillis();
        
        // ruleid: java-deprecated-get-configuration
        GetConfigurationResult initialConfig = appConfig.getConfiguration(
            new GetConfigurationRequest()
                .withApplication("DynamicApp")
                .withEnvironment("Production")
                .withConfiguration("DynamicSettings")
                .withClientId(clientId));
        
        // Polling for updates using the deprecated API
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
        executor.scheduleAtFixedRate(() -> {
            try {
                // ruleid: java-deprecated-get-configuration
                GetConfigurationResult updatedConfig = appConfig.getConfiguration(
                    new GetConfigurationRequest()
                        .withApplication("DynamicApp")
                        .withEnvironment("Production")
                        .withConfiguration("DynamicSettings")
                        .withClientId(clientId)
                        .withClientConfigurationVersion(initialConfig.getConfigurationVersion()));
                
                System.out.println("Config updated: " + updatedConfig.getConfigurationVersion());
            } catch (Exception e) {
                System.err.println("Error updating config: " + e.getMessage());
            }
        }, 1, 5, TimeUnit.MINUTES);
    }

    public void bad_case_8() {
        // Using the deprecated API with AWS SDK v1
        AmazonAppConfig appConfigClient = AmazonAppConfigClient.builder().build();
        
        try {
            // ruleid: java-deprecated-get-configuration
            GetConfigurationResult result = appConfigClient.getConfiguration(
                new GetConfigurationRequest()
                    .withApplication("MobileApp")
                    .withEnvironment("Production")
                    .withConfiguration("MobileSettings")
                    .withClientId("MobileClient"));
            
            ByteBuffer content = result.getContent();
            if (content != null) {
                byte[] bytes = new byte[content.remaining()];
                content.get(bytes);
                String configString = new String(bytes);
                System.out.println("Mobile config: " + configString);
            }
        } catch (Exception e) {
            System.err.println("Failed to get mobile configuration: " + e.getMessage());
        }
    }

    public void bad_case_9() {
        // Using the deprecated API with AWS SDK v2
        AppConfigClient appConfigClient = AppConfigClient.create();
        
        // ruleid: java-deprecated-get-configuration
        GetConfigurationResponse response = appConfigClient.getConfiguration(
            software.amazon.awssdk.services.appconfig.model.GetConfigurationRequest.builder()
                .application("BackendService")
                .environment("Production")
                .configuration("ServiceConfig")
                .clientId("BackendClient")
                .build());
        
        String configData = response.content().asUtf8String();
        System.out.println("Backend config: " + configData);
    }

    public void bad_case_10() {
        class ConfigurationManager {
            private final AmazonAppConfig appConfigClient;
            private String lastKnownVersion = null;
            
            public ConfigurationManager() {
                this.appConfigClient = AmazonAppConfigClient.builder().build();
            }
            
            public String getLatestConfig() {
                GetConfigurationRequest request = new GetConfigurationRequest()
                    .withApplication("ConfigManager")
                    .withEnvironment("Production")
                    .withConfiguration("ManagerConfig")
                    .withClientId("ManagerClient");
                
                if (lastKnownVersion != null) {
                    request.withClientConfigurationVersion(lastKnownVersion);
                }
                
                // ruleid: java-deprecated-get-configuration
                GetConfigurationResult result = appConfigClient.getConfiguration(request);
                lastKnownVersion = result.getConfigurationVersion();
                
                return new String(result.getContent().array());
            }
        }
        
        ConfigurationManager manager = new ConfigurationManager();
        String config = manager.getLatestConfig();
        System.out.println("Manager config: " + config);
    }

    public void bad_case_11() {
        AmazonAppConfig appConfig = AmazonAppConfigClient.builder().build();
        String[] applications = {"App1", "App2", "App3"};
        
        for (String app : applications) {
            // ruleid: java-deprecated-get-configuration
            GetConfigurationResult result = appConfig.getConfiguration(
                new GetConfigurationRequest()
                    .withApplication(app)
                    .withEnvironment("Production")
                    .withConfiguration("SharedConfig")
                    .withClientId("MultiAppClient"));
            
            System.out.println("Config for " + app + ": " + new String(result.getContent().array()));
        }
    }

    public void bad_case_12() {
        AmazonAppConfig appConfig = AmazonAppConfigClient.builder().build();
        String application = getApplicationName();
        String environment = getEnvironmentName();
        
        // ruleid: java-deprecated-get-configuration
        GetConfigurationResult result = appConfig.getConfiguration(
            new GetConfigurationRequest()
                .withApplication(application)
                .withEnvironment(environment)
                .withConfiguration("DynamicConfig")
                .withClientId("DynamicClient"));
        
        processConfigData(new String(result.getContent().array()));
    }

    public void bad_case_13() {
        // Lambda function using deprecated AppConfig API
        AmazonAppConfig appConfig = AmazonAppConfigClient.builder().build();
        
        // ruleid: java-deprecated-get-configuration
        GetConfigurationResult result = appConfig.getConfiguration(
            new GetConfigurationRequest()
                .withApplication("LambdaApp")
                .withEnvironment("Production")
                .withConfiguration("LambdaConfig")
                .withClientId("Lambda-" + System.currentTimeMillis()));
        
        String configData = new String(result.getContent().array());
        System.out.println("Lambda config: " + configData);
    }

    public void bad_case_14() {
        // Using deprecated API with conditional logic
        AmazonAppConfig appConfig = AmazonAppConfigClient.builder().build();
        String environment = System.getenv("ENV") != null ? System.getenv("ENV") : "Development";
        
        GetConfigurationRequest request = new GetConfigurationRequest()
            .withApplication("ConditionalApp")
            .withEnvironment(environment)
            .withConfiguration("AppConfig")
            .withClientId("ConditionalClient");
            
        if (shouldIncludeVersion()) {
            request.withClientConfigurationVersion("1.0");
        }
        
        // ruleid: java-deprecated-get-configuration
        GetConfigurationResult result = appConfig.getConfiguration(request);
        
        System.out.println("Config version: " + result.getConfigurationVersion());
    }

    public void bad_case_15() {
        // Using deprecated API with error handling and retry logic
        AmazonAppConfig appConfig = AmazonAppConfigClient.builder().build();
        GetConfigurationRequest request = new GetConfigurationRequest()
            .withApplication("RetryApp")
            .withEnvironment("Production")
            .withConfiguration("RetryConfig")
            .withClientId("RetryClient");
            
        int maxRetries = 3;
        int retryCount = 0;
        GetConfigurationResult result = null;
        
        while (retryCount < maxRetries) {
            try {
                // ruleid: java-deprecated-get-configuration
                result = appConfig.getConfiguration(request);
                break;
            } catch (Exception e) {
                retryCount++;
                if (retryCount >= maxRetries) {
                    throw e;
                }
                try {
                    Thread.sleep(1000 * retryCount);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }
        }
        
        if (result != null) {
            System.out.println("Config after retries: " + new String(result.getContent().array()));
        }
    }

    // True Negatives (Safe Code)

    public void good_case_1() {
        // Using the recommended AppConfig Agent and GetLatestConfiguration API
        AmazonAppConfigData appConfigData = AmazonAppConfigDataClient.builder().build();
        
        // Start a configuration session
        StartConfigurationSessionRequest sessionRequest = new StartConfigurationSessionRequest()
            .withApplicationIdentifier("MyApp")
            .withEnvironmentIdentifier("Production")
            .withConfigurationProfileIdentifier("MyConfig");
        
        // ok: java-deprecated-get-configuration
        StartConfigurationSessionResult sessionResult = appConfigData.startConfigurationSession(sessionRequest);
        
        // Get the latest configuration
        GetLatestConfigurationRequest latestConfigRequest = new GetLatestConfigurationRequest()
            .withConfigurationToken(sessionResult.getInitialConfigurationToken());
        
        GetLatestConfigurationResult latestConfig = appConfigData.getLatestConfiguration(latestConfigRequest);
        
        String configData = new String(latestConfig.getConfiguration().array());
        System.out.println("Config: " + configData);
    }

    public void good_case_2() {
        // Using the recommended AppConfig Agent with AWS SDK v2
        AppConfigDataClient appConfigDataClient = AppConfigDataClient.create();
        
        // ok: java-deprecated-get-configuration
        StartConfigurationSessionResponse sessionResponse = appConfigDataClient.startConfigurationSession(
            software.amazon.awssdk.services.appconfigdata.model.StartConfigurationSessionRequest.builder()
                .applicationIdentifier("MyApp")
                .environmentIdentifier("Staging")
                .configurationProfileIdentifier("FeatureFlags")
                .build());
        
        software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationResponse latestConfig = 
            appConfigDataClient.getLatestConfiguration(
                software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationRequest.builder()
                    .configurationToken(sessionResponse.initialConfigurationToken())
                    .build());
        
        String configData = latestConfig.configuration().asUtf8String();
        System.out.println("Config data: " + configData);
    }

    public void good_case_3() {
        class ConfigurationProvider {
            private final AmazonAppConfigData appConfigDataClient;
            private String configurationToken;
            
            public ConfigurationProvider() {
                this.appConfigDataClient = AmazonAppConfigDataClient.builder().build();
                initializeSession();
            }
            
            private void initializeSession() {
                // ok: java-deprecated-get-configuration
                StartConfigurationSessionResult session = appConfigDataClient.startConfigurationSession(
                    new StartConfigurationSessionRequest()
                        .withApplicationIdentifier("ServiceApp")
                        .withEnvironmentIdentifier("Development")
                        .withConfigurationProfileIdentifier("APISettings"));
                
                this.configurationToken = session.getInitialConfigurationToken();
            }
            
            public String getLatestConfiguration() {
                GetLatestConfigurationResult result = appConfigDataClient.getLatestConfiguration(
                    new GetLatestConfigurationRequest().withConfigurationToken(configurationToken));
                
                // Update the token for the next call
                this.configurationToken = result.getNextPollConfigurationToken();
                
                return new String(result.getConfiguration().array());
            }
        }
        
        ConfigurationProvider provider = new ConfigurationProvider();
        String config = provider.getLatestConfiguration();
        System.out.println("Latest config: " + config);
    }

    public void good_case_4() {
        // Using the recommended API with polling for updates
        AmazonAppConfigData appConfigData = AmazonAppConfigDataClient.builder().build();
        
        // ok: java-deprecated-get-configuration
        StartConfigurationSessionResult session = appConfigData.startConfigurationSession(
            new StartConfigurationSessionRequest()
                .withApplicationIdentifier("PollingApp")
                .withEnvironmentIdentifier("Production")
                .withConfigurationProfileIdentifier("DynamicSettings"));
        
        String configToken = session.getInitialConfigurationToken();
        
        // Initial configuration fetch
        GetLatestConfigurationResult latestConfig = appConfigData.getLatestConfiguration(
            new GetLatestConfigurationRequest().withConfigurationToken(configToken));
        
        String configData = new String(latestConfig.getConfiguration().array());
        System.out.println("Initial config: " + configData);
        
        // Set up polling for updates
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
        executor.scheduleAtFixedRate(() -> {
            try {
                GetLatestConfigurationResult updatedConfig = appConfigData.getLatestConfiguration(
                    new GetLatestConfigurationRequest().withConfigurationToken(configToken));
                
                // Update the token for the next call
                configToken = updatedConfig.getNextPollConfigurationToken();
                
                if (updatedConfig.getConfiguration().remaining() > 0) {
                    String newConfigData = new String(updatedConfig.getConfiguration().array());
                    System.out.println("Updated config: " + newConfigData);
                }
            } catch (Exception e) {
                System.err.println("Error updating config: " + e.getMessage());
            }
        }, 1, 5, TimeUnit.MINUTES);
    }

    public void good_case_5() {
        // Using the recommended API with error handling
        AmazonAppConfigData appConfigData = AmazonAppConfigDataClient.builder().build();
        
        try {
            // ok: java-deprecated-get-configuration
            StartConfigurationSessionResult session = appConfigData.startConfigurationSession(
                new StartConfigurationSessionRequest()
                    .withApplicationIdentifier("ErrorHandlingApp")
                    .withEnvironmentIdentifier("Production")
                    .withConfigurationProfileIdentifier("ErrorConfig"));
            
            GetLatestConfigurationResult latestConfig = appConfigData.getLatestConfiguration(
                new GetLatestConfigurationRequest().withConfigurationToken(session.getInitialConfigurationToken()));
            
            String configData = new String(latestConfig.getConfiguration().array());
            System.out.println("Config loaded successfully: " + configData);
        } catch (Exception e) {
            System.err.println("Failed to load configuration: " + e.getMessage());
        }
    }

    public void good_case_6() {
        // Using the recommended API with AWS SDK v2 and multiple environments
        AppConfigDataClient appConfigDataClient = AppConfigDataClient.create();
        
        for (String environment : new String[]{"Dev", "Test", "Prod"}) {
            // ok: java-deprecated-get-configuration
            StartConfigurationSessionResponse sessionResponse = appConfigDataClient.startConfigurationSession(
                software.amazon.awssdk.services.appconfigdata.model.StartConfigurationSessionRequest.builder()
                    .applicationIdentifier("MultiEnvApp")
                    .environmentIdentifier(environment)
                    .configurationProfileIdentifier("AppSettings")
                    .build());
            
            software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationResponse latestConfig = 
                appConfigDataClient.getLatestConfiguration(
                    software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationRequest.builder()
                        .configurationToken(sessionResponse.initialConfigurationToken())
                        .build());
            
            System.out.println("Config for " + environment + ": " + latestConfig.configuration().asUtf8String());
        }
    }

    public void good_case_7() {
        // Using the recommended API with a configuration manager class
        class AppConfigManager {
            private final AmazonAppConfigData appConfigDataClient;
            private String configToken;
            private String lastKnownVersion;
            
            public AppConfigManager() {
                this.appConfigDataClient = AmazonAppConfigDataClient.builder().build();
                initializeSession();
            }
            
            private void initializeSession() {
                // ok: java-deprecated-get-configuration
                StartConfigurationSessionResult session = appConfigDataClient.startConfigurationSession(
                    new StartConfigurationSessionRequest()
                        .withApplicationIdentifier("ConfigManager")
                        .withEnvironmentIdentifier("Production")
                        .withConfigurationProfileIdentifier("ManagerConfig"));
                
                this.configToken = session.getInitialConfigurationToken();
            }
            
            public String getConfiguration() {
                GetLatestConfigurationResult result = appConfigDataClient.getLatestConfiguration(
                    new GetLatestConfigurationRequest().withConfigurationToken(configToken));
                
                // Update the token for the next call
                this.configToken = result.getNextPollConfigurationToken();
                this.lastKnownVersion = result.getContentType(); // Using contentType as version for example
                
                return new String(result.getConfiguration().array());
            }
            
            public String getLastKnownVersion() {
                return lastKnownVersion;
            }
        }
        
        AppConfigManager manager = new AppConfigManager();
        String config = manager.getConfiguration();
        System.out.println("Manager config: " + config);
    }

    public void good_case_8() {
        // Using the recommended API with multiple applications
        AmazonAppConfigData appConfigData = AmazonAppConfigDataClient.builder().build();
        String[] applications = {"App1", "App2", "App3"};
        
        for (String app : applications) {
            // ok: java-deprecated-get-configuration
            StartConfigurationSessionResult session = appConfigData.startConfigurationSession(
                new StartConfigurationSessionRequest()
                    .withApplicationIdentifier(app)
                    .withEnvironmentIdentifier("Production")
                    .withConfigurationProfileIdentifier("SharedConfig"));
            
            GetLatestConfigurationResult latestConfig = appConfigData.getLatestConfiguration(
                new GetLatestConfigurationRequest().withConfigurationToken(session.getInitialConfigurationToken()));
            
            System.out.println("Config for " + app + ": " + new String(latestConfig.getConfiguration().array()));
        }
    }

    public void good_case_9() {
        // Using the recommended API with dynamic application and environment names
        AmazonAppConfigData appConfigData = AmazonAppConfigDataClient.builder().build();
        String application = getApplicationName();
        String environment = getEnvironmentName();
        
        // ok: java-deprecated-get-configuration
        StartConfigurationSessionResult session = appConfigData.startConfigurationSession(
            new StartConfigurationSessionRequest()
                .withApplicationIdentifier(application)
                .withEnvironmentIdentifier(environment)
                .withConfigurationProfileIdentifier("DynamicConfig"));
        
        GetLatestConfigurationResult latestConfig = appConfigData.getLatestConfiguration(
            new GetLatestConfigurationRequest().withConfigurationToken(session.getInitialConfigurationToken()));
        
        processConfigData(new String(latestConfig.getConfiguration().array()));
    }

    public void good_case_10() {
        // Using the recommended API in a Lambda function
        AmazonAppConfigData appConfigData = AmazonAppConfigDataClient.builder().build();
        
        // ok: java-deprecated-get-configuration
        StartConfigurationSessionResult session = appConfigData.startConfigurationSession(
            new StartConfigurationSessionRequest()
                .withApplicationIdentifier("LambdaApp")
                .withEnvironmentIdentifier("Production")
                .withConfigurationProfileIdentifier("LambdaConfig"));
        
        GetLatestConfigurationResult latestConfig = appConfigData.getLatestConfiguration(
            new GetLatestConfigurationRequest().withConfigurationToken(session.getInitialConfigurationToken()));
        
        String configData = new String(latestConfig.getConfiguration().array());
        System.out.println("Lambda config: " + configData);
    }

    public void good_case_11() {
        // Using the recommended API with conditional logic
        AmazonAppConfigData appConfigData = AmazonAppConfigDataClient.builder().build();
        String environment = System.getenv("ENV") != null ? System.getenv("ENV") : "Development";
        
        // ok: java-deprecated-get-configuration
        StartConfigurationSessionRequest sessionRequest = new StartConfigurationSessionRequest()
            .withApplicationIdentifier("ConditionalApp")
            .withEnvironmentIdentifier(environment)
            .withConfigurationProfileIdentifier("AppConfig");
            
        if (shouldIncludeVersion()) {
            // Add optional parameters if needed
            sessionRequest.withRequiredMinimumPollIntervalInSeconds(60);
        }
        
        StartConfigurationSessionResult session = appConfigData.startConfigurationSession(sessionRequest);
        
        GetLatestConfigurationResult latestConfig = appConfigData.getLatestConfiguration(
            new GetLatestConfigurationRequest().withConfigurationToken(session.getInitialConfigurationToken()));
        
        System.out.println("Config data size: " + latestConfig.getConfiguration().remaining());
    }

    public void good_case_12() {
        // Using the recommended API with retry logic
        AmazonAppConfigData appConfigData = AmazonAppConfigDataClient.builder().build();
        
        // ok: java-deprecated-get-configuration
        StartConfigurationSessionResult session = null;
        int maxRetries = 3;
        int retryCount = 0;
        
        while (retryCount < maxRetries) {
            try {
                session = appConfigData.startConfigurationSession(
                    new StartConfigurationSessionRequest()
                        .withApplicationIdentifier("RetryApp")
                        .withEnvironmentIdentifier("Production")
                        .withConfigurationProfileIdentifier("RetryConfig"));
                break;
            } catch (Exception e) {
                retryCount++;
                if (retryCount >= maxRetries) {
                    throw e;
                }
                try {
                    Thread.sleep(1000 * retryCount);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }
        }
        
        if (session != null) {
            GetLatestConfigurationResult latestConfig = appConfigData.getLatestConfiguration(
                new GetLatestConfigurationRequest().withConfigurationToken(session.getInitialConfigurationToken()));
            
            System.out.println("Config after retries: " + new String(latestConfig.getConfiguration().array()));
        }
    }

    public void good_case_13() {
        // Using the recommended API with AWS SDK v2 and custom client configuration
        software.amazon.awssdk.services.appconfigdata.AppConfigDataClient appConfigDataClient = 
            software.amazon.awssdk.services.appconfigdata.AppConfigDataClient.builder()
                .region(software.amazon.awssdk.regions.Region.US_WEST_2)
                .build();
        
        // ok: java-deprecated-get-configuration
        software.amazon.awssdk.services.appconfigdata.model.StartConfigurationSessionResponse sessionResponse = 
            appConfigDataClient.startConfigurationSession(
                software.amazon.awssdk.services.appconfigdata.model.StartConfigurationSessionRequest.builder()
                    .applicationIdentifier("CustomApp")
                    .environmentIdentifier("Production")
                    .configurationProfileIdentifier("CustomConfig")
                    .build());
        
        software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationResponse latestConfig = 
            appConfigDataClient.getLatestConfiguration(
                software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationRequest.builder()
                    .configurationToken(sessionResponse.initialConfigurationToken())
                    .build());
        
        System.out.println("Custom config: " + latestConfig.configuration().asUtf8String());
    }

    public void good_case_14() {
        // Using the recommended API with a custom configuration cache
        class ConfigCache {
            private final AmazonAppConfigData appConfigDataClient;
            private String configToken;
            private ByteBuffer cachedConfig;
            private long lastFetchTime;
            private final long cacheTimeoutMs = 60000; // 1 minute cache
            
            public ConfigCache() {
                this.appConfigDataClient = AmazonAppConfigDataClient.builder().build();
                initializeSession();
            }
            
            private void initializeSession() {
                // ok: java-deprecated-get-configuration
                StartConfigurationSessionResult session = appConfigDataClient.startConfigurationSession(
                    new StartConfigurationSessionRequest()
                        .withApplicationIdentifier("CacheApp")
                        .withEnvironmentIdentifier("Production")
                        .withConfigurationProfileIdentifier("CachedConfig"));
                
                this.configToken = session.getInitialConfigurationToken();
                fetchLatestConfig();
            }
            
            private void fetchLatestConfig() {
                GetLatestConfigurationResult result = appConfigDataClient.getLatestConfiguration(
                    new GetLatestConfigurationRequest().withConfigurationToken(configToken));
                
                // Update the token for the next call
                this.configToken = result.getNextPollConfigurationToken();
                
                // Only update cache if we got new content
                if (result.getConfiguration().remaining() > 0) {
                    this.cachedConfig = result.getConfiguration();
                }
                
                this.lastFetchTime = System.currentTimeMillis();
            }
            
            public String getConfiguration() {
                // Check if cache needs refresh
                if (System.currentTimeMillis() - lastFetchTime > cacheTimeoutMs) {
                    fetchLatestConfig();
                }
                
                return cachedConfig != null ? new String(cachedConfig.array()) : "";
            }
        }
        
        ConfigCache cache = new ConfigCache();
        String config = cache.getConfiguration();
        System.out.println("Cached config: " + config);
    }

    public void good_case_15() {
        // Using the recommended API with feature flag handling
        AmazonAppConfigData appConfigData = AmazonAppConfigDataClient.builder().build();
        
        // ok: java-deprecated-get-configuration
        StartConfigurationSessionResult session = appConfigData.startConfigurationSession(
            new StartConfigurationSessionRequest()
                .withApplicationIdentifier("FeatureFlagApp")
                .withEnvironmentIdentifier("Production")
                .withConfigurationProfileIdentifier("FeatureFlags"));
        
        GetLatestConfigurationResult latestConfig = appConfigData.getLatestConfiguration(
            new GetLatestConfigurationRequest().withConfigurationToken(session.getInitialConfigurationToken()));
        
        String featureFlagsJson = new String(latestConfig.getConfiguration().array());
        
        // Process feature flags (simplified example)
        if (featureFlagsJson.contains("\"newFeature\": true")) {
            System.out.println("New feature is enabled!");
            enableNewFeature();
        } else {
            System.out.println("New feature is disabled");
        }
    }

    // Helper methods
    private void processConfiguration(GetConfigurationResult result) {
        System.out.println("Processing configuration version: " + result.getConfigurationVersion());
    }
    
    private void processConfigData(String configData) {
        System.out.println("Processing config data: " + configData);
    }
    
    private String getApplicationName() {
        return "DynamicApp";
    }
    
    private String getEnvironmentName() {
        return "Production";
    }
    
    private boolean shouldIncludeVersion() {
        return true;
    }
    
    private void enableNewFeature() {
        System.out.println("New feature enabled!");
    }
}
// {/fact}