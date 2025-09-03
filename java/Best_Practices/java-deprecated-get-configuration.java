import com.amazonaws.services.appconfig.AmazonAppConfig;
import com.amazonaws.services.appconfig.AmazonAppConfigClient;
import com.amazonaws.services.appconfig.AmazonAppConfigClientBuilder;
import com.amazonaws.services.appconfig.model.GetConfigurationRequest;
import com.amazonaws.services.appconfig.model.GetConfigurationResult;
import software.amazon.awssdk.services.appconfigdata.AppConfigDataClient;
import software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationRequest;
import software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationResponse;
import software.amazon.awssdk.services.appconfigdata.model.StartConfigurationSessionRequest;
import software.amazon.awssdk.services.appconfigdata.model.StartConfigurationSessionResponse;
import java.nio.charset.StandardCharsets;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.auth.EnvironmentVariableCredentialsProvider;
import com.amazonaws.auth.SystemPropertiesCredentialsProvider;
import com.amazonaws.regions.Regions;
import java.util.Properties;
import java.io.FileInputStream;
import java.io.IOException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

public class AppConfigExamples {

    // True Positive Examples (Vulnerable Code)
    
// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public void bad_case_1() {
        AmazonAppConfig appConfigClient = AmazonAppConfigClientBuilder.standard().build();
        
        // ruleid: java-deprecated-get-configuration
        GetConfigurationResult result = appConfigClient.getConfiguration(
            new GetConfigurationRequest()
                .withApplication("MyApp")
                .withEnvironment("Production")
                .withConfiguration("MyConfig")
        );
        
        String configData = new String(result.getContent().array(), StandardCharsets.UTF_8);
        System.out.println("Retrieved configuration: " + configData);
    }
    
    public void bad_case_2() {
        AmazonAppConfig client = AmazonAppConfigClientBuilder.standard()
                .withRegion(Regions.US_WEST_2)
                .build();
        
        // ruleid: java-deprecated-get-configuration
        GetConfigurationResult config = client.getConfiguration(
                new GetConfigurationRequest()
                    .withApplication("ServiceApp")
                    .withEnvironment("Beta")
                    .withConfiguration("FeatureFlags")
                    .withClientId("client-123"));
        
        if (config.getContent() != null) {
            processConfiguration(config);
        }
    }
    
    public void bad_case_3() {
        AmazonAppConfigClient appConfigClient = new AmazonAppConfigClient();
        String appId = "MyApplication";
        String envId = "Development";
        String configId = "APISettings";
        
        try {
            // ruleid: java-deprecated-get-configuration
            GetConfigurationResult result = appConfigClient.getConfiguration(
                new GetConfigurationRequest()
                    .withApplication(appId)
                    .withEnvironment(envId)
                    .withConfiguration(configId)
                    .withClientId("web-frontend")
            );
            
            handleConfigUpdate(result);
        } catch (Exception e) {
            System.err.println("Failed to get configuration: " + e.getMessage());
        }
    }
    
    public void bad_case_4() {
        AmazonAppConfig appConfigClient = AmazonAppConfigClientBuilder.defaultClient();
        
        for (String environment : new String[]{"Dev", "Staging", "Prod"}) {
            // ruleid: java-deprecated-get-configuration
            GetConfigurationResult result = appConfigClient.getConfiguration(
                new GetConfigurationRequest()
                    .withApplication("PaymentService")
                    .withEnvironment(environment)
                    .withConfiguration("Endpoints")
            );
            
            if (result.getConfigurationVersion() != null) {
                System.out.println("Config version: " + result.getConfigurationVersion());
            }
        }
    }
    
    public void bad_case_5() {
        AmazonAppConfig appConfigClient = AmazonAppConfigClientBuilder.standard()
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .withRegion(Regions.EU_CENTRAL_1)
                .build();
        
        String clientId = generateClientId();
        
        // ruleid: java-deprecated-get-configuration
        GetConfigurationResult initialConfig = appConfigClient.getConfiguration(
            new GetConfigurationRequest()
                .withApplication("OrderSystem")
                .withEnvironment("Production")
                .withConfiguration("DatabaseSettings")
                .withClientId(clientId)
        );
        
        startPollingForUpdates(appConfigClient, initialConfig, clientId);
    }
    
    public void bad_case_6() {
        class ConfigurationManager {
            private final AmazonAppConfig client;
            
            public ConfigurationManager() {
                this.client = AmazonAppConfigClientBuilder.standard().build();
            }
            
            public String fetchConfig(String app, String env, String config) {
                // ruleid: java-deprecated-get-configuration
                GetConfigurationResult result = client.getConfiguration(
                    new GetConfigurationRequest()
                        .withApplication(app)
                        .withEnvironment(env)
                        .withConfiguration(config)
                );
                
                return new String(result.getContent().array(), StandardCharsets.UTF_8);
            }
        }
        
        ConfigurationManager manager = new ConfigurationManager();
        String config = manager.fetchConfig("AuthService", "Production", "SecuritySettings");
    }
    
    public void bad_case_7() {
        AmazonAppConfig appConfigClient = AmazonAppConfigClientBuilder.standard().build();
        String previousVersion = null;
        
        while (true) {
            try {
                GetConfigurationRequest request = new GetConfigurationRequest()
                    .withApplication("NotificationService")
                    .withEnvironment("Production")
                    .withConfiguration("EmailTemplates")
                    .withClientId("service-poller");
                
                if (previousVersion != null) {
                    request.withClientConfigurationVersion(previousVersion);
                }
                
                // ruleid: java-deprecated-get-configuration
                GetConfigurationResult result = appConfigClient.getConfiguration(request);
                
                if (!result.getConfigurationVersion().equals(previousVersion)) {
                    previousVersion = result.getConfigurationVersion();
                    updateTemplates(result);
                }
                
                Thread.sleep(30000); // Poll every 30 seconds
            } catch (Exception e) {
                System.err.println("Error polling for configuration: " + e.getMessage());
            }
        }
    }
    
    public void bad_case_8() {
        AmazonAppConfig appConfigClient = AmazonAppConfigClientBuilder.standard()
                .withRegion(Regions.US_EAST_1)
                .build();
        
        try {
            // ruleid: java-deprecated-get-configuration
            GetConfigurationResult result = appConfigClient.getConfiguration(
                new GetConfigurationRequest()
                    .withApplication("UserService")
                    .withEnvironment(getEnvironmentFromSystemProperty())
                    .withConfiguration("RateLimits")
            );
            
            if (result.getContent() != null) {
                updateRateLimits(result.getContent());
            }
        } catch (Exception e) {
            fallbackToDefaultRateLimits();
        }
    }
    
    public void bad_case_9() {
        class ConfigFetcher implements Runnable {
            private final AmazonAppConfig client;
            
            public ConfigFetcher() {
                client = AmazonAppConfigClientBuilder.standard().build();
            }
            
            @Override
            public void run() {
                try {
                    // ruleid: java-deprecated-get-configuration
                    GetConfigurationResult result = client.getConfiguration(
                        new GetConfigurationRequest()
                            .withApplication("LoggingService")
                            .withEnvironment("Production")
                            .withConfiguration("LogLevels")
                    );
                    
                    updateLogLevels(result.getContent());
                } catch (Exception e) {
                    System.err.println("Failed to fetch configuration: " + e.getMessage());
                }
            }
        }
        
        new Thread(new ConfigFetcher()).start();
    }
    
    public void bad_case_10() {
        AmazonAppConfig appConfigClient = AmazonAppConfigClientBuilder.standard().build();
        
        String[] applications = {"Frontend", "Backend", "Database"};
        String[] configurations = {"Timeouts", "Retries", "Connections"};
        
        for (String app : applications) {
            for (String config : configurations) {
                // ruleid: java-deprecated-get-configuration
                GetConfigurationResult result = appConfigClient.getConfiguration(
                    new GetConfigurationRequest()
                        .withApplication(app)
                        .withEnvironment("Production")
                        .withConfiguration(config)
                );
                
                applyConfiguration(app, config, result.getContent());
            }
        }
    }
    
    public void bad_case_11() {
        AmazonAppConfig appConfigClient = null;
        try {
            appConfigClient = AmazonAppConfigClientBuilder.standard()
                    .withCredentials(new BasicAWSCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"))
                    .withRegion(Regions.US_WEST_2)
                    .build();
            
            // ruleid: java-deprecated-get-configuration
            GetConfigurationResult result = appConfigClient.getConfiguration(
                new GetConfigurationRequest()
                    .withApplication("SecurityService")
                    .withEnvironment("Production")
                    .withConfiguration("FirewallRules")
            );
            
            updateFirewallRules(result);
        } finally {
            if (appConfigClient != null) {
                appConfigClient.shutdown();
            }
        }
    }
    
    public void bad_case_12() {
        AmazonAppConfig appConfigClient = AmazonAppConfigClientBuilder.standard().build();
        
        switch (getCurrentDeploymentStage()) {
            case "dev":
                // ruleid: java-deprecated-get-configuration
                GetConfigurationResult devResult = appConfigClient.getConfiguration(
                    new GetConfigurationRequest()
                        .withApplication("MyApp")
                        .withEnvironment("Development")
                        .withConfiguration("AppSettings")
                );
                processDevConfig(devResult);
                break;
            case "prod":
                // ruleid: java-deprecated-get-configuration
                GetConfigurationResult prodResult = appConfigClient.getConfiguration(
                    new GetConfigurationRequest()
                        .withApplication("MyApp")
                        .withEnvironment("Production")
                        .withConfiguration("AppSettings")
                );
                processProdConfig(prodResult);
                break;
        }
    }
    
    public void bad_case_13() {
        AmazonAppConfig appConfigClient = AmazonAppConfigClientBuilder.standard().build();
        
        try {
            // ruleid: java-deprecated-get-configuration
            GetConfigurationResult result = appConfigClient.getConfiguration(
                new GetConfigurationRequest()
                    .withApplication("AnalyticsService")
                    .withEnvironment("Production")
                    .withConfiguration("SamplingRates")
                    .withClientConfigurationVersion("1.0.0")
            );
            
            if (result.getContent() != null) {
                applySamplingRates(result.getContent());
            }
        } catch (Exception e) {
            System.err.println("Failed to get configuration: " + e.getMessage());
            useDefaultSamplingRates();
        }
    }
    
    public void bad_case_14() {
        AmazonAppConfig appConfigClient = AmazonAppConfigClientBuilder.standard()
                .withRegion(Regions.AP_NORTHEAST_1)
                .build();
        
        String clientId = "mobile-app-" + System.currentTimeMillis();
        
        // ruleid: java-deprecated-get-configuration
        GetConfigurationResult result = appConfigClient.getConfiguration(
            new GetConfigurationRequest()
                .withApplication("MobileApp")
                .withEnvironment("Production")
                .withConfiguration("UISettings")
                .withClientId(clientId)
        );
        
        if (result.getContent() != null) {
            String uiConfig = new String(result.getContent().array(), StandardCharsets.UTF_8);
            System.out.println("UI Configuration: " + uiConfig);
        }
    }
    
    public void bad_case_15() {
        class ConfigurationService {
            private final AmazonAppConfig client;
            private String lastKnownVersion = null;
            
            public ConfigurationService() {
                client = AmazonAppConfigClientBuilder.standard().build();
            }
            
            public byte[] getLatestConfiguration() {
                GetConfigurationRequest request = new GetConfigurationRequest()
                    .withApplication("RecommendationEngine")
                    .withEnvironment("Production")
                    .withConfiguration("AlgorithmParameters")
                    .withClientId("recommendation-service");
                
                if (lastKnownVersion != null) {
                    request.withClientConfigurationVersion(lastKnownVersion);
                }
                
                // ruleid: java-deprecated-get-configuration
                GetConfigurationResult result = client.getConfiguration(request);
                lastKnownVersion = result.getConfigurationVersion();
                
                return result.getContent() != null ? result.getContent().array() : null;
            }
        }
        
        ConfigurationService service = new ConfigurationService();
        byte[] config = service.getLatestConfiguration();
    }
    
    // True Negative Examples (Safe Code)
    
    public void good_case_1() {
        AppConfigDataClient appConfigClient = AppConfigDataClient.create();
        
        // Start a configuration session
        StartConfigurationSessionResponse sessionResponse = appConfigClient.startConfigurationSession(
            StartConfigurationSessionRequest.builder()
                .applicationIdentifier("MyApp")
                .environmentIdentifier("Production")
                .configurationProfileIdentifier("MyConfig")
                .build()
        );
        
        // ok: java-deprecated-get-configuration
        GetLatestConfigurationResponse result = appConfigClient.getLatestConfiguration(
            GetLatestConfigurationRequest.builder()
                .configurationToken(sessionResponse.initialConfigurationToken())
                .build()
        );
        
        String configData = new String(result.configuration().asByteArray(), StandardCharsets.UTF_8);
        System.out.println("Retrieved configuration: " + configData);
    }
    
    public void good_case_2() {
        AppConfigDataClient client = AppConfigDataClient.builder()
                .region(software.amazon.awssdk.regions.Region.US_WEST_2)
                .build();
        
        StartConfigurationSessionResponse sessionResponse = client.startConfigurationSession(
            StartConfigurationSessionRequest.builder()
                .applicationIdentifier("ServiceApp")
                .environmentIdentifier("Beta")
                .configurationProfileIdentifier("FeatureFlags")
                .build()
        );
        
        // ok: java-deprecated-get-configuration
        GetLatestConfigurationResponse config = client.getLatestConfiguration(
            GetLatestConfigurationRequest.builder()
                .configurationToken(sessionResponse.initialConfigurationToken())
                .build()
        );
        
        if (config.configuration() != null) {
            processConfiguration(config);
        }
    }
    
    public void good_case_3() {
        AppConfigDataClient appConfigClient = AppConfigDataClient.create();
        String appId = "MyApplication";
        String envId = "Development";
        String configId = "APISettings";
        
        try {
            StartConfigurationSessionResponse sessionResponse = appConfigClient.startConfigurationSession(
                StartConfigurationSessionRequest.builder()
                    .applicationIdentifier(appId)
                    .environmentIdentifier(envId)
                    .configurationProfileIdentifier(configId)
                    .build()
            );
            
            // ok: java-deprecated-get-configuration
            GetLatestConfigurationResponse result = appConfigClient.getLatestConfiguration(
                GetLatestConfigurationRequest.builder()
                    .configurationToken(sessionResponse.initialConfigurationToken())
                    .build()
            );
            
            handleConfigUpdate(result);
        } catch (Exception e) {
            System.err.println("Failed to get configuration: " + e.getMessage());
        }
    }
    
    public void good_case_4() {
        AppConfigDataClient appConfigClient = AppConfigDataClient.create();
        
        for (String environment : new String[]{"Dev", "Staging", "Prod"}) {
            StartConfigurationSessionResponse sessionResponse = appConfigClient.startConfigurationSession(
                StartConfigurationSessionRequest.builder()
                    .applicationIdentifier("PaymentService")
                    .environmentIdentifier(environment)
                    .configurationProfileIdentifier("Endpoints")
                    .build()
            );
            
            // ok: java-deprecated-get-configuration
            GetLatestConfigurationResponse result = appConfigClient.getLatestConfiguration(
                GetLatestConfigurationRequest.builder()
                    .configurationToken(sessionResponse.initialConfigurationToken())
                    .build()
            );
            
            System.out.println("Config version: " + result.configurationVersion());
        }
    }
    
    public void good_case_5() {
        AppConfigDataClient appConfigClient = AppConfigDataClient.builder()
                .region(software.amazon.awssdk.regions.Region.EU_CENTRAL_1)
                .build();
        
        StartConfigurationSessionResponse sessionResponse = appConfigClient.startConfigurationSession(
            StartConfigurationSessionRequest.builder()
                .applicationIdentifier("OrderSystem")
                .environmentIdentifier("Production")
                .configurationProfileIdentifier("DatabaseSettings")
                .build()
        );
        
        // ok: java-deprecated-get-configuration
        GetLatestConfigurationResponse initialConfig = appConfigClient.getLatestConfiguration(
            GetLatestConfigurationRequest.builder()
                .configurationToken(sessionResponse.initialConfigurationToken())
                .build()
        );
        
        startPollingForUpdates(appConfigClient, initialConfig, sessionResponse.initialConfigurationToken());
    }
    
    public void good_case_6() {
        class ConfigurationManager {
            private final AppConfigDataClient client;
            
            public ConfigurationManager() {
                this.client = AppConfigDataClient.create();
            }
            
            public String fetchConfig(String app, String env, String config) {
                StartConfigurationSessionResponse sessionResponse = client.startConfigurationSession(
                    StartConfigurationSessionRequest.builder()
                        .applicationIdentifier(app)
                        .environmentIdentifier(env)
                        .configurationProfileIdentifier(config)
                        .build()
                );
                
                // ok: java-deprecated-get-configuration
                GetLatestConfigurationResponse result = client.getLatestConfiguration(
                    GetLatestConfigurationRequest.builder()
                        .configurationToken(sessionResponse.initialConfigurationToken())
                        .build()
                );
                
                return new String(result.configuration().asByteArray(), StandardCharsets.UTF_8);
            }
        }
        
        ConfigurationManager manager = new ConfigurationManager();
        String config = manager.fetchConfig("AuthService", "Production", "SecuritySettings");
    }
    
    public void good_case_7() {
        AppConfigDataClient appConfigClient = AppConfigDataClient.create();
        
        StartConfigurationSessionResponse sessionResponse = appConfigClient.startConfigurationSession(
            StartConfigurationSessionRequest.builder()
                .applicationIdentifier("NotificationService")
                .environmentIdentifier("Production")
                .configurationProfileIdentifier("EmailTemplates")
                .build()
        );
        
        String configToken = sessionResponse.initialConfigurationToken();
        
        while (true) {
            try {
                // ok: java-deprecated-get-configuration
                GetLatestConfigurationResponse result = appConfigClient.getLatestConfiguration(
                    GetLatestConfigurationRequest.builder()
                        .configurationToken(configToken)
                        .build()
                );
                
                configToken = result.nextPollConfigurationToken();
                
                if (result.configuration().asByteArray().length > 0) {
                    updateTemplates(result);
                }
                
                Thread.sleep(30000); // Poll every 30 seconds
            } catch (Exception e) {
                System.err.println("Error polling for configuration: " + e.getMessage());
            }
        }
    }
    
    public void good_case_8() {
        AppConfigDataClient appConfigClient = AppConfigDataClient.builder()
                .region(software.amazon.awssdk.regions.Region.US_EAST_1)
                .build();
        
        try {
            StartConfigurationSessionResponse sessionResponse = appConfigClient.startConfigurationSession(
                StartConfigurationSessionRequest.builder()
                    .applicationIdentifier("UserService")
                    .environmentIdentifier(getEnvironmentFromSystemProperty())
                    .configurationProfileIdentifier("RateLimits")
                    .build()
            );
            
            // ok: java-deprecated-get-configuration
            GetLatestConfigurationResponse result = appConfigClient.getLatestConfiguration(
                GetLatestConfigurationRequest.builder()
                    .configurationToken(sessionResponse.initialConfigurationToken())
                    .build()
            );
            
            if (result.configuration() != null) {
                updateRateLimits(result.configuration());
            }
        } catch (Exception e) {
            fallbackToDefaultRateLimits();
        }
    }
    
    public void good_case_9() {
        class ConfigFetcher implements Runnable {
            private final AppConfigDataClient client;
            
            public ConfigFetcher() {
                client = AppConfigDataClient.create();
            }
            
            @Override
            public void run() {
                try {
                    StartConfigurationSessionResponse sessionResponse = client.startConfigurationSession(
                        StartConfigurationSessionRequest.builder()
                            .applicationIdentifier("LoggingService")
                            .environmentIdentifier("Production")
                            .configurationProfileIdentifier("LogLevels")
                            .build()
                    );
                    
                    // ok: java-deprecated-get-configuration
                    GetLatestConfigurationResponse result = client.getLatestConfiguration(
                        GetLatestConfigurationRequest.builder()
                            .configurationToken(sessionResponse.initialConfigurationToken())
                            .build()
                    );
                    
                    updateLogLevels(result.configuration());
                } catch (Exception e) {
                    System.err.println("Failed to fetch configuration: " + e.getMessage());
                }
            }
        }
        
        new Thread(new ConfigFetcher()).start();
    }
    
    public void good_case_10() {
        AppConfigDataClient appConfigClient = AppConfigDataClient.create();
        
        String[] applications = {"Frontend", "Backend", "Database"};
        String[] configurations = {"Timeouts", "Retries", "Connections"};
        
        for (String app : applications) {
            for (String config : configurations) {
                StartConfigurationSessionResponse sessionResponse = appConfigClient.startConfigurationSession(
                    StartConfigurationSessionRequest.builder()
                        .applicationIdentifier(app)
                        .environmentIdentifier("Production")
                        .configurationProfileIdentifier(config)
                        .build()
                );
                
                // ok: java-deprecated-get-configuration
                GetLatestConfigurationResponse result = appConfigClient.getLatestConfiguration(
                    GetLatestConfigurationRequest.builder()
                        .configurationToken(sessionResponse.initialConfigurationToken())
                        .build()
                );
                
                applyConfiguration(app, config, result.configuration());
            }
        }
    }
    
    public void good_case_11() {
        AppConfigDataClient appConfigClient = null;
        try {
            appConfigClient = AppConfigDataClient.builder()
                    .region(software.amazon.awssdk.regions.Region.US_WEST_2)
                    .build();
            
            StartConfigurationSessionResponse sessionResponse = appConfigClient.startConfigurationSession(
                StartConfigurationSessionRequest.builder()
                    .applicationIdentifier("SecurityService")
                    .environmentIdentifier("Production")
                    .configurationProfileIdentifier("FirewallRules")
                    .build()
            );
            
            // ok: java-deprecated-get-configuration
            GetLatestConfigurationResponse result = appConfigClient.getLatestConfiguration(
                GetLatestConfigurationRequest.builder()
                    .configurationToken(sessionResponse.initialConfigurationToken())
                    .build()
            );
            
            updateFirewallRules(result);
        } finally {
            if (appConfigClient != null) {
                appConfigClient.close();
            }
        }
    }
    
    public void good_case_12() {
        AppConfigDataClient appConfigClient = AppConfigDataClient.create();
        
        switch (getCurrentDeploymentStage()) {
            case "dev":
                StartConfigurationSessionResponse devSessionResponse = appConfigClient.startConfigurationSession(
                    StartConfigurationSessionRequest.builder()
                        .applicationIdentifier("MyApp")
                        .environmentIdentifier("Development")
                        .configurationProfileIdentifier("AppSettings")
                        .build()
                );
                
                // ok: java-deprecated-get-configuration
                GetLatestConfigurationResponse devResult = appConfigClient.getLatestConfiguration(
                    GetLatestConfigurationRequest.builder()
                        .configurationToken(devSessionResponse.initialConfigurationToken())
                        .build()
                );
                processDevConfig(devResult);
                break;
            case "prod":
                StartConfigurationSessionResponse prodSessionResponse = appConfigClient.startConfigurationSession(
                    StartConfigurationSessionRequest.builder()
                        .applicationIdentifier("MyApp")
                        .environmentIdentifier("Production")
                        .configurationProfileIdentifier("AppSettings")
                        .build()
                );
                
                // ok: java-deprecated-get-configuration
                GetLatestConfigurationResponse prodResult = appConfigClient.getLatestConfiguration(
                    GetLatestConfigurationRequest.builder()
                        .configurationToken(prodSessionResponse.initialConfigurationToken())
                        .build()
                );
                processProdConfig(prodResult);
                break;
        }
    }
    
    public void good_case_13() {
        AppConfigDataClient appConfigClient = AppConfigDataClient.create();
        
        try {
            StartConfigurationSessionResponse sessionResponse = appConfigClient.startConfigurationSession(
                StartConfigurationSessionRequest.builder()
                    .applicationIdentifier("AnalyticsService")
                    .environmentIdentifier("Production")
                    .configurationProfileIdentifier("SamplingRates")
                    .build()
            );
            
            // ok: java-deprecated-get-configuration
            GetLatestConfigurationResponse result = appConfigClient.getLatestConfiguration(
                GetLatestConfigurationRequest.builder()
                    .configurationToken(sessionResponse.initialConfigurationToken())
                    .build()
            );
            
            if (result.configuration() != null) {
                applySamplingRates(result.configuration());
            }
        } catch (Exception e) {
            System.err.println("Failed to get configuration: " + e.getMessage());
            useDefaultSamplingRates();
        }
    }
    
    public void good_case_14() {
        AppConfigDataClient appConfigClient = AppConfigDataClient.builder()
                .region(software.amazon.awssdk.regions.Region.AP_NORTHEAST_1)
                .build();
        
        StartConfigurationSessionResponse sessionResponse = appConfigClient.startConfigurationSession(
            StartConfigurationSessionRequest.builder()
                .applicationIdentifier("MobileApp")
                .environmentIdentifier("Production")
                .configurationProfileIdentifier("UISettings")
                .build()
        );
        
        // ok: java-deprecated-get-configuration
        GetLatestConfigurationResponse result = appConfigClient.getLatestConfiguration(
            GetLatestConfigurationRequest.builder()
                .configurationToken(sessionResponse.initialConfigurationToken())
                .build()
        );
        
        if (result.configuration() != null) {
            String uiConfig = new String(result.configuration().asByteArray(), StandardCharsets.UTF_8);
            System.out.println("UI Configuration: " + uiConfig);
        }
    }
    
    public void good_case_15() {
        class ConfigurationService {
            private final AppConfigDataClient client;
            private String configToken = null;
            
            public ConfigurationService() {
                client = AppConfigDataClient.create();
                StartConfigurationSessionResponse sessionResponse = client.startConfigurationSession(
                    StartConfigurationSessionRequest.builder()
                        .applicationIdentifier("RecommendationEngine")
                        .environmentIdentifier("Production")
                        .configurationProfileIdentifier("AlgorithmParameters")
                        .build()
                );
                configToken = sessionResponse.initialConfigurationToken();
            }
            
            public byte[] getLatestConfiguration() {
                // ok: java-deprecated-get-configuration
                GetLatestConfigurationResponse result = client.getLatestConfiguration(
                    GetLatestConfigurationRequest.builder()
                        .configurationToken(configToken)
                        .build()
                );
                
                configToken = result.nextPollConfigurationToken();
                
                return result.configuration().asByteArray();
            }
        }
        
        ConfigurationService service = new ConfigurationService();
        byte[] config = service.getLatestConfiguration();
    }
    
    // Helper methods to make the examples compile
    private void processConfiguration(Object config) {}
    private void handleConfigUpdate(Object result) {}
    private String generateClientId() { return "client-" + System.currentTimeMillis(); }
    private void startPollingForUpdates(Object client, Object config, Object token) {}
    private void updateTemplates(Object result) {}
    private String getEnvironmentFromSystemProperty() { return System.getProperty("env", "dev"); }
    private void updateRateLimits(Object content) {}
    private void fallbackToDefaultRateLimits() {}
    private void updateLogLevels(Object content) {}
    private void applyConfiguration(String app, String config, Object content) {}
    private void updateFirewallRules(Object result) {}
    private String getCurrentDeploymentStage() { return "dev"; }
    private void processDevConfig(Object result) {}
    private void processProdConfig(Object result) {}
    private void applySamplingRates(Object content) {}
    private void useDefaultSamplingRates() {}
}
// {/fact}