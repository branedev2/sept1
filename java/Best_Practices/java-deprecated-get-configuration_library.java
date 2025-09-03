import com.amazonaws.services.appconfig.AmazonAppConfig;
import com.amazonaws.services.appconfig.AmazonAppConfigClient;
import com.amazonaws.services.appconfig.AmazonAppConfigClientBuilder;
import com.amazonaws.services.appconfig.model.GetConfigurationRequest;
import com.amazonaws.services.appconfig.model.GetConfigurationResult;
import software.amazon.awssdk.services.appconfig.AppConfigClient;
import software.amazon.awssdk.services.appconfig.model.GetLatestConfigurationRequest;
import software.amazon.awssdk.services.appconfig.model.GetLatestConfigurationResponse;
import software.amazon.awssdk.services.appconfigdata.AppConfigDataClient;
import software.amazon.awssdk.services.appconfigdata.model.StartConfigurationSessionRequest;
import software.amazon.awssdk.services.appconfigdata.model.StartConfigurationSessionResponse;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.http.crt.AwsCrtHttpClient;
import software.amazon.awssdk.http.nio.netty.NettyNioAsyncHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.auth.credentials.EnvironmentVariableCredentialsProvider;
import software.amazon.awssdk.auth.credentials.InstanceProfileCredentialsProvider;
import software.amazon.awssdk.auth.credentials.WebIdentityTokenFileCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ContainerCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ProcessCredentialsProvider;
import software.amazon.awssdk.services.appconfigdata.AppConfigDataClientBuilder;
import software.amazon.awssdk.services.appconfigdata.AppConfigDataAsyncClient;
import software.amazon.awssdk.services.appconfigdata.AppConfigDataAsyncClientBuilder;
import software.amazon.awssdk.services.appconfig.AppConfigAsyncClient;
import software.amazon.awssdk.services.appconfig.AppConfigAsyncClientBuilder;
import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import java.util.Map;
import java.util.HashMap;

// Security Issue: Using the deprecated AWS AppConfig GetConfiguration API instead of the recommended AWS AppConfig Agent and GetLatestConfiguration API

// True Positive Examples (Vulnerable/Insecure Code)
public class DeprecatedAppConfigExamples {

// {fact rule=guru-cfn-lint@v1.0 defects=1}
    public static void bad_case_1(HttpServletRequest request) {
        // Using deprecated GetConfiguration with AmazonAppConfigClient
        String applicationId = request.getParameter("appId");
        String environmentId = request.getParameter("envId");
        String configurationId = request.getParameter("configId");
        
        AmazonAppConfig appConfigClient = AmazonAppConfigClientBuilder.standard().build();
        
        // ruleid: java-deprecated-get-configuration
        GetConfigurationResult result = appConfigClient.getConfiguration(
                new GetConfigurationRequest()
                        .withApplication(applicationId)
                        .withEnvironment(environmentId)
                        .withConfiguration(configurationId)
                        .withClientId("Example-Client-ID"));
    }
    
    public static void bad_case_2(HttpServletRequest request) {
        // Using deprecated GetConfiguration with explicit region
        String applicationId = request.getParameter("appId");
        String environmentId = request.getParameter("envId");
        String configurationId = request.getParameter("configId");
        
        AmazonAppConfig appConfigClient = AmazonAppConfigClientBuilder.standard()
                .withRegion("us-west-2")
                .build();
        
        // ruleid: java-deprecated-get-configuration
        GetConfigurationResult result = appConfigClient.getConfiguration(
                new GetConfigurationRequest()
                        .withApplication(applicationId)
                        .withEnvironment(environmentId)
                        .withConfiguration(configurationId)
                        .withClientId("Example-Client-ID-2"));
    }
    
    public static void bad_case_3() {
        // Using deprecated GetConfiguration in a Spring REST controller
        AmazonAppConfig appConfigClient = AmazonAppConfigClientBuilder.standard().build();
        
        // ruleid: java-deprecated-get-configuration
        GetConfigurationResult result = appConfigClient.getConfiguration(
                new GetConfigurationRequest()
                        .withApplication("MyApp")
                        .withEnvironment("Production")
                        .withConfiguration("FeatureFlags")
                        .withClientId("Spring-Controller-Client"));
    }
    
    @RestController
    public static class BadCase4Controller {
        private final AmazonAppConfig appConfigClient;
        
        @Autowired
        public BadCase4Controller() {
            this.appConfigClient = AmazonAppConfigClientBuilder.standard().build();
        }
        
        @GetMapping("/config/{appId}/{envId}/{configId}")
        public ResponseEntity<String> bad_case_4(@PathVariable String appId, 
                                               @PathVariable String envId,
                                               @PathVariable String configId) {
            // Using deprecated GetConfiguration in a Spring REST controller with path variables
            // ruleid: java-deprecated-get-configuration
            GetConfigurationResult result = appConfigClient.getConfiguration(
                    new GetConfigurationRequest()
                            .withApplication(appId)
                            .withEnvironment(envId)
                            .withConfiguration(configId)
                            .withClientId("REST-Controller-Client"));
            
            return ResponseEntity.ok(new String(result.getContent().array()));
        }
    }
    
    public static void bad_case_5(HttpServletRequest request) {
        // Using deprecated GetConfiguration with custom client configuration
        String applicationId = request.getParameter("appId");
        String environmentId = request.getParameter("envId");
        String configurationId = request.getParameter("configId");
        
        com.amazonaws.ClientConfiguration clientConfig = new com.amazonaws.ClientConfiguration();
        clientConfig.setConnectionTimeout(5000);
        clientConfig.setSocketTimeout(5000);
        
        AmazonAppConfig appConfigClient = AmazonAppConfigClientBuilder.standard()
                .withClientConfiguration(clientConfig)
                .build();
        
        // ruleid: java-deprecated-get-configuration
        GetConfigurationResult result = appConfigClient.getConfiguration(
                new GetConfigurationRequest()
                        .withApplication(applicationId)
                        .withEnvironment(environmentId)
                        .withConfiguration(configurationId)
                        .withClientId("Custom-Config-Client"));
    }
    
    public static void bad_case_6(HttpServletRequest request) {
        // Using deprecated GetConfiguration with custom credentials provider
        String applicationId = request.getParameter("appId");
        String environmentId = request.getParameter("envId");
        String configurationId = request.getParameter("configId");
        
        AmazonAppConfig appConfigClient = AmazonAppConfigClientBuilder.standard()
                .withCredentials(new com.amazonaws.auth.DefaultAWSCredentialsProviderChain())
                .build();
        
        // ruleid: java-deprecated-get-configuration
        GetConfigurationResult result = appConfigClient.getConfiguration(
                new GetConfigurationRequest()
                        .withApplication(applicationId)
                        .withEnvironment(environmentId)
                        .withConfiguration(configurationId)
                        .withClientId("Custom-Creds-Client"));
    }
    
    public static void bad_case_7() {
        // Using deprecated GetConfiguration with direct client instantiation
        AmazonAppConfig appConfigClient = new AmazonAppConfigClient();
        
        // ruleid: java-deprecated-get-configuration
        GetConfigurationResult result = appConfigClient.getConfiguration(
                new GetConfigurationRequest()
                        .withApplication("DirectApp")
                        .withEnvironment("DirectEnv")
                        .withConfiguration("DirectConfig")
                        .withClientId("Direct-Client"));
    }
    
    public static void bad_case_8(HttpServletRequest request) {
        // Using deprecated GetConfiguration with version parameter
        String applicationId = request.getParameter("appId");
        String environmentId = request.getParameter("envId");
        String configurationId = request.getParameter("configId");
        String version = request.getParameter("version");
        
        AmazonAppConfig appConfigClient = AmazonAppConfigClientBuilder.standard().build();
        
        // ruleid: java-deprecated-get-configuration
        GetConfigurationResult result = appConfigClient.getConfiguration(
                new GetConfigurationRequest()
                        .withApplication(applicationId)
                        .withEnvironment(environmentId)
                        .withConfiguration(configurationId)
                        .withClientId("Version-Client")
                        .withClientConfigurationVersion(version));
    }
    
    public static void bad_case_9(HttpServletRequest request) {
        // Using deprecated GetConfiguration in a try-catch block
        String applicationId = request.getParameter("appId");
        String environmentId = request.getParameter("envId");
        String configurationId = request.getParameter("configId");
        
        AmazonAppConfig appConfigClient = AmazonAppConfigClientBuilder.standard().build();
        
        try {
            // ruleid: java-deprecated-get-configuration
            GetConfigurationResult result = appConfigClient.getConfiguration(
                    new GetConfigurationRequest()
                            .withApplication(applicationId)
                            .withEnvironment(environmentId)
                            .withConfiguration(configurationId)
                            .withClientId("TryCatch-Client"));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void bad_case_10(HttpServletRequest request) {
        // Using deprecated GetConfiguration with request object created separately
        String applicationId = request.getParameter("appId");
        String environmentId = request.getParameter("envId");
        String configurationId = request.getParameter("configId");
        
        AmazonAppConfig appConfigClient = AmazonAppConfigClientBuilder.standard().build();
        
        GetConfigurationRequest configRequest = new GetConfigurationRequest()
                .withApplication(applicationId)
                .withEnvironment(environmentId)
                .withConfiguration(configurationId)
                .withClientId("Separate-Request-Client");
        
        // ruleid: java-deprecated-get-configuration
        GetConfigurationResult result = appConfigClient.getConfiguration(configRequest);
    }
    
    public static class ConfigService {
        private final AmazonAppConfig appConfigClient;
        
        public ConfigService() {
            this.appConfigClient = AmazonAppConfigClientBuilder.standard().build();
        }
        
        public void bad_case_11(HttpServletRequest request) {
            // Using deprecated GetConfiguration in a service class
            String applicationId = request.getParameter("appId");
            String environmentId = request.getParameter("envId");
            String configurationId = request.getParameter("configId");
            
            // ruleid: java-deprecated-get-configuration
            GetConfigurationResult result = appConfigClient.getConfiguration(
                    new GetConfigurationRequest()
                            .withApplication(applicationId)
                            .withEnvironment(environmentId)
                            .withConfiguration(configurationId)
                            .withClientId("Service-Class-Client"));
        }
    }
    
    public static void bad_case_12(HttpServletRequest request) {
        // Using deprecated GetConfiguration with endpoint override
        String applicationId = request.getParameter("appId");
        String environmentId = request.getParameter("envId");
        String configurationId = request.getParameter("configId");
        
        AmazonAppConfig appConfigClient = AmazonAppConfigClientBuilder.standard()
                .withEndpointConfiguration(new com.amazonaws.client.builder.AwsClientBuilder.EndpointConfiguration(
                        "https://appconfig.us-west-2.amazonaws.com", "us-west-2"))
                .build();
        
        // ruleid: java-deprecated-get-configuration
        GetConfigurationResult result = appConfigClient.getConfiguration(
                new GetConfigurationRequest()
                        .withApplication(applicationId)
                        .withEnvironment(environmentId)
                        .withConfiguration(configurationId)
                        .withClientId("Endpoint-Override-Client"));
    }
    
    public static void bad_case_13(HttpServletRequest request) {
        // Using deprecated GetConfiguration with async client
        String applicationId = request.getParameter("appId");
        String environmentId = request.getParameter("envId");
        String configurationId = request.getParameter("configId");
        
        com.amazonaws.services.appconfig.AmazonAppConfigAsync appConfigAsyncClient = 
                com.amazonaws.services.appconfig.AmazonAppConfigAsyncClientBuilder.standard().build();
        
        // ruleid: java-deprecated-get-configuration
        java.util.concurrent.Future<GetConfigurationResult> futureResult = 
                appConfigAsyncClient.getConfigurationAsync(
                        new GetConfigurationRequest()
                                .withApplication(applicationId)
                                .withEnvironment(environmentId)
                                .withConfiguration(configurationId)
                                .withClientId("Async-Client"));
    }
    
    public static void bad_case_14(HttpServletRequest request) {
        // Using deprecated GetConfiguration with variable assignment
        String applicationId = request.getParameter("appId");
        String environmentId = request.getParameter("envId");
        String configurationId = request.getParameter("configId");
        
        AmazonAppConfig appConfigClient = AmazonAppConfigClientBuilder.standard().build();
        GetConfigurationRequest configRequest = new GetConfigurationRequest();
        configRequest.setApplication(applicationId);
        configRequest.setEnvironment(environmentId);
        configRequest.setConfiguration(configurationId);
        configRequest.setClientId("Variable-Assignment-Client");
        
        // ruleid: java-deprecated-get-configuration
        GetConfigurationResult result = appConfigClient.getConfiguration(configRequest);
    }
    
    public static void bad_case_15(HttpServletRequest request, HttpServletResponse response) {
        // Using deprecated GetConfiguration and returning result in servlet
        String applicationId = request.getParameter("appId");
        String environmentId = request.getParameter("envId");
        String configurationId = request.getParameter("configId");
        
        AmazonAppConfig appConfigClient = AmazonAppConfigClientBuilder.standard().build();
        
        try {
            // ruleid: java-deprecated-get-configuration
            GetConfigurationResult result = appConfigClient.getConfiguration(
                    new GetConfigurationRequest()
                            .withApplication(applicationId)
                            .withEnvironment(environmentId)
                            .withConfiguration(configurationId)
                            .withClientId("Servlet-Response-Client"));
            
            response.setContentType("application/json");
            response.getWriter().write(new String(result.getContent().array()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // True Negative Examples (Safe/Secure Code)
    public static void good_case_1(HttpServletRequest request) {
        // Using recommended AppConfigData client with StartConfigurationSession and GetLatestConfiguration
        String applicationId = request.getParameter("appId");
        String environmentId = request.getParameter("envId");
        String configurationId = request.getParameter("configId");
        
        AppConfigDataClient appConfigDataClient = AppConfigDataClient.builder().build();
        
        // ok: java-deprecated-get-configuration
        StartConfigurationSessionResponse sessionResponse = appConfigDataClient.startConfigurationSession(
                StartConfigurationSessionRequest.builder()
                        .applicationIdentifier(applicationId)
                        .environmentIdentifier(environmentId)
                        .configurationProfileIdentifier(configurationId)
                        .build());
        
        // ok: java-deprecated-get-configuration
        software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationResponse latestConfig = 
                appConfigDataClient.getLatestConfiguration(
                        software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationRequest.builder()
                                .configurationToken(sessionResponse.initialConfigurationToken())
                                .build());
    }
    
    public static void good_case_2(HttpServletRequest request) {
        // Using recommended AppConfigData client with custom region
        String applicationId = request.getParameter("appId");
        String environmentId = request.getParameter("envId");
        String configurationId = request.getParameter("configId");
        
        AppConfigDataClient appConfigDataClient = AppConfigDataClient.builder()
                .region(Region.US_WEST_2)
                .build();
        
        // ok: java-deprecated-get-configuration
        StartConfigurationSessionResponse sessionResponse = appConfigDataClient.startConfigurationSession(
                StartConfigurationSessionRequest.builder()
                        .applicationIdentifier(applicationId)
                        .environmentIdentifier(environmentId)
                        .configurationProfileIdentifier(configurationId)
                        .build());
        
        // ok: java-deprecated-get-configuration
        software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationResponse latestConfig = 
                appConfigDataClient.getLatestConfiguration(
                        software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationRequest.builder()
                                .configurationToken(sessionResponse.initialConfigurationToken())
                                .build());
    }
    
    @RestController
    public static class GoodCase3Controller {
        private final AppConfigDataClient appConfigDataClient;
        
        @Autowired
        public GoodCase3Controller() {
            this.appConfigDataClient = AppConfigDataClient.builder().build();
        }
        
        @GetMapping("/safe-config/{appId}/{envId}/{configId}")
        public ResponseEntity<String> good_case_3(@PathVariable String appId, 
                                                @PathVariable String envId,
                                                @PathVariable String configId) {
            // Using recommended AppConfigData client in a Spring REST controller
            // ok: java-deprecated-get-configuration
            StartConfigurationSessionResponse sessionResponse = appConfigDataClient.startConfigurationSession(
                    StartConfigurationSessionRequest.builder()
                            .applicationIdentifier(appId)
                            .environmentIdentifier(envId)
                            .configurationProfileIdentifier(configId)
                            .build());
            
            // ok: java-deprecated-get-configuration
            software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationResponse latestConfig = 
                    appConfigDataClient.getLatestConfiguration(
                            software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationRequest.builder()
                                    .configurationToken(sessionResponse.initialConfigurationToken())
                                    .build());
            
            return ResponseEntity.ok(latestConfig.configuration().asUtf8String());
        }
    }
    
    public static void good_case_4(HttpServletRequest request) {
        // Using recommended AppConfigData client with custom HTTP client
        String applicationId = request.getParameter("appId");
        String environmentId = request.getParameter("envId");
        String configurationId = request.getParameter("configId");
        
        SdkHttpClient httpClient = ApacheHttpClient.builder()
                .connectionTimeout(java.time.Duration.ofSeconds(5))
                .build();
        
        AppConfigDataClient appConfigDataClient = AppConfigDataClient.builder()
                .httpClient(httpClient)
                .build();
        
        // ok: java-deprecated-get-configuration
        StartConfigurationSessionResponse sessionResponse = appConfigDataClient.startConfigurationSession(
                StartConfigurationSessionRequest.builder()
                        .applicationIdentifier(applicationId)
                        .environmentIdentifier(environmentId)
                        .configurationProfileIdentifier(configurationId)
                        .build());
        
        // ok: java-deprecated-get-configuration
        software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationResponse latestConfig = 
                appConfigDataClient.getLatestConfiguration(
                        software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationRequest.builder()
                                .configurationToken(sessionResponse.initialConfigurationToken())
                                .build());
    }
    
    public static void good_case_5(HttpServletRequest request) {
        // Using recommended AppConfigData client with custom credentials provider
        String applicationId = request.getParameter("appId");
        String environmentId = request.getParameter("envId");
        String configurationId = request.getParameter("configId");
        
        AppConfigDataClient appConfigDataClient = AppConfigDataClient.builder()
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build();
        
        // ok: java-deprecated-get-configuration
        StartConfigurationSessionResponse sessionResponse = appConfigDataClient.startConfigurationSession(
                StartConfigurationSessionRequest.builder()
                        .applicationIdentifier(applicationId)
                        .environmentIdentifier(environmentId)
                        .configurationProfileIdentifier(configurationId)
                        .build());
        
        // ok: java-deprecated-get-configuration
        software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationResponse latestConfig = 
                appConfigDataClient.getLatestConfiguration(
                        software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationRequest.builder()
                                .configurationToken(sessionResponse.initialConfigurationToken())
                                .build());
    }
    
    public static void good_case_6(HttpServletRequest request) {
        // Using recommended AppConfigData async client
        String applicationId = request.getParameter("appId");
        String environmentId = request.getParameter("envId");
        String configurationId = request.getParameter("configId");
        
        AppConfigDataAsyncClient appConfigDataAsyncClient = AppConfigDataAsyncClient.builder().build();
        
        // ok: java-deprecated-get-configuration
        CompletableFuture<StartConfigurationSessionResponse> sessionFuture = 
                appConfigDataAsyncClient.startConfigurationSession(
                        StartConfigurationSessionRequest.builder()
                                .applicationIdentifier(applicationId)
                                .environmentIdentifier(environmentId)
                                .configurationProfileIdentifier(configurationId)
                                .build());
        
        sessionFuture.thenCompose(sessionResponse -> {
            // ok: java-deprecated-get-configuration
            return appConfigDataAsyncClient.getLatestConfiguration(
                    software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationRequest.builder()
                            .configurationToken(sessionResponse.initialConfigurationToken())
                            .build());
        });
    }
    
    public static void good_case_7(HttpServletRequest request) {
        // Using recommended AppConfigData client with URL connection HTTP client
        String applicationId = request.getParameter("appId");
        String environmentId = request.getParameter("envId");
        String configurationId = request.getParameter("configId");
        
        SdkHttpClient httpClient = UrlConnectionHttpClient.builder().build();
        
        AppConfigDataClient appConfigDataClient = AppConfigDataClient.builder()
                .httpClient(httpClient)
                .build();
        
        // ok: java-deprecated-get-configuration
        StartConfigurationSessionResponse sessionResponse = appConfigDataClient.startConfigurationSession(
                StartConfigurationSessionRequest.builder()
                        .applicationIdentifier(applicationId)
                        .environmentIdentifier(environmentId)
                        .configurationProfileIdentifier(configurationId)
                        .build());
        
        // ok: java-deprecated-get-configuration
        software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationResponse latestConfig = 
                appConfigDataClient.getLatestConfiguration(
                        software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationRequest.builder()
                                .configurationToken(sessionResponse.initialConfigurationToken())
                                .build());
    }
    
    public static void good_case_8(HttpServletRequest request) {
        // Using recommended AppConfigData client with profile credentials provider
        String applicationId = request.getParameter("appId");
        String environmentId = request.getParameter("envId");
        String configurationId = request.getParameter("configId");
        String profile = request.getParameter("profile");
        
        AppConfigDataClient appConfigDataClient = AppConfigDataClient.builder()
                .credentialsProvider(ProfileCredentialsProvider.create(profile))
                .build();
        
        // ok: java-deprecated-get-configuration
        StartConfigurationSessionResponse sessionResponse = appConfigDataClient.startConfigurationSession(
                StartConfigurationSessionRequest.builder()
                        .applicationIdentifier(applicationId)
                        .environmentIdentifier(environmentId)
                        .configurationProfileIdentifier(configurationId)
                        .build());
        
        // ok: java-deprecated-get-configuration
        software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationResponse latestConfig = 
                appConfigDataClient.getLatestConfiguration(
                        software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationRequest.builder()
                                .configurationToken(sessionResponse.initialConfigurationToken())
                                .build());
    }
    
    public static void good_case_9(HttpServletRequest request) {
        // Using recommended AppConfigData client with environment variable credentials provider
        String applicationId = request.getParameter("appId");
        String environmentId = request.getParameter("envId");
        String configurationId = request.getParameter("configId");
        
        AppConfigDataClient appConfigDataClient = AppConfigDataClient.builder()
                .credentialsProvider(EnvironmentVariableCredentialsProvider.create())
                .build();
        
        // ok: java-deprecated-get-configuration
        StartConfigurationSessionResponse sessionResponse = appConfigDataClient.startConfigurationSession(
                StartConfigurationSessionRequest.builder()
                        .applicationIdentifier(applicationId)
                        .environmentIdentifier(environmentId)
                        .configurationProfileIdentifier(configurationId)
                        .build());
        
        // ok: java-deprecated-get-configuration
        software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationResponse latestConfig = 
                appConfigDataClient.getLatestConfiguration(
                        software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationRequest.builder()
                                .configurationToken(sessionResponse.initialConfigurationToken())
                                .build());
    }
    
    public static void good_case_10(HttpServletRequest request) {
        // Using recommended AppConfigData client with instance profile credentials provider
        String applicationId = request.getParameter("appId");
        String environmentId = request.getParameter("envId");
        String configurationId = request.getParameter("configId");
        
        AppConfigDataClient appConfigDataClient = AppConfigDataClient.builder()
                .credentialsProvider(InstanceProfileCredentialsProvider.create())
                .build();
        
        // ok: java-deprecated-get-configuration
        StartConfigurationSessionResponse sessionResponse = appConfigDataClient.startConfigurationSession(
                StartConfigurationSessionRequest.builder()
                        .applicationIdentifier(applicationId)
                        .environmentIdentifier(environmentId)
                        .configurationProfileIdentifier(configurationId)
                        .build());
        
        // ok: java-deprecated-get-configuration
        software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationResponse latestConfig = 
                appConfigDataClient.getLatestConfiguration(
                        software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationRequest.builder()
                                .configurationToken(sessionResponse.initialConfigurationToken())
                                .build());
    }
    
    public static void good_case_11(HttpServletRequest request) {
        // Using recommended AppConfigData client with web identity token file credentials provider
        String applicationId = request.getParameter("appId");
        String environmentId = request.getParameter("envId");
        String configurationId = request.getParameter("configId");
        
        AppConfigDataClient appConfigDataClient = AppConfigDataClient.builder()
                .credentialsProvider(WebIdentityTokenFileCredentialsProvider.create())
                .build();
        
        // ok: java-deprecated-get-configuration
        StartConfigurationSessionResponse sessionResponse = appConfigDataClient.startConfigurationSession(
                StartConfigurationSessionRequest.builder()
                        .applicationIdentifier(applicationId)
                        .environmentIdentifier(environmentId)
                        .configurationProfileIdentifier(configurationId)
                        .build());
        
        // ok: java-deprecated-get-configuration
        software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationResponse latestConfig = 
                appConfigDataClient.getLatestConfiguration(
                        software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationRequest.builder()
                                .configurationToken(sessionResponse.initialConfigurationToken())
                                .build());
    }
    
    public static void good_case_12(HttpServletRequest request) {
        // Using recommended AppConfigData client with container credentials provider
        String applicationId = request.getParameter("appId");
        String environmentId = request.getParameter("envId");
        String configurationId = request.getParameter("configId");
        
        AppConfigDataClient appConfigDataClient = AppConfigDataClient.builder()
                .credentialsProvider(ContainerCredentialsProvider.builder().build())
                .build();
        
        // ok: java-deprecated-get-configuration
        StartConfigurationSessionResponse sessionResponse = appConfigDataClient.startConfigurationSession(
                StartConfigurationSessionRequest.builder()
                        .applicationIdentifier(applicationId)
                        .environmentIdentifier(environmentId)
                        .configurationProfileIdentifier(configurationId)
                        .build());
        
        // ok: java-deprecated-get-configuration
        software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationResponse latestConfig = 
                appConfigDataClient.getLatestConfiguration(
                        software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationRequest.builder()
                                .configurationToken(sessionResponse.initialConfigurationToken())
                                .build());
    }
    
    public static void good_case_13(HttpServletRequest request) {
        // Using recommended AppConfigData client with process credentials provider
        String applicationId = request.getParameter("appId");
        String environmentId = request.getParameter("envId");
        String configurationId = request.getParameter("configId");
        
        AppConfigDataClient appConfigDataClient = AppConfigDataClient.builder()
                .credentialsProvider(ProcessCredentialsProvider.builder()
                        .command("credential-process")
                        .build())
                .build();
        
        // ok: java-deprecated-get-configuration
        StartConfigurationSessionResponse sessionResponse = appConfigDataClient.startConfigurationSession(
                StartConfigurationSessionRequest.builder()
                        .applicationIdentifier(applicationId)
                        .environmentIdentifier(environmentId)
                        .configurationProfileIdentifier(configurationId)
                        .build());
        
        // ok: java-deprecated-get-configuration
        software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationResponse latestConfig = 
                appConfigDataClient.getLatestConfiguration(
                        software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationRequest.builder()
                                .configurationToken(sessionResponse.initialConfigurationToken())
                                .build());
    }
    
    public static void good_case_14(HttpServletRequest request) {
        // Using recommended AppConfigData client with AWS CRT HTTP client
        String applicationId = request.getParameter("appId");
        String environmentId = request.getParameter("envId");
        String configurationId = request.getParameter("configId");
        
        SdkHttpClient httpClient = AwsCrtHttpClient.builder().build();
        
        AppConfigDataClient appConfigDataClient = AppConfigDataClient.builder()
                .httpClient(httpClient)
                .build();
        
        // ok: java-deprecated-get-configuration
        StartConfigurationSessionResponse sessionResponse = appConfigDataClient.startConfigurationSession(
                StartConfigurationSessionRequest.builder()
                        .applicationIdentifier(applicationId)
                        .environmentIdentifier(environmentId)
                        .configurationProfileIdentifier(configurationId)
                        .build());
        
        // ok: java-deprecated-get-configuration
        software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationResponse latestConfig = 
                appConfigDataClient.getLatestConfiguration(
                        software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationRequest.builder()
                                .configurationToken(sessionResponse.initialConfigurationToken())
                                .build());
    }
    
    public static void good_case_15(HttpServletRequest request, HttpServletResponse response) {
        // Using recommended AppConfigData client and returning result in servlet
        String applicationId = request.getParameter("appId");
        String environmentId = request.getParameter("envId");
        String configurationId = request.getParameter("configId");
        
        AppConfigDataClient appConfigDataClient = AppConfigDataClient.builder().build();
        
        try {
            // ok: java-deprecated-get-configuration
            StartConfigurationSessionResponse sessionResponse = appConfigDataClient.startConfigurationSession(
                    StartConfigurationSessionRequest.builder()
                            .applicationIdentifier(applicationId)
                            .environmentIdentifier(environmentId)
                            .configurationProfileIdentifier(configurationId)
                            .build());
            
            // ok: java-deprecated-get-configuration
            software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationResponse latestConfig = 
                    appConfigDataClient.getLatestConfiguration(
                            software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationRequest.builder()
                                    .configurationToken(sessionResponse.initialConfigurationToken())
                                    .build());
            
            response.setContentType("application/json");
            response.getWriter().write(latestConfig.configuration().asUtf8String());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}