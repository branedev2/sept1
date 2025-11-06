import com.amazon.horizonte.auth.AaaTlsAuthorizationAttribute;
import com.amazon.horizonte.auth.CloudAuthConfiguration;
import com.amazon.horizonte.auth.AuthorizationResult;
import com.amazon.horizonte.auth.PassThroughAuthorizationHandler;
import com.amazon.horizonte.auth.CloudAuthHandler;
import com.amazon.horizonte.auth.TlsAuthorizationHandler;
import com.amazon.horizonte.auth.ServiceAuthorizationConfig;
import com.amazon.horizonte.auth.AuthorizationContext;
import com.amazon.horizonte.auth.ServiceIdentity;
import com.amazon.horizonte.auth.AuthorizationPolicy;
import com.amazon.horizonte.auth.CloudAuthClient;
import com.amazon.horizonte.auth.TlsAuthorizationConfig;
import com.amazon.horizonte.auth.AuthorizationManager;
import com.amazon.horizonte.auth.AuthorizationHandlerChain;
import com.amazon.horizonte.auth.AuthorizationHandlerFactory;
import com.amazon.horizonte.service.ServiceConfiguration;
import com.amazon.horizonte.service.ServiceContext;
import com.amazon.horizonte.service.RequestContext;
import com.amazon.horizonte.service.ResponseContext;
import com.amazon.horizonte.service.ServiceBuilder;
import com.amazon.horizonte.service.ServiceEndpoint;
import com.amazon.horizonte.service.ServiceRequest;
import com.amazon.horizonte.service.ServiceResponse;
import com.amazon.horizonte.http.HttpRequest;
import com.amazon.horizonte.http.HttpResponse;
import com.amazon.horizonte.http.HttpHeaders;
import com.amazon.horizonte.http.HttpMethod;
import com.amazon.horizonte.http.HttpStatus;
import com.amazon.horizonte.util.ConfigurationLoader;
import com.amazon.horizonte.util.SecurityUtils;

import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.Optional;

// Security Issue: Overriding AaaTlsAuthorizationAttribute with PassThrough result code without proper CloudAuth configuration

// True Positive Examples (Vulnerable/Insecure Code)
public class VulnerableServiceConfigurations {

// {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
    public void bad_case_1() {
        // Basic service configuration with PassThrough without CloudAuth
        ServiceConfiguration serviceConfig = new ServiceConfiguration.Builder()
            .withServiceName("PaymentService")
            .withEndpoint("/api/payments")
            .build();
        
        AuthorizationManager authManager = new AuthorizationManager.Builder()
            .withServiceConfig(serviceConfig)
            // ruleid: java-horizonteaaapassthroughwithoutcloudauth
            .withAuthorizationResult(AaaTlsAuthorizationAttribute.RESULT_CODE, AuthorizationResult.PASS_THROUGH)
            .build();
    }

    public void bad_case_2() {
        // Custom authorization handler with PassThrough in API Gateway service
        ServiceEndpoint endpoint = new ServiceEndpoint("/api/orders");
        
        TlsAuthorizationHandler authHandler = new TlsAuthorizationHandler.Builder()
            .withEndpoint(endpoint)
            // ruleid: java-horizonteaaapassthroughwithoutcloudauth
            .withAttributeOverride(AaaTlsAuthorizationAttribute.RESULT_CODE, AuthorizationResult.PASS_THROUGH)
            .build();
        
        endpoint.setAuthorizationHandler(authHandler);
    }

    public void bad_case_3() {
        // Authorization context with PassThrough in a microservice
        AuthorizationContext authContext = new AuthorizationContext();
        Map<String, String> attributes = new HashMap<>();
        // ruleid: java-horizonteaaapassthroughwithoutcloudauth
        attributes.put(AaaTlsAuthorizationAttribute.RESULT_CODE.getName(), AuthorizationResult.PASS_THROUGH.getValue());
        authContext.setAttributes(attributes);
        
        ServiceRequest request = new ServiceRequest("/api/users");
        request.setAuthorizationContext(authContext);
    }

    public void bad_case_4() {
        // Service builder with PassThrough in request processing
        ServiceBuilder serviceBuilder = new ServiceBuilder()
            .withName("DataProcessingService")
            .withVersion("1.0");
        
        AuthorizationHandlerChain authChain = new AuthorizationHandlerChain();
        // ruleid: java-horizonteaaapassthroughwithoutcloudauth
        authChain.addAttribute(AaaTlsAuthorizationAttribute.RESULT_CODE, AuthorizationResult.PASS_THROUGH);
        
        serviceBuilder.withAuthorizationChain(authChain);
    }

    public void bad_case_5() {
        // PassThrough in authorization policy without CloudAuth
        AuthorizationPolicy policy = new AuthorizationPolicy.Builder()
            .withPolicyName("OpenAccessPolicy")
            // ruleid: java-horizonteaaapassthroughwithoutcloudauth
            .withAttribute(AaaTlsAuthorizationAttribute.RESULT_CODE, AuthorizationResult.PASS_THROUGH)
            .build();
        
        ServiceIdentity identity = new ServiceIdentity("analytics-service");
        identity.applyPolicy(policy);
    }

    public void bad_case_6() {
        // PassThrough in configuration file loading
        ConfigurationLoader loader = new ConfigurationLoader();
        Map<String, String> configMap = loader.loadFromFile("service-config.json");
        
        AuthorizationHandlerFactory factory = new AuthorizationHandlerFactory();
        // ruleid: java-horizonteaaapassthroughwithoutcloudauth
        factory.setAttribute(AaaTlsAuthorizationAttribute.RESULT_CODE, AuthorizationResult.PASS_THROUGH);
        factory.createFromConfig(configMap);
    }

    public void bad_case_7() {
        // PassThrough in HTTP request handler
        HttpRequest request = new HttpRequest(HttpMethod.POST, "/api/data");
        
        AuthorizationContext authContext = new AuthorizationContext();
        // ruleid: java-horizonteaaapassthroughwithoutcloudauth
        authContext.setAttribute(AaaTlsAuthorizationAttribute.RESULT_CODE, AuthorizationResult.PASS_THROUGH);
        
        RequestContext requestContext = new RequestContext(request);
        requestContext.setAuthorizationContext(authContext);
    }

    public void bad_case_8() {
        // PassThrough in service response processing
        ServiceResponse response = new ServiceResponse();
        
        AuthorizationHandlerChain authChain = new AuthorizationHandlerChain();
        // ruleid: java-horizonteaaapassthroughwithoutcloudauth
        authChain.setAttribute(AaaTlsAuthorizationAttribute.RESULT_CODE, AuthorizationResult.PASS_THROUGH);
        
        ResponseContext responseContext = new ResponseContext(response);
        responseContext.setAuthorizationChain(authChain);
    }

    public void bad_case_9() {
        // PassThrough in dynamic attribute setting
        ServiceContext context = new ServiceContext("NotificationService");
        
        Map<String, Object> attributes = new HashMap<>();
        // ruleid: java-horizonteaaapassthroughwithoutcloudauth
        attributes.put(AaaTlsAuthorizationAttribute.RESULT_CODE.toString(), AuthorizationResult.PASS_THROUGH);
        
        context.setAttributes(attributes);
    }

    public void bad_case_10() {
        // PassThrough in authorization handler creation
        PassThroughAuthorizationHandler handler = new PassThroughAuthorizationHandler();
        // ruleid: java-horizonteaaapassthroughwithoutcloudauth
        handler.setResultCodeAttribute(AaaTlsAuthorizationAttribute.RESULT_CODE, AuthorizationResult.PASS_THROUGH);
        
        ServiceEndpoint endpoint = new ServiceEndpoint("/api/messages");
        endpoint.setAuthorizationHandler(handler);
    }

    public void bad_case_11() {
        // PassThrough in service configuration with explicit null CloudAuth
        ServiceConfiguration config = new ServiceConfiguration();
        
        // ruleid: java-horizonteaaapassthroughwithoutcloudauth
        config.setAuthorizationAttribute(AaaTlsAuthorizationAttribute.RESULT_CODE, AuthorizationResult.PASS_THROUGH);
        config.setCloudAuthConfiguration(null);
        
        ServiceBuilder builder = new ServiceBuilder();
        builder.withConfiguration(config);
    }

    public void bad_case_12() {
        // PassThrough in TLS configuration
        TlsAuthorizationConfig tlsConfig = new TlsAuthorizationConfig();
        // ruleid: java-horizonteaaapassthroughwithoutcloudauth
        tlsConfig.setAttribute(AaaTlsAuthorizationAttribute.RESULT_CODE, AuthorizationResult.PASS_THROUGH);
        
        ServiceAuthorizationConfig authConfig = new ServiceAuthorizationConfig();
        authConfig.setTlsConfig(tlsConfig);
    }

    public void bad_case_13() {
        // PassThrough in service identity validation
        ServiceIdentity identity = new ServiceIdentity("data-service");
        
        AuthorizationContext context = new AuthorizationContext();
        // ruleid: java-horizonteaaapassthroughwithoutcloudauth
        context.addAttribute(AaaTlsAuthorizationAttribute.RESULT_CODE, AuthorizationResult.PASS_THROUGH);
        
        identity.validate(context);
    }

    public void bad_case_14() {
        // PassThrough in authorization result processing
        AuthorizationResult result = AuthorizationResult.PASS_THROUGH;
        
        Map<AaaTlsAuthorizationAttribute, AuthorizationResult> attributeMap = new HashMap<>();
        // ruleid: java-horizonteaaapassthroughwithoutcloudauth
        attributeMap.put(AaaTlsAuthorizationAttribute.RESULT_CODE, result);
        
        AuthorizationContext context = new AuthorizationContext();
        context.setAttributeMap(attributeMap);
    }

    public void bad_case_15() {
        // PassThrough in service request handling with empty CloudAuth
        ServiceRequest request = new ServiceRequest("/api/analytics");
        
        AuthorizationContext authContext = new AuthorizationContext();
        // ruleid: java-horizonteaaapassthroughwithoutcloudauth
        authContext.setAttribute(AaaTlsAuthorizationAttribute.RESULT_CODE, AuthorizationResult.PASS_THROUGH);
        
        CloudAuthConfiguration cloudConfig = new CloudAuthConfiguration.Builder().build(); // Empty config
        authContext.setCloudAuthConfig(cloudConfig); // Empty/default config is insufficient
        
        request.setAuthorizationContext(authContext);
    }

    // True Negative Examples (Safe/Secure Code)
    public void good_case_1() {
        // Basic service configuration with proper CloudAuth
        ServiceConfiguration serviceConfig = new ServiceConfiguration.Builder()
            .withServiceName("PaymentService")
            .withEndpoint("/api/payments")
            .build();
        
        CloudAuthConfiguration cloudAuthConfig = new CloudAuthConfiguration.Builder()
            .withAuthEndpoint("https://cloudauth.amazon.com")
            .withCredentials("service-credentials")
            .withPolicyName("payment-service-policy")
            .build();
        
        AuthorizationManager authManager = new AuthorizationManager.Builder()
            .withServiceConfig(serviceConfig)
            .withCloudAuthConfig(cloudAuthConfig)
            // ok: java-horizonteaaapassthroughwithoutcloudauth
            .withAuthorizationResult(AaaTlsAuthorizationAttribute.RESULT_CODE, AuthorizationResult.PASS_THROUGH)
            .build();
    }

    public void good_case_2() {
        // Custom authorization handler with CloudAuth in API Gateway service
        ServiceEndpoint endpoint = new ServiceEndpoint("/api/orders");
        
        CloudAuthConfiguration cloudAuthConfig = new CloudAuthConfiguration.Builder()
            .withRegion("us-west-2")
            .withServiceName("order-service")
            .withRoleArn("arn:aws:iam::123456789012:role/service-role")
            .build();
        
        TlsAuthorizationHandler authHandler = new TlsAuthorizationHandler.Builder()
            .withEndpoint(endpoint)
            .withCloudAuthConfig(cloudAuthConfig)
            // ok: java-horizonteaaapassthroughwithoutcloudauth
            .withAttributeOverride(AaaTlsAuthorizationAttribute.RESULT_CODE, AuthorizationResult.PASS_THROUGH)
            .build();
        
        endpoint.setAuthorizationHandler(authHandler);
    }

    public void good_case_3() {
        // Authorization context with CloudAuth in a microservice
        AuthorizationContext authContext = new AuthorizationContext();
        
        CloudAuthConfiguration cloudAuthConfig = new CloudAuthConfiguration.Builder()
            .withAuthType("IAM")
            .withPolicyDocument("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}")
            .build();
        
        authContext.setCloudAuthConfig(cloudAuthConfig);
        
        Map<String, String> attributes = new HashMap<>();
        // ok: java-horizonteaaapassthroughwithoutcloudauth
        attributes.put(AaaTlsAuthorizationAttribute.RESULT_CODE.getName(), AuthorizationResult.PASS_THROUGH.getValue());
        authContext.setAttributes(attributes);
        
        ServiceRequest request = new ServiceRequest("/api/users");
        request.setAuthorizationContext(authContext);
    }

    public void good_case_4() {
        // Service builder with CloudAuth in request processing
        ServiceBuilder serviceBuilder = new ServiceBuilder()
            .withName("DataProcessingService")
            .withVersion("1.0");
        
        CloudAuthConfiguration cloudAuthConfig = new CloudAuthConfiguration.Builder()
            .withClientId("data-processing-client")
            .withClientSecret("secret-key-123")
            .withTokenEndpoint("https://auth.amazon.com/token")
            .build();
        
        AuthorizationHandlerChain authChain = new AuthorizationHandlerChain();
        authChain.setCloudAuthConfig(cloudAuthConfig);
        // ok: java-horizonteaaapassthroughwithoutcloudauth
        authChain.addAttribute(AaaTlsAuthorizationAttribute.RESULT_CODE, AuthorizationResult.PASS_THROUGH);
        
        serviceBuilder.withAuthorizationChain(authChain);
    }

    public void good_case_5() {
        // CloudAuth in authorization policy
        CloudAuthConfiguration cloudAuthConfig = new CloudAuthConfiguration.Builder()
            .withAuthProvider("AWS")
            .withPolicyArn("arn:aws:iam::123456789012:policy/service-policy")
            .build();
        
        AuthorizationPolicy policy = new AuthorizationPolicy.Builder()
            .withPolicyName("SecureAccessPolicy")
            .withCloudAuthConfig(cloudAuthConfig)
            // ok: java-horizonteaaapassthroughwithoutcloudauth
            .withAttribute(AaaTlsAuthorizationAttribute.RESULT_CODE, AuthorizationResult.PASS_THROUGH)
            .build();
        
        ServiceIdentity identity = new ServiceIdentity("analytics-service");
        identity.applyPolicy(policy);
    }

    public void good_case_6() {
        // CloudAuth in configuration file loading
        ConfigurationLoader loader = new ConfigurationLoader();
        Map<String, String> configMap = loader.loadFromFile("service-config.json");
        
        CloudAuthConfiguration cloudAuthConfig = new CloudAuthConfiguration.Builder()
            .withConfigMap(configMap)
            .withDefaultRegion("us-east-1")
            .build();
        
        AuthorizationHandlerFactory factory = new AuthorizationHandlerFactory();
        factory.setCloudAuthConfig(cloudAuthConfig);
        // ok: java-horizonteaaapassthroughwithoutcloudauth
        factory.setAttribute(AaaTlsAuthorizationAttribute.RESULT_CODE, AuthorizationResult.PASS_THROUGH);
        factory.createFromConfig(configMap);
    }

    public void good_case_7() {
        // CloudAuth in HTTP request handler
        HttpRequest request = new HttpRequest(HttpMethod.POST, "/api/data");
        
        CloudAuthConfiguration cloudAuthConfig = new CloudAuthConfiguration.Builder()
            .withCredentialsProvider("instance-profile")
            .withServiceEndpoint("https://cloudauth.amazon.com/auth")
            .build();
        
        AuthorizationContext authContext = new AuthorizationContext();
        authContext.setCloudAuthConfig(cloudAuthConfig);
        // ok: java-horizonteaaapassthroughwithoutcloudauth
        authContext.setAttribute(AaaTlsAuthorizationAttribute.RESULT_CODE, AuthorizationResult.PASS_THROUGH);
        
        RequestContext requestContext = new RequestContext(request);
        requestContext.setAuthorizationContext(authContext);
    }

    public void good_case_8() {
        // CloudAuth in service response processing
        ServiceResponse response = new ServiceResponse();
        
        CloudAuthClient cloudAuthClient = new CloudAuthClient.Builder()
            .withRegion("us-west-2")
            .withCredentials("service-role")
            .build();
        
        CloudAuthConfiguration cloudAuthConfig = new CloudAuthConfiguration.Builder()
            .withClient(cloudAuthClient)
            .build();
        
        AuthorizationHandlerChain authChain = new AuthorizationHandlerChain();
        authChain.setCloudAuthConfig(cloudAuthConfig);
        // ok: java-horizonteaaapassthroughwithoutcloudauth
        authChain.setAttribute(AaaTlsAuthorizationAttribute.RESULT_CODE, AuthorizationResult.PASS_THROUGH);
        
        ResponseContext responseContext = new ResponseContext(response);
        responseContext.setAuthorizationChain(authChain);
    }

    public void good_case_9() {
        // CloudAuth in dynamic attribute setting
        ServiceContext context = new ServiceContext("NotificationService");
        
        CloudAuthConfiguration cloudAuthConfig = new CloudAuthConfiguration.Builder()
            .withAuthType("OAuth2")
            .withClientId("notification-client")
            .withScope("service.notify")
            .build();
        
        context.setCloudAuthConfig(cloudAuthConfig);
        
        Map<String, Object> attributes = new HashMap<>();
        // ok: java-horizonteaaapassthroughwithoutcloudauth
        attributes.put(AaaTlsAuthorizationAttribute.RESULT_CODE.toString(), AuthorizationResult.PASS_THROUGH);
        
        context.setAttributes(attributes);
    }

    public void good_case_10() {
        // CloudAuth in authorization handler creation
        CloudAuthHandler cloudAuthHandler = new CloudAuthHandler.Builder()
            .withRegion("eu-west-1")
            .withRoleArn("arn:aws:iam::123456789012:role/service-role")
            .build();
        
        PassThroughAuthorizationHandler handler = new PassThroughAuthorizationHandler();
        handler.setCloudAuthHandler(cloudAuthHandler);
        // ok: java-horizonteaaapassthroughwithoutcloudauth
        handler.setResultCodeAttribute(AaaTlsAuthorizationAttribute.RESULT_CODE, AuthorizationResult.PASS_THROUGH);
        
        ServiceEndpoint endpoint = new ServiceEndpoint("/api/messages");
        endpoint.setAuthorizationHandler(handler);
    }

    public void good_case_11() {
        // CloudAuth in service configuration
        CloudAuthConfiguration cloudAuthConfig = new CloudAuthConfiguration.Builder()
            .withAuthEndpoint("https://auth.amazon.com")
            .withTokenRefreshStrategy("proactive")
            .withSessionDuration(3600)
            .build();
        
        ServiceConfiguration config = new ServiceConfiguration();
        config.setCloudAuthConfiguration(cloudAuthConfig);
        // ok: java-horizonteaaapassthroughwithoutcloudauth
        config.setAuthorizationAttribute(AaaTlsAuthorizationAttribute.RESULT_CODE, AuthorizationResult.PASS_THROUGH);
        
        ServiceBuilder builder = new ServiceBuilder();
        builder.withConfiguration(config);
    }

    public void good_case_12() {
        // CloudAuth in TLS configuration
        CloudAuthConfiguration cloudAuthConfig = new CloudAuthConfiguration.Builder()
            .withIdentityProvider("cognito")
            .withUserPoolId("us-east-1_abcdefghi")
            .withClientId("client-id-123")
            .build();
        
        TlsAuthorizationConfig tlsConfig = new TlsAuthorizationConfig();
        tlsConfig.setCloudAuthConfig(cloudAuthConfig);
        // ok: java-horizonteaaapassthroughwithoutcloudauth
        tlsConfig.setAttribute(AaaTlsAuthorizationAttribute.RESULT_CODE, AuthorizationResult.PASS_THROUGH);
        
        ServiceAuthorizationConfig authConfig = new ServiceAuthorizationConfig();
        authConfig.setTlsConfig(tlsConfig);
    }

    public void good_case_13() {
        // CloudAuth in service identity validation
        CloudAuthConfiguration cloudAuthConfig = new CloudAuthConfiguration.Builder()
            .withAuthType("JWT")
            .withJwtIssuer("https://auth.amazon.com")
            .withJwtAudience("data-service")
            .build();
        
        ServiceIdentity identity = new ServiceIdentity("data-service");
        identity.setCloudAuthConfig(cloudAuthConfig);
        
        AuthorizationContext context = new AuthorizationContext();
        // ok: java-horizonteaaapassthroughwithoutcloudauth
        context.addAttribute(AaaTlsAuthorizationAttribute.RESULT_CODE, AuthorizationResult.PASS_THROUGH);
        
        identity.validate(context);
    }

    public void good_case_14() {
        // CloudAuth in authorization result processing
        CloudAuthConfiguration cloudAuthConfig = new CloudAuthConfiguration.Builder()
            .withAuthType("STS")
            .withRoleSessionName("service-session")
            .withExternalId("external-id-123")
            .build();
        
        AuthorizationResult result = AuthorizationResult.PASS_THROUGH;
        
        Map<AaaTlsAuthorizationAttribute, AuthorizationResult> attributeMap = new HashMap<>();
        // ok: java-horizonteaaapassthroughwithoutcloudauth
        attributeMap.put(AaaTlsAuthorizationAttribute.RESULT_CODE, result);
        
        AuthorizationContext context = new AuthorizationContext();
        context.setCloudAuthConfig(cloudAuthConfig);
        context.setAttributeMap(attributeMap);
    }

    public void good_case_15() {
        // CloudAuth in service request handling
        ServiceRequest request = new ServiceRequest("/api/analytics");
        
        CloudAuthConfiguration cloudAuthConfig = new CloudAuthConfiguration.Builder()
            .withAuthType("IAM")
            .withRegion("us-east-2")
            .withServiceName("analytics-service")
            .withPolicyName("analytics-access-policy")
            .build();
        
        AuthorizationContext authContext = new AuthorizationContext();
        authContext.setCloudAuthConfig(cloudAuthConfig);
        // ok: java-horizonteaaapassthroughwithoutcloudauth
        authContext.setAttribute(AaaTlsAuthorizationAttribute.RESULT_CODE, AuthorizationResult.PASS_THROUGH);
        
        request.setAuthorizationContext(authContext);
    }
}
// {/fact}