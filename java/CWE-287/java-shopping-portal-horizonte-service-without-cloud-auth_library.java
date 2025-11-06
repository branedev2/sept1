import com.horizonte.security.AaaTlsStaticDataSourceDescriptor;
import com.horizonte.security.CloudAuthResourceServer;
import com.horizonte.security.ShoppingPortalSession;
import com.horizonte.security.PassThroughCode;
import com.horizonte.config.SecurityConfiguration;
import com.horizonte.service.ShoppingService;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import com.azure.spring.cloud.autoconfigure.aad.AadResourceServerWebSecurityConfigurerAdapter;
import com.azure.spring.cloud.autoconfigure.aad.AadWebSecurityConfigurerAdapter;

import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.KeycloakSecurityComponents;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;

import com.okta.spring.boot.oauth.Okta;
import com.okta.spring.boot.oauth.OktaOAuth2Properties;

import com.auth0.spring.security.api.JwtWebSecurityConfigurer;
import com.auth0.spring.security.api.Auth0SecurityConfig;

import io.micronaut.security.token.jwt.validator.JwtTokenValidator;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;

import org.pac4j.core.config.Config;
import org.pac4j.springframework.security.web.SecurityFilter;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthRequest;

import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.keycloak.admin.client.Keycloak;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseToken;

import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.providers.KeycloakAuth;

import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.realm.Realm;

// Security Issue: Using AAA PassThrough code values without properly configured CloudAuth resource server

// True Positive Examples (Vulnerable/Insecure Code)
public class VulnerableShoppingPortalConfigurations {

// {fact rule=hardcoded-credentials@v1.0 defects=1}
    public void bad_case_1() {
        SecurityConfiguration config = new SecurityConfiguration();
        ShoppingService service = new ShoppingService();
        
        // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
        AaaTlsStaticDataSourceDescriptor descriptor = new AaaTlsStaticDataSourceDescriptor();
        descriptor.setPassThroughCode(PassThroughCode.OVERRIDE_ALL);
        
        service.setDataSourceDescriptor(descriptor);
        // No CloudAuth resource server configured
        service.initialize();
    }

    public void bad_case_2() {
        ShoppingPortalSession session = new ShoppingPortalSession();
        
        // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
        session.setProperty("opt-out", "true");
        session.setPassThroughCode(PassThroughCode.BYPASS_AAA_CHECKS);
        
        // Using session without CloudAuth resource server
        session.initialize();
    }

    public void bad_case_3() {
        SecurityConfiguration config = new SecurityConfiguration();
        
        // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
        config.setProperty("horizonte.security.aaa.passthrough", "true");
        config.setProperty("horizonte.security.aaa.tls.bypass", "enabled");
        
        // CloudAuth is disabled
        config.setProperty("horizonte.security.cloudauth.enabled", "false");
        
        config.apply();
    }

    public void bad_case_4() {
        ShoppingService service = new ShoppingService();
        
        // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
        service.enablePassThrough(PassThroughCode.ADMIN_OVERRIDE);
        
        // CloudAuth resource server is null
        service.setCloudAuthResourceServer(null);
        service.start();
    }

    public void bad_case_5() {
        SecurityConfiguration config = new SecurityConfiguration();
        
        // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
        config.setAaaPassThroughEnabled(true);
        
        // CloudAuth resource server is not initialized
        config.apply();
    }

    @Configuration
    public class bad_case_6 extends AadWebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            super.configure(http);
            
            // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
            AaaTlsStaticDataSourceDescriptor descriptor = new AaaTlsStaticDataSourceDescriptor();
            descriptor.setPassThroughCode(PassThroughCode.SKIP_VALIDATION);
            
            // Azure AD configuration but no CloudAuth resource server
            http.authorizeRequests().anyRequest().authenticated();
        }
    }

    public class bad_case_7 extends KeycloakWebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            super.configure(http);
            
            // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
            ShoppingPortalSession session = new ShoppingPortalSession();
            session.setProperty("opt-out", "true");
            
            // Keycloak configuration but no CloudAuth resource server
            http.authorizeRequests().anyRequest().authenticated();
        }
    }

    public void bad_case_8() {
        OktaOAuth2Properties properties = new OktaOAuth2Properties();
        properties.setIssuer("https://dev-123456.okta.com/oauth2/default");
        
        // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
        SecurityConfiguration config = new SecurityConfiguration();
        config.setProperty("horizonte.security.aaa.passthrough", "enabled");
        
        // Okta configuration but no CloudAuth resource server
        Okta.configureResourceServer(null, properties);
    }

    public void bad_case_9() {
        String domain = "example.auth0.com";
        String apiAudience = "YOUR_API_AUDIENCE";
        
        // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
        AaaTlsStaticDataSourceDescriptor descriptor = new AaaTlsStaticDataSourceDescriptor();
        descriptor.enablePassThrough();
        
        // Auth0 configuration but no CloudAuth resource server
        JwtWebSecurityConfigurer.forRS256(apiAudience, domain);
    }

    public void bad_case_10() {
        SignatureConfiguration signatureConfig = null; // Placeholder
        JwtTokenValidator validator = null; // Placeholder
        
        // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
        ShoppingPortalSession session = new ShoppingPortalSession();
        session.setPassThroughCode(PassThroughCode.OVERRIDE_ALL);
        
        // Micronaut security configuration but no CloudAuth resource server
        validator.validateToken("token", signatureConfig);
    }

    public void bad_case_11() {
        Config pac4jConfig = new Config();
        SecurityFilter filter = new SecurityFilter();
        filter.setConfig(pac4jConfig);
        
        // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
        SecurityConfiguration config = new SecurityConfiguration();
        config.setAaaPassThroughEnabled(true);
        
        // Pac4j configuration but no CloudAuth resource server
        filter.init(null);
    }

    public void bad_case_12() {
        AWSCognitoIdentityProvider cognitoClient = null; // Placeholder
        AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest();
        
        // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
        AaaTlsStaticDataSourceDescriptor descriptor = new AaaTlsStaticDataSourceDescriptor();
        descriptor.setPassThroughCode(PassThroughCode.BYPASS_AAA_CHECKS);
        
        // AWS Cognito configuration but no CloudAuth resource server
        cognitoClient.adminInitiateAuth(authRequest);
    }

    public void bad_case_13() {
        QuarkusSecurityIdentity identity = QuarkusSecurityIdentity.builder().build();
        
        // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
        ShoppingPortalSession session = new ShoppingPortalSession();
        session.setProperty("opt-out", "true");
        
        // Quarkus security configuration but no CloudAuth resource server
        identity.isAnonymous();
    }

    public void bad_case_14() {
        Keycloak keycloak = Keycloak.getInstance(
            "https://auth-server/auth",
            "master",
            "admin",
            "password",
            "admin-cli");
        
        // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
        SecurityConfiguration config = new SecurityConfiguration();
        config.setProperty("horizonte.security.aaa.tls.bypass", "enabled");
        
        // Keycloak admin client but no CloudAuth resource server
        keycloak.realm("master").users().get("user-id");
    }

    public void bad_case_15() {
        FirebaseAuth firebaseAuth = FirebaseAuth.getInstance();
        
        // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
        AaaTlsStaticDataSourceDescriptor descriptor = new AaaTlsStaticDataSourceDescriptor();
        descriptor.setPassThroughCode(PassThroughCode.ADMIN_OVERRIDE);
        
        // Firebase Auth but no CloudAuth resource server
        firebaseAuth.verifyIdToken("token");
    }

    // True Negative Examples (Safe/Secure Code)
    public void good_case_1() {
        SecurityConfiguration config = new SecurityConfiguration();
        ShoppingService service = new ShoppingService();
        
        // Configure CloudAuth resource server first
        CloudAuthResourceServer cloudAuth = new CloudAuthResourceServer();
        cloudAuth.setEnabled(true);
        cloudAuth.initialize();
        
        // ok: java-shopping-portal-horizonte-service-without-cloud-auth
        AaaTlsStaticDataSourceDescriptor descriptor = new AaaTlsStaticDataSourceDescriptor();
        descriptor.setPassThroughCode(PassThroughCode.OVERRIDE_ALL);
        
        service.setCloudAuthResourceServer(cloudAuth);
        service.setDataSourceDescriptor(descriptor);
        service.initialize();
    }

    public void good_case_2() {
        // Configure CloudAuth resource server first
        CloudAuthResourceServer cloudAuth = new CloudAuthResourceServer();
        cloudAuth.setEnabled(true);
        cloudAuth.initialize();
        
        ShoppingPortalSession session = new ShoppingPortalSession();
        session.setCloudAuthResourceServer(cloudAuth);
        
        // ok: java-shopping-portal-horizonte-service-without-cloud-auth
        session.setProperty("opt-out", "true");
        session.setPassThroughCode(PassThroughCode.BYPASS_AAA_CHECKS);
        
        session.initialize();
    }

    public void good_case_3() {
        SecurityConfiguration config = new SecurityConfiguration();
        
        // Configure CloudAuth resource server first
        config.setProperty("horizonte.security.cloudauth.enabled", "true");
        config.setProperty("horizonte.security.cloudauth.url", "https://auth.example.com");
        
        // ok: java-shopping-portal-horizonte-service-without-cloud-auth
        config.setProperty("horizonte.security.aaa.passthrough", "true");
        config.setProperty("horizonte.security.aaa.tls.bypass", "enabled");
        
        config.apply();
    }

    public void good_case_4() {
        ShoppingService service = new ShoppingService();
        
        // Configure CloudAuth resource server first
        CloudAuthResourceServer cloudAuth = new CloudAuthResourceServer();
        cloudAuth.setEnabled(true);
        cloudAuth.initialize();
        service.setCloudAuthResourceServer(cloudAuth);
        
        // ok: java-shopping-portal-horizonte-service-without-cloud-auth
        service.enablePassThrough(PassThroughCode.ADMIN_OVERRIDE);
        
        service.start();
    }

    public void good_case_5() {
        SecurityConfiguration config = new SecurityConfiguration();
        
        // Configure CloudAuth resource server first
        CloudAuthResourceServer cloudAuth = new CloudAuthResourceServer();
        cloudAuth.setEnabled(true);
        cloudAuth.initialize();
        config.setCloudAuthResourceServer(cloudAuth);
        
        // ok: java-shopping-portal-horizonte-service-without-cloud-auth
        config.setAaaPassThroughEnabled(true);
        
        config.apply();
    }

    @Configuration
    public class good_case_6 extends AadResourceServerWebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            super.configure(http);
            
            // Configure CloudAuth resource server first
            CloudAuthResourceServer cloudAuth = new CloudAuthResourceServer();
            cloudAuth.setEnabled(true);
            cloudAuth.initialize();
            
            // ok: java-shopping-portal-horizonte-service-without-cloud-auth
            AaaTlsStaticDataSourceDescriptor descriptor = new AaaTlsStaticDataSourceDescriptor();
            descriptor.setPassThroughCode(PassThroughCode.SKIP_VALIDATION);
            descriptor.setCloudAuthResourceServer(cloudAuth);
            
            http.authorizeRequests().anyRequest().authenticated();
        }
    }

    @Configuration
    public class good_case_7 extends KeycloakWebSecurityConfigurerAdapter {
        @Bean
        public CloudAuthResourceServer cloudAuthResourceServer() {
            CloudAuthResourceServer cloudAuth = new CloudAuthResourceServer();
            cloudAuth.setEnabled(true);
            cloudAuth.initialize();
            return cloudAuth;
        }
        
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            super.configure(http);
            
            ShoppingPortalSession session = new ShoppingPortalSession();
            session.setCloudAuthResourceServer(cloudAuthResourceServer());
            
            // ok: java-shopping-portal-horizonte-service-without-cloud-auth
            session.setProperty("opt-out", "true");
            
            http.authorizeRequests().anyRequest().authenticated();
        }
    }

    public void good_case_8() {
        OktaOAuth2Properties properties = new OktaOAuth2Properties();
        properties.setIssuer("https://dev-123456.okta.com/oauth2/default");
        
        // Configure CloudAuth resource server first
        CloudAuthResourceServer cloudAuth = new CloudAuthResourceServer();
        cloudAuth.setEnabled(true);
        cloudAuth.initialize();
        
        SecurityConfiguration config = new SecurityConfiguration();
        config.setCloudAuthResourceServer(cloudAuth);
        
        // ok: java-shopping-portal-horizonte-service-without-cloud-auth
        config.setProperty("horizonte.security.aaa.passthrough", "enabled");
        
        Okta.configureResourceServer(null, properties);
    }

    public void good_case_9() {
        String domain = "example.auth0.com";
        String apiAudience = "YOUR_API_AUDIENCE";
        
        // Configure CloudAuth resource server first
        CloudAuthResourceServer cloudAuth = new CloudAuthResourceServer();
        cloudAuth.setEnabled(true);
        cloudAuth.initialize();
        
        // ok: java-shopping-portal-horizonte-service-without-cloud-auth
        AaaTlsStaticDataSourceDescriptor descriptor = new AaaTlsStaticDataSourceDescriptor();
        descriptor.enablePassThrough();
        descriptor.setCloudAuthResourceServer(cloudAuth);
        
        JwtWebSecurityConfigurer.forRS256(apiAudience, domain);
    }

    public void good_case_10() {
        SignatureConfiguration signatureConfig = null; // Placeholder
        JwtTokenValidator validator = null; // Placeholder
        
        // Configure CloudAuth resource server first
        CloudAuthResourceServer cloudAuth = new CloudAuthResourceServer();
        cloudAuth.setEnabled(true);
        cloudAuth.initialize();
        
        ShoppingPortalSession session = new ShoppingPortalSession();
        session.setCloudAuthResourceServer(cloudAuth);
        
        // ok: java-shopping-portal-horizonte-service-without-cloud-auth
        session.setPassThroughCode(PassThroughCode.OVERRIDE_ALL);
        
        validator.validateToken("token", signatureConfig);
    }

    public void good_case_11() {
        Config pac4jConfig = new Config();
        SecurityFilter filter = new SecurityFilter();
        filter.setConfig(pac4jConfig);
        
        // Configure CloudAuth resource server first
        CloudAuthResourceServer cloudAuth = new CloudAuthResourceServer();
        cloudAuth.setEnabled(true);
        cloudAuth.initialize();
        
        SecurityConfiguration config = new SecurityConfiguration();
        config.setCloudAuthResourceServer(cloudAuth);
        
        // ok: java-shopping-portal-horizonte-service-without-cloud-auth
        config.setAaaPassThroughEnabled(true);
        
        filter.init(null);
    }

    public void good_case_12() {
        AWSCognitoIdentityProvider cognitoClient = null; // Placeholder
        AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest();
        
        // Configure CloudAuth resource server first
        CloudAuthResourceServer cloudAuth = new CloudAuthResourceServer();
        cloudAuth.setEnabled(true);
        cloudAuth.initialize();
        
        // ok: java-shopping-portal-horizonte-service-without-cloud-auth
        AaaTlsStaticDataSourceDescriptor descriptor = new AaaTlsStaticDataSourceDescriptor();
        descriptor.setPassThroughCode(PassThroughCode.BYPASS_AAA_CHECKS);
        descriptor.setCloudAuthResourceServer(cloudAuth);
        
        cognitoClient.adminInitiateAuth(authRequest);
    }

    public void good_case_13() {
        QuarkusSecurityIdentity identity = QuarkusSecurityIdentity.builder().build();
        
        // Configure CloudAuth resource server first
        CloudAuthResourceServer cloudAuth = new CloudAuthResourceServer();
        cloudAuth.setEnabled(true);
        cloudAuth.initialize();
        
        ShoppingPortalSession session = new ShoppingPortalSession();
        session.setCloudAuthResourceServer(cloudAuth);
        
        // ok: java-shopping-portal-horizonte-service-without-cloud-auth
        session.setProperty("opt-out", "true");
        
        identity.isAnonymous();
    }

    public void good_case_14() {
        Keycloak keycloak = Keycloak.getInstance(
            "https://auth-server/auth",
            "master",
            "admin",
            "password",
            "admin-cli");
        
        // Configure CloudAuth resource server first
        CloudAuthResourceServer cloudAuth = new CloudAuthResourceServer();
        cloudAuth.setEnabled(true);
        cloudAuth.initialize();
        
        SecurityConfiguration config = new SecurityConfiguration();
        config.setCloudAuthResourceServer(cloudAuth);
        
        // ok: java-shopping-portal-horizonte-service-without-cloud-auth
        config.setProperty("horizonte.security.aaa.tls.bypass", "enabled");
        
        keycloak.realm("master").users().get("user-id");
    }

    public void good_case_15() {
        FirebaseAuth firebaseAuth = FirebaseAuth.getInstance();
        
        // Configure CloudAuth resource server first
        CloudAuthResourceServer cloudAuth = new CloudAuthResourceServer();
        cloudAuth.setEnabled(true);
        cloudAuth.initialize();
        
        // ok: java-shopping-portal-horizonte-service-without-cloud-auth
        AaaTlsStaticDataSourceDescriptor descriptor = new AaaTlsStaticDataSourceDescriptor();
        descriptor.setPassThroughCode(PassThroughCode.ADMIN_OVERRIDE);
        descriptor.setCloudAuthResourceServer(cloudAuth);
        
        firebaseAuth.verifyIdToken("token");
    }
}
// {/fact}