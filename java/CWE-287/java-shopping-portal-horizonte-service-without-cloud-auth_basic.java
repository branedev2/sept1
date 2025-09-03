package com.example.shoppingportal;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RestController;

import com.example.shoppingportal.security.AaaTlsStaticDataSourceDescriptor;
import com.example.shoppingportal.security.CloudAuthResourceServer;
import com.example.shoppingportal.security.HorizonteSecurityConfig;
import com.example.shoppingportal.security.PassThroughCodeManager;
import com.example.shoppingportal.security.SecurityProperties;
import com.example.shoppingportal.security.SessionManager;

public class ShoppingPortalSecurityExamples {

    // True Positive Examples (Vulnerable Code)

    @Service
    public static class bad_case_1 {
        @Autowired
        private AaaTlsStaticDataSourceDescriptor aaaDataSource;
        
        public void configureService() {
            // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
            aaaDataSource.setPassThroughCode("OVERRIDE_SECURITY");
            // No CloudAuth resource server is configured
        }
    }

    @Service
    public static class bad_case_2 {
        @Autowired
        private HorizonteSecurityConfig securityConfig;
        
        public void initializePortal() {
            // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
            securityConfig.setProperty("opt-out", "true");
            securityConfig.setPassThroughEnabled(true);
            // CloudAuth is disabled but PassThrough is enabled
        }
    }

    @Configuration
    public static class bad_case_3 {
        @Bean
        public AaaTlsStaticDataSourceDescriptor aaaDataSource() {
            AaaTlsStaticDataSourceDescriptor dataSource = new AaaTlsStaticDataSourceDescriptor();
            // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
            dataSource.setPassThroughCode("BYPASS_AAA_VALIDATION");
            return dataSource;
        }
        
        // No CloudAuth bean is defined
    }

    @Service
    public static class bad_case_4 {
        @Autowired
        private SessionManager sessionManager;
        
        public void configureSessionSecurity() {
            // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
            sessionManager.setRequireAaaAttributes(false);
            sessionManager.enablePassThrough("ADMIN_OVERRIDE");
        }
    }

    @Configuration
    @EnableWebSecurity
    public static class bad_case_5 extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
            http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/**").permitAll();
                
            PassThroughCodeManager.getInstance().registerCode("SKIP_AUTH");
        }
        
        // CloudAuth resource server is not configured
    }

    @Service
    public static class bad_case_6 {
        @Autowired
        private SecurityProperties securityProperties;
        
        public void initService() {
            // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
            securityProperties.setProperty("aaa.passthrough.enabled", "true");
            securityProperties.setProperty("cloudauth.enabled", "false");
        }
    }

    @Configuration
    public static class bad_case_7 {
        @Bean
        public HorizonteSecurityConfig securityConfig() {
            HorizonteSecurityConfig config = new HorizonteSecurityConfig();
            // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
            config.setPassThroughEnabled(true);
            config.setCloudAuthRequired(false);
            return config;
        }
    }

    @Service
    public static class bad_case_8 {
        @Autowired
        private AaaTlsStaticDataSourceDescriptor aaaDataSource;
        
        @Autowired
        private CloudAuthResourceServer cloudAuthServer;
        
        public void configureService() {
            // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
            aaaDataSource.setPassThroughCode("OVERRIDE_AAA_CHECK");
            cloudAuthServer.disable(); // Explicitly disabling CloudAuth
        }
    }

    @RestController
    public static class bad_case_9 {
        @Autowired
        private SessionManager sessionManager;
        
        public void initializeController() {
            // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
            sessionManager.setProperty("aaa.session.validation", "passthrough");
            // No CloudAuth configuration
        }
    }

    @Service
    public static class bad_case_10 {
        @Autowired
        private PassThroughCodeManager passThroughManager;
        
        public void setupPassThroughCodes() {
            // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
            passThroughManager.registerCode("ADMIN_AC_REDACTED_TWILIO_ID");
            passThroughManager.registerCode("SKIP_VALIDATION");
            // CloudAuth is not configured or enabled
        }
    }

    @Configuration
    public static class bad_case_11 {
        @Bean
        public CloudAuthResourceServer cloudAuthServer() {
            CloudAuthResourceServer server = new CloudAuthResourceServer();
            server.setEnabled(false); // Disabled CloudAuth
            return server;
        }
        
        @Bean
        public AaaTlsStaticDataSourceDescriptor aaaDataSource() {
            AaaTlsStaticDataSourceDescriptor dataSource = new AaaTlsStaticDataSourceDescriptor();
            // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
            dataSource.setPassThroughEnabled(true);
            return dataSource;
        }
    }

    @Service
    public static class bad_case_12 {
        @Autowired
        private SecurityProperties securityProperties;
        
        public void configureSecurityProperties() {
            // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
            securityProperties.setProperty("horizonte.session.aaa.required", "false");
            securityProperties.setProperty("horizonte.passthrough.enabled", "true");
            // CloudAuth is not properly configured
        }
    }

    @Configuration
    public static class bad_case_13 {
        @Bean
        public SessionManager sessionManager() {
            SessionManager manager = new SessionManager();
            // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
            manager.setRequireAaaAttributes(false);
            manager.setPassThroughEnabled(true);
            return manager;
        }
        
        // No CloudAuth bean defined
    }

    @Service
    public static class bad_case_14 {
        @Autowired
        private HorizonteSecurityConfig securityConfig;
        
        @Autowired
        private CloudAuthResourceServer cloudAuthServer;
        
        public void initializeService() {
            cloudAuthServer.setEnabled(false);
            
            // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
            securityConfig.setPassThroughCode("BYPASS_SECURITY");
            securityConfig.setProperty("opt-out", "true");
        }
    }

    @Configuration
    public static class bad_case_15 {
        @Bean
        public AaaTlsStaticDataSourceDescriptor aaaDataSource() {
            AaaTlsStaticDataSourceDescriptor dataSource = new AaaTlsStaticDataSourceDescriptor();
            // ruleid: java-shopping-portal-horizonte-service-without-cloud-auth
            dataSource.setPassThroughCode("ADMIN_OVERRIDE");
            dataSource.setProperty("aaa.validation.required", "false");
            return dataSource;
        }
        
        // CloudAuth resource server is missing
    }

    // True Negative Examples (Secure Code)

    @Service
    public static class good_case_1 {
        @Autowired
        private AaaTlsStaticDataSourceDescriptor aaaDataSource;
        
        @Autowired
        private CloudAuthResourceServer cloudAuthServer;
        
        public void configureService() {
            // ok: java-shopping-portal-horizonte-service-without-cloud-auth
            cloudAuthServer.setEnabled(true);
            cloudAuthServer.configure();
            aaaDataSource.setPassThroughCode("OVERRIDE_SECURITY");
        }
    }

    @Configuration
    public static class good_case_2 {
        @Bean
        public CloudAuthResourceServer cloudAuthServer() {
            CloudAuthResourceServer server = new CloudAuthResourceServer();
            server.setEnabled(true);
            return server;
        }
        
        @Bean
        public HorizonteSecurityConfig securityConfig(CloudAuthResourceServer cloudAuthServer) {
            HorizonteSecurityConfig config = new HorizonteSecurityConfig();
            // ok: java-shopping-portal-horizonte-service-without-cloud-auth
            config.setCloudAuthServer(cloudAuthServer);
            config.setPassThroughEnabled(true);
            return config;
        }
    }

    @Service
    public static class good_case_3 {
        @Autowired
        private SessionManager sessionManager;
        
        @Autowired
        private CloudAuthResourceServer cloudAuthServer;
        
        public void configureSessionSecurity() {
            // ok: java-shopping-portal-horizonte-service-without-cloud-auth
            cloudAuthServer.setEnabled(true);
            cloudAuthServer.initialize();
            sessionManager.setRequireAaaAttributes(false);
            sessionManager.enablePassThrough("ADMIN_OVERRIDE");
        }
    }

    @Configuration
    @EnableWebSecurity
    public static class good_case_4 extends WebSecurityConfigurerAdapter {
        @Autowired
        private CloudAuthResourceServer cloudAuthServer;
        
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // ok: java-shopping-portal-horizonte-service-without-cloud-auth
            cloudAuthServer.setEnabled(true);
            cloudAuthServer.configure();
            
            PassThroughCodeManager.getInstance().registerCode("SKIP_AUTH");
            
            http.authorizeRequests()
                .antMatchers("/public/**").permitAll()
                .anyRequest().authenticated();
        }
    }

    @Service
    public static class good_case_5 {
        @Autowired
        private SecurityProperties securityProperties;
        
        @Autowired
        private CloudAuthResourceServer cloudAuthServer;
        
        public void initService() {
            // ok: java-shopping-portal-horizonte-service-without-cloud-auth
            cloudAuthServer.setEnabled(true);
            cloudAuthServer.initialize();
            
            securityProperties.setProperty("aaa.passthrough.enabled", "true");
            securityProperties.setProperty("cloudauth.enabled", "true");
        }
    }

    @Service
    public static class good_case_6 {
        @Autowired
        private AaaTlsStaticDataSourceDescriptor aaaDataSource;
        
        public void configureService() {
            // ok: java-shopping-portal-horizonte-service-without-cloud-auth
            // Not using PassThrough code, so CloudAuth is not required
            aaaDataSource.setProperty("aaa.validation.required", "true");
        }
    }

    @Configuration
    public static class good_case_7 {
        @Bean
        public HorizonteSecurityConfig securityConfig() {
            HorizonteSecurityConfig config = new HorizonteSecurityConfig();
            // ok: java-shopping-portal-horizonte-service-without-cloud-auth
            // Not using PassThrough, so no need for CloudAuth
            config.setPassThroughEnabled(false);
            config.setProperty("opt-out", "false");
            return config;
        }
    }

    @Service
    public static class good_case_8 {
        @Autowired
        private SessionManager sessionManager;
        
        public void configureSessionSecurity() {
            // ok: java-shopping-portal-horizonte-service-without-cloud-auth
            // Not using PassThrough, requiring AAA attributes
            sessionManager.setRequireAaaAttributes(true);
            sessionManager.setPassThroughEnabled(false);
        }
    }

    @Configuration
    public static class good_case_9 {
        @Bean
        public CloudAuthResourceServer cloudAuthServer() {
            CloudAuthResourceServer server = new CloudAuthResourceServer();
            server.setEnabled(true);
            server.configure();
            return server;
        }
        
        @Bean
        public AaaTlsStaticDataSourceDescriptor aaaDataSource(CloudAuthResourceServer cloudAuthServer) {
            AaaTlsStaticDataSourceDescriptor dataSource = new AaaTlsStaticDataSourceDescriptor();
            // ok: java-shopping-portal-horizonte-service-without-cloud-auth
            dataSource.setCloudAuthServer(cloudAuthServer);
            dataSource.setPassThroughCode("OVERRIDE_AAA_CHECK");
            return dataSource;
        }
    }

    @Service
    public static class good_case_10 {
        @Autowired
        private PassThroughCodeManager passThroughManager;
        
        @Autowired
        private CloudAuthResourceServer cloudAuthServer;
        
        public void setupPassThroughCodes() {
            // ok: java-shopping-portal-horizonte-service-without-cloud-auth
            cloudAuthServer.setEnabled(true);
            cloudAuthServer.initialize();
            
            passThroughManager.registerCode("ADMIN_AC_REDACTED_TWILIO_ID");
            passThroughManager.registerCode("SKIP_VALIDATION");
        }
    }

    @Configuration
    public static class good_case_11 {
        @Bean
        public CloudAuthResourceServer cloudAuthServer() {
            CloudAuthResourceServer server = new CloudAuthResourceServer();
            server.setEnabled(true);
            return server;
        }
        
        @Bean
        public SecurityProperties securityProperties(CloudAuthResourceServer cloudAuthServer) {
            SecurityProperties properties = new SecurityProperties();
            // ok: java-shopping-portal-horizonte-service-without-cloud-auth
            properties.setCloudAuthServer(cloudAuthServer);
            properties.setProperty("horizonte.passthrough.enabled", "true");
            return properties;
        }
    }

    @Service
    public static class good_case_12 {
        @Autowired
        private HorizonteSecurityConfig securityConfig;
        
        public void initializeService() {
            // ok: java-shopping-portal-horizonte-service-without-cloud-auth
            // Not using PassThrough codes or opt-out, so CloudAuth not required
            securityConfig.setProperty("aaa.validation.required", "true");
            securityConfig.setPassThroughEnabled(false);
        }
    }

    @Configuration
    public static class good_case_13 {
        @Bean
        public CloudAuthResourceServer cloudAuthServer() {
            CloudAuthResourceServer server = new CloudAuthResourceServer();
            server.setEnabled(true);
            server.configure();
            return server;
        }
        
        @Bean
        public SessionManager sessionManager(CloudAuthResourceServer cloudAuthServer) {
            SessionManager manager = new SessionManager();
            // ok: java-shopping-portal-horizonte-service-without-cloud-auth
            manager.setCloudAuthServer(cloudAuthServer);
            manager.setRequireAaaAttributes(false);
            manager.setPassThroughEnabled(true);
            return manager;
        }
    }

    @Service
    public static class good_case_14 {
        @Autowired
        private AaaTlsStaticDataSourceDescriptor aaaDataSource;
        
        @Autowired
        private CloudAuthResourceServer cloudAuthServer;
        
        public void configureService() {
            // ok: java-shopping-portal-horizonte-service-without-cloud-auth
            if (cloudAuthServer.isEnabled()) {
                aaaDataSource.setPassThroughCode("OVERRIDE_SECURITY");
                aaaDataSource.setProperty("opt-out", "true");
            } else {
                // Don't use PassThrough if CloudAuth is not enabled
                aaaDataSource.setPassThroughEnabled(false);
                aaaDataSource.setProperty("opt-out", "false");
            }
        }
    }

    @Configuration
    public static class good_case_15 {
        @Bean
        public AaaTlsStaticDataSourceDescriptor aaaDataSource() {
            AaaTlsStaticDataSourceDescriptor dataSource = new AaaTlsStaticDataSourceDescriptor();
            // ok: java-shopping-portal-horizonte-service-without-cloud-auth
            // Not using PassThrough codes, so CloudAuth not required
            dataSource.setPassThroughEnabled(false);
            dataSource.setProperty("aaa.validation.required", "true");
            return dataSource;
        }
    }
}