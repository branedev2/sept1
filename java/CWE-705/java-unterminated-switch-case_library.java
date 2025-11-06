import java.util.Scanner;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;
import org.apache.struts2.interceptor.ServletRequestAware;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import org.apache.http.client.methods.HttpGet;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import org.apache.commons.configuration.Configuration;
import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.google.cloud.functions.HttpFunction;
import com.google.cloud.functions.HttpRequest;
import com.google.cloud.functions.HttpResponse;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.CamelContext;
import org.apache.camel.impl.DefaultCamelContext;
import org.apache.commons.io.FileUtils;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.cfg.Configuration;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.CommandLine;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.quartz.JobBuilder;
import org.quartz.JobDetail;
import org.quartz.Scheduler;
import org.quartz.SimpleScheduleBuilder;
import org.quartz.Trigger;
import org.quartz.TriggerBuilder;
import org.quartz.impl.StdSchedulerFactory;
import io.vertx.core.Vertx;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import redis.clients.jedis.Jedis;

// Security Issue: Improper termination of `case` statements in a `switch` block can lead to unintended code execution

// True Positive Examples (Vulnerable/Insecure Code)
class VulnerableExamples {
// {fact rule=code-injection@v1.0 defects=1}
    public void bad_case_1(HttpServletRequest request) {
        // Spring MVC example with unterminated switch case
        String action = request.getParameter("action");
        int actionCode = Integer.parseInt(action);
        
        switch (actionCode) {
            // ruleid: java-unterminated-switch-case
            case 1:
                System.out.println("Processing action 1");
                // Missing break statement causes fall-through to case 2
            case 2:
                System.out.println("Processing action 2");
                break;
            case 3:
                System.out.println("Processing action 3");
                break;
        }
    }

    public void bad_case_2(javax.ws.rs.core.Request request) {
        // JAX-RS example with unterminated switch case
        String operation = request.getProperty("operation").toString();
        
        switch (operation) {
            // ruleid: java-unterminated-switch-case
            case "create":
                System.out.println("Creating resource");
                // Missing break statement
            case "update":
                System.out.println("Updating resource");
                break;
            case "delete":
                System.out.println("Deleting resource");
                break;
        }
    }

    public void bad_case_3() {
        // OkHttp client example with unterminated switch case
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://api.example.com/status")
            .build();
            
        try {
            okhttp3.Response response = client.newCall(request).execute();
            int statusCode = response.code();
            
            switch (statusCode) {
                // ruleid: java-unterminated-switch-case
                case 200:
                    System.out.println("Success");
                    // Missing break statement
                case 404:
                    System.out.println("Not found");
                    break;
                case 500:
                    System.out.println("Server error");
                    break;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4(HttpServletRequest request) {
        // Apache Commons Exec example with unterminated switch case
        String command = request.getParameter("cmd");
        int mode = Integer.parseInt(request.getParameter("mode"));
        
        try {
            CommandLine cmdLine = CommandLine.parse(command);
            DefaultExecutor executor = new DefaultExecutor();
            
            switch (mode) {
                // ruleid: java-unterminated-switch-case
                case 1:
                    executor.setExitValue(0);
                    // Missing break statement
                case 2:
                    executor.setExitValue(1);
                    break;
                default:
                    executor.setExitValues(null);
            }
            
            executor.execute(cmdLine);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5(HttpServletRequest request) {
        // JSch (SSH) example with unterminated switch case
        String host = request.getParameter("host");
        int authType = Integer.parseInt(request.getParameter("authType"));
        
        try {
            JSch jsch = new JSch();
            com.jcraft.jsch.Session session = jsch.getSession("user", host, 22);
            
            switch (authType) {
                // ruleid: java-unterminated-switch-case
                case 1: // Password auth
                    session.setPassword("password");
                    // Missing break statement
                case 2: // Key auth
                    jsch.addIdentity("~/.ssh/id_rsa");
                    break;
                case 3: // Agent auth
                    jsch.setConfig("PreferredAuthentications", "publickey");
                    break;
            }
            
            session.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6(HttpServletRequest request) {
        // Apache Commons Configuration example with unterminated switch case
        String configType = request.getParameter("configType");
        
        try {
            org.apache.commons.configuration.Configuration config = null;
            
            switch (configType) {
                // ruleid: java-unterminated-switch-case
                case "properties":
                    config = new org.apache.commons.configuration.PropertiesConfiguration("config.properties");
                    // Missing break statement
                case "xml":
                    config = new org.apache.commons.configuration.XMLConfiguration("config.xml");
                    break;
                case "ini":
                    config = new org.apache.commons.configuration.INIConfiguration("config.ini");
                    break;
            }
            
            String value = config.getString("key");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7(HttpServletRequest request) {
        // AWS Lambda example with unterminated switch case
        String functionName = request.getParameter("function");
        String region = request.getParameter("region");
        int invocationType = Integer.parseInt(request.getParameter("type"));
        
        AWSLambda lambdaClient = AWSLambdaClientBuilder.standard()
                .withRegion(region)
                .build();
        
        switch (invocationType) {
            // ruleid: java-unterminated-switch-case
            case 1: // Synchronous
                System.out.println("Invoking synchronously");
                // Missing break statement
            case 2: // Asynchronous
                System.out.println("Invoking asynchronously");
                break;
            case 3: // DryRun
                System.out.println("Dry run only");
                break;
        }
    }

    public void bad_case_8(HttpServletRequest request) {
        // Google Cloud Functions example with unterminated switch case
        String logLevel = request.getParameter("logLevel");
        
        switch (logLevel) {
            // ruleid: java-unterminated-switch-case
            case "DEBUG":
                System.out.println("Setting debug level");
                // Missing break statement
            case "INFO":
                System.out.println("Setting info level");
                break;
            case "ERROR":
                System.out.println("Setting error level");
                break;
        }
    }

    public void bad_case_9(HttpServletRequest request) {
        // Apache Camel example with unterminated switch case
        String routeType = request.getParameter("routeType");
        
        try {
            CamelContext context = new DefaultCamelContext();
            
            switch (routeType) {
                // ruleid: java-unterminated-switch-case
                case "direct":
                    context.addRoutes(new RouteBuilder() {
                        @Override
                        public void configure() {
                            from("direct:start").to("mock:result");
                        }
                    });
                    // Missing break statement
                case "timer":
                    context.addRoutes(new RouteBuilder() {
                        @Override
                        public void configure() {
                            from("timer:foo").to("log:bar");
                        }
                    });
                    break;
            }
            
            context.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10(HttpServletRequest request) {
        // Hibernate example with unterminated switch case
        String entityType = request.getParameter("entityType");
        
        SessionFactory sessionFactory = new Configuration().configure().buildSessionFactory();
        org.hibernate.Session session = sessionFactory.openSession();
        
        switch (entityType) {
            // ruleid: java-unterminated-switch-case
            case "user":
                session.createQuery("from User").list();
                // Missing break statement
            case "product":
                session.createQuery("from Product").list();
                break;
            case "order":
                session.createQuery("from Order").list();
                break;
        }
    }

    public void bad_case_11(HttpServletRequest request) {
        // Apache Commons CLI example with unterminated switch case
        String[] args = request.getParameter("args").split(" ");
        int parserType = Integer.parseInt(request.getParameter("parserType"));
        
        Options options = new Options();
        options.addOption("h", "help", false, "Print help");
        
        try {
            CommandLineParser parser = null;
            
            switch (parserType) {
                // ruleid: java-unterminated-switch-case
                case 1:
                    parser = new DefaultParser();
                    // Missing break statement
                case 2:
                    parser = new org.apache.commons.cli.GnuParser();
                    break;
                case 3:
                    parser = new org.apache.commons.cli.PosixParser();
                    break;
            }
            
            org.apache.commons.cli.CommandLine cmd = parser.parse(options, args);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12(HttpServletRequest request) {
        // Azure Storage example with unterminated switch case
        String storageType = request.getParameter("storageType");
        
        switch (storageType) {
            // ruleid: java-unterminated-switch-case
            case "blob":
                System.out.println("Using blob storage");
                // Missing break statement
            case "queue":
                System.out.println("Using queue storage");
                break;
            case "table":
                System.out.println("Using table storage");
                break;
        }
    }

    public void bad_case_13(HttpServletRequest request) {
        // Kafka example with unterminated switch case
        String topicType = request.getParameter("topicType");
        
        switch (topicType) {
            // ruleid: java-unterminated-switch-case
            case "events":
                System.out.println("Processing events topic");
                // Missing break statement
            case "logs":
                System.out.println("Processing logs topic");
                break;
            case "metrics":
                System.out.println("Processing metrics topic");
                break;
        }
    }

    public void bad_case_14(HttpServletRequest request) {
        // Quartz Scheduler example with unterminated switch case
        String jobType = request.getParameter("jobType");
        
        try {
            Scheduler scheduler = StdSchedulerFactory.getDefaultScheduler();
            
            switch (jobType) {
                // ruleid: java-unterminated-switch-case
                case "email":
                    System.out.println("Scheduling email job");
                    // Missing break statement
                case "backup":
                    System.out.println("Scheduling backup job");
                    break;
                case "cleanup":
                    System.out.println("Scheduling cleanup job");
                    break;
            }
            
            scheduler.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15(HttpServletRequest request) {
        // Vert.x example with unterminated switch case
        String routeAction = request.getParameter("routeAction");
        
        Vertx vertx = Vertx.vertx();
        Router router = Router.router(vertx);
        
        switch (routeAction) {
            // ruleid: java-unterminated-switch-case
            case "get":
                router.get("/api").handler(this::handleGet);
                // Missing break statement
            case "post":
                router.post("/api").handler(this::handlePost);
                break;
            case "delete":
                router.delete("/api").handler(this::handleDelete);
                break;
        }
    }
    
    private void handleGet(RoutingContext context) {}
    private void handlePost(RoutingContext context) {}
    private void handleDelete(RoutingContext context) {}
}
// {/fact}

// True Negative Examples (Safe/Secure Code)
class SecureExamples {
// {fact rule=code-injection@v1.0 defects=0}
    public void good_case_1(HttpServletRequest request) {
        // Spring MVC example with properly terminated switch case
        String action = request.getParameter("action");
        int actionCode = Integer.parseInt(action);
        
        switch (actionCode) {
            // ok: java-unterminated-switch-case
            case 1:
                System.out.println("Processing action 1");
                break;
            case 2:
                System.out.println("Processing action 2");
                break;
            case 3:
                System.out.println("Processing action 3");
                break;
        }
    }

    public void good_case_2(javax.ws.rs.core.Request request) {
        // JAX-RS example with properly terminated switch case
        String operation = request.getProperty("operation").toString();
        
        switch (operation) {
            // ok: java-unterminated-switch-case
            case "create":
                System.out.println("Creating resource");
                break;
            case "update":
                System.out.println("Updating resource");
                break;
            case "delete":
                System.out.println("Deleting resource");
                break;
        }
    }

    public void good_case_3() {
        // OkHttp client example with properly terminated switch case
        OkHttpClient client = new OkHttpClient();
        Request request = new Request.Builder()
            .url("https://api.example.com/status")
            .build();
            
        try {
            okhttp3.Response response = client.newCall(request).execute();
            int statusCode = response.code();
            
            switch (statusCode) {
                // ok: java-unterminated-switch-case
                case 200:
                    System.out.println("Success");
                    break;
                case 404:
                    System.out.println("Not found");
                    break;
                case 500:
                    System.out.println("Server error");
                    break;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_4(HttpServletRequest request) {
        // Apache Commons Exec example with properly terminated switch case
        String command = request.getParameter("cmd");
        int mode = Integer.parseInt(request.getParameter("mode"));
        
        try {
            CommandLine cmdLine = CommandLine.parse(command);
            DefaultExecutor executor = new DefaultExecutor();
            
            switch (mode) {
                // ok: java-unterminated-switch-case
                case 1:
                    executor.setExitValue(0);
                    break;
                case 2:
                    executor.setExitValue(1);
                    break;
                default:
                    executor.setExitValues(null);
                    break;
            }
            
            executor.execute(cmdLine);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_5(HttpServletRequest request) {
        // JSch (SSH) example with properly terminated switch case
        String host = request.getParameter("host");
        int authType = Integer.parseInt(request.getParameter("authType"));
        
        try {
            JSch jsch = new JSch();
            com.jcraft.jsch.Session session = jsch.getSession("user", host, 22);
            
            switch (authType) {
                // ok: java-unterminated-switch-case
                case 1: // Password auth
                    session.setPassword("password");
                    break;
                case 2: // Key auth
                    jsch.addIdentity("~/.ssh/id_rsa");
                    break;
                case 3: // Agent auth
                    jsch.setConfig("PreferredAuthentications", "publickey");
                    break;
            }
            
            session.connect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_6(HttpServletRequest request) {
        // Apache Commons Configuration example with properly terminated switch case
        String configType = request.getParameter("configType");
        
        try {
            org.apache.commons.configuration.Configuration config = null;
            
            switch (configType) {
                // ok: java-unterminated-switch-case
                case "properties":
                    config = new org.apache.commons.configuration.PropertiesConfiguration("config.properties");
                    break;
                case "xml":
                    config = new org.apache.commons.configuration.XMLConfiguration("config.xml");
                    break;
                case "ini":
                    config = new org.apache.commons.configuration.INIConfiguration("config.ini");
                    break;
            }
            
            String value = config.getString("key");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_7(HttpServletRequest request) {
        // AWS Lambda example with properly terminated switch case
        String functionName = request.getParameter("function");
        String region = request.getParameter("region");
        int invocationType = Integer.parseInt(request.getParameter("type"));
        
        AWSLambda lambdaClient = AWSLambdaClientBuilder.standard()
                .withRegion(region)
                .build();
        
        switch (invocationType) {
            // ok: java-unterminated-switch-case
            case 1: // Synchronous
                System.out.println("Invoking synchronously");
                break;
            case 2: // Asynchronous
                System.out.println("Invoking asynchronously");
                break;
            case 3: // DryRun
                System.out.println("Dry run only");
                break;
        }
    }

    public void good_case_8(HttpServletRequest request) {
        // Google Cloud Functions example with properly terminated switch case
        String logLevel = request.getParameter("logLevel");
        
        switch (logLevel) {
            // ok: java-unterminated-switch-case
            case "DEBUG":
                System.out.println("Setting debug level");
                break;
            case "INFO":
                System.out.println("Setting info level");
                break;
            case "ERROR":
                System.out.println("Setting error level");
                break;
        }
    }

    public void good_case_9(HttpServletRequest request) {
        // Apache Camel example with properly terminated switch case
        String routeType = request.getParameter("routeType");
        
        try {
            CamelContext context = new DefaultCamelContext();
            
            switch (routeType) {
                // ok: java-unterminated-switch-case
                case "direct":
                    context.addRoutes(new RouteBuilder() {
                        @Override
                        public void configure() {
                            from("direct:start").to("mock:result");
                        }
                    });
                    break;
                case "timer":
                    context.addRoutes(new RouteBuilder() {
                        @Override
                        public void configure() {
                            from("timer:foo").to("log:bar");
                        }
                    });
                    break;
            }
            
            context.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_10(HttpServletRequest request) {
        // Hibernate example with properly terminated switch case
        String entityType = request.getParameter("entityType");
        
        SessionFactory sessionFactory = new Configuration().configure().buildSessionFactory();
        org.hibernate.Session session = sessionFactory.openSession();
        
        switch (entityType) {
            // ok: java-unterminated-switch-case
            case "user":
                session.createQuery("from User").list();
                break;
            case "product":
                session.createQuery("from Product").list();
                break;
            case "order":
                session.createQuery("from Order").list();
                break;
        }
    }

    public void good_case_11(HttpServletRequest request) {
        // Apache Commons CLI example with properly terminated switch case
        String[] args = request.getParameter("args").split(" ");
        int parserType = Integer.parseInt(request.getParameter("parserType"));
        
        Options options = new Options();
        options.addOption("h", "help", false, "Print help");
        
        try {
            CommandLineParser parser = null;
            
            switch (parserType) {
                // ok: java-unterminated-switch-case
                case 1:
                    parser = new DefaultParser();
                    break;
                case 2:
                    parser = new org.apache.commons.cli.GnuParser();
                    break;
                case 3:
                    parser = new org.apache.commons.cli.PosixParser();
                    break;
            }
            
            org.apache.commons.cli.CommandLine cmd = parser.parse(options, args);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_12(HttpServletRequest request) {
        // Azure Storage example with properly terminated switch case
        String storageType = request.getParameter("storageType");
        
        switch (storageType) {
            // ok: java-unterminated-switch-case
            case "blob":
                System.out.println("Using blob storage");
                break;
            case "queue":
                System.out.println("Using queue storage");
                break;
            case "table":
                System.out.println("Using table storage");
                break;
        }
    }

    public void good_case_13(HttpServletRequest request) {
        // Kafka example with properly terminated switch case
        String topicType = request.getParameter("topicType");
        
        switch (topicType) {
            // ok: java-unterminated-switch-case
            case "events":
                System.out.println("Processing events topic");
                break;
            case "logs":
                System.out.println("Processing logs topic");
                break;
            case "metrics":
                System.out.println("Processing metrics topic");
                break;
        }
    }

    public void good_case_14(HttpServletRequest request) {
        // Quartz Scheduler example with properly terminated switch case
        String jobType = request.getParameter("jobType");
        
        try {
            Scheduler scheduler = StdSchedulerFactory.getDefaultScheduler();
            
            switch (jobType) {
                // ok: java-unterminated-switch-case
                case "email":
                    System.out.println("Scheduling email job");
                    break;
                case "backup":
                    System.out.println("Scheduling backup job");
                    break;
                case "cleanup":
                    System.out.println("Scheduling cleanup job");
                    break;
            }
            
            scheduler.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_15(HttpServletRequest request) {
        // Vert.x example with properly terminated switch case
        String routeAction = request.getParameter("routeAction");
        
        Vertx vertx = Vertx.vertx();
        Router router = Router.router(vertx);
        
        switch (routeAction) {
            // ok: java-unterminated-switch-case
            case "get":
                router.get("/api").handler(this::handleGet);
                break;
            case "post":
                router.post("/api").handler(this::handlePost);
                break;
            case "delete":
                router.delete("/api").handler(this::handleDelete);
                break;
        }
    }
    
    private void handleGet(RoutingContext context) {}
    private void handlePost(RoutingContext context) {}
    private void handleDelete(RoutingContext context) {}
}
// {/fact}