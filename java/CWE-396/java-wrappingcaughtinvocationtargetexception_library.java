import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.io.IOException;
import java.sql.SQLException;
import java.net.HttpURLConnection;
import java.net.URL;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.lambda.model.InvokeRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import retrofit2.Retrofit;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import com.google.cloud.functions.HttpFunction;
import com.google.cloud.functions.HttpRequest;
import com.google.cloud.functions.HttpResponse;
import org.apache.commons.io.FileUtils;
import com.azure.storage.blob.BlobClient;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.quartz.Job;
import javax.jms.Connection;
import javax.jms.ConnectionFactory;
import javax.jms.JMSException;
import javax.jms.MessageProducer;
import javax.jms.Session;
import javax.jms.TextMessage;
import javax.jms.Topic;
import java.util.Properties;
import java.io.File;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Callable;

// Security Issue: Wrapping caught InvocationTargetException into a new unchecked exception instead of type-casting and throwing the original cause

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(HttpServletRequest request) {
    String className = request.getParameter("class");
    String methodName = request.getParameter("method");
    
    try {
        Class<?> clazz = Class.forName(className);
        Method method = clazz.getDeclaredMethod(methodName);
        method.invoke(clazz.newInstance());
    } catch (InvocationTargetException e) {
        // ruleid: java-wrappingcaughtinvocationtargetexception
        throw new RuntimeException("Error invoking method", e);
    } catch (Exception e) {
        throw new RuntimeException("Other error", e);
    }
}

public void bad_case_2() {
    OkHttpClient client = new OkHttpClient();
    Request request = new Request.Builder()
        .url("https://api.example.com/data")
        .build();
        
    try {
        Class<?> clazz = Class.forName("DynamicHandler");
        Method method = clazz.getDeclaredMethod("processResponse", okhttp3.Response.class);
        method.invoke(clazz.newInstance(), client.newCall(request).execute());
    } catch (InvocationTargetException e) {
        // ruleid: java-wrappingcaughtinvocationtargetexception
        throw new IllegalStateException("Failed to process API response", e);
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

public void bad_case_3(HttpServletRequest request) {
    String functionName = request.getParameter("function");
    AWSLambda lambdaClient = AWSLambdaClientBuilder.defaultClient();
    InvokeRequest invokeRequest = new InvokeRequest()
        .withFunctionName(functionName);
    
    try {
        Class<?> handler = Class.forName("LambdaHandler");
        Method method = handler.getDeclaredMethod("handleRequest", InvokeRequest.class);
        method.invoke(handler.newInstance(), invokeRequest);
    } catch (InvocationTargetException e) {
        // ruleid: java-wrappingcaughtinvocationtargetexception
        throw new RuntimeException("Lambda invocation failed", e);
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

public void bad_case_4(HttpServletRequest request) {
    String command = request.getParameter("command");
    CommandLine cmdLine = CommandLine.parse(command);
    DefaultExecutor executor = new DefaultExecutor();
    
    try {
        Class<?> execHelper = Class.forName("CommandExecutionHelper");
        Method method = execHelper.getDeclaredMethod("executeCommand", CommandLine.class, DefaultExecutor.class);
        method.invoke(execHelper.newInstance(), cmdLine, executor);
    } catch (InvocationTargetException e) {
        // ruleid: java-wrappingcaughtinvocationtargetexception
        throw new IllegalArgumentException("Command execution failed", e);
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

public void bad_case_5(HttpServletRequest request, SessionFactory sessionFactory) {
    String query = request.getParameter("query");
    
    try {
        Class<?> dbHelper = Class.forName("DatabaseHelper");
        Method method = dbHelper.getDeclaredMethod("executeHQL", SessionFactory.class, String.class);
        method.invoke(dbHelper.newInstance(), sessionFactory, query);
    } catch (InvocationTargetException e) {
        // ruleid: java-wrappingcaughtinvocationtargetexception
        throw new RuntimeException("Database query failed", e);
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

public void bad_case_6(HttpServletRequest request) {
    String args = request.getParameter("args");
    Options options = new Options();
    options.addOption("f", "file", true, "file path");
    CommandLineParser parser = new DefaultParser();
    
    try {
        Class<?> argsProcessor = Class.forName("ArgumentProcessor");
        Method method = argsProcessor.getDeclaredMethod("parseAndProcess", CommandLineParser.class, Options.class, String[].class);
        method.invoke(argsProcessor.newInstance(), parser, options, args.split(" "));
    } catch (InvocationTargetException e) {
        // ruleid: java-wrappingcaughtinvocationtargetexception
        throw new IllegalStateException("Failed to process command line arguments", e);
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

public void bad_case_7(com.google.cloud.functions.HttpRequest request) {
    String data = request.getReader().lines().reduce("", String::concat);
    
    try {
        Class<?> cloudFunctionHandler = Class.forName("CloudFunctionHandler");
        Method method = cloudFunctionHandler.getDeclaredMethod("processRequest", String.class);
        method.invoke(cloudFunctionHandler.newInstance(), data);
    } catch (InvocationTargetException e) {
        // ruleid: java-wrappingcaughtinvocationtargetexception
        throw new RuntimeException("Cloud function processing failed", e);
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

public void bad_case_8(HttpServletRequest request) {
    String filePath = request.getParameter("file");
    File file = new File(filePath);
    
    try {
        Class<?> fileProcessor = Class.forName("FileProcessor");
        Method method = fileProcessor.getDeclaredMethod("processFile", File.class);
        method.invoke(fileProcessor.newInstance(), file);
    } catch (InvocationTargetException e) {
        // ruleid: java-wrappingcaughtinvocationtargetexception
        throw new IllegalArgumentException("File processing failed", e);
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

public void bad_case_9(HttpServletRequest request) {
    String blobName = request.getParameter("blob");
    BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
        .connectionString("connection-string")
        .buildClient();
    BlobClient blobClient = blobServiceClient.getBlobContainerClient("container").getBlobClient(blobName);
    
    try {
        Class<?> azureHandler = Class.forName("AzureBlobHandler");
        Method method = azureHandler.getDeclaredMethod("downloadAndProcess", BlobClient.class);
        method.invoke(azureHandler.newInstance(), blobClient);
    } catch (InvocationTargetException e) {
        // ruleid: java-wrappingcaughtinvocationtargetexception
        throw new RuntimeException("Azure blob processing failed", e);
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

public void bad_case_10(HttpServletRequest request) {
    String topic = request.getParameter("topic");
    String message = request.getParameter("message");
    Properties props = new Properties();
    props.put("bootstrap.servers", "localhost:9092");
    KafkaProducer<String, String> producer = new KafkaProducer<>(props);
    
    try {
        Class<?> kafkaHelper = Class.forName("KafkaHelper");
        Method method = kafkaHelper.getDeclaredMethod("sendMessage", KafkaProducer.class, String.class, String.class);
        method.invoke(kafkaHelper.newInstance(), producer, topic, message);
    } catch (InvocationTargetException e) {
        // ruleid: java-wrappingcaughtinvocationtargetexception
        throw new RuntimeException("Kafka message sending failed", e);
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

public void bad_case_11(HttpServletRequest request) implements Job {
    String jobData = request.getParameter("jobData");
    
    try {
        Class<?> quartzHelper = Class.forName("QuartzJobHelper");
        Method method = quartzHelper.getDeclaredMethod("executeJob", String.class);
        method.invoke(quartzHelper.newInstance(), jobData);
    } catch (InvocationTargetException e) {
        // ruleid: java-wrappingcaughtinvocationtargetexception
        throw new JobExecutionException("Job execution failed", e);
    } catch (Exception e) {
        throw new JobExecutionException(e);
    }
}

public void bad_case_12(HttpServletRequest request, ConnectionFactory connectionFactory) {
    String message = request.getParameter("message");
    String topicName = request.getParameter("topic");
    
    try {
        Class<?> jmsHelper = Class.forName("JmsHelper");
        Method method = jmsHelper.getDeclaredMethod("sendToTopic", ConnectionFactory.class, String.class, String.class);
        method.invoke(jmsHelper.newInstance(), connectionFactory, topicName, message);
    } catch (InvocationTargetException e) {
        // ruleid: java-wrappingcaughtinvocationtargetexception
        throw new RuntimeException("JMS message sending failed", e);
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

public void bad_case_13(HttpServletRequest request) {
    String url = request.getParameter("url");
    
    try {
        Class<?> retrofitHelper = Class.forName("RetrofitApiHelper");
        Method method = retrofitHelper.getDeclaredMethod("makeApiCall", String.class);
        method.invoke(retrofitHelper.newInstance(), url);
    } catch (InvocationTargetException e) {
        // ruleid: java-wrappingcaughtinvocationtargetexception
        throw new IllegalStateException("API call failed", e);
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

public void bad_case_14(HttpServletRequest request) {
    String jsonData = request.getParameter("data");
    ObjectMapper mapper = new ObjectMapper();
    
    try {
        Class<?> jsonHelper = Class.forName("JsonProcessor");
        Method method = jsonHelper.getDeclaredMethod("processJson", ObjectMapper.class, String.class);
        method.invoke(jsonHelper.newInstance(), mapper, jsonData);
    } catch (InvocationTargetException e) {
        // ruleid: java-wrappingcaughtinvocationtargetexception
        throw new RuntimeException("JSON processing failed", e);
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

public void bad_case_15(HttpServletRequest request) {
    String task = request.getParameter("task");
    ExecutorService executor = Executors.newSingleThreadExecutor();
    
    try {
        Class<?> taskProcessor = Class.forName("TaskProcessor");
        Method method = taskProcessor.getDeclaredMethod("submitTask", ExecutorService.class, String.class);
        method.invoke(taskProcessor.newInstance(), executor, task);
    } catch (InvocationTargetException e) {
        // ruleid: java-wrappingcaughtinvocationtargetexception
        throw new IllegalStateException("Task submission failed", e);
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(HttpServletRequest request) {
    String className = request.getParameter("class");
    String methodName = request.getParameter("method");
    
    try {
        Class<?> clazz = Class.forName(className);
        Method method = clazz.getDeclaredMethod(methodName);
        method.invoke(clazz.newInstance());
    } catch (InvocationTargetException e) {
        // ok: java-wrappingcaughtinvocationtargetexception
        throw (RuntimeException) e.getCause();
    } catch (Exception e) {
        throw new RuntimeException("Other error", e);
    }
}

public void good_case_2() {
    OkHttpClient client = new OkHttpClient();
    Request request = new Request.Builder()
        .url("https://api.example.com/data")
        .build();
        
    try {
        Class<?> clazz = Class.forName("DynamicHandler");
        Method method = clazz.getDeclaredMethod("processResponse", okhttp3.Response.class);
        method.invoke(clazz.newInstance(), client.newCall(request).execute());
    } catch (InvocationTargetException e) {
        // ok: java-wrappingcaughtinvocationtargetexception
        Throwable cause = e.getCause();
        if (cause instanceof RuntimeException) {
            throw (RuntimeException) cause;
        } else {
            throw new RuntimeException(cause);
        }
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

public void good_case_3(HttpServletRequest request) {
    String functionName = request.getParameter("function");
    AWSLambda lambdaClient = AWSLambdaClientBuilder.defaultClient();
    InvokeRequest invokeRequest = new InvokeRequest()
        .withFunctionName(functionName);
    
    try {
        Class<?> handler = Class.forName("LambdaHandler");
        Method method = handler.getDeclaredMethod("handleRequest", InvokeRequest.class);
        method.invoke(handler.newInstance(), invokeRequest);
    } catch (InvocationTargetException e) {
        // ok: java-wrappingcaughtinvocationtargetexception
        Throwable cause = e.getCause();
        if (cause instanceof RuntimeException) {
            throw (RuntimeException) cause;
        } else if (cause instanceof Error) {
            throw (Error) cause;
        } else {
            throw new RuntimeException(cause);
        }
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

public void good_case_4(HttpServletRequest request) {
    String command = request.getParameter("command");
    CommandLine cmdLine = CommandLine.parse(command);
    DefaultExecutor executor = new DefaultExecutor();
    
    try {
        Class<?> execHelper = Class.forName("CommandExecutionHelper");
        Method method = execHelper.getDeclaredMethod("executeCommand", CommandLine.class, DefaultExecutor.class);
        method.invoke(execHelper.newInstance(), cmdLine, executor);
    } catch (InvocationTargetException e) {
        // ok: java-wrappingcaughtinvocationtargetexception
        Throwable cause = e.getTargetException();
        if (cause instanceof RuntimeException) {
            throw (RuntimeException) cause;
        } else if (cause instanceof IOException) {
            throw new UncheckedIOException((IOException) cause);
        } else {
            throw new RuntimeException(cause);
        }
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

public void good_case_5(HttpServletRequest request, SessionFactory sessionFactory) {
    String query = request.getParameter("query");
    
    try {
        Class<?> dbHelper = Class.forName("DatabaseHelper");
        Method method = dbHelper.getDeclaredMethod("executeHQL", SessionFactory.class, String.class);
        method.invoke(dbHelper.newInstance(), sessionFactory, query);
    } catch (InvocationTargetException e) {
        // ok: java-wrappingcaughtinvocationtargetexception
        if (e.getCause() instanceof SQLException) {
            throw new RuntimeException(e.getCause());
        } else if (e.getCause() instanceof RuntimeException) {
            throw (RuntimeException) e.getCause();
        } else {
            throw new RuntimeException(e.getCause());
        }
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

public void good_case_6(HttpServletRequest request) {
    String args = request.getParameter("args");
    Options options = new Options();
    options.addOption("f", "file", true, "file path");
    CommandLineParser parser = new DefaultParser();
    
    try {
        Class<?> argsProcessor = Class.forName("ArgumentProcessor");
        Method method = argsProcessor.getDeclaredMethod("parseAndProcess", CommandLineParser.class, Options.class, String[].class);
        method.invoke(argsProcessor.newInstance(), parser, options, args.split(" "));
    } catch (InvocationTargetException e) {
        // ok: java-wrappingcaughtinvocationtargetexception
        Throwable cause = e.getCause();
        if (cause instanceof ParseException) {
            throw new IllegalArgumentException(cause.getMessage(), cause);
        } else if (cause instanceof RuntimeException) {
            throw (RuntimeException) cause;
        } else {
            throw new RuntimeException(cause);
        }
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

public void good_case_7(com.google.cloud.functions.HttpRequest request) {
    String data = request.getReader().lines().reduce("", String::concat);
    
    try {
        Class<?> cloudFunctionHandler = Class.forName("CloudFunctionHandler");
        Method method = cloudFunctionHandler.getDeclaredMethod("processRequest", String.class);
        method.invoke(cloudFunctionHandler.newInstance(), data);
    } catch (InvocationTargetException e) {
        // ok: java-wrappingcaughtinvocationtargetexception
        Throwable cause = e.getTargetException();
        if (cause instanceof RuntimeException) {
            throw (RuntimeException) cause;
        } else if (cause instanceof IOException) {
            throw new UncheckedIOException((IOException) cause);
        } else {
            throw new RuntimeException(cause);
        }
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

public void good_case_8(HttpServletRequest request) {
    String filePath = request.getParameter("file");
    File file = new File(filePath);
    
    try {
        Class<?> fileProcessor = Class.forName("FileProcessor");
        Method method = fileProcessor.getDeclaredMethod("processFile", File.class);
        method.invoke(fileProcessor.newInstance(), file);
    } catch (InvocationTargetException e) {
        // ok: java-wrappingcaughtinvocationtargetexception
        Throwable cause = e.getCause();
        if (cause instanceof IOException) {
            throw new UncheckedIOException("File processing failed", (IOException) cause);
        } else if (cause instanceof RuntimeException) {
            throw (RuntimeException) cause;
        } else {
            throw new RuntimeException(cause);
        }
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

public void good_case_9(HttpServletRequest request) {
    String blobName = request.getParameter("blob");
    BlobServiceClient blobServiceClient = new BlobServiceClientBuilder()
        .connectionString("connection-string")
        .buildClient();
    BlobClient blobClient = blobServiceClient.getBlobContainerClient("container").getBlobClient(blobName);
    
    try {
        Class<?> azureHandler = Class.forName("AzureBlobHandler");
        Method method = azureHandler.getDeclaredMethod("downloadAndProcess", BlobClient.class);
        method.invoke(azureHandler.newInstance(), blobClient);
    } catch (InvocationTargetException e) {
        // ok: java-wrappingcaughtinvocationtargetexception
        if (e.getCause() instanceof RuntimeException) {
            throw (RuntimeException) e.getCause();
        } else if (e.getCause() instanceof IOException) {
            throw new UncheckedIOException((IOException) e.getCause());
        } else {
            throw new RuntimeException(e.getCause());
        }
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

public void good_case_10(HttpServletRequest request) {
    String topic = request.getParameter("topic");
    String message = request.getParameter("message");
    Properties props = new Properties();
    props.put("bootstrap.servers", "localhost:9092");
    KafkaProducer<String, String> producer = new KafkaProducer<>(props);
    
    try {
        Class<?> kafkaHelper = Class.forName("KafkaHelper");
        Method method = kafkaHelper.getDeclaredMethod("sendMessage", KafkaProducer.class, String.class, String.class);
        method.invoke(kafkaHelper.newInstance(), producer, topic, message);
    } catch (InvocationTargetException e) {
        // ok: java-wrappingcaughtinvocationtargetexception
        Throwable cause = e.getTargetException();
        if (cause instanceof RuntimeException) {
            throw (RuntimeException) cause;
        } else {
            throw new RuntimeException(cause);
        }
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

public void good_case_11(HttpServletRequest request) implements Job {
    String jobData = request.getParameter("jobData");
    
    try {
        Class<?> quartzHelper = Class.forName("QuartzJobHelper");
        Method method = quartzHelper.getDeclaredMethod("executeJob", String.class);
        method.invoke(quartzHelper.newInstance(), jobData);
    } catch (InvocationTargetException e) {
        // ok: java-wrappingcaughtinvocationtargetexception
        Throwable cause = e.getCause();
        if (cause instanceof JobExecutionException) {
            throw (JobExecutionException) cause;
        } else if (cause instanceof RuntimeException) {
            throw (RuntimeException) cause;
        } else {
            throw new JobExecutionException(cause);
        }
    } catch (Exception e) {
        throw new JobExecutionException(e);
    }
}

public void good_case_12(HttpServletRequest request, ConnectionFactory connectionFactory) {
    String message = request.getParameter("message");
    String topicName = request.getParameter("topic");
    
    try {
        Class<?> jmsHelper = Class.forName("JmsHelper");
        Method method = jmsHelper.getDeclaredMethod("sendToTopic", ConnectionFactory.class, String.class, String.class);
        method.invoke(jmsHelper.newInstance(), connectionFactory, topicName, message);
    } catch (InvocationTargetException e) {
        // ok: java-wrappingcaughtinvocationtargetexception
        Throwable cause = e.getCause();
        if (cause instanceof JMSException) {
            throw new RuntimeException(cause);
        } else if (cause instanceof RuntimeException) {
            throw (RuntimeException) cause;
        } else {
            throw new RuntimeException(cause);
        }
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

public void good_case_13(HttpServletRequest request) {
    String url = request.getParameter("url");
    
    try {
        Class<?> retrofitHelper = Class.forName("RetrofitApiHelper");
        Method method = retrofitHelper.getDeclaredMethod("makeApiCall", String.class);
        method.invoke(retrofitHelper.newInstance(), url);
    } catch (InvocationTargetException e) {
        // ok: java-wrappingcaughtinvocationtargetexception
        Throwable cause = e.getTargetException();
        if (cause instanceof IOException) {
            throw new UncheckedIOException((IOException) cause);
        } else if (cause instanceof RuntimeException) {
            throw (RuntimeException) cause;
        } else {
            throw new RuntimeException(cause);
        }
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

public void good_case_14(HttpServletRequest request) {
    String jsonData = request.getParameter("data");
    ObjectMapper mapper = new ObjectMapper();
    
    try {
        Class<?> jsonHelper = Class.forName("JsonProcessor");
        Method method = jsonHelper.getDeclaredMethod("processJson", ObjectMapper.class, String.class);
        method.invoke(jsonHelper.newInstance(), mapper, jsonData);
    } catch (InvocationTargetException e) {
        // ok: java-wrappingcaughtinvocationtargetexception
        Throwable cause = e.getCause();
        if (cause instanceof IOException) {
            throw new UncheckedIOException((IOException) cause);
        } else if (cause instanceof RuntimeException) {
            throw (RuntimeException) cause;
        } else {
            throw new RuntimeException(cause);
        }
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}

public void good_case_15(HttpServletRequest request) {
    String task = request.getParameter("task");
    ExecutorService executor = Executors.newSingleThreadExecutor();
    
    try {
        Class<?> taskProcessor = Class.forName("TaskProcessor");
        Method method = taskProcessor.getDeclaredMethod("submitTask", ExecutorService.class, String.class);
        method.invoke(taskProcessor.newInstance(), executor, task);
    } catch (InvocationTargetException e) {
        // ok: java-wrappingcaughtinvocationtargetexception
        Throwable cause = e.getTargetException();
        if (cause instanceof RuntimeException) {
            throw (RuntimeException) cause;
        } else if (cause instanceof Error) {
            throw (Error) cause;
        } else {
            throw new RuntimeException(cause);
        }
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}