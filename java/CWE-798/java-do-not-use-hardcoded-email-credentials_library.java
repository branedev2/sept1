import java.util.Properties;
import javax.mail.*;
import javax.mail.internet.*;
import java.io.FileInputStream;
import java.io.IOException;
import org.apache.commons.mail.Email;
import org.apache.commons.mail.SimpleEmail;
import org.apache.commons.mail.EmailException;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.SimpleMailMessage;
import com.sendgrid.SendGrid;
import com.sendgrid.Request;
import com.sendgrid.Response;
import com.sendgrid.Method;
import com.sendgrid.helpers.mail.Mail;
import com.sendgrid.helpers.mail.objects.Content;
import com.amazonaws.services.simpleemail.AmazonSimpleEmailService;
import com.amazonaws.services.simpleemail.AmazonSimpleEmailServiceClientBuilder;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.regions.Regions;
import com.mailjet.client.MailjetClient;
import com.mailjet.client.ClientOptions;
import com.mailjet.client.transactional.SendContact;
import com.mailjet.client.transactional.SendEmailsRequest;
import com.mailjet.client.transactional.TransactionalEmail;
import com.mailgun.api.v3.MailgunMessagesApi;
import com.mailgun.client.MailgunClient;
import com.sparkpost.Client;
import com.sparkpost.exception.SparkPostException;
import org.simplejavamail.email.EmailBuilder;
import org.simplejavamail.mailer.MailerBuilder;
import com.postmarkapp.postmark.Postmark;
import com.postmarkapp.postmark.client.ApiClient;
import com.postmarkapp.postmark.client.data.model.message.Message;
import com.sendinblue.api.ApiClient;
import com.sendinblue.api.ApiException;
import com.sendinblue.api.Configuration;
import com.sendinblue.api.auth.ApiKeyAuth;
import com.sendinblue.api.model.CreateSmtpEmail;
import com.sendinblue.api.model.SendSmtpEmail;
import com.sendinblue.api.model.SendSmtpEmailSender;
import com.sendinblue.api.model.SendSmtpEmailTo;
import io.pepipost.api.client.Configuration;
import io.pepipost.api.client.auth.ApiKeyAuth;
import io.pepipost.api.client.model.*;
import io.pepipost.api.client.api.SendApi;
import java.util.Scanner;
import java.util.prefs.Preferences;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.auth.Credentials;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.entity.StringEntity;
import org.apache.http.HttpResponse;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.GmailScopes;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.List;
import java.io.Console;
import java.io.File;
import java.io.FileReader;
import java.io.BufferedReader;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.jasypt.util.text.BasicTextEncryptor;
import org.jasypt.util.text.TextEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.properties.EncryptableProperties;

// Security Issue: Hardcoded email credentials pose a significant security risk as they can be easily discovered and exploited by attackers

// True Positive Examples (Vulnerable/Insecure Code)
public class EmailCredentialsExamples {

// {fact rule=hardcoded-credentials@v1.0 defects=1}
    public static void bad_case_1() {
        // JavaMail API with hardcoded credentials
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");
        
        // ruleid: java-do-not-use-hardcoded-email-credentials
        Session session = Session.getInstance(props, new Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication("admin@example.com", "P@ssw0rd123");
            }
        });
        
        try {
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress("from@example.com"));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse("to@example.com"));
            message.setSubject("Test Subject");
            message.setText("Test Message");
            Transport.send(message);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }
    
    public static void bad_case_2() {
        // Apache Commons Email with hardcoded credentials
        try {
            Email email = new SimpleEmail();
            email.setHostName("smtp.googlemail.com");
            email.setSmtpPort(465);
            email.setSSLOnConnect(true);
            // ruleid: java-do-not-use-hardcoded-email-credentials
            email.setAuthentication("user@company.com", "secretPassword!");
            email.setFrom("user@company.com");
            email.setSubject("Test message");
            email.setMsg("This is a test message");
            email.addTo("foo@bar.com");
            email.send();
        } catch (EmailException e) {
            e.printStackTrace();
        }
    }
    
    public static void bad_case_3() {
        // Spring JavaMailSender with hardcoded credentials
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost("smtp.gmail.com");
        mailSender.setPort(587);
        
        // ruleid: java-do-not-use-hardcoded-email-credentials
        mailSender.setUsername("spring.user@gmail.com");
        mailSender.setPassword("spring_secure_pwd123");
        
        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom("spring.user@gmail.com");
        message.setTo("recipient@example.com");
        message.setSubject("Spring Mail Test");
        message.setText("Hello from Spring Mail");
        
        mailSender.send(message);
    }
    
    public static void bad_case_4() {
        // SendGrid API with hardcoded API key
        try {
            // ruleid: java-do-not-use-hardcoded-email-credentials
            SendGrid sendGrid = new SendGrid("SG.REDAC_REDACTED_TWILIO_ID_SENDGRID_KEY");
            
            Mail mail = new Mail(
                new com.sendgrid.helpers.mail.objects.Email("from@example.com"),
                "Subject",
                new com.sendgrid.helpers.mail.objects.Email("to@example.com"),
                new Content("text/plain", "Hello SendGrid!")
            );
            
            Request request = new Request();
            request.setMethod(Method.POST);
            request.setEndpoint("mail/send");
            request.setBody(mail.build());
            
            Response response = sendGrid.api(request);
            System.out.println(response.getStatusCode());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void bad_case_5() {
        // AWS SES with hardcoded credentials
        // ruleid: java-do-not-use-hardcoded-email-credentials
        BasicAWSCredentials awsCreds = new BasicAWSCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        
        AmazonSimpleEmailService client = AmazonSimpleEmailServiceClientBuilder.standard()
            .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
            .withRegion(Regions.US_WEST_2)
            .build();
            
        // Rest of the email sending code would go here
    }
    
    public static void bad_case_6() {
        // Mailjet with hardcoded credentials
        try {
            // ruleid: java-do-not-use-hardcoded-email-credentials
            MailjetClient client = new MailjetClient("api_key_123456789", "api_secret_abcdefghij", new ClientOptions("v3.1"));
            
            TransactionalEmail message = TransactionalEmail
                .builder()
                .to(new SendContact("passenger@mailjet.com"))
                .from(new SendContact("pilot@mailjet.com"))
                .subject("Your email flight plan!")
                .textPart("Dear passenger, welcome to Mailjet!")
                .build();

            SendEmailsRequest request = SendEmailsRequest
                .builder()
                .message(message)
                .build();
                
            // Send the email (commented out for example purposes)
            // request.sendWith(client);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void bad_case_7() {
        // Mailgun with hardcoded API key
        // ruleid: java-do-not-use-hardcoded-email-credentials
        MailgunMessagesApi mailgunMessagesApi = MailgunClient.config("api-key-3ax6xnjp29jd6fds4gc373sgvjxteol0")
            .createApi(MailgunMessagesApi.class);
            
        // Rest of the email sending code would go here
    }
    
    public static void bad_case_8() {
        // SparkPost with hardcoded API key
        try {
            // ruleid: java-do-not-use-hardcoded-email-credentials
            Client client = new Client("sparkpost_api_key_12345abcde");
            
            // Rest of the email sending code would go here
        } catch (SparkPostException e) {
            e.printStackTrace();
        }
    }
    
    public static void bad_case_9() {
        // SimpleJavaMail with hardcoded credentials
        org.simplejavamail.api.mailer.Mailer mailer = MailerBuilder
            .withSMTPServer("smtp.host.com", 587)
            // ruleid: java-do-not-use-hardcoded-email-credentials
            .withSMTPServerUsername("simple_user@example.com")
            .withSMTPServerPassword("simple_password_123")
            .buildMailer();
            
        org.simplejavamail.api.email.Email email = EmailBuilder.startingBlank()
            .from("From", "from@example.com")
            .to("To", "to@example.com")
            .withSubject("SimpleJavaMail test")
            .withPlainText("This is a test email")
            .buildEmail();
            
        // mailer.sendMail(email);
    }
    
    public static void bad_case_10() {
        // Postmark with hardcoded server token
        // ruleid: java-do-not-use-hardcoded-email-credentials
        ApiClient client = Postmark.getApiClient("postmark_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY");
        
        Message message = new Message();
        message.setFrom("sender@example.com");
        message.setTo("receiver@example.com");
        message.setSubject("Hello from Postmark");
        message.setTextBody("This is a test email sent through the Postmark API");
        
        // client.deliverMessage(message);
    }
    
    public static void bad_case_11() {
        // Sendinblue with hardcoded API key
        com.sendinblue.api.ApiClient defaultClient = Configuration.getDefaultApiClient();
        // ruleid: java-do-not-use-hardcoded-email-credentials
        ApiKeyAuth apiKey = (ApiKeyAuth) defaultClient.getAuthentication("api-key");
        apiKey.setApiKey("sendinblue_api_key_xkeysib-abcdef123456789-ghijklmnopqrst");
        
        // Rest of the email sending code would go here
    }
    
    public static void bad_case_12() {
        // Pepipost with hardcoded API key
        io.pepipost.api.client.Configuration.Default.apiKey = new HashMap<String, String>();
        // ruleid: java-do-not-use-hardcoded-email-credentials
        io.pepipost.api.client.Configuration.Default.apiKey.put("api_key", "pepipost_api_key_12345abcde");
        
        SendApi sendController = new SendApi();
        
        // Rest of the email sending code would go here
    }
    
    public static void bad_case_13() {
        // HTTP Basic Auth for email service with hardcoded credentials
        try {
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpPost httpPost = new HttpPost("https://api.emailservice.com/send");
            
            // ruleid: java-do-not-use-hardcoded-email-credentials
            Credentials credentials = new UsernamePasswordCredentials("email_api_user", "email_api_password");
            String authHeader = BasicScheme.authenticate(credentials, "US-ASCII", false);
            httpPost.setHeader("Authorization", authHeader);
            
            StringEntity entity = new StringEntity("{\"to\":\"recipient@example.com\",\"subject\":\"Test\",\"body\":\"Test email\"}");
            httpPost.setEntity(entity);
            httpPost.setHeader("Content-type", "application/json");
            
            HttpResponse response = httpClient.execute(httpPost);
            // Process response
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void bad_case_14() {
        // Gmail API with hardcoded credentials
        try {
            final NetHttpTransport HTTP_TRANSPORT = GoogleNetHttpTransport.newTrustedTransport();
            JsonFactory JSON_FAC_REDACTED_TWILIO_ID = JacksonFactory.getDefaultInstance();
            
            // ruleid: java-do-not-use-hardcoded-email-credentials
            GoogleCredential credential = new GoogleCredential.Builder()
                .setClientSecrets("gmail_client_id_12345", "gmail_client_secret_abcde")
                .build();
                
            Gmail service = new Gmail.Builder(HTTP_TRANSPORT, JSON_FAC_REDACTED_TWILIO_ID, credential)
                .setApplicationName("Gmail API Java Example")
                .build();
                
            // Rest of the email sending code would go here
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void bad_case_15() {
        // Custom email service with hardcoded credentials in properties
        Properties emailProps = new Properties();
        emailProps.setProperty("mail.smtp.host", "smtp.customservice.com");
        emailProps.setProperty("mail.smtp.port", "587");
        // ruleid: java-do-not-use-hardcoded-email-credentials
        emailProps.setProperty("mail.smtp.user", "custom_service_user");
        emailProps.setProperty("mail.smtp.password", "custom_service_password_123");
        emailProps.setProperty("mail.smtp.auth", "true");
        emailProps.setProperty("mail.smtp.starttls.enable", "true");
        
        // Use these properties to send email
        Session session = Session.getInstance(emailProps);
        // Rest of the email sending code would go here
    }
    
    // True Negative Examples (Safe/Secure Code)
    public static void good_case_1() {
        // JavaMail API with credentials from environment variables
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");
        
        final String username = System.getenv("EMAIL_USERNAME");
        final String password = System.getenv("EMAIL_PASSWORD");
        
        // ok: java-do-not-use-hardcoded-email-credentials
        Session session = Session.getInstance(props, new Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(username, password);
            }
        });
        
        try {
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress("from@example.com"));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse("to@example.com"));
            message.setSubject("Test Subject");
            message.setText("Test Message");
            Transport.send(message);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }
    
    public static void good_case_2() {
        // Apache Commons Email with credentials from properties file
        try {
            Properties props = new Properties();
            FileInputStream fis = new FileInputStream("email.properties");
            props.load(fis);
            fis.close();
            
            Email email = new SimpleEmail();
            email.setHostName("smtp.googlemail.com");
            email.setSmtpPort(465);
            email.setSSLOnConnect(true);
            
            // ok: java-do-not-use-hardcoded-email-credentials
            email.setAuthentication(props.getProperty("email.username"), props.getProperty("email.password"));
            email.setFrom("user@company.com");
            email.setSubject("Test message");
            email.setMsg("This is a test message");
            email.addTo("foo@bar.com");
            email.send();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void good_case_3() {
        // Spring JavaMailSender with credentials from system properties
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost("smtp.gmail.com");
        mailSender.setPort(587);
        
        // ok: java-do-not-use-hardcoded-email-credentials
        mailSender.setUsername(System.getProperty("spring.mail.username"));
        mailSender.setPassword(System.getProperty("spring.mail.password"));
        
        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom("spring.user@gmail.com");
        message.setTo("recipient@example.com");
        message.setSubject("Spring Mail Test");
        message.setText("Hello from Spring Mail");
        
        mailSender.send(message);
    }
    
    public static void good_case_4() {
        // SendGrid API with API key from environment variable
        try {
            // ok: java-do-not-use-hardcoded-email-credentials
            SendGrid sendGrid = new SendGrid(System.getenv("SENDGRID_API_KEY"));
            
            Mail mail = new Mail(
                new com.sendgrid.helpers.mail.objects.Email("from@example.com"),
                "Subject",
                new com.sendgrid.helpers.mail.objects.Email("to@example.com"),
                new Content("text/plain", "Hello SendGrid!")
            );
            
            Request request = new Request();
            request.setMethod(Method.POST);
            request.setEndpoint("mail/send");
            request.setBody(mail.build());
            
            Response response = sendGrid.api(request);
            System.out.println(response.getStatusCode());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void good_case_5() {
        // AWS SES with credentials from environment variables
        String accessKey = System.getenv("AWS_AC_REDACTED_TWILIO_ID_KEY");
        String secretKey = System.getenv("AWS_SECRET_KEY");
        
        // ok: java-do-not-use-hardcoded-email-credentials
        BasicAWSCredentials awsCreds = new BasicAWSCredentials(accessKey, secretKey);
        
        AmazonSimpleEmailService client = AmazonSimpleEmailServiceClientBuilder.standard()
            .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
            .withRegion(Regions.US_WEST_2)
            .build();
            
        // Rest of the email sending code would go here
    }
    
    public static void good_case_6() {
        // Mailjet with credentials from configuration file
        try {
            Properties config = new Properties();
            config.load(new FileInputStream("mailjet.properties"));
            String apiKey = config.getProperty("mailjet.apikey");
            String apiSecret = config.getProperty("mailjet.apisecret");
            
            // ok: java-do-not-use-hardcoded-email-credentials
            MailjetClient client = new MailjetClient(apiKey, apiSecret, new ClientOptions("v3.1"));
            
            TransactionalEmail message = TransactionalEmail
                .builder()
                .to(new SendContact("passenger@mailjet.com"))
                .from(new SendContact("pilot@mailjet.com"))
                .subject("Your email flight plan!")
                .textPart("Dear passenger, welcome to Mailjet!")
                .build();

            SendEmailsRequest request = SendEmailsRequest
                .builder()
                .message(message)
                .build();
                
            // Send the email (commented out for example purposes)
            // request.sendWith(client);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void good_case_7() {
        // Mailgun with API key from user input (console)
        Console console = System.console();
        String apiKey = null;
        
        if (console != null) {
            apiKey = new String(console.readPassword("Enter Mailgun API key: "));
        } else {
            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter Mailgun API key: ");
            apiKey = scanner.nextLine();
            scanner.close();
        }
        
        // ok: java-do-not-use-hardcoded-email-credentials
        MailgunMessagesApi mailgunMessagesApi = MailgunClient.config(apiKey)
            .createApi(MailgunMessagesApi.class);
            
        // Rest of the email sending code would go here
    }
    
    public static void good_case_8() {
        // SparkPost with API key from Java Preferences API
        Preferences prefs = Preferences.userRoot().node("com.myapp.email");
        String apiKey = prefs.get("sparkpost.apikey", null);
        
        if (apiKey == null) {
            // Handle missing API key
            System.out.println("API key not found in preferences");
            return;
        }
        
        try {
            // ok: java-do-not-use-hardcoded-email-credentials
            Client client = new Client(apiKey);
            
            // Rest of the email sending code would go here
        } catch (SparkPostException e) {
            e.printStackTrace();
        }
    }
    
    public static void good_case_9() {
        // SimpleJavaMail with credentials from external file
        try {
            File credFile = new File("email_creds.txt");
            BufferedReader reader = new BufferedReader(new FileReader(credFile));
            String username = reader.readLine();
            String password = reader.readLine();
            reader.close();
            
            org.simplejavamail.api.mailer.Mailer mailer = MailerBuilder
                .withSMTPServer("smtp.host.com", 587)
                // ok: java-do-not-use-hardcoded-email-credentials
                .withSMTPServerUsername(username)
                .withSMTPServerPassword(password)
                .buildMailer();
                
            org.simplejavamail.api.email.Email email = EmailBuilder.startingBlank()
                .from("From", "from@example.com")
                .to("To", "to@example.com")
                .withSubject("SimpleJavaMail test")
                .withPlainText("This is a test email")
                .buildEmail();
                
            // mailer.sendMail(email);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public static void good_case_10() {
        // Postmark with server token from environment variable
        String serverToken = System.getenv("POSTMARK_SERVER_TOKEN");
        
        // ok: java-do-not-use-hardcoded-email-credentials
        ApiClient client = Postmark.getApiClient(serverToken);
        
        Message message = new Message();
        message.setFrom("sender@example.com");
        message.setTo("receiver@example.com");
        message.setSubject("Hello from Postmark");
        message.setTextBody("This is a test email sent through the Postmark API");
        
        // client.deliverMessage(message);
    }
    
    public static void good_case_11() {
        // Sendinblue with API key loaded from encrypted storage
        try {
            // Read encrypted API key from file
            byte[] encryptedKey = Files.readAllBytes(Paths.get("sendinblue_api_key.enc"));
            
            // Decrypt the API key (simplified example)
            String password = System.getenv("ENCRYPTION_PASSWORD");
            SecretKeySpec secretKey = new SecretKeySpec(password.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            String apiKey = new String(cipher.doFinal(encryptedKey));
            
            com.sendinblue.api.ApiClient defaultClient = Configuration.getDefaultApiClient();
            // ok: java-do-not-use-hardcoded-email-credentials
            ApiKeyAuth apiKeyAuth = (ApiKeyAuth) defaultClient.getAuthentication("api-key");
            apiKeyAuth.setApiKey(apiKey);
            
            // Rest of the email sending code would go here
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void good_case_12() {
        // Pepipost with API key from properties file using Jasypt encryption
        try {
            // Load encrypted properties
            StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
            encryptor.setPassword(System.getenv("JASYPT_PASSWORD"));
            
            Properties props = new EncryptableProperties(encryptor);
            props.load(new FileInputStream("pepipost.properties"));
            
            String apiKey = props.getProperty("pepipost.apikey");
            
            io.pepipost.api.client.Configuration.Default.apiKey = new HashMap<String, String>();
            // ok: java-do-not-use-hardcoded-email-credentials
            io.pepipost.api.client.Configuration.Default.apiKey.put("api_key", apiKey);
            
            SendApi sendController = new SendApi();
            
            // Rest of the email sending code would go here
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void good_case_13() {
        // HTTP Basic Auth for email service with credentials from system properties
        try {
            CloseableHttpClient httpClient = HttpClients.createDefault();
            HttpPost httpPost = new HttpPost("https://api.emailservice.com/send");
            
            String username = System.getProperty("email.api.username");
            String password = System.getProperty("email.api.password");
            
            // ok: java-do-not-use-hardcoded-email-credentials
            Credentials credentials = new UsernamePasswordCredentials(username, password);
            String authHeader = BasicScheme.authenticate(credentials, "US-ASCII", false);
            httpPost.setHeader("Authorization", authHeader);
            
            StringEntity entity = new StringEntity("{\"to\":\"recipient@example.com\",\"subject\":\"Test\",\"body\":\"Test email\"}");
            httpPost.setEntity(entity);
            httpPost.setHeader("Content-type", "application/json");
            
            HttpResponse response = httpClient.execute(httpPost);
            // Process response
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void good_case_14() {
        // Gmail API with credentials from file
        try {
            final NetHttpTransport HTTP_TRANSPORT = GoogleNetHttpTransport.newTrustedTransport();
            JsonFactory JSON_FAC_REDACTED_TWILIO_ID = JacksonFactory.getDefaultInstance();
            
            // Load client secrets from a local file
            File clientSecretFile = new File(System.getProperty("user.home"), ".credentials/gmail-credentials.json");
            
            // ok: java-do-not-use-hardcoded-email-credentials
            GoogleCredential credential = GoogleCredential.fromStream(
                new FileInputStream(clientSecretFile),
                HTTP_TRANSPORT,
                JSON_FAC_REDACTED_TWILIO_ID
            ).createScoped(Collections.singleton(GmailScopes.GMAIL_SEND));
            
            Gmail service = new Gmail.Builder(HTTP_TRANSPORT, JSON_FAC_REDACTED_TWILIO_ID, credential)
                .setApplicationName("Gmail API Java Example")
                .build();
                
            // Rest of the email sending code would go here
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void good_case_15() {
        // Custom email service with credentials from Jasypt text encryptor
        try {
            // Initialize the encryptor with a master password from environment
            TextEncryptor encryptor = new BasicTextEncryptor();
            ((BasicTextEncryptor)encryptor).setPassword(System.getenv("MASTER_PASSWORD"));
            
            // Read encrypted credentials from file
            List<String> lines = Files.readAllLines(Paths.get("encrypted_email_creds.txt"));
            String encryptedUsername = lines.get(0);
            String encryptedPassword = lines.get(1);
            
            // Decrypt the credentials
            String username = encryptor.decrypt(encryptedUsername);
            String password = encryptor.decrypt(encryptedPassword);
            
            Properties emailProps = new Properties();
            emailProps.setProperty("mail.smtp.host", "smtp.customservice.com");
            emailProps.setProperty("mail.smtp.port", "587");
            // ok: java-do-not-use-hardcoded-email-credentials
            emailProps.setProperty("mail.smtp.user", username);
            emailProps.setProperty("mail.smtp.password", password);
            emailProps.setProperty("mail.smtp.auth", "true");
            emailProps.setProperty("mail.smtp.starttls.enable", "true");
            
            // Use these properties to send email
            Session session = Session.getInstance(emailProps);
            // Rest of the email sending code would go here
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}