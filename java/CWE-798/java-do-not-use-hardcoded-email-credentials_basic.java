import java.util.Properties;
import javax.mail.*;
import javax.mail.internet.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import com.amazonaws.services.secretsmanager.*;
import com.amazonaws.services.secretsmanager.model.*;
import org.json.JSONObject;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.context.annotation.Bean;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

public class EmailCredentialExamples {

    // True Positive Examples (Vulnerable Code)

// {fact rule=hardcoded-credentials@v1.0 defects=1}
    public void bad_case_1() {
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");
        
        // ruleid: java-do-not-use-hardcoded-email-credentials
        Session session = Session.getInstance(props, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication("company_admin@example.com", "P@ssw0rd123!");
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

    public void bad_case_2() {
        String username = "notifications@company.com";
        // ruleid: java-do-not-use-hardcoded-email-credentials
        String password = "NotificationSystem2023!";
        
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.host", "smtp.office365.com");
        props.put("mail.smtp.port", "587");
        props.put("mail.smtp.starttls.enable", "true");
        
        Session session = Session.getInstance(props, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(username, password);
            }
        });
        
        try {
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress(username));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse("customer@example.com"));
            message.setSubject("Order Confirmation");
            message.setText("Your order has been processed.");
            Transport.send(message);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() {
        // ruleid: java-do-not-use-hardcoded-email-credentials
        final String smtpUser = "system_alerts@example.org";
        final String smtpPass = "Sy$temAl3rt$2023";
        
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost("smtp.example.org");
        mailSender.setPort(587);
        mailSender.setUsername(smtpUser);
        mailSender.setPassword(smtpPass);
        
        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            helper.setFrom(smtpUser);
            helper.setTo("admin@example.org");
            helper.setSubject("System Alert");
            helper.setText("Critical system alert detected!");
            mailSender.send(message);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() {
        Properties props = System.getProperties();
        props.setProperty("mail.smtp.host", "smtp.amazon.com");
        props.setProperty("mail.smtp.port", "587");
        props.setProperty("mail.smtp.auth", "true");
        props.setProperty("mail.smtp.starttls.enable", "true");
        
        // ruleid: java-do-not-use-hardcoded-email-credentials
        Session session = Session.getDefaultInstance(props, new javax.mail.Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
            }
        });
        
        try {
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress("no-reply@example.com"));
            message.addRecipient(Message.RecipientType.TO, new InternetAddress("user@example.com"));
            message.setSubject("AWS Notification");
            message.setText("Your AWS resources have been updated.");
            Transport.send(message);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }

    @Service
    public class EmailService {
        public void bad_case_5() {
            // ruleid: java-do-not-use-hardcoded-email-credentials
            final String EMAIL_USERNAME = "marketing@company.com";
            final String EMAIL_PASSWORD = "M@rk3t1ng2023!";
            
            Properties properties = new Properties();
            properties.put("mail.smtp.host", "smtp.company.com");
            properties.put("mail.smtp.port", "465");
            properties.put("mail.smtp.auth", "true");
            properties.put("mail.smtp.socketFactory.port", "465");
            properties.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
            
            Session session = Session.getInstance(properties, new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(EMAIL_USERNAME, EMAIL_PASSWORD);
                }
            });
            
            try {
                MimeMessage message = new MimeMessage(session);
                message.setFrom(new InternetAddress(EMAIL_USERNAME));
                message.setRecipients(Message.RecipientType.TO, InternetAddress.parse("subscribers@example.com"));
                message.setSubject("Weekly Newsletter");
                message.setText("Here's your weekly newsletter!");
                Transport.send(message);
            } catch (MessagingException e) {
                e.printStackTrace();
            }
        }
    }

    public void bad_case_6() {
        // ruleid: java-do-not-use-hardcoded-email-credentials
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost("smtp.mailgun.org");
        mailSender.setPort(587);
        mailSender.setUsername("postmaster@sandbox123.mailgun.org");
        mailSender.setPassword("3kh9umujora5");
        
        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            helper.setFrom("noreply@company.com");
            helper.setTo("customer@example.com");
            helper.setSubject("Your account has been created");
            helper.setText("Welcome to our service!");
            mailSender.send(message);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() {
        // ruleid: java-do-not-use-hardcoded-email-credentials
        final String username = "support@helpdesk.com";
        final String password = "H3lpD3sk2023!";
        
        Properties props = new Properties();
        props.put("mail.smtp.host", "smtp.helpdesk.com");
        props.put("mail.smtp.socketFactory.port", "465");
        props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.port", "465");
        
        if (isTicketUrgent()) {
            Session session = Session.getDefaultInstance(props, new javax.mail.Authenticator() {
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(username, password);
                }
            });
            
            try {
                MimeMessage message = new MimeMessage(session);
                message.setFrom(new InternetAddress(username));
                message.addRecipient(Message.RecipientType.TO, new InternetAddress("manager@example.com"));
                message.setSubject("URGENT: Support Ticket Escalation");
                message.setText("A high priority ticket requires immediate attention.");
                Transport.send(message);
            } catch (MessagingException e) {
                e.printStackTrace();
            }
        }
    }

    private boolean isTicketUrgent() {
        return true; // Simplified for example
    }

    public void bad_case_8() {
        // ruleid: java-do-not-use-hardcoded-email-credentials
        String smtpUsername = "api";
        String smtpPassword = "key-3ax6xnjp29jd6fds4gc373sgvjxteol0";
        
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", "smtp.mailgun.org");
        props.put("mail.smtp.port", "587");
        
        for (String recipient : getRecipientList()) {
            Session session = Session.getInstance(props, new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(smtpUsername, smtpPassword);
                }
            });
            
            try {
                Message message = new MimeMessage(session);
                message.setFrom(new InternetAddress("no-reply@company.com"));
                message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(recipient));
                message.setSubject("Bulk Email");
                message.setText("This is a bulk email message.");
                Transport.send(message);
            } catch (MessagingException e) {
                e.printStackTrace();
            }
        }
    }

    private String[] getRecipientList() {
        return new String[]{"user1@example.com", "user2@example.com"};
    }

    public void bad_case_9() {
        // ruleid: java-do-not-use-hardcoded-email-credentials
        Properties config = new Properties();
        config.put("mail.smtp.host", "email-smtp.us-west-2.amazonaws.com");
        config.put("mail.smtp.port", "587");
        config.put("mail.smtp.auth", "true");
        config.put("mail.smtp.starttls.enable", "true");
        config.put("mail.smtp.user", "AKIAIOSFODNN7EXAMPLE");
        config.put("mail.smtp.password", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        
        Session session = Session.getInstance(config, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(
                    config.getProperty("mail.smtp.user"),
                    config.getProperty("mail.smtp.password")
                );
            }
        });
        
        try {
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress("ses-notifications@company.com"));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse("recipient@example.com"));
            message.setSubject("AWS SES Test");
            message.setText("This is a test email sent through Amazon SES.");
            Transport.send(message);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10() {
        // ruleid: java-do-not-use-hardcoded-email-credentials
        final String SMTP_SERVER = "smtp.sendgrid.net";
        final String SMTP_USERNAME = "apikey";
        final String SMTP_API_KEY = "SG.REDAC_REDACTED_TWILIO_ID_SENDGRID_KEY.913f7b7db4f35ff9a68d641c19e11bd3f4ecfddd79455d118ec55ad849cc5b7";
        
        Properties props = new Properties();
        props.put("mail.smtp.host", SMTP_SERVER);
        props.put("mail.smtp.port", "587");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        
        try {
            Session session = Session.getInstance(props, new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(SMTP_USERNAME, SMTP_API_KEY);
                }
            });
            
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress("marketing@company.com"));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse("customer@example.com"));
            message.setSubject("Special Offer");
            message.setText("Check out our latest products!");
            Transport.send(message);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() {
        // ruleid: java-do-not-use-hardcoded-email-credentials
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost("smtp.office365.com");
        mailSender.setPort(587);
        mailSender.setUsername("reports@contoso.com");
        mailSender.setPassword("R3p0rt$2023!");
        
        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.debug", "true");
        
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            helper.setFrom("reports@contoso.com");
            helper.setTo("executives@contoso.com");
            helper.setSubject("Monthly Report");
            helper.setText("Please find attached the monthly report.");
            
            // Attach a file
            helper.addAttachment("report.pdf", new java.io.File("path/to/report.pdf"));
            
            mailSender.send(message);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }

    public void bad_case_12() {
        // ruleid: java-do-not-use-hardcoded-email-credentials
        final String username = "noreply@example.com";
        final String password = "N0R3ply@2023";
        
        Properties props = new Properties();
        props.put("mail.smtp.host", "smtp.example.com");
        props.put("mail.smtp.port", "587");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        
        switch (getEmailPriority()) {
            case HIGH:
                props.put("mail.smtp.connectiontimeout", "5000");
                props.put("mail.smtp.timeout", "5000");
                break;
            case NORMAL:
                props.put("mail.smtp.connectiontimeout", "10000");
                props.put("mail.smtp.timeout", "10000");
                break;
            default:
                props.put("mail.smtp.connectiontimeout", "30000");
                props.put("mail.smtp.timeout", "30000");
        }
        
        Session session = Session.getInstance(props, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(username, password);
            }
        });
        
        try {
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(username));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse("recipient@example.com"));
            message.setSubject("Automated Notification");
            message.setText("This is an automated notification.");
            Transport.send(message);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }

    private EmailPriority getEmailPriority() {
        return EmailPriority.NORMAL; // Simplified for example
    }

    enum EmailPriority {
        HIGH, NORMAL, LOW
    }

    public void bad_case_13() {
        // ruleid: java-do-not-use-hardcoded-email-credentials
        final String smtpUser = "newsletter@example.com";
        final String smtpPassword = "N3w$L3tt3r!";
        
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", "smtp.example.com");
        props.put("mail.smtp.port", "587");
        
        Session session = Session.getInstance(props, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(smtpUser, smtpPassword);
            }
        });
        
        try {
            for (int i = 0; i < 3; i++) {
                try {
                    MimeMessage message = new MimeMessage(session);
                    message.setFrom(new InternetAddress(smtpUser));
                    message.setRecipients(Message.RecipientType.TO, InternetAddress.parse("subscriber@example.com"));
                    message.setSubject("Newsletter #" + (i+1));
                    message.setText("This is newsletter #" + (i+1));
                    Transport.send(message);
                    break;
                } catch (MessagingException e) {
                    if (i == 2) throw e;
                    // Retry logic
                    Thread.sleep(1000);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() {
        // ruleid: java-do-not-use-hardcoded-email-credentials
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost("smtp.gmail.com");
        mailSender.setPort(587);
        
        if (isProductionEnvironment()) {
            mailSender.setUsername("prod-alerts@company.com");
            mailSender.setPassword("Pr0d@l3rt$2023");
        } else {
            mailSender.setUsername("dev-alerts@company.com");
            mailSender.setPassword("D3v@l3rt$2023");
        }
        
        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            helper.setFrom(mailSender.getUsername());
            helper.setTo("admin@company.com");
            helper.setSubject("Environment Alert");
            helper.setText("An alert has been triggered in the " + 
                          (isProductionEnvironment() ? "production" : "development") + 
                          " environment.");
            mailSender.send(message);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }

    private boolean isProductionEnvironment() {
        return true; // Simplified for example
    }

    public void bad_case_15() {
        // ruleid: java-do-not-use-hardcoded-email-credentials
        final Map<String, String> emailConfig = Map.of(
            "host", "smtp.mailchimp.com",
            "port", "587",
            "username", "apikey",
            "password", "c42a3d03b1c2d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z"
        );
        
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", emailConfig.get("host"));
        props.put("mail.smtp.port", emailConfig.get("port"));
        
        Session session = Session.getInstance(props, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(
                    emailConfig.get("username"),
                    emailConfig.get("password")
                );
            }
        });
        
        try {
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress("campaigns@company.com"));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse("customer@example.com"));
            message.setSubject("Campaign Update");
            message.setText("Here's an update on our latest campaign.");
            Transport.send(message);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Secure Code)

    public void good_case_1() {
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");
        
        // ok: java-do-not-use-hardcoded-email-credentials
        String username = System.getenv("EMAIL_USERNAME");
        String password = System.getenv("EMAIL_PASSWORD");
        
        Session session = Session.getInstance(props, new Authenticator() {
            @Override
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

    public void good_case_2() {
        Properties props = new Properties();
        try {
            // ok: java-do-not-use-hardcoded-email-credentials
            props.load(new FileInputStream("config.properties"));
            
            String username = props.getProperty("mail.username");
            String password = props.getProperty("mail.password");
            
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.host", "smtp.office365.com");
            props.put("mail.smtp.port", "587");
            props.put("mail.smtp.starttls.enable", "true");
            
            Session session = Session.getInstance(props, new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(username, password);
                }
            });
            
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress(username));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse("customer@example.com"));
            message.setSubject("Order Confirmation");
            message.setText("Your order has been processed.");
            Transport.send(message);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Service
    public class SecureEmailService {
        @Value("${email.username}")
        private String emailUsername;
        
        @Value("${email.password}")
        private String emailPassword;
        
        public void good_case_3() {
            JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
            mailSender.setHost("smtp.example.org");
            mailSender.setPort(587);
            
            // ok: java-do-not-use-hardcoded-email-credentials
            mailSender.setUsername(emailUsername);
            mailSender.setPassword(emailPassword);
            
            Properties props = mailSender.getJavaMailProperties();
            props.put("mail.transport.protocol", "smtp");
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            
            try {
                MimeMessage message = mailSender.createMimeMessage();
                MimeMessageHelper helper = new MimeMessageHelper(message, true);
                helper.setFrom(emailUsername);
                helper.setTo("admin@example.org");
                helper.setSubject("System Alert");
                helper.setText("Critical system alert detected!");
                mailSender.send(message);
            } catch (MessagingException e) {
                e.printStackTrace();
            }
        }
    }

    public void good_case_4() {
        Properties props = System.getProperties();
        props.setProperty("mail.smtp.host", "smtp.amazon.com");
        props.setProperty("mail.smtp.port", "587");
        props.setProperty("mail.smtp.auth", "true");
        props.setProperty("mail.smtp.starttls.enable", "true");
        
        try {
            // ok: java-do-not-use-hardcoded-email-credentials
            AWSSecretsManager secretsManager = AWSSecretsManagerClientBuilder.standard()
                                                .withRegion("us-west-2")
                                                .build();
            
            GetSecretValueRequest getSecretValueRequest = new GetSecretValueRequest()
                                                        .withSecretId("email/smtp-credentials");
            
            GetSecretValueResult getSecretValueResult = secretsManager.getSecretValue(getSecretValueRequest);
            String secret = getSecretValueResult.getSecretString();
            
            JSONObject secretJson = new JSONObject(secret);
            final String username = secretJson.getString("username");
            final String password = secretJson.getString("password");
            
            Session session = Session.getDefaultInstance(props, new javax.mail.Authenticator() {
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(username, password);
                }
            });
            
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress("no-reply@example.com"));
            message.addRecipient(Message.RecipientType.TO, new InternetAddress("user@example.com"));
            message.setSubject("AWS Notification");
            message.setText("Your AWS resources have been updated.");
            Transport.send(message);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_5() {
        try {
            // ok: java-do-not-use-hardcoded-email-credentials
            Properties configProps = new Properties();
            InputStream input = new FileInputStream("secure-config.properties");
            configProps.load(input);
            input.close();
            
            final String EMAIL_USERNAME = configProps.getProperty("email.username");
            final String EMAIL_PASSWORD = configProps.getProperty("email.password");
            
            Properties smtpProps = new Properties();
            smtpProps.put("mail.smtp.host", "smtp.company.com");
            smtpProps.put("mail.smtp.port", "465");
            smtpProps.put("mail.smtp.auth", "true");
            smtpProps.put("mail.smtp.socketFactory.port", "465");
            smtpProps.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
            
            Session session = Session.getInstance(smtpProps, new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(EMAIL_USERNAME, EMAIL_PASSWORD);
                }
            });
            
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress(EMAIL_USERNAME));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse("subscribers@example.com"));
            message.setSubject("Weekly Newsletter");
            message.setText("Here's your weekly newsletter!");
            Transport.send(message);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Bean
    public JavaMailSender good_case_6() {
        // ok: java-do-not-use-hardcoded-email-credentials
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost("${smtp.host}");
        mailSender.setPort(587);
        mailSender.setUsername("${smtp.username}");
        mailSender.setPassword("${smtp.password}");
        
        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        
        return mailSender;
    }

    public void good_case_7() {
        try {
            // ok: java-do-not-use-hardcoded-email-credentials
            String encryptedPassword = Files.readString(Paths.get("encrypted_password.txt"));
            String secretKey = System.getenv("EMAIL_SECRET_KEY");
            
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            
            byte[] decodedPassword = Base64.getDecoder().decode(encryptedPassword);
            byte[] decryptedPasswordBytes = cipher.doFinal(decodedPassword);
            String decryptedPassword = new String(decryptedPasswordBytes);
            
            final String username = System.getenv("EMAIL_USERNAME");
            final String password = decryptedPassword;
            
            Properties props = new Properties();
            props.put("mail.smtp.host", "smtp.helpdesk.com");
            props.put("mail.smtp.socketFactory.port", "465");
            props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.port", "465");
            
            Session session = Session.getDefaultInstance(props, new javax.mail.Authenticator() {
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(username, password);
                }
            });
            
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress(username));
            message.addRecipient(Message.RecipientType.TO, new InternetAddress("manager@example.com"));
            message.setSubject("Support Ticket Escalation");
            message.setText("A high priority ticket requires attention.");
            Transport.send(message);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_8() {
        // ok: java-do-not-use-hardcoded-email-credentials
        String smtpUsername = System.getProperty("mail.username");
        String smtpPassword = System.getProperty("mail.password");
        
        if (smtpUsername == null || smtpPassword == null) {
            throw new IllegalStateException("Email credentials not provided");
        }
        
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", "smtp.mailgun.org");
        props.put("mail.smtp.port", "587");
        
        for (String recipient : getRecipientList()) {
            Session session = Session.getInstance(props, new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(smtpUsername, smtpPassword);
                }
            });
            
            try {
                Message message = new MimeMessage(session);
                message.setFrom(new InternetAddress("no-reply@company.com"));
                message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(recipient));
                message.setSubject("Bulk Email");
                message.setText("This is a bulk email message.");
                Transport.send(message);
            } catch (MessagingException e) {
                e.printStackTrace();
            }
        }
    }

    public void good_case_9() {
        try {
            // ok: java-do-not-use-hardcoded-email-credentials
            Properties configProps = new Properties();
            configProps.load(new FileInputStream("aws-config.properties"));
            
            Properties mailProps = new Properties();
            mailProps.put("mail.smtp.host", configProps.getProperty("mail.smtp.host"));
            mailProps.put("mail.smtp.port", configProps.getProperty("mail.smtp.port"));
            mailProps.put("mail.smtp.auth", "true");
            mailProps.put("mail.smtp.starttls.enable", "true");
            
            final String smtpUser = configProps.getProperty("mail.smtp.user");
            final String smtpPassword = configProps.getProperty("mail.smtp.password");
            
            Session session = Session.getInstance(mailProps, new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(smtpUser, smtpPassword);
                }
            });
            
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress("ses-notifications@company.com"));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse("recipient@example.com"));
            message.setSubject("AWS SES Test");
            message.setText("This is a test email sent through Amazon SES.");
            Transport.send(message);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Service
    public class ConfigurableEmailService {
        @Value("${smtp.server}")
        private String smtpServer;
        
        @Value("${smtp.username}")
        private String smtpUsername;
        
        @Value("${smtp.password}")
        private String smtpPassword;
        
        public void good_case_10() {
            // ok: java-do-not-use-hardcoded-email-credentials
            Properties props = new Properties();
            props.put("mail.smtp.host", smtpServer);
            props.put("mail.smtp.port", "587");
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            
            try {
                Session session = Session.getInstance(props, new Authenticator() {
                    @Override
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(smtpUsername, smtpPassword);
                    }
                });
                
                Message message = new MimeMessage(session);
                message.setFrom(new InternetAddress("marketing@company.com"));
                message.setRecipients(Message.RecipientType.TO, InternetAddress.parse("customer@example.com"));
                message.setSubject("Special Offer");
                message.setText("Check out our latest products!");
                Transport.send(message);
            } catch (MessagingException e) {
                e.printStackTrace();
            }
        }
    }

    public void good_case_11() {
        // ok: java-do-not-use-hardcoded-email-credentials
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        
        try {
            Properties configProps = new Properties();
            configProps.load(Thread.currentThread().getContextClassLoader().getResourceAsStream("mail.properties"));
            
            mailSender.setHost(configProps.getProperty("mail.host"));
            mailSender.setPort(Integer.parseInt(configProps.getProperty("mail.port")));
            mailSender.setUsername(configProps.getProperty("mail.username"));
            mailSender.setPassword(configProps.getProperty("mail.password"));
            
            Properties props = mailSender.getJavaMailProperties();
            props.put("mail.transport.protocol", "smtp");
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.debug", "true");
            
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            helper.setFrom(mailSender.getUsername());
            helper.setTo("executives@contoso.com");
            helper.setSubject("Monthly Report");
            helper.setText("Please find attached the monthly report.");
            
            // Attach a file
            helper.addAttachment("report.pdf", new java.io.File("path/to/report.pdf"));
            
            mailSender.send(message);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_12() {
        // ok: java-do-not-use-hardcoded-email-credentials
        final String username;
        final String password;
        
        // Get credentials based on environment
        if (System.getProperty("env").equals("prod")) {
            username = System.getenv("PROD_EMAIL_USERNAME");
            password = System.getenv("PROD_EMAIL_PASSWORD");
        } else {
            username = System.getenv("DEV_EMAIL_USERNAME");
            password = System.getenv("DEV_EMAIL_PASSWORD");
        }
        
        Properties props = new Properties();
        props.put("mail.smtp.host", "smtp.example.com");
        props.put("mail.smtp.port", "587");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        
        switch (getEmailPriority()) {
            case HIGH:
                props.put("mail.smtp.connectiontimeout", "5000");
                props.put("mail.smtp.timeout", "5000");
                break;
            case NORMAL:
                props.put("mail.smtp.connectiontimeout", "10000");
                props.put("mail.smtp.timeout", "10000");
                break;
            default:
                props.put("mail.smtp.connectiontimeout", "30000");
                props.put("mail.smtp.timeout", "30000");
        }
        
        Session session = Session.getInstance(props, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(username, password);
            }
        });
        
        try {
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(username));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse("recipient@example.com"));
            message.setSubject("Automated Notification");
            message.setText("This is an automated notification.");
            Transport.send(message);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() {
        try {
            // ok: java-do-not-use-hardcoded-email-credentials
            // Use a secure credential provider
            CredentialProvider credProvider = new CredentialProvider();
            final String smtpUser = credProvider.getUsername("email.newsletter");
            final String smtpPassword = credProvider.getPassword("email.newsletter");
            
            Properties props = new Properties();
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.host", "smtp.example.com");
            props.put("mail.smtp.port", "587");
            
            Session session = Session.getInstance(props, new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(smtpUser, smtpPassword);
                }
            });
            
            for (int i = 0; i < 3; i++) {
                try {
                    MimeMessage message = new MimeMessage(session);
                    message.setFrom(new InternetAddress(smtpUser));
                    message.setRecipients(Message.RecipientType.TO, InternetAddress.parse("subscriber@example.com"));
                    message.setSubject("Newsletter #" + (i+1));
                    message.setText("This is newsletter #" + (i+1));
                    Transport.send(message);
                    break;
                } catch (MessagingException e) {
                    if (i == 2) throw e;
                    // Retry logic
                    Thread.sleep(1000);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Mock credential provider for example
    private class CredentialProvider {
        public String getUsername(String key) {
            // In a real implementation, this would retrieve from a secure store
            return System.getenv(key + "_USERNAME");
        }
        
        public String getPassword(String key) {
            // In a real implementation, this would retrieve from a secure store
            return System.getenv(key + "_PASSWORD");
        }
    }

    public void good_case_14() {
        // ok: java-do-not-use-hardcoded-email-credentials
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost("smtp.gmail.com");
        mailSender.setPort(587);
        
        String username;
        String password;
        
        if (isProductionEnvironment()) {
            username = System.getenv("PROD_EMAIL_USERNAME");
            password = System.getenv("PROD_EMAIL_PASSWORD");
        } else {
            username = System.getenv("DEV_EMAIL_USERNAME");
            password = System.getenv("DEV_EMAIL_PASSWORD");
        }
        
        mailSender.setUsername(username);
        mailSender.setPassword(password);
        
        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            helper.setFrom(username);
            helper.setTo("admin@company.com");
            helper.setSubject("Environment Alert");
            helper.setText("An alert has been triggered in the " + 
                          (isProductionEnvironment() ? "production" : "development") + 
                          " environment.");
            mailSender.send(message);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() {
        try {
            // ok: java-do-not-use-hardcoded-email-credentials
            // Load configuration from a secure vault or environment
            Map<String, String> emailConfig = loadSecureConfiguration();
            
            Properties props = new Properties();
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.host", emailConfig.get("host"));
            props.put("mail.smtp.port", emailConfig.get("port"));
            
            Session session = Session.getInstance(props, new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(
                        emailConfig.get("username"),
                        emailConfig.get("password")
                    );
                }
            });
            
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress("campaigns@company.com"));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse("customer@example.com"));
            message.setSubject("Campaign Update");
            message.setText("Here's an update on our latest campaign.");
            Transport.send(message);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private Map<String, String> loadSecureConfiguration() {
        // In a real implementation, this would load from a secure vault or environment variables
        return Map.of(
            "host", System.getenv("EMAIL_HOST"),
            "port", System.getenv("EMAIL_PORT"),
            "username", System.getenv("EMAIL_USERNAME"),
            "password", System.getenv("EMAIL_PASSWORD")
        );
    }
}
// {/fact}