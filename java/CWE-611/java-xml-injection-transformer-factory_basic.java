import javax.xml.XMLConstants;
import javax.xml.transform.*;
import javax.xml.transform.stream.*;
import java.io.*;
import javax.xml.parsers.*;
import org.xml.sax.*;
import org.w3c.dom.*;
import java.net.URL;
import java.net.HttpURLConnection;

public class TransformerFactorySecurityExamples {

    // True Positives (Vulnerable Code)

// {fact rule=xml-external-entity@v1.0 defects=1}
    public void bad_case_1() throws TransformerException {
        // Creating a TransformerFactory without any security settings
        TransformerFactory factory = TransformerFactory.newInstance();
        // ruleid: java-xml-injection-transformer-factory
        Transformer transformer = factory.newTransformer();
        
        // Using the insecure transformer
        try {
            transformer.transform(
                new StreamSource(new File("input.xml")), 
                new StreamResult(new File("output.xml"))
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_2() throws TransformerException {
        // Creating a TransformerFactory with incomplete security settings
        TransformerFactory factory = TransformerFactory.newInstance();
        // Only setting one security attribute but missing others
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        // ruleid: java-xml-injection-transformer-factory
        Transformer transformer = factory.newTransformer();
        
        try {
            transformer.transform(
                new StreamSource(new StringReader("<data>test</data>")), 
                new StreamResult(System.out)
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_3() throws TransformerException {
        // Creating a TransformerFactory with incomplete security settings
        TransformerFactory factory = TransformerFactory.newInstance();
        // Only setting one security attribute but missing others
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        // ruleid: java-xml-injection-transformer-factory
        Transformer transformer = factory.newTransformer(new StreamSource(new File("style.xsl")));
        
        try {
            transformer.transform(
                new StreamSource(new File("data.xml")), 
                new StreamResult(new FileOutputStream("output.xml"))
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_4() throws Exception {
        // Creating a TransformerFactory with only secure processing but missing other attributes
        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        // ruleid: java-xml-injection-transformer-factory
        Templates templates = factory.newTemplates(new StreamSource(new File("template.xsl")));
        Transformer transformer = templates.newTransformer();
        
        try {
            transformer.transform(
                new StreamSource(new FileInputStream("input.xml")), 
                new StreamResult(new FileWriter("output.xml"))
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_5() throws Exception {
        // Creating a TransformerFactory with incorrect attribute values
        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "all"); // Insecure - allows all external DTDs
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, ""); // This is secure
        // ruleid: java-xml-injection-transformer-factory
        Transformer transformer = factory.newTransformer();
        
        try {
            transformer.transform(
                new StreamSource(new URL("http://example.com/data.xml").openStream()), 
                new StreamResult(new File("output.xml"))
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_6() throws TransformerException {
        // Creating a TransformerFactory in a different way but still insecure
        String factoryImpl = "com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl";
        TransformerFactory factory = TransformerFactory.newInstance(factoryImpl, null);
        // ruleid: java-xml-injection-transformer-factory
        Transformer transformer = factory.newTransformer();
        
        try {
            transformer.transform(
                new StreamSource(new StringReader("<root><data>test</data></root>")), 
                new StreamResult(new StringWriter())
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7() throws Exception {
        // Creating a TransformerFactory with secure processing disabled
        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, false); // Explicitly disabled
        // ruleid: java-xml-injection-transformer-factory
        Transformer transformer = factory.newTransformer();
        
        try {
            transformer.transform(
                new StreamSource(new File("input.xml")), 
                new StreamResult(System.out)
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_8() throws Exception {
        // Using a TransformerFactory in a method that processes user input
        String userInput = getUserInput();
        TransformerFactory factory = TransformerFactory.newInstance();
        // No security settings applied
        // ruleid: java-xml-injection-transformer-factory
        Transformer transformer = factory.newTransformer();
        
        try {
            transformer.transform(
                new StreamSource(new StringReader(userInput)), 
                new StreamResult(new File("output.xml"))
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_9() throws Exception {
        // Using a TransformerFactory with a custom ErrorListener but no security settings
        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setErrorListener(new CustomErrorListener());
        // ruleid: java-xml-injection-transformer-factory
        Transformer transformer = factory.newTransformer();
        
        try {
            transformer.transform(
                new StreamSource(new File("input.xml")), 
                new StreamResult(new File("output.xml"))
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10() throws Exception {
        // Using a TransformerFactory with a custom URIResolver but no security settings
        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setURIResolver(new CustomURIResolver());
        // ruleid: java-xml-injection-transformer-factory
        Transformer transformer = factory.newTransformer();
        
        try {
            transformer.transform(
                new StreamSource(new File("input.xml")), 
                new StreamResult(new File("output.xml"))
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_11() throws Exception {
        // Using a TransformerFactory in a web service context
        HttpURLConnection connection = (HttpURLConnection) new URL("http://example.com/data").openConnection();
        InputStream inputStream = connection.getInputStream();
        
        TransformerFactory factory = TransformerFactory.newInstance();
        // No security settings applied
        // ruleid: java-xml-injection-transformer-factory
        Transformer transformer = factory.newTransformer();
        
        try {
            transformer.transform(
                new StreamSource(inputStream), 
                new StreamResult(new File("output.xml"))
            );
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            inputStream.close();
        }
    }

    public void bad_case_12() throws Exception {
        // Using a TransformerFactory with parameters but no security settings
        TransformerFactory factory = TransformerFactory.newInstance();
        // ruleid: java-xml-injection-transformer-factory
        Transformer transformer = factory.newTransformer();
        
        transformer.setParameter("param1", "value1");
        transformer.setParameter("param2", "value2");
        
        try {
            transformer.transform(
                new StreamSource(new File("input.xml")), 
                new StreamResult(new File("output.xml"))
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_13() throws Exception {
        // Using a TransformerFactory with output properties but no security settings
        TransformerFactory factory = TransformerFactory.newInstance();
        // ruleid: java-xml-injection-transformer-factory
        Transformer transformer = factory.newTransformer();
        
        transformer.setOutputProperty(OutputKeys.METHOD, "xml");
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        
        try {
            transformer.transform(
                new StreamSource(new File("input.xml")), 
                new StreamResult(new File("output.xml"))
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_14() throws Exception {
        // Using a TransformerFactory with a custom stylesheet but no security settings
        TransformerFactory factory = TransformerFactory.newInstance();
        Source xslt = new StreamSource(new File("transform.xsl"));
        // ruleid: java-xml-injection-transformer-factory
        Transformer transformer = factory.newTransformer(xslt);
        
        try {
            transformer.transform(
                new StreamSource(new File("input.xml")), 
                new StreamResult(new File("output.xml"))
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_15() throws Exception {
        // Using a TransformerFactory in a multi-step transformation but no security settings
        TransformerFactory factory = TransformerFactory.newInstance();
        // ruleid: java-xml-injection-transformer-factory
        Transformer transformer1 = factory.newTransformer(new StreamSource(new File("step1.xsl")));
        Transformer transformer2 = factory.newTransformer(new StreamSource(new File("step2.xsl")));
        
        try {
            // First transformation
            StringWriter intermediateResult = new StringWriter();
            transformer1.transform(
                new StreamSource(new File("input.xml")), 
                new StreamResult(intermediateResult)
            );
            
            // Second transformation
            transformer2.transform(
                new StreamSource(new StringReader(intermediateResult.toString())), 
                new StreamResult(new File("output.xml"))
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negatives (Secure Code)

    public void good_case_1() throws TransformerException {
        // Creating a TransformerFactory with all required security settings
        TransformerFactory factory = TransformerFactory.newInstance();
        // ok: java-xml-injection-transformer-factory
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        Transformer transformer = factory.newTransformer();
        
        try {
            transformer.transform(
                new StreamSource(new File("input.xml")), 
                new StreamResult(new File("output.xml"))
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_2() throws TransformerException {
        // Creating a TransformerFactory with all required security settings and a stylesheet
        TransformerFactory factory = TransformerFactory.newInstance();
        // ok: java-xml-injection-transformer-factory
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        Transformer transformer = factory.newTransformer(new StreamSource(new File("style.xsl")));
        
        try {
            transformer.transform(
                new StreamSource(new StringReader("<data>test</data>")), 
                new StreamResult(System.out)
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_3() throws Exception {
        // Creating a TransformerFactory with all required security settings and templates
        TransformerFactory factory = TransformerFactory.newInstance();
        // ok: java-xml-injection-transformer-factory
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        Templates templates = factory.newTemplates(new StreamSource(new File("template.xsl")));
        Transformer transformer = templates.newTransformer();
        
        try {
            transformer.transform(
                new StreamSource(new FileInputStream("input.xml")), 
                new StreamResult(new FileWriter("output.xml"))
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_4() throws Exception {
        // Creating a TransformerFactory with all required security settings and a custom implementation
        String factoryImpl = "com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl";
        TransformerFactory factory = TransformerFactory.newInstance(factoryImpl, null);
        // ok: java-xml-injection-transformer-factory
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        Transformer transformer = factory.newTransformer();
        
        try {
            transformer.transform(
                new StreamSource(new StringReader("<root><data>test</data></root>")), 
                new StreamResult(new StringWriter())
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_5() throws Exception {
        // Creating a TransformerFactory with all required security settings and processing user input
        String userInput = getUserInput();
        TransformerFactory factory = TransformerFactory.newInstance();
        // ok: java-xml-injection-transformer-factory
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        Transformer transformer = factory.newTransformer();
        
        try {
            transformer.transform(
                new StreamSource(new StringReader(userInput)), 
                new StreamResult(new File("output.xml"))
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_6() throws Exception {
        // Creating a TransformerFactory with all required security settings and a custom ErrorListener
        TransformerFactory factory = TransformerFactory.newInstance();
        // ok: java-xml-injection-transformer-factory
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setErrorListener(new CustomErrorListener());
        Transformer transformer = factory.newTransformer();
        
        try {
            transformer.transform(
                new StreamSource(new File("input.xml")), 
                new StreamResult(new File("output.xml"))
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_7() throws Exception {
        // Creating a TransformerFactory with all required security settings and a custom URIResolver
        TransformerFactory factory = TransformerFactory.newInstance();
        // ok: java-xml-injection-transformer-factory
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setURIResolver(new CustomURIResolver());
        Transformer transformer = factory.newTransformer();
        
        try {
            transformer.transform(
                new StreamSource(new File("input.xml")), 
                new StreamResult(new File("output.xml"))
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_8() throws Exception {
        // Creating a TransformerFactory with all required security settings in a web service context
        HttpURLConnection connection = (HttpURLConnection) new URL("http://example.com/data").openConnection();
        InputStream inputStream = connection.getInputStream();
        
        TransformerFactory factory = TransformerFactory.newInstance();
        // ok: java-xml-injection-transformer-factory
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        Transformer transformer = factory.newTransformer();
        
        try {
            transformer.transform(
                new StreamSource(inputStream), 
                new StreamResult(new File("output.xml"))
            );
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            inputStream.close();
        }
    }

    public void good_case_9() throws Exception {
        // Creating a TransformerFactory with all required security settings and parameters
        TransformerFactory factory = TransformerFactory.newInstance();
        // ok: java-xml-injection-transformer-factory
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        Transformer transformer = factory.newTransformer();
        
        transformer.setParameter("param1", "value1");
        transformer.setParameter("param2", "value2");
        
        try {
            transformer.transform(
                new StreamSource(new File("input.xml")), 
                new StreamResult(new File("output.xml"))
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_10() throws Exception {
        // Creating a TransformerFactory with all required security settings and output properties
        TransformerFactory factory = TransformerFactory.newInstance();
        // ok: java-xml-injection-transformer-factory
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        Transformer transformer = factory.newTransformer();
        
        transformer.setOutputProperty(OutputKeys.METHOD, "xml");
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        
        try {
            transformer.transform(
                new StreamSource(new File("input.xml")), 
                new StreamResult(new File("output.xml"))
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_11() throws Exception {
        // Creating a TransformerFactory with all required security settings and a custom stylesheet
        TransformerFactory factory = TransformerFactory.newInstance();
        // ok: java-xml-injection-transformer-factory
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        Source xslt = new StreamSource(new File("transform.xsl"));
        Transformer transformer = factory.newTransformer(xslt);
        
        try {
            transformer.transform(
                new StreamSource(new File("input.xml")), 
                new StreamResult(new File("output.xml"))
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_12() throws Exception {
        // Creating a TransformerFactory with all required security settings in a multi-step transformation
        TransformerFactory factory = TransformerFactory.newInstance();
        // ok: java-xml-injection-transformer-factory
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        Transformer transformer1 = factory.newTransformer(new StreamSource(new File("step1.xsl")));
        Transformer transformer2 = factory.newTransformer(new StreamSource(new File("step2.xsl")));
        
        try {
            // First transformation
            StringWriter intermediateResult = new StringWriter();
            transformer1.transform(
                new StreamSource(new File("input.xml")), 
                new StreamResult(intermediateResult)
            );
            
            // Second transformation
            transformer2.transform(
                new StreamSource(new StringReader(intermediateResult.toString())), 
                new StreamResult(new File("output.xml"))
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_13() throws Exception {
        // Creating a TransformerFactory with all required security settings and handling exceptions properly
        TransformerFactory factory = TransformerFactory.newInstance();
        // ok: java-xml-injection-transformer-factory
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        
        try {
            Transformer transformer = factory.newTransformer();
            transformer.transform(
                new StreamSource(new File("input.xml")), 
                new StreamResult(new File("output.xml"))
            );
        } catch (TransformerConfigurationException e) {
            System.err.println("Configuration error: " + e.getMessage());
            throw e;
        } catch (TransformerException e) {
            System.err.println("Transformation error: " + e.getMessage());
            throw e;
        }
    }

    public void good_case_14() throws Exception {
        // Creating a TransformerFactory with all required security settings and using a different order of configuration
        TransformerFactory factory = TransformerFactory.newInstance();
        // ok: java-xml-injection-transformer-factory
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        Transformer transformer = factory.newTransformer();
        
        try {
            transformer.transform(
                new StreamSource(new File("input.xml")), 
                new StreamResult(new File("output.xml"))
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_15() throws Exception {
        // Creating a TransformerFactory with all required security settings and using a try-with-resources
        TransformerFactory factory = TransformerFactory.newInstance();
        // ok: java-xml-injection-transformer-factory
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        Transformer transformer = factory.newTransformer();
        
        try (InputStream is = new FileInputStream("input.xml");
             OutputStream os = new FileOutputStream("output.xml")) {
            transformer.transform(
                new StreamSource(is), 
                new StreamResult(os)
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Helper methods and classes
    private String getUserInput() {
        return "<data>sample</data>"; // Simulated user input
    }

    private class CustomErrorListener implements ErrorListener {
        @Override
        public void warning(TransformerException e) { System.err.println(e.getMessage()); }
        @Override
        public void error(TransformerException e) throws TransformerException { throw e; }
        @Override
        public void fatalError(TransformerException e) throws TransformerException { throw e; }
    }

    private class CustomURIResolver implements URIResolver {
        @Override
        public Source resolve(String href, String base) {
            try {
                return new StreamSource(new File(href));
            } catch (Exception e) {
                return null;
            }
        }
    }
}
// {/fact}