import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import org.w3c.dom.Document;
import java.io.*;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import org.xml.sax.InputSource;
import java.net.URL;
import java.util.Properties;

public class XXETransformerFactoryExamples extends HttpServlet {

    // True Positive Examples (Vulnerable Code)

// {fact rule=xml-external-entity@v1.0 defects=1}
    protected void bad_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            StringReader reader = new StringReader(xmlData);
            
            TransformerFactory factory = TransformerFactory.newInstance();
            // ruleid: java-xxe-in-transformerfactory
            Transformer transformer = factory.newTransformer(new StreamSource(reader));
            
            StringWriter writer = new StringWriter();
            transformer.transform(new StreamSource(reader), new StreamResult(writer));
            
            response.getWriter().write(writer.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            InputStream xmlStream = request.getInputStream();
            
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            // ruleid: java-xxe-in-transformerfactory
            Templates templates = transformerFactory.newTemplates(new StreamSource(xmlStream));
            
            Transformer transformer = templates.newTransformer();
            StringWriter output = new StringWriter();
            transformer.transform(new StreamSource(xmlStream), new StreamResult(output));
            
            response.getWriter().write(output.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlContent = request.getHeader("X-XML-Data");
            ByteArrayInputStream inputStream = new ByteArrayInputStream(xmlContent.getBytes());
            
            TransformerFactory factory = TransformerFactory.newInstance("com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl", null);
            // ruleid: java-xxe-in-transformerfactory
            Transformer transformer = factory.newTransformer(new StreamSource(inputStream));
            
            StringWriter resultWriter = new StringWriter();
            transformer.transform(new StreamSource(inputStream), new StreamResult(resultWriter));
            
            response.getWriter().write(resultWriter.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlFile = request.getParameter("xmlFile");
            File file = new File(xmlFile);
            
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            // ruleid: java-xxe-in-transformerfactory
            Templates templates = transformerFactory.newTemplates(new StreamSource(file));
            
            Transformer transformer = templates.newTransformer();
            StringWriter writer = new StringWriter();
            transformer.transform(new StreamSource(file), new StreamResult(writer));
            
            response.getWriter().write(writer.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlUrl = request.getParameter("url");
            URL url = new URL(xmlUrl);
            
            TransformerFactory factory = TransformerFactory.newInstance();
            // ruleid: java-xxe-in-transformerfactory
            Transformer transformer = factory.newTransformer(new StreamSource(url.openStream()));
            
            StringWriter writer = new StringWriter();
            transformer.transform(new StreamSource(url.openStream()), new StreamResult(writer));
            
            response.getWriter().write(writer.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            InputSource source = new InputSource(new StringReader(xmlData));
            
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document document = db.parse(source);
            
            TransformerFactory factory = TransformerFactory.newInstance();
            // ruleid: java-xxe-in-transformerfactory
            Transformer transformer = factory.newTransformer();
            
            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(document), new StreamResult(writer));
            
            response.getWriter().write(writer.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xsltData = request.getParameter("xslt");
            String xmlData = request.getParameter("xml");
            
            TransformerFactory factory = TransformerFactory.newInstance();
            // ruleid: java-xxe-in-transformerfactory
            Transformer transformer = factory.newTransformer(new StreamSource(new StringReader(xsltData)));
            
            StringWriter writer = new StringWriter();
            transformer.transform(new StreamSource(new StringReader(xmlData)), new StreamResult(writer));
            
            response.getWriter().write(writer.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            Reader reader = new StringReader(xmlData);
            
            TransformerFactory factory = TransformerFactory.newInstance();
            // No explicit security settings
            // ruleid: java-xxe-in-transformerfactory
            Templates templates = factory.newTemplates(new StreamSource(reader));
            
            Transformer transformer = templates.newTransformer();
            StringWriter writer = new StringWriter();
            transformer.transform(new StreamSource(reader), new StreamResult(writer));
            
            response.getWriter().write(writer.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            Part filePart = request.getPart("xmlFile");
            InputStream fileContent = filePart.getInputStream();
            
            TransformerFactory factory = TransformerFactory.newInstance();
            // ruleid: java-xxe-in-transformerfactory
            Transformer transformer = factory.newTransformer(new StreamSource(fileContent));
            
            StringWriter writer = new StringWriter();
            transformer.transform(new StreamSource(fileContent), new StreamResult(writer));
            
            response.getWriter().write(writer.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            TransformerFactory factory = TransformerFactory.newInstance();
            
            // Incomplete security configuration - missing FEATURE_SECURE_PROCESSING
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            
            // ruleid: java-xxe-in-transformerfactory
            Transformer transformer = factory.newTransformer(new StreamSource(new StringReader(xmlData)));
            
            StringWriter writer = new StringWriter();
            transformer.transform(new StreamSource(new StringReader(xmlData)), new StreamResult(writer));
            
            response.getWriter().write(writer.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            TransformerFactory factory = TransformerFactory.newInstance();
            
            // Incomplete security configuration - missing AC_REDACTED_TWILIO_ID_EXTERNAL_DTD
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            
            // ruleid: java-xxe-in-transformerfactory
            Transformer transformer = factory.newTransformer(new StreamSource(new StringReader(xmlData)));
            
            StringWriter writer = new StringWriter();
            transformer.transform(new StreamSource(new StringReader(xmlData)), new StreamResult(writer));
            
            response.getWriter().write(writer.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            TransformerFactory factory = TransformerFactory.newInstance();
            
            // Incomplete security configuration - missing AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            
            // ruleid: java-xxe-in-transformerfactory
            Transformer transformer = factory.newTransformer(new StreamSource(new StringReader(xmlData)));
            
            StringWriter writer = new StringWriter();
            transformer.transform(new StreamSource(new StringReader(xmlData)), new StreamResult(writer));
            
            response.getWriter().write(writer.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            
            // Using a custom factory implementation but without security settings
            TransformerFactory factory = TransformerFactory.newInstance("net.sf.saxon.TransformerFactoryImpl", null);
            
            // ruleid: java-xxe-in-transformerfactory
            Transformer transformer = factory.newTransformer(new StreamSource(new StringReader(xmlData)));
            
            StringWriter writer = new StringWriter();
            transformer.transform(new StreamSource(new StringReader(xmlData)), new StreamResult(writer));
            
            response.getWriter().write(writer.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            TransformerFactory factory = TransformerFactory.newInstance();
            
            // Incorrect security setting (using null instead of empty string)
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, null);
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, null);
            
            // ruleid: java-xxe-in-transformerfactory
            Transformer transformer = factory.newTransformer(new StreamSource(new StringReader(xmlData)));
            
            StringWriter writer = new StringWriter();
            transformer.transform(new StreamSource(new StringReader(xmlData)), new StreamResult(writer));
            
            response.getWriter().write(writer.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void bad_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            TransformerFactory factory = TransformerFactory.newInstance();
            
            // Security settings applied after creating transformer (too late)
            // ruleid: java-xxe-in-transformerfactory
            Transformer transformer = factory.newTransformer(new StreamSource(new StringReader(xmlData)));
            
            // These settings don't affect the already created transformer
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            
            StringWriter writer = new StringWriter();
            transformer.transform(new StreamSource(new StringReader(xmlData)), new StreamResult(writer));
            
            response.getWriter().write(writer.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // True Negative Examples (Secure Code)

    protected void good_case_1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            StringReader reader = new StringReader(xmlData);
            
            TransformerFactory factory = TransformerFactory.newInstance();
            // ok: java-xxe-in-transformerfactory
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            
            Transformer transformer = factory.newTransformer(new StreamSource(reader));
            
            StringWriter writer = new StringWriter();
            transformer.transform(new StreamSource(reader), new StreamResult(writer));
            
            response.getWriter().write(writer.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void good_case_2(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            InputStream xmlStream = request.getInputStream();
            
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            // ok: java-xxe-in-transformerfactory
            transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            
            Templates templates = transformerFactory.newTemplates(new StreamSource(xmlStream));
            
            Transformer transformer = templates.newTransformer();
            StringWriter output = new StringWriter();
            transformer.transform(new StreamSource(xmlStream), new StreamResult(output));
            
            response.getWriter().write(output.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void good_case_3(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlContent = request.getHeader("X-XML-Data");
            ByteArrayInputStream inputStream = new ByteArrayInputStream(xmlContent.getBytes());
            
            TransformerFactory factory = TransformerFactory.newInstance("com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl", null);
            // ok: java-xxe-in-transformerfactory
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            
            Transformer transformer = factory.newTransformer(new StreamSource(inputStream));
            
            StringWriter resultWriter = new StringWriter();
            transformer.transform(new StreamSource(inputStream), new StreamResult(resultWriter));
            
            response.getWriter().write(resultWriter.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void good_case_4(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlFile = request.getParameter("xmlFile");
            File file = new File(xmlFile);
            
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            // ok: java-xxe-in-transformerfactory
            transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            transformerFactory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            
            Templates templates = transformerFactory.newTemplates(new StreamSource(file));
            
            Transformer transformer = templates.newTransformer();
            StringWriter writer = new StringWriter();
            transformer.transform(new StreamSource(file), new StreamResult(writer));
            
            response.getWriter().write(writer.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void good_case_5(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlUrl = request.getParameter("url");
            URL url = new URL(xmlUrl);
            
            TransformerFactory factory = TransformerFactory.newInstance();
            // ok: java-xxe-in-transformerfactory
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            
            Transformer transformer = factory.newTransformer(new StreamSource(url.openStream()));
            
            StringWriter writer = new StringWriter();
            transformer.transform(new StreamSource(url.openStream()), new StreamResult(writer));
            
            response.getWriter().write(writer.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void good_case_6(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            
            // First secure the DocumentBuilderFactory
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document document = db.parse(new InputSource(new StringReader(xmlData)));
            
            // Then secure the TransformerFactory
            TransformerFactory factory = TransformerFactory.newInstance();
            // ok: java-xxe-in-transformerfactory
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            
            Transformer transformer = factory.newTransformer();
            
            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(document), new StreamResult(writer));
            
            response.getWriter().write(writer.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void good_case_7(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xsltData = request.getParameter("xslt");
            String xmlData = request.getParameter("xml");
            
            TransformerFactory factory = TransformerFactory.newInstance();
            // ok: java-xxe-in-transformerfactory
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            
            Transformer transformer = factory.newTransformer(new StreamSource(new StringReader(xsltData)));
            
            StringWriter writer = new StringWriter();
            transformer.transform(new StreamSource(new StringReader(xmlData)), new StreamResult(writer));
            
            response.getWriter().write(writer.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void good_case_8(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            Reader reader = new StringReader(xmlData);
            
            TransformerFactory factory = TransformerFactory.newInstance();
            // ok: java-xxe-in-transformerfactory
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            
            Templates templates = factory.newTemplates(new StreamSource(reader));
            
            Transformer transformer = templates.newTransformer();
            StringWriter writer = new StringWriter();
            transformer.transform(new StreamSource(reader), new StreamResult(writer));
            
            response.getWriter().write(writer.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void good_case_9(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            Part filePart = request.getPart("xmlFile");
            InputStream fileContent = filePart.getInputStream();
            
            TransformerFactory factory = TransformerFactory.newInstance();
            // ok: java-xxe-in-transformerfactory
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            
            Transformer transformer = factory.newTransformer(new StreamSource(fileContent));
            
            StringWriter writer = new StringWriter();
            transformer.transform(new StreamSource(fileContent), new StreamResult(writer));
            
            response.getWriter().write(writer.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void good_case_10(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            
            // Using a custom factory implementation with security settings
            TransformerFactory factory = TransformerFactory.newInstance("net.sf.saxon.TransformerFactoryImpl", null);
            // ok: java-xxe-in-transformerfactory
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            
            Transformer transformer = factory.newTransformer(new StreamSource(new StringReader(xmlData)));
            
            StringWriter writer = new StringWriter();
            transformer.transform(new StreamSource(new StringReader(xmlData)), new StreamResult(writer));
            
            response.getWriter().write(writer.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void good_case_11(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            
            // Using a system property to set secure processing
            System.setProperty(XMLConstants.FEATURE_SECURE_PROCESSING, "true");
            
            TransformerFactory factory = TransformerFactory.newInstance();
            // ok: java-xxe-in-transformerfactory
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            
            Transformer transformer = factory.newTransformer(new StreamSource(new StringReader(xmlData)));
            
            StringWriter writer = new StringWriter();
            transformer.transform(new StreamSource(new StringReader(xmlData)), new StreamResult(writer));
            
            response.getWriter().write(writer.toString());
            
            // Reset the system property
            System.clearProperty(XMLConstants.FEATURE_SECURE_PROCESSING);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void good_case_12(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            
            // Create a secure factory using a helper method
            TransformerFactory factory = createSecureTransformerFactory();
            // ok: java-xxe-in-transformerfactory
            Transformer transformer = factory.newTransformer(new StreamSource(new StringReader(xmlData)));
            
            StringWriter writer = new StringWriter();
            transformer.transform(new StreamSource(new StringReader(xmlData)), new StreamResult(writer));
            
            response.getWriter().write(writer.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private TransformerFactory createSecureTransformerFactory() throws TransformerConfigurationException {
        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
        return factory;
    }

    protected void good_case_13(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            
            // Load security settings from properties file
            Properties securityProps = new Properties();
            securityProps.load(getClass().getResourceAsStream("/security.properties"));
            
            TransformerFactory factory = TransformerFactory.newInstance();
            // ok: java-xxe-in-transformerfactory
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, Boolean.parseBoolean(securityProps.getProperty("xml.secure.processing", "true")));
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, securityProps.getProperty("xml.access.external.dtd", ""));
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, securityProps.getProperty("xml.access.external.stylesheet", ""));
            
            Transformer transformer = factory.newTransformer(new StreamSource(new StringReader(xmlData)));
            
            StringWriter writer = new StringWriter();
            transformer.transform(new StreamSource(new StringReader(xmlData)), new StreamResult(writer));
            
            response.getWriter().write(writer.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void good_case_14(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            
            // Using a different approach - disabling DTD processing completely
            TransformerFactory factory = TransformerFactory.newInstance();
            // ok: java-xxe-in-transformerfactory
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            
            Transformer transformer = factory.newTransformer(new StreamSource(new StringReader(xmlData)));
            
            StringWriter writer = new StringWriter();
            transformer.transform(new StreamSource(new StringReader(xmlData)), new StreamResult(writer));
            
            response.getWriter().write(writer.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void good_case_15(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String xmlData = request.getParameter("xml");
            
            // Using all available security features
            TransformerFactory factory = TransformerFactory.newInstance();
            // ok: java-xxe-in-transformerfactory
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.AC_REDACTED_TWILIO_ID_EXTERNAL_STYLESHEET, "");
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            
            Transformer transformer = factory.newTransformer(new StreamSource(new StringReader(xmlData)));
            
            StringWriter writer = new StringWriter();
            transformer.transform(new StreamSource(new StringReader(xmlData)), new StreamResult(writer));
            
            response.getWriter().write(writer.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
// {/fact}