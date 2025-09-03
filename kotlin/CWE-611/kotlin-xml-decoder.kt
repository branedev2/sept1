import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.parsers.SAXParserFactory
import org.xml.sax.InputSource
import java.io.StringReader
import javax.xml.stream.XMLInputFactory
import org.dom4j.io.SAXReader
import org.jdom2.input.SAXBuilder
import org.w3c.dom.Document
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import java.io.ByteArrayInputStream
import javax.xml.transform.stream.StreamSource
import javax.xml.validation.SchemaFactory
import org.xml.sax.helpers.XMLReaderFactory
import nu.xom.Builder
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import java.io.File

// True Positive Examples (Vulnerable Code)

// {fact rule=xml-external-entity@v1.0 defects=1}
@RestController
fun bad_case_1(request: HttpServletRequest, response: HttpServletResponse) {
    val xmlData = request.getParameter("xml")
    val dbf = DocumentBuilderFactory.newInstance()
    // ruleid: kotlin-xml-decoder
    val db = dbf.newDocumentBuilder()
    val doc = db.parse(InputSource(StringReader(xmlData)))
    response.writer.write(doc.documentElement.textContent)
}
// {/fact}

@RestController
@RequestMapping("/api")
class XmlController {
// {fact rule=xml-external-entity@v1.0 defects=1}
    @PostMapping("/parse")
    fun bad_case_2(@RequestBody xmlData: String): String {
        val factory = SAXParserFactory.newInstance()
        // ruleid: kotlin-xml-decoder
        val parser = factory.newSAXParser()
        val source = InputSource(StringReader(xmlData))
        val handler = CustomHandler()
        parser.parse(source, handler)
        return "XML processed"
    }
// {/fact}
}

class CustomHandler : org.xml.sax.helpers.DefaultHandler()

// {fact rule=xml-external-entity@v1.0 defects=1}
fun bad_case_3(request: HttpServletRequest): String {
    val xmlContent = request.getParameter("xmlContent")
    val reader = SAXReader()
    // ruleid: kotlin-xml-decoder
    val document = reader.read(StringReader(xmlContent))
    return document.rootElement.text
}
// {/fact}

@Controller
class XmlProcessingController {
// {fact rule=xml-external-entity@v1.0 defects=1}
    @RequestMapping("/process-xml")
    fun bad_case_4(request: HttpServletRequest): String {
        val xmlInput = request.getParameter("xml")
        val builder = SAXBuilder()
        // ruleid: kotlin-xml-decoder
        val document = builder.build(StringReader(xmlInput))
        return document.rootElement.text
    }
// {/fact}
}

// {fact rule=xml-external-entity@v1.0 defects=1}
fun bad_case_5(request: HttpServletRequest): String {
    val xmlData = request.getParameter("data")
    val inputFactory = XMLInputFactory.newInstance()
    // ruleid: kotlin-xml-decoder
    val reader = inputFactory.createXMLStreamReader(StringReader(xmlData))
    var result = ""
    while (reader.hasNext()) {
        reader.next()
        if (reader.isStartElement()) {
            result += reader.localName
        }
    }
    return result
}
// {/fact}

@RestController
class DocumentController {
// {fact rule=xml-external-entity@v1.0 defects=1}
    @PostMapping("/validate")
    fun bad_case_6(@RequestBody xmlContent: String): String {
        val factory = SchemaFactory.newInstance("http://www.w3.org/2001/XMLSchema")
        val stream = ByteArrayInputStream(xmlContent.toByteArray())
        // ruleid: kotlin-xml-decoder
        val schema = factory.newSchema(StreamSource(stream))
        return "Schema validated"
    }
// {/fact}
}

// {fact rule=xml-external-entity@v1.0 defects=1}
fun bad_case_7(request: HttpServletRequest): String {
    val xmlData = request.getParameter("xml")
    // ruleid: kotlin-xml-decoder
    val xmlReader = XMLReaderFactory.createXMLReader()
    val handler = CustomHandler()
    xmlReader.contentHandler = handler
    xmlReader.parse(InputSource(StringReader(xmlData)))
    return "XML parsed"
}
// {/fact}

@RestController
class XomController {
// {fact rule=xml-external-entity@v1.0 defects=1}
    @PostMapping("/xom-parse")
    fun bad_case_8(@RequestBody xmlData: String): String {
        val builder = Builder()
        // ruleid: kotlin-xml-decoder
        val document = builder.build(StringReader(xmlData))
        return document.query("/root").size.toString()
    }
// {/fact}
}

// {fact rule=xml-external-entity@v1.0 defects=1}
fun bad_case_9(request: HttpServletRequest): String {
    val xmlContent = request.getParameter("content")
    val dbf = DocumentBuilderFactory.newInstance()
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", true)
    // ruleid: kotlin-xml-decoder
    val db = dbf.newDocumentBuilder()
    val doc = db.parse(InputSource(StringReader(xmlContent)))
    return doc.documentElement.nodeName
}
// {/fact}

@RestController
class TransformController {
// {fact rule=xml-external-entity@v1.0 defects=1}
    @PostMapping("/transform")
    fun bad_case_10(@RequestBody xml: String): String {
        val factory = javax.xml.transform.TransformerFactory.newInstance()
        // ruleid: kotlin-xml-decoder
        val transformer = factory.newTransformer()
        val source = javax.xml.transform.stream.StreamSource(StringReader(xml))
        val result = javax.xml.transform.stream.StreamResult(StringWriter())
        transformer.transform(source, result)
        return result.writer.toString()
    }
// {/fact}
}

// {fact rule=xml-external-entity@v1.0 defects=1}
fun bad_case_11(request: HttpServletRequest): Document {
    val xmlData = request.getParameter("xml")
    val dbf = DocumentBuilderFactory.newInstance()
    dbf.isNamespaceAware = true
    // ruleid: kotlin-xml-decoder
    val db = dbf.newDocumentBuilder()
    return db.parse(ByteArrayInputStream(xmlData.toByteArray()))
}
// {/fact}

@Controller
class XPathController {
// {fact rule=xml-external-entity@v1.0 defects=1}
    @RequestMapping("/xpath")
    fun bad_case_12(@RequestParam xml: String): String {
        val dbf = DocumentBuilderFactory.newInstance()
        // ruleid: kotlin-xml-decoder
        val doc = dbf.newDocumentBuilder().parse(InputSource(StringReader(xml)))
        val xPath = javax.xml.xpath.XPathFactory.newInstance().newXPath()
        val expr = xPath.compile("/root/element")
        return expr.evaluate(doc)
    }
// {/fact}
}

// {fact rule=xml-external-entity@v1.0 defects=1}
fun bad_case_13(request: HttpServletRequest): String {
    val xmlContent = request.getParameter("xml")
    val factory = javax.xml.parsers.SAXParserFactory.newInstance()
    factory.isValidating = true
    // ruleid: kotlin-xml-decoder
    val parser = factory.newSAXParser()
    val handler = CustomHandler()
    parser.parse(InputSource(StringReader(xmlContent)), handler)
    return "Parsed with validation"
}
// {/fact}

@RestController
class StAXController {
// {fact rule=xml-external-entity@v1.0 defects=1}
    @PostMapping("/stax-process")
    fun bad_case_14(@RequestBody xml: String): String {
        val factory = javax.xml.stream.XMLInputFactory.newInstance()
        // ruleid: kotlin-xml-decoder
        val eventReader = factory.createXMLEventReader(StringReader(xml))
        var result = ""
        while (eventReader.hasNext()) {
            val event = eventReader.nextEvent()
            if (event.isStartElement()) {
                result += event.asStartElement().name.localPart + " "
            }
        }
        return result
    }
// {/fact}
}

// {fact rule=xml-external-entity@v1.0 defects=1}
fun bad_case_15(request: HttpServletRequest): String {
    val xmlData = request.getParameter("data")
    val dbf = DocumentBuilderFactory.newInstance()
    dbf.isExpandEntityReferences = true
    // ruleid: kotlin-xml-decoder
    val doc = dbf.newDocumentBuilder().parse(InputSource(StringReader(xmlData)))
    return doc.documentElement.getAttribute("id")
}
// {/fact}

// True Negative Examples (Secure Code)

// {fact rule=xml-external-entity@v1.0 defects=0}
@RestController
fun good_case_1(request: HttpServletRequest, response: HttpServletResponse) {
    val xmlData = request.getParameter("xml")
    val dbf = DocumentBuilderFactory.newInstance()
    // ok: kotlin-xml-decoder
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", false)
    dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
    val db = dbf.newDocumentBuilder()
    val doc = db.parse(InputSource(StringReader(xmlData)))
    response.writer.write(doc.documentElement.textContent)
}
// {/fact}

@RestController
@RequestMapping("/api")
class SecureXmlController {
// {fact rule=xml-external-entity@v1.0 defects=0}
    @PostMapping("/parse")
    fun good_case_2(@RequestBody xmlData: String): String {
        val factory = SAXParserFactory.newInstance()
        // ok: kotlin-xml-decoder
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
        val parser = factory.newSAXParser()
        val source = InputSource(StringReader(xmlData))
        val handler = CustomHandler()
        parser.parse(source, handler)
        return "XML processed securely"
    }
// {/fact}
}

// {fact rule=xml-external-entity@v1.0 defects=0}
fun good_case_3(request: HttpServletRequest): String {
    val xmlContent = request.getParameter("xmlContent")
    val reader = SAXReader()
    // ok: kotlin-xml-decoder
    reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    reader.setFeature("http://xml.org/sax/features/external-general-entities", false)
    reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
    val document = reader.read(StringReader(xmlContent))
    return document.rootElement.text
}
// {/fact}

@Controller
class SecureXmlProcessingController {
// {fact rule=xml-external-entity@v1.0 defects=0}
    @RequestMapping("/process-xml")
    fun good_case_4(request: HttpServletRequest): String {
        val xmlInput = request.getParameter("xml")
        val builder = SAXBuilder()
        // ok: kotlin-xml-decoder
        builder.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        builder.setFeature("http://xml.org/sax/features/external-general-entities", false)
        builder.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
        val document = builder.build(StringReader(xmlInput))
        return document.rootElement.text
    }
// {/fact}
}

// {fact rule=xml-external-entity@v1.0 defects=0}
fun good_case_5(request: HttpServletRequest): String {
    val xmlData = request.getParameter("data")
    val inputFactory = XMLInputFactory.newInstance()
    // ok: kotlin-xml-decoder
    inputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false)
    inputFactory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)
    val reader = inputFactory.createXMLStreamReader(StringReader(xmlData))
    var result = ""
    while (reader.hasNext()) {
        reader.next()
        if (reader.isStartElement()) {
            result += reader.localName
        }
    }
    return result
}
// {/fact}

@RestController
class SecureDocumentController {
// {fact rule=xml-external-entity@v1.0 defects=0}
    @PostMapping("/validate")
    fun good_case_6(@RequestBody xmlContent: String): String {
        val factory = SchemaFactory.newInstance("http://www.w3.org/2001/XMLSchema")
        // ok: kotlin-xml-decoder
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false)
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        val stream = ByteArrayInputStream(xmlContent.toByteArray())
        val schema = factory.newSchema(StreamSource(stream))
        return "Schema validated securely"
    }
// {/fact}
}

// {fact rule=xml-external-entity@v1.0 defects=0}
fun good_case_7(request: HttpServletRequest): String {
    val xmlData = request.getParameter("xml")
    val xmlReader = XMLReaderFactory.createXMLReader()
    // ok: kotlin-xml-decoder
    xmlReader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    xmlReader.setFeature("http://xml.org/sax/features/external-general-entities", false)
    xmlReader.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
    val handler = CustomHandler()
    xmlReader.contentHandler = handler
    xmlReader.parse(InputSource(StringReader(xmlData)))
    return "XML parsed securely"
}
// {/fact}

@RestController
class SecureXomController {
// {fact rule=xml-external-entity@v1.0 defects=0}
    @PostMapping("/xom-parse")
    fun good_case_8(@RequestBody xmlData: String): String {
        // ok: kotlin-xml-decoder
        val parser = org.xml.sax.helpers.XMLReaderFactory.createXMLReader()
        parser.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        parser.setFeature("http://xml.org/sax/features/external-general-entities", false)
        val builder = Builder(parser)
        val document = builder.build(StringReader(xmlData))
        return document.query("/root").size.toString()
    }
// {/fact}
}

// {fact rule=xml-external-entity@v1.0 defects=0}
fun good_case_9(request: HttpServletRequest): String {
    val xmlContent = request.getParameter("content")
    val dbf = DocumentBuilderFactory.newInstance()
    // ok: kotlin-xml-decoder
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", false)
    dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
    dbf.setXIncludeAware(false)
    dbf.setExpandEntityReferences(false)
    val db = dbf.newDocumentBuilder()
    val doc = db.parse(InputSource(StringReader(xmlContent)))
    return doc.documentElement.nodeName
}
// {/fact}

@RestController
class SecureTransformController {
// {fact rule=xml-external-entity@v1.0 defects=0}
    @PostMapping("/transform")
    fun good_case_10(@RequestBody xml: String): String {
        val factory = javax.xml.transform.TransformerFactory.newInstance()
        // ok: kotlin-xml-decoder
        factory.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD, "")
        factory.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "")
        val transformer = factory.newTransformer()
        val source = javax.xml.transform.stream.StreamSource(StringReader(xml))
        val result = javax.xml.transform.stream.StreamResult(StringWriter())
        transformer.transform(source, result)
        return result.writer.toString()
    }
// {/fact}
}

// {fact rule=xml-external-entity@v1.0 defects=0}
fun good_case_11(request: HttpServletRequest): Document {
    val xmlData = request.getParameter("xml")
    val dbf = DocumentBuilderFactory.newInstance()
    // ok: kotlin-xml-decoder
    dbf.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD, "")
    dbf.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_SCHEMA, "")
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    val db = dbf.newDocumentBuilder()
    return db.parse(ByteArrayInputStream(xmlData.toByteArray()))
}
// {/fact}

@Controller
class SecureXPathController {
// {fact rule=xml-external-entity@v1.0 defects=0}
    @RequestMapping("/xpath")
    fun good_case_12(@RequestParam xml: String): String {
        val dbf = DocumentBuilderFactory.newInstance()
        // ok: kotlin-xml-decoder
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false)
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
        val doc = dbf.newDocumentBuilder().parse(InputSource(StringReader(xml)))
        val xPath = javax.xml.xpath.XPathFactory.newInstance().newXPath()
        val expr = xPath.compile("/root/element")
        return expr.evaluate(doc)
    }
// {/fact}
}

// {fact rule=xml-external-entity@v1.0 defects=0}
fun good_case_13(request: HttpServletRequest): String {
    val xmlContent = request.getParameter("xml")
    val factory = javax.xml.parsers.SAXParserFactory.newInstance()
    // ok: kotlin-xml-decoder
    factory.setFeature(javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING, true)
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
    val parser = factory.newSAXParser()
    val handler = CustomHandler()
    parser.parse(InputSource(StringReader(xmlContent)), handler)
    return "Parsed with validation securely"
}
// {/fact}

@RestController
class SecureStAXController {
// {fact rule=xml-external-entity@v1.0 defects=0}
    @PostMapping("/stax-process")
    fun good_case_14(@RequestBody xml: String): String {
        val factory = javax.xml.stream.XMLInputFactory.newInstance()
        // ok: kotlin-xml-decoder
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false)
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)
        factory.setProperty(XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, false)
        val eventReader = factory.createXMLEventReader(StringReader(xml))
        var result = ""
        while (eventReader.hasNext()) {
            val event = eventReader.nextEvent()
            if (event.isStartElement()) {
                result += event.asStartElement().name.localPart + " "
            }
        }
        return result
    }
// {/fact}
}

// {fact rule=xml-external-entity@v1.0 defects=0}
fun good_case_15(request: HttpServletRequest): String {
    val xmlData = request.getParameter("data")
    val dbf = DocumentBuilderFactory.newInstance()
    // ok: kotlin-xml-decoder
    dbf.isExpandEntityReferences = false
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", false)
    dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
    val doc = dbf.newDocumentBuilder().parse(InputSource(StringReader(xmlData)))
    return doc.documentElement.getAttribute("id")
}
// {/fact}