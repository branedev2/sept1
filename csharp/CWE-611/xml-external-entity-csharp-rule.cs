using System;
using System.IO;
using System.Net;
using System.Text;
using System.Xml;
using System.Xml.Schema;
using System.Xml.Serialization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace XxeVulnerabilityExamples
{
    public class XxeController : Controller
    {
// {fact rule=xml-external-entity@v1.0 defects=1}
        // True Positive Examples (Vulnerable Code)

        public void bad_case_1()
        {
            // Get XML from request
            string xmlData = Request.Form["xmlData"];
            
            // Create XmlReader with default resolver (vulnerable)
            XmlReaderSettings settings = new XmlReaderSettings();
            // ruleid: xml-external-entity-csharp-rule
            settings.DtdProcessing = DtdProcessing.Parse;
            
            using (StringReader stringReader = new StringReader(xmlData))
            using (XmlReader reader = XmlReader.Create(stringReader, settings))
            {
                while (reader.Read())
                {
                    // Process XML data
                }
            }
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

        public void bad_case_2()
        {
            // Get XML from query string
            string xmlData = Request.Query["xml"];
            
            XmlReaderSettings settings = new XmlReaderSettings();
            // ruleid: xml-external-entity-csharp-rule
            settings.DtdProcessing = DtdProcessing.Parse;
            settings.XmlResolver = new XmlUrlResolver(); // Explicitly setting resolver
            
            using (StringReader sr = new StringReader(xmlData))
            using (XmlReader reader = XmlReader.Create(sr, settings))
            {
                XmlDocument doc = new XmlDocument();
                doc.Load(reader);
                // Process document
            }
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

        public void bad_case_3()
        {
            // Get XML from request body
            string xmlData = "";
            using (StreamReader reader = new StreamReader(Request.Body))
            {
                xmlData = reader.ReadToEnd();
            }
            
            // ruleid: xml-external-entity-csharp-rule
            XmlDocument doc = new XmlDocument();
            doc.XmlResolver = new XmlUrlResolver(); // Default resolver is vulnerable
            doc.LoadXml(xmlData);
            
            // Process XML document
            string value = doc.SelectSingleNode("//data").InnerText;
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

        public void bad_case_4()
        {
            // Get XML from request header
            string xmlData = Request.Headers["X-Xml-Data"];
            
            XmlReaderSettings settings = new XmlReaderSettings();
            // ruleid: xml-external-entity-csharp-rule
            settings.DtdProcessing = DtdProcessing.Parse;
            settings.ValidationType = ValidationType.None;
            
            using (StringReader stringReader = new StringReader(xmlData))
            using (XmlReader reader = XmlReader.Create(stringReader, settings))
            {
                XmlDocument doc = new XmlDocument();
                doc.Load(reader);
                // Process document
            }
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

        public void bad_case_5()
        {
            // Get XML from cookie
            string xmlData = Request.Cookies["xmlData"];
            
            // ruleid: xml-external-entity-csharp-rule
            XmlTextReader reader = new XmlTextReader(new StringReader(xmlData));
            reader.DtdProcessing = DtdProcessing.Parse;
            
            while (reader.Read())
            {
                // Process XML data
            }
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

        public void bad_case_6(HttpRequest request)
        {
            // Get XML from request
            string xmlData = "";
            using (StreamReader reader = new StreamReader(request.Body))
            {
                xmlData = reader.ReadToEnd();
            }
            
            XmlReaderSettings settings = new XmlReaderSettings();
            // ruleid: xml-external-entity-csharp-rule
            settings.DtdProcessing = DtdProcessing.Parse;
            settings.ValidationType = ValidationType.DTD;
            
            using (StringReader stringReader = new StringReader(xmlData))
            using (XmlReader reader = XmlReader.Create(stringReader, settings))
            {
                // Process XML
                while (reader.Read()) { }
            }
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

        public void bad_case_7()
        {
            // Get XML from request
            string xmlData = Request.Form["data"];
            
            // ruleid: xml-external-entity-csharp-rule
            XmlDocument doc = new XmlDocument();
            doc.XmlResolver = new XmlUrlResolver();
            doc.LoadXml(xmlData);
            
            // Use the document
            string result = doc.DocumentElement.InnerText;
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

        public void bad_case_8()
        {
            // Get XML from request
            string xmlData = Request.Query["xml"];
            
            // Create settings with unsafe configuration
            XmlReaderSettings settings = new XmlReaderSettings();
            // ruleid: xml-external-entity-csharp-rule
            settings.DtdProcessing = DtdProcessing.Parse;
            settings.ConformanceLevel = ConformanceLevel.Document;
            
            // Process XML
            using (StringReader sr = new StringReader(xmlData))
            using (XmlReader reader = XmlReader.Create(sr, settings))
            {
                while (reader.Read())
                {
                    // Process nodes
                }
            }
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

        public void bad_case_9()
        {
            // Get XML from request
            string xmlData = "";
            using (StreamReader reader = new StreamReader(Request.Body))
            {
                xmlData = reader.ReadToEnd();
            }
            
            // ruleid: xml-external-entity-csharp-rule
            XmlTextReader reader = new XmlTextReader(xmlData, XmlNodeType.Document, null);
            reader.DtdProcessing = DtdProcessing.Parse;
            
            XmlDocument doc = new XmlDocument();
            doc.Load(reader);
            
            // Process document
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

        public void bad_case_10()
        {
            // Get XML from request
            string xmlData = Request.Headers["Content-Data"];
            
            XmlReaderSettings settings = new XmlReaderSettings();
            // ruleid: xml-external-entity-csharp-rule
            settings.DtdProcessing = DtdProcessing.Parse;
            settings.IgnoreComments = true;
            settings.IgnoreWhitespace = true;
            
            using (StringReader sr = new StringReader(xmlData))
            using (XmlReader reader = XmlReader.Create(sr, settings))
            {
                // Process XML
                while (reader.Read()) { }
            }
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

        public void bad_case_11()
        {
            // Get XML from request
            string xmlData = Request.Form["xmlPayload"];
            
            // ruleid: xml-external-entity-csharp-rule
            XmlDocument doc = new XmlDocument { XmlResolver = new XmlUrlResolver() };
            doc.LoadXml(xmlData);
            
            // Process document
            string value = doc.SelectSingleNode("//root/element").InnerText;
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

        public void bad_case_12()
        {
            // Get XML from request
            string xmlData = Request.Query["data"];
            
            XmlReaderSettings settings = new XmlReaderSettings();
            // ruleid: xml-external-entity-csharp-rule
            settings.DtdProcessing = DtdProcessing.Parse;
            settings.CheckCharacters = true;
            
            using (StringReader sr = new StringReader(xmlData))
            using (XmlReader reader = XmlReader.Create(sr, settings))
            {
                XmlDocument doc = new XmlDocument();
                doc.Load(reader);
                // Process document
            }
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

        public void bad_case_13()
        {
            // Get XML from request
            string xmlData = Request.Cookies["data"];
            
            // ruleid: xml-external-entity-csharp-rule
            XmlTextReader reader = new XmlTextReader(new StringReader(xmlData)) {
                DtdProcessing = DtdProcessing.Parse,
                WhitespaceHandling = WhitespaceHandling.None
            };
            
            while (reader.Read())
            {
                // Process XML
            }
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

        public void bad_case_14()
        {
            // Get XML from request
            string xmlData = "";
            using (StreamReader reader = new StreamReader(Request.Body))
            {
                xmlData = reader.ReadToEnd();
            }
            
            XmlReaderSettings settings = new XmlReaderSettings();
            // ruleid: xml-external-entity-csharp-rule
            settings.DtdProcessing = DtdProcessing.Parse;
            settings.MaxCharactersInDocument = 1000000;
            
            using (StringReader sr = new StringReader(xmlData))
            using (XmlReader reader = XmlReader.Create(sr, settings))
            {
                // Process XML
                while (reader.Read()) { }
            }
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=1}

        public void bad_case_15()
        {
            // Get XML from request
            string xmlData = Request.Headers["X-Custom-Xml"];
            
            // ruleid: xml-external-entity-csharp-rule
            XmlDocument doc = new XmlDocument();
            doc.XmlResolver = new XmlUrlResolver();
            
            // Load potentially dangerous XML
            doc.LoadXml(xmlData);
            
            // Process document
            string result = doc.InnerText;
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

        // True Negative Examples (Secure Code)

        public void good_case_1()
        {
            // Get XML from request
            string xmlData = Request.Form["xmlData"];
            
            XmlReaderSettings settings = new XmlReaderSettings();
            // ok: xml-external-entity-csharp-rule
            settings.DtdProcessing = DtdProcessing.Prohibit;
            settings.XmlResolver = null;
            
            using (StringReader stringReader = new StringReader(xmlData))
            using (XmlReader reader = XmlReader.Create(stringReader, settings))
            {
                while (reader.Read())
                {
                    // Process XML data safely
                }
            }
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

        public void good_case_2()
        {
            // Get XML from query string
            string xmlData = Request.Query["xml"];
            
            XmlReaderSettings settings = new XmlReaderSettings();
            // ok: xml-external-entity-csharp-rule
            settings.DtdProcessing = DtdProcessing.Prohibit;
            
            using (StringReader sr = new StringReader(xmlData))
            using (XmlReader reader = XmlReader.Create(sr, settings))
            {
                XmlDocument doc = new XmlDocument();
                doc.Load(reader);
                // Process document safely
            }
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

        public void good_case_3()
        {
            // Get XML from request body
            string xmlData = "";
            using (StreamReader reader = new StreamReader(Request.Body))
            {
                xmlData = reader.ReadToEnd();
            }
            
            // ok: xml-external-entity-csharp-rule
            XmlDocument doc = new XmlDocument();
            doc.XmlResolver = null; // Disable external entity resolution
            doc.LoadXml(xmlData);
            
            // Process XML document safely
            string value = doc.SelectSingleNode("//data").InnerText;
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

        public void good_case_4()
        {
            // Get XML from request header
            string xmlData = Request.Headers["X-Xml-Data"];
            
            XmlReaderSettings settings = new XmlReaderSettings();
            // ok: xml-external-entity-csharp-rule
            settings.DtdProcessing = DtdProcessing.Prohibit;
            settings.XmlResolver = null;
            settings.ValidationType = ValidationType.None;
            
            using (StringReader stringReader = new StringReader(xmlData))
            using (XmlReader reader = XmlReader.Create(stringReader, settings))
            {
                XmlDocument doc = new XmlDocument();
                doc.Load(reader);
                // Process document safely
            }
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

        public void good_case_5()
        {
            // Get XML from cookie
            string xmlData = Request.Cookies["xmlData"];
            
            XmlReaderSettings settings = new XmlReaderSettings();
            // ok: xml-external-entity-csharp-rule
            settings.DtdProcessing = DtdProcessing.Prohibit;
            
            using (StringReader stringReader = new StringReader(xmlData))
            using (XmlReader reader = XmlReader.Create(stringReader, settings))
            {
                while (reader.Read())
                {
                    // Process XML data safely
                }
            }
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

        public void good_case_6(HttpRequest request)
        {
            // Get XML from request
            string xmlData = "";
            using (StreamReader reader = new StreamReader(request.Body))
            {
                xmlData = reader.ReadToEnd();
            }
            
            // ok: xml-external-entity-csharp-rule
            XmlReaderSettings settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                ValidationType = ValidationType.None
            };
            
            using (StringReader stringReader = new StringReader(xmlData))
            using (XmlReader reader = XmlReader.Create(stringReader, settings))
            {
                // Process XML safely
                while (reader.Read()) { }
            }
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

        public void good_case_7()
        {
            // Get XML from request
            string xmlData = Request.Form["data"];
            
            // ok: xml-external-entity-csharp-rule
            XmlDocument doc = new XmlDocument { XmlResolver = null };
            doc.LoadXml(xmlData);
            
            // Use the document safely
            string result = doc.DocumentElement.InnerText;
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

        public void good_case_8()
        {
            // Get XML from request
            string xmlData = Request.Query["xml"];
            
            // Create settings with safe configuration
            XmlReaderSettings settings = new XmlReaderSettings();
            // ok: xml-external-entity-csharp-rule
            settings.DtdProcessing = DtdProcessing.Prohibit;
            settings.XmlResolver = null;
            settings.ConformanceLevel = ConformanceLevel.Document;
            
            // Process XML safely
            using (StringReader sr = new StringReader(xmlData))
            using (XmlReader reader = XmlReader.Create(sr, settings))
            {
                while (reader.Read())
                {
                    // Process nodes safely
                }
            }
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

        public void good_case_9()
        {
            // Get XML from request
            string xmlData = "";
            using (StreamReader reader = new StreamReader(Request.Body))
            {
                xmlData = reader.ReadToEnd();
            }
            
            XmlReaderSettings settings = new XmlReaderSettings();
            // ok: xml-external-entity-csharp-rule
            settings.DtdProcessing = DtdProcessing.Ignore;
            settings.XmlResolver = null;
            
            using (StringReader sr = new StringReader(xmlData))
            using (XmlReader reader = XmlReader.Create(sr, settings))
            {
                XmlDocument doc = new XmlDocument();
                doc.Load(reader);
                // Process document safely
            }
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

        public void good_case_10()
        {
            // Get XML from request
            string xmlData = Request.Headers["Content-Data"];
            
            // ok: xml-external-entity-csharp-rule
            XmlReaderSettings settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                IgnoreComments = true,
                IgnoreWhitespace = true
            };
            
            using (StringReader sr = new StringReader(xmlData))
            using (XmlReader reader = XmlReader.Create(sr, settings))
            {
                // Process XML safely
                while (reader.Read()) { }
            }
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

        public void good_case_11()
        {
            // Get XML from request
            string xmlData = Request.Form["xmlPayload"];
            
            // Create a secure XmlDocument
            // ok: xml-external-entity-csharp-rule
            XmlDocument doc = new XmlDocument();
            doc.XmlResolver = null; // Disable external entity resolution
            
            // Load XML safely
            doc.LoadXml(xmlData);
            
            // Process document
            string value = doc.SelectSingleNode("//root/element").InnerText;
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

        public void good_case_12()
        {
            // Get XML from request
            string xmlData = Request.Query["data"];
            
            // Use XDocument instead which is safer by default
            // ok: xml-external-entity-csharp-rule
            var doc = System.Xml.Linq.XDocument.Parse(xmlData);
            
            // Process the document safely
            var elements = doc.Descendants("element");
            foreach (var element in elements)
            {
                // Process elements
            }
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

        public void good_case_13()
        {
            // Get XML from request
            string xmlData = Request.Cookies["data"];
            
            XmlReaderSettings settings = new XmlReaderSettings();
            // ok: xml-external-entity-csharp-rule
            settings.DtdProcessing = DtdProcessing.Prohibit;
            settings.XmlResolver = null;
            settings.ValidationType = ValidationType.None;
            settings.CheckCharacters = true;
            
            using (StringReader sr = new StringReader(xmlData))
            using (XmlReader reader = XmlReader.Create(sr, settings))
            {
                // Process XML safely
                while (reader.Read()) { }
            }
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

        public void good_case_14()
        {
            // Get XML from request
            string xmlData = "";
            using (StreamReader reader = new StreamReader(Request.Body))
            {
                xmlData = reader.ReadToEnd();
            }
            
            // ok: xml-external-entity-csharp-rule
            XmlReaderSettings settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = 1000000
            };
            
            using (StringReader sr = new StringReader(xmlData))
            using (XmlReader reader = XmlReader.Create(sr, settings))
            {
                // Process XML safely
                while (reader.Read()) { }
            }
        }
// {/fact}
// {fact rule=xml-external-entity@v1.0 defects=0}

        public void good_case_15()
        {
            // Get XML from request
            string xmlData = Request.Headers["X-Custom-Xml"];
            
            // Create a secure serializer
            // ok: xml-external-entity-csharp-rule
            XmlSerializer serializer = new XmlSerializer(typeof(MyDataClass));
            
            using (StringReader reader = new StringReader(xmlData))
            {
                // Deserialize safely
                var result = (MyDataClass)serializer.Deserialize(reader);
                // Process result
            }
        }
// {/fact}
    }

    public class MyDataClass
    {
        public string Property1 { get; set; }
        public int Property2 { get; set; }
    }
}