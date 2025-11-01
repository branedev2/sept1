using System;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization;
using System.Collections.Generic;

namespace RegionInfoVulnerabilityExamples
{
    public class RegionInfoExamples
    {
// {fact rule=guru-cfn-lint@v1.0 defects=1}
        // True Positive Examples (Vulnerable Code)

        public static void bad_case_1()
        {
            // Creating RegionInfo with two-letter ISO code
            RegionInfo regionInfo = new RegionInfo("US");
            
            // Writing to named pipe
            using (NamedPipeServerStream pipeServer = new NamedPipeServerStream("regionpipe", PipeDirection.Out))
            {
                pipeServer.WaitForConnection();
                
                // ruleid: regioninfo-inter-process-write
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(pipeServer, regionInfo);
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}

        public static void bad_case_2()
        {
            // Creating RegionInfo with two-letter ISO code
            RegionInfo regionInfo = new RegionInfo("DE");
            
            // Writing to file for inter-process communication
            using (FileStream fs = new FileStream("region_data.bin", FileMode.Create))
            {
                // ruleid: regioninfo-inter-process-write
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(fs, regionInfo);
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}

        public static void bad_case_3()
        {
            // Creating RegionInfo with two-letter ISO code
            RegionInfo regionInfo = new RegionInfo("JP");
            
            // Using anonymous pipe for inter-process communication
            using (AnonymousPipeServerStream pipeServer = new AnonymousPipeServerStream(PipeDirection.Out))
            {
                string handleName = pipeServer.GetClientHandleAsString();
                Console.WriteLine("Child process should use this handle: {0}", handleName);
                
                // ruleid: regioninfo-inter-process-write
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(pipeServer, regionInfo);
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}

        public static void bad_case_4()
        {
            // Creating RegionInfo with two-letter ISO code from HTTP request
            string countryCode = "FR"; // Assume this comes from an HTTP request
            RegionInfo regionInfo = new RegionInfo(countryCode);
            
            // Sending over network stream
            using (TcpClient client = new TcpClient("localhost", 8080))
            using (NetworkStream stream = client.GetStream())
            {
                // ruleid: regioninfo-inter-process-write
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(stream, regionInfo);
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}

        public static void bad_case_5()
        {
            // Creating RegionInfo with two-letter ISO code
            RegionInfo regionInfo = new RegionInfo("IT");
            
            // Serializing to memory stream for later use in another process
            using (MemoryStream ms = new MemoryStream())
            {
                // ruleid: regioninfo-inter-process-write
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(ms, regionInfo);
                
                // Save to file for another process to read
                File.WriteAllBytes("region_data.bin", ms.ToArray());
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}

        public static void bad_case_6()
        {
            // Creating RegionInfo with two-letter ISO code
            RegionInfo regionInfo = new RegionInfo("CA");
            
            // Using DataContractSerializer for inter-process communication
            using (FileStream fs = new FileStream("region_contract.xml", FileMode.Create))
            {
                // ruleid: regioninfo-inter-process-write
                DataContractSerializer serializer = new DataContractSerializer(typeof(RegionInfo));
                serializer.WriteObject(fs, regionInfo);
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}

        public static void bad_case_7()
        {
            // Creating multiple RegionInfo objects with two-letter ISO codes
            List<RegionInfo> regions = new List<RegionInfo>
            {
                new RegionInfo("UK"),
                new RegionInfo("AU"),
                new RegionInfo("NZ")
            };
            
            // Serializing collection to file for inter-process use
            using (FileStream fs = new FileStream("region_collection.bin", FileMode.Create))
            {
                // ruleid: regioninfo-inter-process-write
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(fs, regions);
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}

        public static void bad_case_8()
        {
            // Creating RegionInfo with two-letter ISO code
            RegionInfo regionInfo = new RegionInfo("BR");
            
            // Using custom wrapper for serialization
            RegionInfoWrapper wrapper = new RegionInfoWrapper { Region = regionInfo };
            
            using (FileStream fs = new FileStream("wrapped_region.xml", FileMode.Create))
            {
                // ruleid: regioninfo-inter-process-write
                XmlSerializer serializer = new XmlSerializer(typeof(RegionInfoWrapper));
                serializer.Serialize(fs, wrapper);
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}

        public static void bad_case_9()
        {
            // Creating RegionInfo with two-letter ISO code
            RegionInfo regionInfo = new RegionInfo("MX");
            
            // Async pipe writing
            using (NamedPipeServerStream pipeServer = new NamedPipeServerStream("asyncregionpipe", PipeDirection.Out))
            {
                pipeServer.WaitForConnection();
                
                // ruleid: regioninfo-inter-process-write
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(pipeServer, regionInfo);
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}

        public static async Task bad_case_10()
        {
            // Creating RegionInfo with two-letter ISO code
            RegionInfo regionInfo = new RegionInfo("IN");
            
            // Using HTTP response to send RegionInfo to another process/system
            HttpListener listener = new HttpListener();
            listener.Prefixes.Add("http://localhost:8080/regions/");
            listener.Start();
            
            HttpListenerContext context = await listener.GetContextAsync();
            HttpListenerResponse response = context.Response;
            
            using (MemoryStream ms = new MemoryStream())
            {
                // ruleid: regioninfo-inter-process-write
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(ms, regionInfo);
                
                byte[] buffer = ms.ToArray();
                response.ContentLength64 = buffer.Length;
                response.OutputStream.Write(buffer, 0, buffer.Length);
            }
            
            listener.Stop();
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}

        public static void bad_case_11()
        {
            // Creating RegionInfo with two-letter ISO code
            RegionInfo regionInfo = new RegionInfo("RU");
            
            // Using custom serialization to byte array for inter-process communication
            using (MemoryStream ms = new MemoryStream())
            {
                // ruleid: regioninfo-inter-process-write
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(ms, regionInfo);
                
                byte[] serializedData = ms.ToArray();
                
                // Send over a socket or save to file
                File.WriteAllBytes("region_bytes.bin", serializedData);
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}

        public static void bad_case_12()
        {
            // Dictionary containing RegionInfo objects with two-letter ISO codes
            Dictionary<string, RegionInfo> regionMap = new Dictionary<string, RegionInfo>
            {
                { "United States", new RegionInfo("US") },
                { "Germany", new RegionInfo("DE") },
                { "Japan", new RegionInfo("JP") }
            };
            
            // Serializing dictionary to file for inter-process use
            using (FileStream fs = new FileStream("region_dictionary.bin", FileMode.Create))
            {
                // ruleid: regioninfo-inter-process-write
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(fs, regionMap);
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}

        public static void bad_case_13()
        {
            // Creating RegionInfo with two-letter ISO code
            RegionInfo regionInfo = new RegionInfo("CN");
            
            // Creating a custom object that contains RegionInfo
            CustomDataObject dataObject = new CustomDataObject
            {
                Name = "China Region",
                Region = regionInfo,
                Description = "Region information for China"
            };
            
            // Serializing to file for inter-process communication
            using (FileStream fs = new FileStream("custom_region_data.bin", FileMode.Create))
            {
                // ruleid: regioninfo-inter-process-write
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(fs, dataObject);
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}

        public static void bad_case_14()
        {
            // Creating RegionInfo with two-letter ISO code
            RegionInfo regionInfo = new RegionInfo("KR");
            
            // Using a memory-mapped file for inter-process communication
            using (MemoryMappedFile mmf = MemoryMappedFile.CreateNew("RegionInfoSharedMemory", 1024))
            using (MemoryMappedViewStream stream = mmf.CreateViewStream())
            {
                // ruleid: regioninfo-inter-process-write
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(stream, regionInfo);
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=1}

        public static void bad_case_15()
        {
            // Creating multiple RegionInfo objects with two-letter ISO codes
            RegionInfo[] regions = new RegionInfo[]
            {
                new RegionInfo("ES"),
                new RegionInfo("PT"),
                new RegionInfo("GR")
            };
            
            // Using a custom serialization method to write to pipe
            using (NamedPipeServerStream pipeServer = new NamedPipeServerStream("regionArrayPipe", PipeDirection.Out))
            {
                pipeServer.WaitForConnection();
                
                // ruleid: regioninfo-inter-process-write
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(pipeServer, regions);
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}

        // True Negative Examples (Secure Code)

        public static void good_case_1()
        {
            // Creating RegionInfo with full culture name instead of two-letter code
            // ok: regioninfo-inter-process-write
            RegionInfo regionInfo = new RegionInfo("en-US");
            
            // Writing to named pipe
            using (NamedPipeServerStream pipeServer = new NamedPipeServerStream("regionpipe", PipeDirection.Out))
            {
                pipeServer.WaitForConnection();
                
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(pipeServer, regionInfo);
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}

        public static void good_case_2()
        {
            // Creating RegionInfo with full culture name instead of two-letter code
            // ok: regioninfo-inter-process-write
            RegionInfo regionInfo = new RegionInfo("de-DE");
            
            // Writing to file for inter-process communication
            using (FileStream fs = new FileStream("region_data.bin", FileMode.Create))
            {
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(fs, regionInfo);
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}

        public static void good_case_3()
        {
            // Creating RegionInfo with full culture name instead of two-letter code
            // ok: regioninfo-inter-process-write
            RegionInfo regionInfo = new RegionInfo("ja-JP");
            
            // Using anonymous pipe for inter-process communication
            using (AnonymousPipeServerStream pipeServer = new AnonymousPipeServerStream(PipeDirection.Out))
            {
                string handleName = pipeServer.GetClientHandleAsString();
                Console.WriteLine("Child process should use this handle: {0}", handleName);
                
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(pipeServer, regionInfo);
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}

        public static void good_case_4()
        {
            // Instead of serializing RegionInfo, serialize only the necessary properties
            RegionInfo regionInfo = new RegionInfo("FR");
            
            // Create a custom object with just the needed properties
            RegionInfoDto dto = new RegionInfoDto
            {
                Name = regionInfo.Name,
                EnglishName = regionInfo.EnglishName,
                NativeName = regionInfo.NativeName,
                CurrencySymbol = regionInfo.CurrencySymbol
            };
            
            // ok: regioninfo-inter-process-write
            using (TcpClient client = new TcpClient("localhost", 8080))
            using (NetworkStream stream = client.GetStream())
            {
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(stream, dto);
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}

        public static void good_case_5()
        {
            // Creating RegionInfo with full culture name instead of two-letter code
            // ok: regioninfo-inter-process-write
            RegionInfo regionInfo = new RegionInfo("it-IT");
            
            // Serializing to memory stream for later use in another process
            using (MemoryStream ms = new MemoryStream())
            {
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(ms, regionInfo);
                
                // Save to file for another process to read
                File.WriteAllBytes("region_data.bin", ms.ToArray());
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}

        public static void good_case_6()
        {
            // Instead of serializing RegionInfo, serialize just the region name
            RegionInfo regionInfo = new RegionInfo("CA");
            string regionName = regionInfo.Name;
            
            // ok: regioninfo-inter-process-write
            using (FileStream fs = new FileStream("region_name.txt", FileMode.Create))
            using (StreamWriter writer = new StreamWriter(fs))
            {
                writer.Write(regionName);
            }
            
            // The other process can recreate the RegionInfo using the full name
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}

        public static void good_case_7()
        {
            // Creating multiple RegionInfo objects with full culture names
            // ok: regioninfo-inter-process-write
            List<RegionInfo> regions = new List<RegionInfo>
            {
                new RegionInfo("en-GB"),
                new RegionInfo("en-AU"),
                new RegionInfo("en-NZ")
            };
            
            // Serializing collection to file for inter-process use
            using (FileStream fs = new FileStream("region_collection.bin", FileMode.Create))
            {
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(fs, regions);
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}

        public static void good_case_8()
        {
            // Instead of serializing RegionInfo directly, serialize a DTO with the necessary properties
            RegionInfo regionInfo = new RegionInfo("BR");
            
            RegionInfoDto dto = new RegionInfoDto
            {
                Name = regionInfo.Name,
                EnglishName = regionInfo.EnglishName,
                NativeName = regionInfo.NativeName,
                CurrencySymbol = regionInfo.CurrencySymbol
            };
            
            // ok: regioninfo-inter-process-write
            using (FileStream fs = new FileStream("region_dto.xml", FileMode.Create))
            {
                XmlSerializer serializer = new XmlSerializer(typeof(RegionInfoDto));
                serializer.Serialize(fs, dto);
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}

        public static void good_case_9()
        {
            // Creating RegionInfo with full culture name instead of two-letter code
            // ok: regioninfo-inter-process-write
            RegionInfo regionInfo = new RegionInfo("es-MX");
            
            // Async pipe writing
            using (NamedPipeServerStream pipeServer = new NamedPipeServerStream("asyncregionpipe", PipeDirection.Out))
            {
                pipeServer.WaitForConnection();
                
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(pipeServer, regionInfo);
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}

        public static async Task good_case_10()
        {
            // Creating RegionInfo with full culture name instead of two-letter code
            // ok: regioninfo-inter-process-write
            RegionInfo regionInfo = new RegionInfo("hi-IN");
            
            // Using HTTP response to send RegionInfo to another process/system
            HttpListener listener = new HttpListener();
            listener.Prefixes.Add("http://localhost:8080/regions/");
            listener.Start();
            
            HttpListenerContext context = await listener.GetContextAsync();
            HttpListenerResponse response = context.Response;
            
            using (MemoryStream ms = new MemoryStream())
            {
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(ms, regionInfo);
                
                byte[] buffer = ms.ToArray();
                response.ContentLength64 = buffer.Length;
                response.OutputStream.Write(buffer, 0, buffer.Length);
            }
            
            listener.Stop();
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}

        public static void good_case_11()
        {
            // Instead of serializing RegionInfo, serialize just the necessary data
            RegionInfo regionInfo = new RegionInfo("RU");
            
            // Create a simple string representation
            string regionData = $"{regionInfo.Name},{regionInfo.EnglishName},{regionInfo.CurrencySymbol}";
            
            // ok: regioninfo-inter-process-write
            File.WriteAllText("region_data.csv", regionData);
            
            // The other process can parse this data and create a RegionInfo using the full name if needed
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}

        public static void good_case_12()
        {
            // Dictionary containing RegionInfo objects with full culture names
            // ok: regioninfo-inter-process-write
            Dictionary<string, RegionInfo> regionMap = new Dictionary<string, RegionInfo>
            {
                { "United States", new RegionInfo("en-US") },
                { "Germany", new RegionInfo("de-DE") },
                { "Japan", new RegionInfo("ja-JP") }
            };
            
            // Serializing dictionary to file for inter-process use
            using (FileStream fs = new FileStream("region_dictionary.bin", FileMode.Create))
            {
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(fs, regionMap);
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}

        public static void good_case_13()
        {
            // Creating RegionInfo with full culture name instead of two-letter code
            // ok: regioninfo-inter-process-write
            RegionInfo regionInfo = new RegionInfo("zh-CN");
            
            // Creating a custom object that contains RegionInfo
            CustomDataObject dataObject = new CustomDataObject
            {
                Name = "China Region",
                Region = regionInfo,
                Description = "Region information for China"
            };
            
            // Serializing to file for inter-process communication
            using (FileStream fs = new FileStream("custom_region_data.bin", FileMode.Create))
            {
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(fs, dataObject);
            }
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}

        public static void good_case_14()
        {
            // Instead of serializing RegionInfo, serialize just the name for reconstruction
            RegionInfo regionInfo = new RegionInfo("KR");
            string regionName = regionInfo.Name; // This is the full name, not the two-letter code
            
            // ok: regioninfo-inter-process-write
            using (MemoryMappedFile mmf = MemoryMappedFile.CreateNew("RegionInfoSharedMemory", 1024))
            using (MemoryMappedViewStream stream = mmf.CreateViewStream())
            using (BinaryWriter writer = new BinaryWriter(stream))
            {
                writer.Write(regionName);
            }
            
            // The other process can read the name and create a RegionInfo using the full name
        }
// {/fact}
// {fact rule=guru-cfn-lint@v1.0 defects=0}

        public static void good_case_15()
        {
            // Creating multiple RegionInfo objects with full culture names
            // ok: regioninfo-inter-process-write
            RegionInfo[] regions = new RegionInfo[]
            {
                new RegionInfo("es-ES"),
                new RegionInfo("pt-PT"),
                new RegionInfo("el-GR")
            };
            
            // Using a custom serialization method to write to pipe
            using (NamedPipeServerStream pipeServer = new NamedPipeServerStream("regionArrayPipe", PipeDirection.Out))
            {
                pipeServer.WaitForConnection();
                
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(pipeServer, regions);
            }
        }
// {/fact}
    }

    [Serializable]
    public class RegionInfoWrapper
    {
        public RegionInfo Region { get; set; }
    }

    [Serializable]
    public class RegionInfoDto
    {
        public string Name { get; set; }
        public string EnglishName { get; set; }
        public string NativeName { get; set; }
        public string CurrencySymbol { get; set; }
    }

    [Serializable]
    public class CustomDataObject
    {
        public string Name { get; set; }
        public RegionInfo Region { get; set; }
        public string Description { get; set; }
    }
}