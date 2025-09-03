using System;
using System.IO;
using System.Data.SqlClient;
using System.Net;
using System.Net.Sockets;
using Microsoft.Win32;
using System.Drawing;
using System.Threading;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Xml;

namespace ResourceLeakExamples
{
    public class ResourceLeakCases
    {
// {fact rule=improper-resource-shutdown@v1.0 defects=1}
        // True Positives (Vulnerable Code)

        public void bad_case_1()
        {
            // File resource leak - not closing the stream
            FileStream fs = new FileStream("data.txt", FileMode.Open);
            byte[] data = new byte[1024];
            // ruleid: resource-leak-csharp-rule
            fs.Read(data, 0, data.Length);
            // No fs.Close() or fs.Dispose() call
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=1}

        public void bad_case_2()
        {
            // Database connection leak
            SqlConnection connection = new SqlConnection("Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;");
            // ruleid: resource-leak-csharp-rule
            connection.Open();
            SqlCommand command = new SqlCommand("SELECT * FROM Users", connection);
            SqlDataReader reader = command.ExecuteReader();
            // No connection.Close() or connection.Dispose()
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=1}

        public void bad_case_3()
        {
            // Socket resource leak
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            // ruleid: resource-leak-csharp-rule
            socket.Connect(new IPEndPoint(IPAddress.Parse("127.0.0.1"), 8080));
            byte[] buffer = new byte[1024];
            socket.Receive(buffer);
            // No socket.Close() or socket.Dispose()
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=1}

        public void bad_case_4()
        {
            // Registry key leak
            RegistryKey key = Registry.LocalMachine.OpenSubKey("Software");
            // ruleid: resource-leak-csharp-rule
            string[] valueNames = key.GetValueNames();
            foreach (string name in valueNames)
            {
                Console.WriteLine(name);
            }
            // No key.Close() or key.Dispose()
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=1}

        public void bad_case_5()
        {
            // Graphics resource leak
            Bitmap bitmap = new Bitmap(100, 100);
            // ruleid: resource-leak-csharp-rule
            Graphics graphics = Graphics.FromImage(bitmap);
            graphics.DrawLine(new Pen(Color.Black), 0, 0, 100, 100);
            // No graphics.Dispose()
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=1}

        public void bad_case_6()
        {
            // Multiple resource leaks in try block
            try
            {
                FileStream fs = new FileStream("data.txt", FileMode.Open);
                StreamReader reader = new StreamReader(fs);
                // ruleid: resource-leak-csharp-rule
                string content = reader.ReadToEnd();
                Console.WriteLine(content);
                // No reader.Close() or fs.Close()
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=1}

        public void bad_case_7()
        {
            // Mutex resource leak
            Mutex mutex = new Mutex(true, "MyMutex");
            // ruleid: resource-leak-csharp-rule
            bool acquired = mutex.WaitOne(TimeSpan.FromSeconds(5));
            if (acquired)
            {
                Console.WriteLine("Mutex acquired");
                // No mutex.ReleaseMutex() call
            }
            // No mutex.Close() or mutex.Dispose()
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=1}

        public void bad_case_8()
        {
            // Cryptographic resource leak
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            // ruleid: resource-leak-csharp-rule
            byte[] encrypted = rsa.Encrypt(new byte[] { 1, 2, 3 }, false);
            // No rsa.Dispose()
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=1}

        public void bad_case_9()
        {
            // XML resource leak
            XmlTextReader reader = new XmlTextReader("data.xml");
            // ruleid: resource-leak-csharp-rule
            while (reader.Read())
            {
                Console.WriteLine(reader.Name);
            }
            // No reader.Close() or reader.Dispose()
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=1}

        public void bad_case_10()
        {
            // Memory stream leak in conditional
            MemoryStream ms = new MemoryStream();
            // ruleid: resource-leak-csharp-rule
            if (DateTime.Now.Hour > 12)
            {
                byte[] data = new byte[] { 1, 2, 3 };
                ms.Write(data, 0, data.Length);
                return; // Early return without closing the stream
            }
            // No ms.Close() or ms.Dispose() in all code paths
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=1}

        public void bad_case_11()
        {
            // Resource leak in loop
            for (int i = 0; i < 5; i++)
            {
                // ruleid: resource-leak-csharp-rule
                StreamWriter writer = new StreamWriter($"file{i}.txt");
                writer.WriteLine($"Data for file {i}");
                // No writer.Close() or writer.Dispose() inside the loop
            }
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=1}

        public void bad_case_12()
        {
            // SqlTransaction resource leak
            SqlConnection connection = new SqlConnection("connection_string");
            connection.Open();
            // ruleid: resource-leak-csharp-rule
            SqlTransaction transaction = connection.BeginTransaction();
            SqlCommand command = new SqlCommand("INSERT INTO Table VALUES (1)", connection, transaction);
            command.ExecuteNonQuery();
            // No transaction.Commit() or transaction.Rollback()
            connection.Close();
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=1}

        public void bad_case_13()
        {
            // WebClient resource leak
            WebClient client = new WebClient();
            // ruleid: resource-leak-csharp-rule
            string data = client.DownloadString("http://example.com");
            Console.WriteLine(data);
            // No client.Dispose()
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=1}

        public void bad_case_14()
        {
            // Timer resource leak
            Timer timer = new Timer(state => Console.WriteLine("Timer callback"), null, 0, 1000);
            // ruleid: resource-leak-csharp-rule
            Console.WriteLine("Timer started");
            // No timer.Dispose()
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=1}

        public void bad_case_15()
        {
            // Dictionary enumerator leak
            Dictionary<string, int> dict = new Dictionary<string, int>
            {
                { "one", 1 },
                { "two", 2 }
            };
            // ruleid: resource-leak-csharp-rule
            IEnumerator<KeyValuePair<string, int>> enumerator = dict.GetEnumerator();
            while (enumerator.MoveNext())
            {
                Console.WriteLine(enumerator.Current);
            }
            // No enumerator.Dispose() for IEnumerator<T>
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=0}

        // True Negatives (Safe Code)

        public void good_case_1()
        {
            // Properly closing file stream with using statement
            // ok: resource-leak-csharp-rule
            using (FileStream fs = new FileStream("data.txt", FileMode.Open))
            {
                byte[] data = new byte[1024];
                fs.Read(data, 0, data.Length);
            } // Automatically calls Dispose
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=0}

        public void good_case_2()
        {
            // Properly closing database connection with using statement
            // ok: resource-leak-csharp-rule
            using (SqlConnection connection = new SqlConnection("Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;"))
            {
                connection.Open();
                SqlCommand command = new SqlCommand("SELECT * FROM Users", connection);
                SqlDataReader reader = command.ExecuteReader();
                while (reader.Read())
                {
                    Console.WriteLine(reader["Name"]);
                }
            } // Automatically calls Dispose
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=0}

        public void good_case_3()
        {
            // Properly closing socket with explicit Close
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                socket.Connect(new IPEndPoint(IPAddress.Parse("127.0.0.1"), 8080));
                byte[] buffer = new byte[1024];
                socket.Receive(buffer);
            }
            finally
            {
                // ok: resource-leak-csharp-rule
                socket.Close();
            }
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=0}

        public void good_case_4()
        {
            // Properly closing registry key with using statement
            // ok: resource-leak-csharp-rule
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey("Software"))
            {
                if (key != null)
                {
                    string[] valueNames = key.GetValueNames();
                    foreach (string name in valueNames)
                    {
                        Console.WriteLine(name);
                    }
                }
            } // Automatically calls Dispose
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=0}

        public void good_case_5()
        {
            // Properly disposing graphics resource
            Bitmap bitmap = new Bitmap(100, 100);
            Graphics graphics = Graphics.FromImage(bitmap);
            try
            {
                graphics.DrawLine(new Pen(Color.Black), 0, 0, 100, 100);
            }
            finally
            {
                // ok: resource-leak-csharp-rule
                graphics.Dispose();
                bitmap.Dispose();
            }
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=0}

        public void good_case_6()
        {
            // Properly handling multiple resources with nested using statements
            // ok: resource-leak-csharp-rule
            using (FileStream fs = new FileStream("data.txt", FileMode.Open))
            using (StreamReader reader = new StreamReader(fs))
            {
                string content = reader.ReadToEnd();
                Console.WriteLine(content);
            } // Both reader and fs are disposed
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=0}

        public void good_case_7()
        {
            // Properly releasing mutex
            Mutex mutex = new Mutex(true, "MyMutex");
            try
            {
                bool acquired = mutex.WaitOne(TimeSpan.FromSeconds(5));
                if (acquired)
                {
                    Console.WriteLine("Mutex acquired");
                    // ok: resource-leak-csharp-rule
                    mutex.ReleaseMutex();
                }
            }
            finally
            {
                mutex.Close();
            }
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=0}

        public void good_case_8()
        {
            // Properly disposing cryptographic resources
            // ok: resource-leak-csharp-rule
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                byte[] encrypted = rsa.Encrypt(new byte[] { 1, 2, 3 }, false);
                Console.WriteLine(encrypted.Length);
            } // Automatically calls Dispose
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=0}

        public void good_case_9()
        {
            // Properly disposing XML reader
            // ok: resource-leak-csharp-rule
            using (XmlTextReader reader = new XmlTextReader("data.xml"))
            {
                while (reader.Read())
                {
                    Console.WriteLine(reader.Name);
                }
            } // Automatically calls Dispose
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=0}

        public void good_case_10()
        {
            // Properly handling memory stream in conditional with finally block
            MemoryStream ms = new MemoryStream();
            try
            {
                if (DateTime.Now.Hour > 12)
                {
                    byte[] data = new byte[] { 1, 2, 3 };
                    ms.Write(data, 0, data.Length);
                    return; // Early return is fine with finally block
                }
            }
            finally
            {
                // ok: resource-leak-csharp-rule
                ms.Dispose();
            }
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=0}

        public void good_case_11()
        {
            // Properly disposing resources in loop
            for (int i = 0; i < 5; i++)
            {
                // ok: resource-leak-csharp-rule
                using (StreamWriter writer = new StreamWriter($"file{i}.txt"))
                {
                    writer.WriteLine($"Data for file {i}");
                } // Automatically calls Dispose at each iteration
            }
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=0}

        public void good_case_12()
        {
            // Properly handling SQL transaction
            // ok: resource-leak-csharp-rule
            using (SqlConnection connection = new SqlConnection("connection_string"))
            {
                connection.Open();
                using (SqlTransaction transaction = connection.BeginTransaction())
                {
                    try
                    {
                        SqlCommand command = new SqlCommand("INSERT INTO Table VALUES (1)", connection, transaction);
                        command.ExecuteNonQuery();
                        transaction.Commit();
                    }
                    catch
                    {
                        transaction.Rollback();
                        throw;
                    }
                }
            } // Automatically disposes connection and transaction
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=0}

        public void good_case_13()
        {
            // Properly disposing WebClient
            // ok: resource-leak-csharp-rule
            using (WebClient client = new WebClient())
            {
                string data = client.DownloadString("http://example.com");
                Console.WriteLine(data);
            } // Automatically calls Dispose
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=0}

        public void good_case_14()
        {
            // Properly disposing Timer
            Timer timer = new Timer(state => Console.WriteLine("Timer callback"), null, 0, 1000);
            try
            {
                Console.WriteLine("Timer started");
                Thread.Sleep(5000); // Let it run for 5 seconds
            }
            finally
            {
                // ok: resource-leak-csharp-rule
                timer.Dispose();
            }
        }
// {/fact}
// {fact rule=improper-resource-shutdown@v1.0 defects=0}

        public void good_case_15()
        {
            // Properly disposing dictionary enumerator
            Dictionary<string, int> dict = new Dictionary<string, int>
            {
                { "one", 1 },
                { "two", 2 }
            };
            
            // ok: resource-leak-csharp-rule
            using (IEnumerator<KeyValuePair<string, int>> enumerator = dict.GetEnumerator())
            {
                while (enumerator.MoveNext())
                {
                    Console.WriteLine(enumerator.Current);
                }
            } // Automatically calls Dispose
        }
// {/fact}
    }
}