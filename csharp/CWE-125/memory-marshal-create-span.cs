using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;

namespace MemoryMarshalExamples
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Memory Marshal Examples");
        }
// {fact rule=out-of-bounds-read@v1.0 defects=1}

        // True Positive Examples (Vulnerable Code)

        static void bad_case_1()
        {
            byte[] data = new byte[10];
            int length = 20; // Exceeds array bounds

            // ruleid: memory-marshal-create-span
            Span<byte> span = MemoryMarshal.CreateSpan(ref data[0], length);
            
            // This will potentially read beyond array bounds
            for (int i = 0; i < span.Length; i++)
            {
                Console.WriteLine(span[i]);
            }
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

        static void bad_case_2()
        {
            int[] array = new int[5];
            int userInput = int.Parse(Console.ReadLine()); // User could input a large number

            // ruleid: memory-marshal-create-span
            Span<int> span = MemoryMarshal.CreateSpan(ref array[0], userInput);
            
            // Potential out-of-bounds access
            for (int i = 0; i < span.Length; i++)
            {
                span[i] = i;
            }
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

        static void bad_case_3()
        {
            char[] buffer = new char[10];
            string userInput = Console.ReadLine();
            int length = userInput.Length; // Could be larger than buffer

            // ruleid: memory-marshal-create-span
            Span<char> span = MemoryMarshal.CreateSpan(ref buffer[0], length);
            
            // Might write beyond buffer bounds
            for (int i = 0; i < span.Length; i++)
            {
                if (i < userInput.Length)
                    span[i] = userInput[i];
            }
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

        static void bad_case_4()
        {
            byte[] data = new byte[100];
            HttpClient client = new HttpClient();
            string sizeStr = client.GetStringAsync("http://example.com/size").Result;
            int size = int.Parse(sizeStr);

            // ruleid: memory-marshal-create-span
            Span<byte> span = MemoryMarshal.CreateSpan(ref data[0], size);
            
            // Potential out-of-bounds access with network-supplied length
            for (int i = 0; i < span.Length; i++)
            {
                span[i] = 0xFF;
            }
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

        static void bad_case_5()
        {
            int[] array = new int[10];
            string input = File.ReadAllText("config.txt");
            int length = int.Parse(input);

            // ruleid: memory-marshal-create-span
            Span<int> span = MemoryMarshal.CreateSpan(ref array[0], length);
            
            // File-supplied length could exceed array bounds
            for (int i = 0; i < span.Length; i++)
            {
                Console.WriteLine(span[i]);
            }
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

        static void bad_case_6()
        {
            double[] values = new double[5];
            int multiplier = 2;
            int requestedLength = values.Length * multiplier; // Intentionally too large

            // ruleid: memory-marshal-create-span
            Span<double> span = MemoryMarshal.CreateSpan(ref values[0], requestedLength);
            
            // Will access beyond array bounds
            for (int i = 0; i < span.Length; i++)
            {
                span[i] = i * 1.5;
            }
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

        static void bad_case_7()
        {
            byte[] buffer = new byte[50];
            Dictionary<string, int> config = new Dictionary<string, int>
            {
                { "spanSize", 100 } // Intentionally larger than buffer
            };

            // ruleid: memory-marshal-create-span
            Span<byte> span = MemoryMarshal.CreateSpan(ref buffer[0], config["spanSize"]);
            
            // Configuration-driven out-of-bounds access
            for (int i = 0; i < span.Length; i++)
            {
                span[i] = (byte)(i % 256);
            }
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

        static void bad_case_8()
        {
            short[] data = new short[20];
            int offset = 5;
            int requestedLength = 20; // Will exceed bounds when combined with offset

            // ruleid: memory-marshal-create-span
            Span<short> span = MemoryMarshal.CreateSpan(ref data[offset], requestedLength);
            
            // Out-of-bounds access due to offset + length exceeding array size
            for (int i = 0; i < span.Length; i++)
            {
                span[i] = (short)i;
            }
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

        static void bad_case_9()
        {
            long[] array = new long[15];
            string input = Console.ReadLine();
            string[] parts = input.Split(',');
            int start = int.Parse(parts[0]);
            int length = int.Parse(parts[1]);

            // ruleid: memory-marshal-create-span
            Span<long> span = MemoryMarshal.CreateSpan(ref array[start], length);
            
            // User-controlled start and length could lead to out-of-bounds
            for (int i = 0; i < span.Length; i++)
            {
                span[i] = i * 1000;
            }
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

        static void bad_case_10()
        {
            float[] data = new float[10];
            Random random = new Random();
            int size = random.Next(5, 20); // Could exceed array bounds

            // ruleid: memory-marshal-create-span
            Span<float> span = MemoryMarshal.CreateSpan(ref data[0], size);
            
            // Random size might exceed array bounds
            for (int i = 0; i < span.Length; i++)
            {
                span[i] = random.NextSingle();
            }
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

        static void bad_case_11()
        {
            int[] source = new int[10];
            int[] destination = new int[5];
            
            // ruleid: memory-marshal-create-span
            Span<int> sourceSpan = MemoryMarshal.CreateSpan(ref source[0], source.Length);
            // ruleid: memory-marshal-create-span
            Span<int> destSpan = MemoryMarshal.CreateSpan(ref destination[0], source.Length); // Using source length for destination
            
            // Will write beyond destination array bounds
            sourceSpan.CopyTo(destSpan);
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

        static void bad_case_12()
        {
            byte[] buffer = new byte[100];
            HttpClient client = new HttpClient();
            byte[] response = client.GetByteArrayAsync("http://example.com/data").Result;

            // ruleid: memory-marshal-create-span
            Span<byte> span = MemoryMarshal.CreateSpan(ref buffer[0], response.Length);
            
            // Network-supplied data length could exceed buffer size
            for (int i = 0; i < response.Length; i++)
            {
                if (i < span.Length)
                    span[i] = response[i];
            }
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

        static void bad_case_13()
        {
            string text = "Hello";
            int requestedLength = 10; // Exceeds string length

            unsafe
            {
                fixed (char* ptr = text)
                {
                    // ruleid: memory-marshal-create-span
                    Span<char> span = MemoryMarshal.CreateSpan(ref *ptr, requestedLength);
                    
                    // Will read beyond string bounds
                    for (int i = 0; i < span.Length; i++)
                    {
                        Console.Write(span[i]);
                    }
                }
            }
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

        static void bad_case_14()
        {
            byte[] data = new byte[25];
            string lengthStr = Environment.GetEnvironmentVariable("SPAN_LENGTH") ?? "50";
            int length = int.Parse(lengthStr);

            // ruleid: memory-marshal-create-span
            Span<byte> span = MemoryMarshal.CreateSpan(ref data[0], length);
            
            // Environment variable could specify a length exceeding array bounds
            for (int i = 0; i < span.Length; i++)
            {
                span[i] = 0;
            }
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=1}

        static void bad_case_15()
        {
            int[] array = new int[10];
            int dynamicLength = 10;
            
            if (DateTime.Now.Second % 2 == 0)
            {
                dynamicLength = 20; // Conditionally exceeds array bounds
            }

            // ruleid: memory-marshal-create-span
            Span<int> span = MemoryMarshal.CreateSpan(ref array[0], dynamicLength);
            
            // Conditionally out-of-bounds
            for (int i = 0; i < span.Length; i++)
            {
                span[i] = i;
            }
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

        // True Negative Examples (Safe Code)

        static void good_case_1()
        {
            byte[] data = new byte[10];
            int length = 10; // Matches array bounds

            // ok: memory-marshal-create-span
            Span<byte> span = MemoryMarshal.CreateSpan(ref data[0], Math.Min(length, data.Length));
            
            for (int i = 0; i < span.Length; i++)
            {
                Console.WriteLine(span[i]);
            }
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

        static void good_case_2()
        {
            int[] array = new int[5];
            int userInput = int.Parse(Console.ReadLine());

            // ok: memory-marshal-create-span
            Span<int> span = MemoryMarshal.CreateSpan(ref array[0], Math.Min(userInput, array.Length));
            
            for (int i = 0; i < span.Length; i++)
            {
                span[i] = i;
            }
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

        static void good_case_3()
        {
            char[] buffer = new char[10];
            string userInput = Console.ReadLine();
            
            // ok: memory-marshal-create-span
            int safeLength = Math.Min(userInput.Length, buffer.Length);
            Span<char> span = MemoryMarshal.CreateSpan(ref buffer[0], safeLength);
            
            for (int i = 0; i < span.Length; i++)
            {
                if (i < userInput.Length)
                    span[i] = userInput[i];
            }
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

        static void good_case_4()
        {
            byte[] data = new byte[100];
            HttpClient client = new HttpClient();
            string sizeStr = client.GetStringAsync("http://example.com/size").Result;
            
            if (int.TryParse(sizeStr, out int size))
            {
                // ok: memory-marshal-create-span
                int safeSize = Math.Min(size, data.Length);
                Span<byte> span = MemoryMarshal.CreateSpan(ref data[0], safeSize);
                
                for (int i = 0; i < span.Length; i++)
                {
                    span[i] = 0xFF;
                }
            }
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

        static void good_case_5()
        {
            int[] array = new int[10];
            string input = File.ReadAllText("config.txt");
            
            if (int.TryParse(input, out int length) && length > 0)
            {
                // ok: memory-marshal-create-span
                int safeLength = Math.Min(length, array.Length);
                Span<int> span = MemoryMarshal.CreateSpan(ref array[0], safeLength);
                
                for (int i = 0; i < span.Length; i++)
                {
                    Console.WriteLine(span[i]);
                }
            }
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

        static void good_case_6()
        {
            double[] values = new double[5];
            
            // ok: memory-marshal-create-span
            Span<double> span = values.AsSpan(); // Using AsSpan instead of CreateSpan
            
            for (int i = 0; i < span.Length; i++)
            {
                span[i] = i * 1.5;
            }
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

        static void good_case_7()
        {
            byte[] buffer = new byte[50];
            Dictionary<string, int> config = new Dictionary<string, int>
            {
                { "spanSize", 100 } // Larger than buffer
            };

            // ok: memory-marshal-create-span
            int safeSize = Math.Min(config["spanSize"], buffer.Length);
            Span<byte> span = MemoryMarshal.CreateSpan(ref buffer[0], safeSize);
            
            for (int i = 0; i < span.Length; i++)
            {
                span[i] = (byte)(i % 256);
            }
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

        static void good_case_8()
        {
            short[] data = new short[20];
            int offset = 5;
            int requestedLength = 20; // Would exceed bounds when combined with offset
            
            // ok: memory-marshal-create-span
            int maxPossibleLength = data.Length - offset;
            int safeLength = Math.Min(requestedLength, maxPossibleLength);
            Span<short> span = MemoryMarshal.CreateSpan(ref data[offset], safeLength);
            
            for (int i = 0; i < span.Length; i++)
            {
                span[i] = (short)i;
            }
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

        static void good_case_9()
        {
            long[] array = new long[15];
            string input = Console.ReadLine();
            string[] parts = input.Split(',');
            
            if (parts.Length == 2 && 
                int.TryParse(parts[0], out int start) && 
                int.TryParse(parts[1], out int length))
            {
                // Validate start index
                if (start < 0 || start >= array.Length)
                {
                    Console.WriteLine("Invalid start index");
                    return;
                }
                
                // ok: memory-marshal-create-span
                int maxLength = array.Length - start;
                int safeLength = Math.Min(length, maxLength);
                Span<long> span = MemoryMarshal.CreateSpan(ref array[start], safeLength);
                
                for (int i = 0; i < span.Length; i++)
                {
                    span[i] = i * 1000;
                }
            }
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

        static void good_case_10()
        {
            float[] data = new float[10];
            Random random = new Random();
            int size = random.Next(5, 20); // Could exceed array bounds
            
            // ok: memory-marshal-create-span
            int safeSize = Math.Min(size, data.Length);
            Span<float> span = MemoryMarshal.CreateSpan(ref data[0], safeSize);
            
            for (int i = 0; i < span.Length; i++)
            {
                span[i] = random.NextSingle();
            }
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

        static void good_case_11()
        {
            int[] source = new int[10];
            int[] destination = new int[5];
            
            // ok: memory-marshal-create-span
            Span<int> sourceSpan = source.AsSpan();
            Span<int> destSpan = destination.AsSpan();
            
            // Copy only what fits in destination
            sourceSpan.Slice(0, Math.Min(sourceSpan.Length, destSpan.Length)).CopyTo(destSpan);
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

        static void good_case_12()
        {
            byte[] buffer = new byte[100];
            HttpClient client = new HttpClient();
            byte[] response = client.GetByteArrayAsync("http://example.com/data").Result;

            // ok: memory-marshal-create-span
            int safeLength = Math.Min(response.Length, buffer.Length);
            Span<byte> span = buffer.AsSpan(0, safeLength);
            
            for (int i = 0; i < safeLength; i++)
            {
                span[i] = response[i];
            }
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

        static void good_case_13()
        {
            string text = "Hello";
            
            // ok: memory-marshal-create-span
            Span<char> span = text.AsSpan(); // Safe alternative using AsSpan
            
            for (int i = 0; i < span.Length; i++)
            {
                Console.Write(span[i]);
            }
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

        static void good_case_14()
        {
            byte[] data = new byte[25];
            string lengthStr = Environment.GetEnvironmentVariable("SPAN_LENGTH") ?? "50";
            
            if (int.TryParse(lengthStr, out int length) && length > 0)
            {
                // ok: memory-marshal-create-span
                int safeLength = Math.Min(length, data.Length);
                Span<byte> span = MemoryMarshal.CreateSpan(ref data[0], safeLength);
                
                for (int i = 0; i < span.Length; i++)
                {
                    span[i] = 0;
                }
            }
        }
// {/fact}
// {fact rule=out-of-bounds-read@v1.0 defects=0}

        static void good_case_15()
        {
            int[] array = new int[10];
            int dynamicLength = 10;
            
            if (DateTime.Now.Second % 2 == 0)
            {
                dynamicLength = 20; // Could exceed array bounds
            }

            // ok: memory-marshal-create-span
            int safeLength = Math.Min(dynamicLength, array.Length);
            Span<int> span = MemoryMarshal.CreateSpan(ref array[0], safeLength);
            
            for (int i = 0; i < span.Length; i++)
            {
                span[i] = i;
            }
        }
// {/fact}
    }
}