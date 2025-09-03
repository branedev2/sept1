using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.IO;
using System.Net.Http;
using System.Text;

namespace ThreadSafetyExamples
{
    public class Program
    {
        // Shared resources for examples
        private static int sharedCounter = 0;
        private static List<string> sharedList = new List<string>();
        private static Dictionary<string, int> sharedDictionary = new Dictionary<string, int>();
        private static StringBuilder sharedStringBuilder = new StringBuilder();
        private static HttpClient sharedHttpClient = new HttpClient();
        private static string sharedFilePath = "shared.txt";
        
        // Thread-safe alternatives
        private static readonly object lockObject = new object();
        private static Mutex mutex = new Mutex();
        private static SemaphoreSlim semaphore = new SemaphoreSlim(1, 1);
        private static ReaderWriterLockSlim rwLock = new ReaderWriterLockSlim();
        private static ConcurrentDictionary<string, int> concurrentDictionary = new ConcurrentDictionary<string, int>();
        private static ConcurrentBag<string> concurrentBag = new ConcurrentBag<string>();
        
        public static void Main()
        {
            // Main method for demonstration purposes
        }
// {fact rule=thread-safety-violation@v1.0 defects=1}

        // TRUE POSITIVES (Vulnerable Code)

        public static void bad_case_1()
        {
            // Parallel access to a shared counter without synchronization
            Parallel.For(0, 1000, i =>
            {
                // ruleid: thread-safety-violation-csharp-rule
                sharedCounter++;
            });
            
            Console.WriteLine($"Final counter value: {sharedCounter}");
        }
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=1}

        public static void bad_case_2()
        {
            // Multiple threads accessing a shared list without synchronization
            Task[] tasks = new Task[10];
            for (int i = 0; i < 10; i++)
            {
                int taskNum = i;
                tasks[i] = Task.Run(() =>
                {
                    // ruleid: thread-safety-violation-csharp-rule
                    sharedList.Add($"Item {taskNum}");
                });
            }
            
            Task.WaitAll(tasks);
        }
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=1}

        public static void bad_case_3()
        {
            // Concurrent access to a shared dictionary without synchronization
            Parallel.ForEach(Enumerable.Range(0, 100), i =>
            {
                // ruleid: thread-safety-violation-csharp-rule
                if (!sharedDictionary.ContainsKey($"key{i}"))
                {
                    sharedDictionary.Add($"key{i}", i);
                }
            });
        }
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=1}

        public static void bad_case_4()
        {
            // Concurrent access to a shared StringBuilder without synchronization
            Parallel.For(0, 100, i =>
            {
                // ruleid: thread-safety-violation-csharp-rule
                sharedStringBuilder.Append($"Append {i};");
            });
            
            Console.WriteLine(sharedStringBuilder.ToString());
        }
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=1}

        public static void bad_case_5()
        {
            // Concurrent file access without synchronization
            Parallel.For(0, 10, i =>
            {
                // ruleid: thread-safety-violation-csharp-rule
                File.AppendAllText(sharedFilePath, $"Line {i}\n");
            });
        }
// {/fact}

        private static int sharedValue = 0;
// {fact rule=thread-safety-violation@v1.0 defects=1}
        public static void bad_case_6()
        {
            // Concurrent read and write to a shared value
            Task writeTask = Task.Run(() =>
            {
                for (int i = 0; i < 1000; i++)
                {
                    // ruleid: thread-safety-violation-csharp-rule
                    sharedValue = i;
                }
            });
            
            Task readTask = Task.Run(() =>
            {
                for (int i = 0; i < 1000; i++)
                {
                    // ruleid: thread-safety-violation-csharp-rule
                    Console.WriteLine(sharedValue);
                }
            });
            
            Task.WaitAll(writeTask, readTask);
        }
// {/fact}

        private static bool isInitialized = false;
        private static object sharedResource = null;
// {fact rule=thread-safety-violation@v1.0 defects=1}
        
        public static void bad_case_7()
        {
            // Double-checked locking pattern implemented incorrectly
            Parallel.For(0, 10, i =>
            {
                if (!isInitialized)
                {
                    // ruleid: thread-safety-violation-csharp-rule
                    sharedResource = new object();
                    isInitialized = true;
                }
            });
        }
// {/fact}

        private static Dictionary<string, HttpClient> clientCache = new Dictionary<string, HttpClient>();
// {fact rule=thread-safety-violation@v1.0 defects=1}
        
        public static void bad_case_8()
        {
            // Concurrent access to a shared cache without synchronization
            Parallel.ForEach(new[] { "api1", "api2", "api3" }, endpoint =>
            {
                // ruleid: thread-safety-violation-csharp-rule
                if (!clientCache.ContainsKey(endpoint))
                {
                    clientCache[endpoint] = new HttpClient { BaseAddress = new Uri($"https://{endpoint}.example.com") };
                }
                
                HttpClient client = clientCache[endpoint];
                // Use client...
            });
        }
// {/fact}

        private static HashSet<string> processedItems = new HashSet<string>();
// {fact rule=thread-safety-violation@v1.0 defects=1}
        
        public static void bad_case_9()
        {
            // Concurrent access to a shared HashSet without synchronization
            string[] items = { "item1", "item2", "item3", "item4", "item5" };
            
            Parallel.ForEach(items, item =>
            {
                // ruleid: thread-safety-violation-csharp-rule
                if (!processedItems.Contains(item))
                {
                    // Process the item
                    Thread.Sleep(10); // Simulate processing
                    processedItems.Add(item);
                }
            });
        }
// {/fact}

        private static int[] sharedArray = new int[100];
// {fact rule=thread-safety-violation@v1.0 defects=1}
        
        public static void bad_case_10()
        {
            // Concurrent access to a shared array without synchronization
            Parallel.For(0, sharedArray.Length, i =>
            {
                // ruleid: thread-safety-violation-csharp-rule
                sharedArray[i] = i * i;
            });
        }
// {/fact}

        private static Queue<string> messageQueue = new Queue<string>();
// {fact rule=thread-safety-violation@v1.0 defects=1}
        
        public static void bad_case_11()
        {
            // Producer-consumer pattern without synchronization
            Task producer = Task.Run(() =>
            {
                for (int i = 0; i < 100; i++)
                {
                    // ruleid: thread-safety-violation-csharp-rule
                    messageQueue.Enqueue($"Message {i}");
                }
            });
            
            Task consumer = Task.Run(() =>
            {
                for (int i = 0; i < 100; i++)
                {
                    if (messageQueue.Count > 0)
                    {
                        // ruleid: thread-safety-violation-csharp-rule
                        string message = messageQueue.Dequeue();
                        Console.WriteLine($"Processed: {message}");
                    }
                }
            });
            
            Task.WaitAll(producer, consumer);
        }
// {/fact}

        private static bool isRunning = true;
// {fact rule=thread-safety-violation@v1.0 defects=1}
        
        public static void bad_case_12()
        {
            // Shared flag for thread coordination without synchronization
            Task worker = Task.Run(() =>
            {
                while (isRunning)
                {
                    // Do work
                    Thread.Sleep(100);
                }
            });
            
            // In another thread
            Task controller = Task.Run(() =>
            {
                Thread.Sleep(5000); // Run for 5 seconds
                // ruleid: thread-safety-violation-csharp-rule
                isRunning = false;
            });
            
            Task.WaitAll(worker, controller);
        }
// {/fact}

        private static Stack<int> sharedStack = new Stack<int>();
// {fact rule=thread-safety-violation@v1.0 defects=1}
        
        public static void bad_case_13()
        {
            // Concurrent access to a shared stack without synchronization
            Task pushTask = Task.Run(() =>
            {
                for (int i = 0; i < 100; i++)
                {
                    // ruleid: thread-safety-violation-csharp-rule
                    sharedStack.Push(i);
                }
            });
            
            Task popTask = Task.Run(() =>
            {
                for (int i = 0; i < 50; i++)
                {
                    if (sharedStack.Count > 0)
                    {
                        // ruleid: thread-safety-violation-csharp-rule
                        int value = sharedStack.Pop();
                        Console.WriteLine($"Popped: {value}");
                    }
                }
            });
            
            Task.WaitAll(pushTask, popTask);
        }
// {/fact}

        private static DateTime lastAccessTime = DateTime.MinValue;
// {fact rule=thread-safety-violation@v1.0 defects=1}
        
        public static void bad_case_14()
        {
            // Concurrent access to a shared DateTime without synchronization
            Parallel.For(0, 1000, i =>
            {
                // ruleid: thread-safety-violation-csharp-rule
                lastAccessTime = DateTime.Now;
                
                // Do something with the time
                TimeSpan timeSinceStart = DateTime.Now - lastAccessTime;
                Console.WriteLine($"Time since last access: {timeSinceStart.TotalMilliseconds}ms");
            });
        }
// {/fact}

        private static StreamWriter sharedLogWriter = new StreamWriter("log.txt", true);
// {fact rule=thread-safety-violation@v1.0 defects=1}
        
        public static void bad_case_15()
        {
            // Concurrent access to a shared StreamWriter without synchronization
            Parallel.For(0, 100, i =>
            {
                // ruleid: thread-safety-violation-csharp-rule
                sharedLogWriter.WriteLine($"Log entry {i} at {DateTime.Now}");
                sharedLogWriter.Flush();
            });
        }
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

        // TRUE NEGATIVES (Safe Code)

        public static void good_case_1()
        {
            // Safe access to a shared counter using lock
            Parallel.For(0, 1000, i =>
            {
                // ok: thread-safety-violation-csharp-rule
                lock (lockObject)
                {
                    sharedCounter++;
                }
            });
            
            Console.WriteLine($"Final counter value: {sharedCounter}");
        }
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

        public static void good_case_2()
        {
            // Safe access to a shared list using lock
            Task[] tasks = new Task[10];
            for (int i = 0; i < 10; i++)
            {
                int taskNum = i;
                tasks[i] = Task.Run(() =>
                {
                    // ok: thread-safety-violation-csharp-rule
                    lock (lockObject)
                    {
                        sharedList.Add($"Item {taskNum}");
                    }
                });
            }
            
            Task.WaitAll(tasks);
        }
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

        public static void good_case_3()
        {
            // Safe access to a dictionary using ConcurrentDictionary
            Parallel.ForEach(Enumerable.Range(0, 100), i =>
            {
                // ok: thread-safety-violation-csharp-rule
                concurrentDictionary.TryAdd($"key{i}", i);
            });
        }
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

        public static void good_case_4()
        {
            // Safe access to a shared StringBuilder using lock
            Parallel.For(0, 100, i =>
            {
                // ok: thread-safety-violation-csharp-rule
                lock (lockObject)
                {
                    sharedStringBuilder.Append($"Append {i};");
                }
            });
            
            Console.WriteLine(sharedStringBuilder.ToString());
        }
// {/fact}
// {fact rule=thread-safety-violation@v1.0 defects=0}

        public static void good_case_5()
        {
            // Safe file access using Mutex
            Parallel.For(0, 10, i =>
            {
                // ok: thread-safety-violation-csharp-rule
                mutex.WaitOne();
                try
                {
                    File.AppendAllText(sharedFilePath, $"Line {i}\n");
                }
                finally
                {
                    mutex.ReleaseMutex();
                }
            });
        }
// {/fact}

        private static int protectedValue = 0;
// {fact rule=thread-safety-violation@v1.0 defects=0}
        public static void good_case_6()
        {
            // Safe concurrent read and write using ReaderWriterLockSlim
            Task writeTask = Task.Run(() =>
            {
                for (int i = 0; i < 1000; i++)
                {
                    // ok: thread-safety-violation-csharp-rule
                    rwLock.EnterWriteLock();
                    try
                    {
                        protectedValue = i;
                    }
                    finally
                    {
                        rwLock.ExitWriteLock();
                    }
                }
            });
            
            Task readTask = Task.Run(() =>
            {
                for (int i = 0; i < 1000; i++)
                {
                    // ok: thread-safety-violation-csharp-rule
                    rwLock.EnterReadLock();
                    try
                    {
                        Console.WriteLine(protectedValue);
                    }
                    finally
                    {
                        rwLock.ExitReadLock();
                    }
                }
            });
            
            Task.WaitAll(writeTask, readTask);
        }
// {/fact}

        private static bool isResourceInitialized = false;
        private static object safeResource = null;
        private static readonly object initLock = new object();
// {fact rule=thread-safety-violation@v1.0 defects=0}
        
        public static void good_case_7()
        {
            // Correct implementation of double-checked locking pattern
            Parallel.For(0, 10, i =>
            {
                if (!isResourceInitialized)
                {
                    // ok: thread-safety-violation-csharp-rule
                    lock (initLock)
                    {
                        if (!isResourceInitialized)
                        {
                            safeResource = new object();
                            isResourceInitialized = true;
                        }
                    }
                }
            });
        }
// {/fact}

        private static ConcurrentDictionary<string, HttpClient> safeClientCache = 
            new ConcurrentDictionary<string, HttpClient>();
// {fact rule=thread-safety-violation@v1.0 defects=0}
        
        public static void good_case_8()
        {
            // Safe concurrent access to a cache using ConcurrentDictionary
            Parallel.ForEach(new[] { "api1", "api2", "api3" }, endpoint =>
            {
                // ok: thread-safety-violation-csharp-rule
                HttpClient client = safeClientCache.GetOrAdd(endpoint, key => 
                    new HttpClient { BaseAddress = new Uri($"https://{key}.example.com") });
                
                // Use client...
            });
        }
// {/fact}

        private static ConcurrentDictionary<string, byte> safeProcessedItems = 
            new ConcurrentDictionary<string, byte>();
// {fact rule=thread-safety-violation@v1.0 defects=0}
        
        public static void good_case_9()
        {
            // Safe concurrent access using ConcurrentDictionary instead of HashSet
            string[] items = { "item1", "item2", "item3", "item4", "item5" };
            
            Parallel.ForEach(items, item =>
            {
                // ok: thread-safety-violation-csharp-rule
                if (safeProcessedItems.TryAdd(item, 1))
                {
                    // Process the item
                    Thread.Sleep(10); // Simulate processing
                }
            });
        }
// {/fact}

        private static int[] safeArray = new int[100];
        private static readonly object arrayLock = new object();
// {fact rule=thread-safety-violation@v1.0 defects=0}
        
        public static void good_case_10()
        {
            // Safe concurrent access to an array using lock
            Parallel.For(0, safeArray.Length, i =>
            {
                // ok: thread-safety-violation-csharp-rule
                lock (arrayLock)
                {
                    safeArray[i] = i * i;
                }
            });
        }
// {/fact}

        private static ConcurrentQueue<string> safeMessageQueue = new ConcurrentQueue<string>();
// {fact rule=thread-safety-violation@v1.0 defects=0}
        
        public static void good_case_11()
        {
            // Safe producer-consumer pattern using ConcurrentQueue
            Task producer = Task.Run(() =>
            {
                for (int i = 0; i < 100; i++)
                {
                    // ok: thread-safety-violation-csharp-rule
                    safeMessageQueue.Enqueue($"Message {i}");
                }
            });
            
            Task consumer = Task.Run(() =>
            {
                for (int i = 0; i < 100; i++)
                {
                    // ok: thread-safety-violation-csharp-rule
                    if (safeMessageQueue.TryDequeue(out string message))
                    {
                        Console.WriteLine($"Processed: {message}");
                    }
                }
            });
            
            Task.WaitAll(producer, consumer);
        }
// {/fact}

        private static volatile bool safeIsRunning = true;
// {fact rule=thread-safety-violation@v1.0 defects=0}
        
        public static void good_case_12()
        {
            // Safe thread coordination using volatile keyword
            Task worker = Task.Run(() =>
            {
                while (safeIsRunning)
                {
                    // Do work
                    Thread.Sleep(100);
                }
            });
            
            // In another thread
            Task controller = Task.Run(() =>
            {
                Thread.Sleep(5000); // Run for 5 seconds
                // ok: thread-safety-violation-csharp-rule
                safeIsRunning = false;
            });
            
            Task.WaitAll(worker, controller);
        }
// {/fact}

        private static ConcurrentStack<int> safeStack = new ConcurrentStack<int>();
// {fact rule=thread-safety-violation@v1.0 defects=0}
        
        public static void good_case_13()
        {
            // Safe concurrent access to a stack using ConcurrentStack
            Task pushTask = Task.Run(() =>
            {
                for (int i = 0; i < 100; i++)
                {
                    // ok: thread-safety-violation-csharp-rule
                    safeStack.Push(i);
                }
            });
            
            Task popTask = Task.Run(() =>
            {
                for (int i = 0; i < 50; i++)
                {
                    // ok: thread-safety-violation-csharp-rule
                    if (safeStack.TryPop(out int value))
                    {
                        Console.WriteLine($"Popped: {value}");
                    }
                }
            });
            
            Task.WaitAll(pushTask, popTask);
        }
// {/fact}

        private static DateTime safeLastAccessTime = DateTime.MinValue;
        private static readonly object timeLock = new object();
// {fact rule=thread-safety-violation@v1.0 defects=0}
        
        public static void good_case_14()
        {
            // Safe concurrent access to a shared DateTime using lock
            Parallel.For(0, 1000, i =>
            {
                // ok: thread-safety-violation-csharp-rule
                lock (timeLock)
                {
                    safeLastAccessTime = DateTime.Now;
                    
                    // Do something with the time
                    TimeSpan timeSinceStart = DateTime.Now - safeLastAccessTime;
                    Console.WriteLine($"Time since last access: {timeSinceStart.TotalMilliseconds}ms");
                }
            });
        }
// {/fact}

        private static readonly object logLock = new object();
        private static StreamWriter safeLogWriter = new StreamWriter("safe_log.txt", true);
// {fact rule=thread-safety-violation@v1.0 defects=0}
        
        public static void good_case_15()
        {
            // Safe concurrent access to a shared StreamWriter using lock
            Parallel.For(0, 100, i =>
            {
                // ok: thread-safety-violation-csharp-rule
                lock (logLock)
                {
                    safeLogWriter.WriteLine($"Log entry {i} at {DateTime.Now}");
                    safeLogWriter.Flush();
                }
            });
        }
// {/fact}
    }
}