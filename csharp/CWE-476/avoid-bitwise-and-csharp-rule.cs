using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace BitwiseAndExamples
{
    public class BitwiseAndExamples
    {
// {fact rule=inconsistent-null-check@v1.0 defects=1}
        // True Positives (Vulnerable Code)

        public void bad_case_1()
        {
            string name = GetUserName();
            
            // ruleid: avoid-bitwise-and-csharp-rule
            if (name != null & name.Length > 0)
            {
                Console.WriteLine("Hello, " + name);
            }
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

        public void bad_case_2()
        {
            User user = GetCurrentUser();
            
            // ruleid: avoid-bitwise-and-csharp-rule
            if (user != null & user.IsAdmin())
            {
                GrantAdminAccess();
            }
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

        public void bad_case_3()
        {
            string[] names = GetNames();
            int index = GetIndex();
            
            // ruleid: avoid-bitwise-and-csharp-rule
            if (names != null & index < names.Length)
            {
                Console.WriteLine(names[index]);
            }
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

        public void bad_case_4()
        {
            FileInfo file = GetFileInfo();
            
            // ruleid: avoid-bitwise-and-csharp-rule
            if (file != null & file.Exists)
            {
                using (StreamReader reader = file.OpenText())
                {
                    string content = reader.ReadToEnd();
                    Console.WriteLine(content);
                }
            }
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

        public void bad_case_5()
        {
            Dictionary<string, int> dict = GetDictionary();
            string key = "test";
            
            // ruleid: avoid-bitwise-and-csharp-rule
            if (dict != null & dict.ContainsKey(key))
            {
                Console.WriteLine(dict[key]);
            }
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

        public void bad_case_6(string input)
        {
            List<string> items = GetItems();
            
            // ruleid: avoid-bitwise-and-csharp-rule
            if (items != null & items.Count > 0 & input != null)
            {
                items.Add(input);
            }
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

        public void bad_case_7()
        {
            Customer customer = GetCustomer();
            
            // ruleid: avoid-bitwise-and-csharp-rule
            if (customer != null & customer.Orders != null & customer.Orders.Count > 0)
            {
                ProcessOrders(customer.Orders);
            }
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

        public void bad_case_8()
        {
            string data = GetData();
            
            // ruleid: avoid-bitwise-and-csharp-rule
            if (data != null & data.StartsWith("VALID"))
            {
                ProcessValidData(data);
            }
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

        public void bad_case_9()
        {
            Response response = GetApiResponse();
            
            // ruleid: avoid-bitwise-and-csharp-rule
            if (response != null & response.IsSuccess & response.Data != null)
            {
                DisplayData(response.Data);
            }
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

        public void bad_case_10()
        {
            Config config = GetConfiguration();
            
            // ruleid: avoid-bitwise-and-csharp-rule
            if (config != null & config.IsEnabled)
            {
                ApplyConfiguration(config);
            }
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

        public void bad_case_11()
        {
            string filePath = GetFilePath();
            
            // ruleid: avoid-bitwise-and-csharp-rule
            if (filePath != null & File.Exists(filePath))
            {
                string content = File.ReadAllText(filePath);
                ProcessContent(content);
            }
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

        public void bad_case_12()
        {
            int? value = GetNullableValue();
            
            // ruleid: avoid-bitwise-and-csharp-rule
            if (value != null & value > 10)
            {
                Console.WriteLine("Value is greater than 10");
            }
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

        public void bad_case_13()
        {
            string[] args = GetCommandLineArgs();
            
            // ruleid: avoid-bitwise-and-csharp-rule
            if (args != null & args.Length > 1 & args[0] == "--verbose")
            {
                EnableVerboseLogging();
            }
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

        public void bad_case_14()
        {
            UserSession session = GetCurrentSession();
            
            // ruleid: avoid-bitwise-and-csharp-rule
            if (session != null & session.IsActive & session.User != null)
            {
                GrantAccess(session.User);
            }
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=1}

        public void bad_case_15()
        {
            Database db = GetDatabase();
            string query = "SELECT * FROM Users";
            
            // ruleid: avoid-bitwise-and-csharp-rule
            if (db != null & db.IsConnected)
            {
                var results = db.ExecuteQuery(query);
                ProcessResults(results);
            }
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

        // True Negatives (Safe Code)

        public void good_case_1()
        {
            string name = GetUserName();
            
            // ok: avoid-bitwise-and-csharp-rule
            if (name != null && name.Length > 0)
            {
                Console.WriteLine("Hello, " + name);
            }
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

        public void good_case_2()
        {
            User user = GetCurrentUser();
            
            // ok: avoid-bitwise-and-csharp-rule
            if (user != null && user.IsAdmin())
            {
                GrantAdminAccess();
            }
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

        public void good_case_3()
        {
            string[] names = GetNames();
            int index = GetIndex();
            
            // ok: avoid-bitwise-and-csharp-rule
            if (names != null && index < names.Length)
            {
                Console.WriteLine(names[index]);
            }
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

        public void good_case_4()
        {
            FileInfo file = GetFileInfo();
            
            // ok: avoid-bitwise-and-csharp-rule
            if (file != null && file.Exists)
            {
                using (StreamReader reader = file.OpenText())
                {
                    string content = reader.ReadToEnd();
                    Console.WriteLine(content);
                }
            }
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

        public void good_case_5()
        {
            Dictionary<string, int> dict = GetDictionary();
            string key = "test";
            
            // ok: avoid-bitwise-and-csharp-rule
            if (dict != null && dict.ContainsKey(key))
            {
                Console.WriteLine(dict[key]);
            }
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

        public void good_case_6()
        {
            // ok: avoid-bitwise-and-csharp-rule
            int flags = 0x01 & 0x02; // Legitimate use of bitwise AND for flag operations
            
            if (flags == 0)
            {
                Console.WriteLine("No flags set");
            }
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

        public void good_case_7()
        {
            Customer customer = GetCustomer();
            
            // ok: avoid-bitwise-and-csharp-rule
            if (customer != null && customer.Orders != null && customer.Orders.Count > 0)
            {
                ProcessOrders(customer.Orders);
            }
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

        public void good_case_8()
        {
            // ok: avoid-bitwise-and-csharp-rule
            int permission = GetUserPermission();
            int requiredPermission = 0x04;
            
            if ((permission & requiredPermission) == requiredPermission) // Legitimate bitwise AND for permission check
            {
                AllowAccess();
            }
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

        public void good_case_9()
        {
            Response response = GetApiResponse();
            
            // ok: avoid-bitwise-and-csharp-rule
            if (response != null && response.IsSuccess && response.Data != null)
            {
                DisplayData(response.Data);
            }
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

        public void good_case_10()
        {
            // ok: avoid-bitwise-and-csharp-rule
            int value1 = 5;
            int value2 = 10;
            
            // No null reference possible here, so bitwise AND is fine
            int result = value1 & value2;
            Console.WriteLine(result);
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

        public void good_case_11()
        {
            string filePath = GetFilePath();
            
            // ok: avoid-bitwise-and-csharp-rule
            if (filePath != null && File.Exists(filePath))
            {
                string content = File.ReadAllText(filePath);
                ProcessContent(content);
            }
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

        public void good_case_12()
        {
            // ok: avoid-bitwise-and-csharp-rule
            // Using bitwise AND for bit manipulation is fine
            byte flags = 0x0F;
            byte mask = 0x03;
            byte result = (byte)(flags & mask);
            
            Console.WriteLine($"Result: {result}");
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

        public void good_case_13()
        {
            string[] args = GetCommandLineArgs();
            
            // ok: avoid-bitwise-and-csharp-rule
            if (args != null && args.Length > 1 && args[0] == "--verbose")
            {
                EnableVerboseLogging();
            }
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

        public void good_case_14()
        {
            // ok: avoid-bitwise-and-csharp-rule
            // Using null-conditional operator to avoid null reference
            UserSession session = GetCurrentSession();
            bool isActiveUser = session?.IsActive == true && session?.User != null;
            
            if (isActiveUser)
            {
                GrantAccess(session.User);
            }
        }
// {/fact}
// {fact rule=inconsistent-null-check@v1.0 defects=0}

        public void good_case_15()
        {
            Database db = GetDatabase();
            
            // ok: avoid-bitwise-and-csharp-rule
            if (db != null && db.IsConnected)
            {
                string query = "SELECT * FROM Users";
                var results = db.ExecuteQuery(query);
                ProcessResults(results);
            }
        }
// {/fact}

        // Helper methods (implementations not provided as they're not relevant to the test cases)
        private string GetUserName() => null;
        private User GetCurrentUser() => null;
        private string[] GetNames() => null;
        private int GetIndex() => 0;
        private FileInfo GetFileInfo() => null;
        private Dictionary<string, int> GetDictionary() => null;
        private void GrantAdminAccess() { }
        private List<string> GetItems() => null;
        private Customer GetCustomer() => null;
        private void ProcessOrders(List<Order> orders) { }
        private string GetData() => null;
        private void ProcessValidData(string data) { }
        private Response GetApiResponse() => null;
        private void DisplayData(object data) { }
        private Config GetConfiguration() => null;
        private void ApplyConfiguration(Config config) { }
        private string GetFilePath() => null;
        private void ProcessContent(string content) { }
        private int? GetNullableValue() => null;
        private string[] GetCommandLineArgs() => null;
        private void EnableVerboseLogging() { }
        private UserSession GetCurrentSession() => null;
        private void GrantAccess(User user) { }
        private Database GetDatabase() => null;
        private void ProcessResults(object results) { }
        private int GetUserPermission() => 0;
        private void AllowAccess() { }
    }

    // Helper classes
    public class User
    {
        public bool IsAdmin() => false;
    }

    public class Customer
    {
        public List<Order> Orders { get; set; }
    }

    public class Order { }

    public class Response
    {
        public bool IsSuccess { get; set; }
        public object Data { get; set; }
    }

    public class Config
    {
        public bool IsEnabled { get; set; }
    }

    public class UserSession
    {
        public bool IsActive { get; set; }
        public User User { get; set; }
    }

    public class Database
    {
        public bool IsConnected { get; set; }
        public object ExecuteQuery(string query) => null;
    }
}