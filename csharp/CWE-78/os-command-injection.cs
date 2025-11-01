using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Linq;

namespace CommandInjectionExamples
{
    public class CommandInjectionController : Controller
    {
// {fact rule=os-command-injection@v1.0 defects=1}
        // True Positives (Vulnerable Code)

        public void bad_case_1()
        {
            // Get user input from query string
            string userInput = Request.QueryString["filename"];
            
            // Execute command with user input directly
            Process process = new Process();
            process.StartInfo.FileName = "cmd.exe";
            process.StartInfo.Arguments = "/c dir " + userInput;
            // ruleid: os-command-injection
            process.Start();
        }
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

        public void bad_case_2()
        {
            // Get user input from form
            string ipAddress = Request.Form["ipAddress"];
            
            // Use user input in command without validation
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "ping";
            psi.Arguments = ipAddress;
            // ruleid: os-command-injection
            Process.Start(psi);
        }
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

        public ActionResult bad_case_3()
        {
            // Get user input from route parameter
            string command = RouteData.Values["cmd"] as string;
            
            // Directly use in shell command
            ProcessStartInfo processInfo = new ProcessStartInfo("cmd.exe", "/c " + command);
            processInfo.RedirectStandardOutput = true;
            processInfo.UseShellExecute = false;
            // ruleid: os-command-injection
            Process process = Process.Start(processInfo);
            
            StreamReader reader = process.StandardOutput;
            string output = reader.ReadToEnd();
            return Content(output);
        }
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

        public void bad_case_4(HttpRequestMessage request)
        {
            // Get user input from header
            string hostname = request.Headers.GetValues("Host-To-Lookup").FirstOrDefault();
            
            // Use in command without sanitization
            var processStartInfo = new ProcessStartInfo
            {
                FileName = "nslookup",
                Arguments = hostname,
                RedirectStandardOutput = true,
                UseShellExecute = false
            };
            // ruleid: os-command-injection
            Process.Start(processStartInfo);
        }
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

        public IActionResult bad_case_5()
        {
            // Get user input from cookie
            string filename = Request.Cookies["file_to_delete"];
            
            // Use in command directly
            var process = new Process();
            process.StartInfo.FileName = "cmd.exe";
            process.StartInfo.Arguments = $"/c del {filename}";
            // ruleid: os-command-injection
            process.Start();
            
            return Ok("File deleted");
        }
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

        public void bad_case_6([FromQuery] string scriptName)
        {
            // Use user input from query parameter in a shell command
            var processInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-File {scriptName}",
                UseShellExecute = false
            };
            // ruleid: os-command-injection
            Process.Start(processInfo);
        }
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

        public IActionResult bad_case_7()
        {
            // Get user input from multiple sources and concatenate
            string path = Request.Query["path"];
            string option = Request.Form["option"];
            
            // Use concatenated input in command
            var process = new Process();
            process.StartInfo.FileName = "cmd.exe";
            process.StartInfo.Arguments = $"/c dir {option} {path}";
            // ruleid: os-command-injection
            process.Start();
            
            return Ok("Command executed");
        }
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

        public void bad_case_8()
        {
            // Get user input and perform minimal transformation
            string username = Request.QueryString["username"].ToLower();
            
            // Still vulnerable despite transformation
            var processInfo = new ProcessStartInfo
            {
                FileName = "net",
                Arguments = "user " + username,
                UseShellExecute = false
            };
            // ruleid: os-command-injection
            Process.Start(processInfo);
        }
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

        public ActionResult bad_case_9()
        {
            // Get user input from JSON body
            var requestBody = new StreamReader(Request.Body).ReadToEnd();
            dynamic data = Newtonsoft.Json.JsonConvert.DeserializeObject(requestBody);
            string command = data.command;
            
            // Execute command directly
            var process = new Process();
            process.StartInfo.FileName = "bash";
            process.StartInfo.Arguments = "-c " + command;
            // ruleid: os-command-injection
            process.Start();
            
            return Ok("Command executed");
        }
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

        public void bad_case_10()
        {
            // Get user input and use string interpolation
            string fileName = Request.Query["file"];
            
            // Still vulnerable with string interpolation
            var processInfo = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c type {fileName}",
                UseShellExecute = false
            };
            // ruleid: os-command-injection
            Process.Start(processInfo);
        }
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

        public IActionResult bad_case_11()
        {
            // Get user input and use in a more complex command
            string searchTerm = Request.Form["search"];
            string directory = Request.Form["directory"];
            
            // Build complex command with user input
            string arguments = $"/c find \"{searchTerm}\" {directory}";
            var processInfo = new ProcessStartInfo("cmd.exe", arguments);
            // ruleid: os-command-injection
            Process.Start(processInfo);
            
            return Ok("Search completed");
        }
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

        public void bad_case_12()
        {
            // Get user input and attempt to escape quotes, but still vulnerable
            string userParam = Request.QueryString["param"].Replace("\"", "\\\"");
            
            // Escaping quotes is insufficient protection
            var processInfo = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c echo {userParam}",
                UseShellExecute = false
            };
            // ruleid: os-command-injection
            Process.Start(processInfo);
        }
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

        public ActionResult bad_case_13()
        {
            // Get user input and use in a different command execution method
            string command = Request.QueryString["cmd"];
            
            // Using different execution method but still vulnerable
            // ruleid: os-command-injection
            string output = ExecuteCommand(command);
            
            return Content(output);
        }
// {/fact}
        
        private string ExecuteCommand(string command)
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c {command}",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            process.Start();
            string result = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            return result;
        }
// {fact rule=os-command-injection@v1.0 defects=1}

        public void bad_case_14()
        {
            // Get user input and use in command with environment variables
            string userDir = Request.QueryString["directory"];
            
            // Using environment variables doesn't make it safe
            var processInfo = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c cd %TEMP% && dir {userDir}",
                UseShellExecute = false
            };
            // ruleid: os-command-injection
            Process.Start(processInfo);
        }
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=1}

        public IActionResult bad_case_15()
        {
            // Get user input and use in a command with conditional logic
            string parameter = Request.Query["param"];
            string command = "echo Default";
            
            if (!string.IsNullOrEmpty(parameter))
            {
                command = parameter;
            }
            
            // Still vulnerable despite conditional logic
            var processInfo = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c {command}",
                UseShellExecute = false
            };
            // ruleid: os-command-injection
            Process.Start(processInfo);
            
            return Ok("Command executed");
        }
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

        // True Negatives (Safe Code)

        public void good_case_1()
        {
            // Get user input from query string
            string userInput = Request.QueryString["filename"];
            
            // Use a whitelist of allowed values
            List<string> allowedFiles = new List<string> { "log.txt", "data.csv", "report.pdf" };
            
            if (allowedFiles.Contains(userInput))
            {
                Process process = new Process();
                process.StartInfo.FileName = "cmd.exe";
                // ok: os-command-injection
                process.StartInfo.Arguments = "/c dir " + userInput;
                process.Start();
            }
            else
            {
                // Handle invalid input
                Response.Write("Invalid filename specified");
            }
        }
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

        public void good_case_2()
        {
            // Get user input from form
            string ipAddress = Request.Form["ipAddress"];
            
            // Validate IP address format using regex
            if (Regex.IsMatch(ipAddress, @"^(\d{1,3}\.){3}\d{1,3}$"))
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "ping";
                // ok: os-command-injection
                psi.Arguments = ipAddress;
                Process.Start(psi);
            }
            else
            {
                // Handle invalid input
                Response.Write("Invalid IP address format");
            }
        }
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

        public ActionResult good_case_3()
        {
            // Use predefined commands instead of user input
            string commandType = RouteData.Values["cmd"] as string;
            string command = "";
            
            // Map user input to safe predefined commands
            switch (commandType)
            {
                case "disk":
                    command = "diskpart list volume";
                    break;
                case "memory":
                    command = "systeminfo | findstr /C:\"Total Physical Memory\"";
                    break;
                default:
                    command = "echo Invalid command";
                    break;
            }
            
            ProcessStartInfo processInfo = new ProcessStartInfo("cmd.exe", "/c " + command);
            processInfo.RedirectStandardOutput = true;
            processInfo.UseShellExecute = false;
            // ok: os-command-injection
            Process process = Process.Start(processInfo);
            
            StreamReader reader = process.StandardOutput;
            string output = reader.ReadToEnd();
            return Content(output);
        }
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

        public void good_case_4(HttpRequestMessage request)
        {
            // Get user input from header
            string hostname = request.Headers.GetValues("Host-To-Lookup").FirstOrDefault();
            
            // Validate hostname format
            if (Regex.IsMatch(hostname, @"^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$"))
            {
                var processStartInfo = new ProcessStartInfo
                {
                    FileName = "nslookup",
                    // ok: os-command-injection
                    Arguments = hostname,
                    RedirectStandardOutput = true,
                    UseShellExecute = false
                };
                Process.Start(processStartInfo);
            }
            else
            {
                // Handle invalid input
                throw new ArgumentException("Invalid hostname format");
            }
        }
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

        public IActionResult good_case_5()
        {
            // Use built-in API instead of shell commands
            string filename = Request.Cookies["file_to_delete"];
            
            // Validate path is within allowed directory
            string fullPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Temp), filename);
            string normalizedPath = Path.GetFullPath(fullPath);
            
            if (normalizedPath.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Temp)))
            {
                // ok: os-command-injection
                if (System.IO.File.Exists(normalizedPath))
                {
                    System.IO.File.Delete(normalizedPath);
                }
                return Ok("File deleted");
            }
            
            return BadRequest("Invalid file path");
        }
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

        public void good_case_6([FromQuery] string scriptName)
        {
            // Validate script name against whitelist
            Dictionary<string, string> allowedScripts = new Dictionary<string, string>
            {
                { "backup", "backup.ps1" },
                { "cleanup", "cleanup.ps1" },
                { "report", "generate_report.ps1" }
            };
            
            if (allowedScripts.TryGetValue(scriptName, out string actualScriptPath))
            {
                var processInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    // ok: os-command-injection
                    Arguments = $"-File {actualScriptPath}",
                    UseShellExecute = false
                };
                Process.Start(processInfo);
            }
            else
            {
                // Handle invalid script name
                throw new ArgumentException("Invalid script specified");
            }
        }
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

        public IActionResult good_case_7()
        {
            // Use command arguments as separate parameters
            string path = Request.Query["path"];
            string option = Request.Form["option"];
            
            // Validate path is within allowed directory
            string fullPath = Path.GetFullPath(path);
            string allowedDirectory = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
            
            if (!fullPath.StartsWith(allowedDirectory))
            {
                return BadRequest("Invalid path");
            }
            
            // Validate option
            List<string> allowedOptions = new List<string> { "/a", "/b", "/c", "/n", "/o" };
            if (!allowedOptions.Contains(option))
            {
                return BadRequest("Invalid option");
            }
            
            var process = new Process();
            process.StartInfo.FileName = "cmd.exe";
            // ok: os-command-injection
            process.StartInfo.Arguments = $"/c dir {option} {fullPath}";
            process.Start();
            
            return Ok("Command executed");
        }
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

        public void good_case_8()
        {
            // Use ProcessStartInfo.ArgumentList instead of Arguments string
            string username = Request.QueryString["username"];
            
            // Validate username format
            if (Regex.IsMatch(username, @"^[a-zA-Z0-9_]{3,20}$"))
            {
                var processInfo = new ProcessStartInfo
                {
                    FileName = "net",
                    UseShellExecute = false
                };
                
                // ok: os-command-injection
                processInfo.ArgumentList.Add("user");
                processInfo.ArgumentList.Add(username);
                Process.Start(processInfo);
            }
            else
            {
                // Handle invalid input
                Response.Write("Invalid username format");
            }
        }
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

        public ActionResult good_case_9()
        {
            // Use a command builder pattern
            var requestBody = new StreamReader(Request.Body).ReadToEnd();
            dynamic data = Newtonsoft.Json.JsonConvert.DeserializeObject(requestBody);
            
            // Map command to predefined actions
            Dictionary<string, Action> commandMap = new Dictionary<string, Action>
            {
                { "list_files", () => ListFiles() },
                { "check_disk", () => CheckDiskSpace() },
                { "system_info", () => GetSystemInfo() }
            };
            
            string commandKey = data.command;
            
            if (commandMap.ContainsKey(commandKey))
            {
                // ok: os-command-injection
                commandMap[commandKey].Invoke();
                return Ok("Command executed");
            }
            
            return BadRequest("Invalid command");
        }
// {/fact}
        
        private void ListFiles()
        {
            Process.Start("cmd.exe", "/c dir");
        }
        
        private void CheckDiskSpace()
        {
            Process.Start("cmd.exe", "/c wmic logicaldisk get size,freespace,caption");
        }
        
        private void GetSystemInfo()
        {
            Process.Start("cmd.exe", "/c systeminfo");
        }
// {fact rule=os-command-injection@v1.0 defects=0}

        public void good_case_10()
        {
            // Use built-in APIs instead of shell commands
            string fileName = Request.Query["file"];
            
            // Validate and sanitize path
            string fullPath = Path.GetFullPath(Path.Combine(Environment.CurrentDirectory, fileName));
            string safeDir = Path.GetFullPath(Environment.CurrentDirectory);
            
            if (fullPath.StartsWith(safeDir) && File.Exists(fullPath))
            {
                // ok: os-command-injection
                string fileContent = File.ReadAllText(fullPath);
                Response.Write(fileContent);
            }
            else
            {
                Response.Write("Invalid file path");
            }
        }
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

        public IActionResult good_case_11()
        {
            // Use a dedicated library instead of shell commands
            string searchTerm = Request.Form["search"];
            string directory = Request.Form["directory"];
            
            // Validate directory
            if (!Directory.Exists(directory))
            {
                return BadRequest("Directory does not exist");
            }
            
            // Use built-in Directory methods instead of shell commands
            // ok: os-command-injection
            var files = Directory.GetFiles(directory, "*" + searchTerm + "*", SearchOption.AllDirectories);
            
            return Ok(new { Results = files });
        }
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

        public void good_case_12()
        {
            // Use a safe command execution pattern with validation
            string userParam = Request.QueryString["param"];
            
            // Validate parameter against whitelist
            if (Regex.IsMatch(userParam, @"^[a-zA-Z0-9\s]+$"))
            {
                var processInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    // ok: os-command-injection
                    Arguments = $"/c echo {userParam}",
                    UseShellExecute = false
                };
                Process.Start(processInfo);
            }
            else
            {
                Response.Write("Invalid parameter format");
            }
        }
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

        public ActionResult good_case_13()
        {
            // Use a command pattern with predefined commands
            string commandKey = Request.QueryString["cmd"];
            
            // Define allowed commands
            Dictionary<string, string> allowedCommands = new Dictionary<string, string>
            {
                { "uptime", "uptime" },
                { "date", "date" },
                { "whoami", "whoami" }
            };
            
            if (allowedCommands.TryGetValue(commandKey, out string command))
            {
                // ok: os-command-injection
                string output = ExecuteSafeCommand(command);
                return Content(output);
            }
            
            return Content("Invalid command");
        }
// {/fact}
        
        private string ExecuteSafeCommand(string command)
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c {command}",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            process.Start();
            string result = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            return result;
        }
// {fact rule=os-command-injection@v1.0 defects=0}

        public void good_case_14()
        {
            // Use a safer approach with environment variables
            string userDir = Request.QueryString["directory"];
            
            // Validate directory name format
            if (Regex.IsMatch(userDir, @"^[a-zA-Z0-9_\-]+$"))
            {
                // Create a safe path within temp directory
                string safePath = Path.Combine(Path.GetTempPath(), userDir);
                
                // Use .NET Directory methods instead of shell commands
                // ok: os-command-injection
                if (!Directory.Exists(safePath))
                {
                    Directory.CreateDirectory(safePath);
                }
                
                string[] files = Directory.GetFiles(safePath);
                foreach (string file in files)
                {
                    Response.Write(file + "<br>");
                }
            }
            else
            {
                Response.Write("Invalid directory name");
            }
        }
// {/fact}
// {fact rule=os-command-injection@v1.0 defects=0}

        public IActionResult good_case_15()
        {
            // Use a command builder with parameter validation
            string parameter = Request.Query["param"];
            
            // Define allowed parameters and commands
            Dictionary<string, ProcessStartInfo> commandMap = new Dictionary<string, ProcessStartInfo>
            {
                { "disk", new ProcessStartInfo("cmd.exe", "/c wmic logicaldisk get caption,freespace,size") },
                { "memory", new ProcessStartInfo("cmd.exe", "/c wmic OS get FreePhysicalMemory,TotalVisibleMemorySize") },
                { "cpu", new ProcessStartInfo("cmd.exe", "/c wmic cpu get caption,deviceid,name") }
            };
            
            if (commandMap.TryGetValue(parameter, out ProcessStartInfo psi))
            {
                psi.RedirectStandardOutput = true;
                psi.UseShellExecute = false;
                
                // ok: os-command-injection
                var process = Process.Start(psi);
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                
                return Content(output);
            }
            
            return BadRequest("Invalid parameter");
        }
// {/fact}
    }
}