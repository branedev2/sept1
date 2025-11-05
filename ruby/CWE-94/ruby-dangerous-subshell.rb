require 'sinatra'
require 'shellwords'
require 'open3'

# True Positive Examples (Vulnerable Code)

# Example 1: Direct command execution with user input using backticks
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_1
  user_input = params[:command]
  result = `ls #{user_input}`  # ruleid: ruby-dangerous-subshell
  "Command output: #{result}"
end
# {/fact}

# Example 2: Using system() with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_2
  directory = params[:dir]
  system("rm -rf #{directory}")  # ruleid: ruby-dangerous-subshell
  "Directory removed"
end
# {/fact}

# Example 3: Using exec with interpolated user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_3
  filename = params[:file]
  exec("cat #{filename}")  # ruleid: ruby-dangerous-subshell
  "File contents displayed"
end
# {/fact}

# Example 4: Using IO.popen with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_4
  command = params[:cmd]
  IO.popen("#{command}") do |io|  # ruleid: ruby-dangerous-subshell
    @output = io.read
  end
# {/fact}
  "Command executed: #{@output}"
end

# Example 5: Using Open3.capture2 with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_5
  command = params[:command]
  stdout, status = Open3.capture2("grep #{command} /var/log/system.log")  # ruleid: ruby-dangerous-subshell
  "Search results: #{stdout}"
end
# {/fact}

# Example 6: Using %x notation with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_6
  query = params[:query]
  result = %x(find /home -name #{query})  # ruleid: ruby-dangerous-subshell
  "Found files: #{result}"
end
# {/fact}

# Example 7: Using Open3.capture3 with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_7
  user_command = request.headers["X-Command"]
  stdout, stderr, status = Open3.capture3("#{user_command}")  # ruleid: ruby-dangerous-subshell
  "Command executed with status: #{status.exitstatus}"
end
# {/fact}

# Example 8: Using Kernel.` with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_8
  file_pattern = params[:pattern]
  output = Kernel.`("grep -r #{file_pattern} /etc/")  # ruleid: ruby-dangerous-subshell
  "Grep results: #{output}"
end
# {/fact}

# Example 9: Using Open3.popen3 with user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_9
  command = request.cookies["command"]
  Open3.popen3("echo #{command} >> /tmp/commands.log") do |stdin, stdout, stderr, wait_thr|  # ruleid: ruby-dangerous-subshell
    @output = stdout.read
  end
# {/fact}
  "Command logged"
end

# Example 10: Using backticks with multiple user inputs
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_10
  search_term = params[:term]
  file_path = params[:path]
  result = `grep #{search_term} #{file_path}`  # ruleid: ruby-dangerous-subshell
  "Search results: #{result}"
end
# {/fact}

# Example 11: Using system with user input in a conditional
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_11
  command = params[:cmd]
  if params[:admin] == "true"
    success = system("sudo #{command}")  # ruleid: ruby-dangerous-subshell
    "Command executed with admin privileges: #{success}"
  else
    "Not authorized"
  end
end
# {/fact}

# Example 12: Using exec with user input after processing
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_12
  user_command = params[:command]
  processed_command = user_command.downcase
  exec("#{processed_command}")  # ruleid: ruby-dangerous-subshell
  "Command executed"
end
# {/fact}

# Example 13: Using backticks with user input in a loop
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_13
  commands = params[:commands].split(',')
  results = []
  commands.each do |cmd|
    results << `#{cmd}`  # ruleid: ruby-dangerous-subshell
  end
# {/fact}
  "Commands executed: #{results.join(', ')}"
end

# Example 14: Using IO.popen with user input in a complex string
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_14
  filename = params[:filename]
  IO.popen("find /var/www -name '*#{filename}*' -type f") do |io|  # ruleid: ruby-dangerous-subshell
    @files = io.read
  end
# {/fact}
  "Files found: #{@files}"
end

# Example 15: Using system with user input from request body
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_15
  data = JSON.parse(request.body.read)
  command = data["command"]
  system("#{command} > /tmp/output.txt")  # ruleid: ruby-dangerous-subshell
  "Command output saved to file"
end
# {/fact}

# True Negative Examples (Safe Code)

# Example 1: Using Shellwords.escape to sanitize input
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_1
  user_input = params[:command]
  safe_input = Shellwords.escape(user_input)  # ok: ruby-dangerous-subshell
  result = `ls #{safe_input}`
  "Command output: #{result}"
end
# {/fact}

# Example 2: Using system with an array of arguments (no shell interpretation)
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_2
  directory = params[:dir]
  system("rm", "-rf", directory)  # ok: ruby-dangerous-subshell
  "Directory removed safely"
end
# {/fact}

# Example 3: Using a whitelist approach
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_3
  filename = params[:file]
  allowed_files = ["report.txt", "data.csv", "config.ini"]
  
  if allowed_files.include?(filename)  # ok: ruby-dangerous-subshell
    content = `cat #{filename}`
    "File contents: #{content}"
  else
    "Access denied to that file"
  end
end
# {/fact}

# Example 4: Using IO.popen with array arguments
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_4
  command = params[:cmd]
  IO.popen(["echo", command]) do |io|  # ok: ruby-dangerous-subshell
    @output = io.read
  end
# {/fact}
  "Command executed safely: #{@output}"
end

# Example 5: Using Open3.capture2 with array arguments
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_5
  search_term = params[:term]
  stdout, status = Open3.capture2("grep", search_term, "/var/log/system.log")  # ok: ruby-dangerous-subshell
  "Search results: #{stdout}"
end
# {/fact}

# Example 6: Using hardcoded commands (no user input)
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_6
  result = `ls -la /tmp`  # ok: ruby-dangerous-subshell
  "Directory listing: #{result}"
end
# {/fact}

# Example 7: Using Open3.capture3 with array arguments and user input
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_7
  user_command = request.headers["X-Command"]
  stdout, stderr, status = Open3.capture3("echo", user_command)  # ok: ruby-dangerous-subshell
  "Command executed safely with status: #{status.exitstatus}"
end
# {/fact}

# Example 8: Using a custom validation function before execution
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_8
  pattern = params[:pattern]
  
  def safe_pattern?(input)  # ok: ruby-dangerous-subshell
    input.match?(/^[a-zA-Z0-9_\-\.]+$/)
  end
  
  if safe_pattern?(pattern)
    output = `grep -r #{pattern} /etc/`
    "Grep results: #{output}"
  else
    "Invalid pattern"
  end
end
# {/fact}

# Example 9: Using Open3.popen3 with array arguments
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_9
  command = request.cookies["command"]
  Open3.popen3("echo", command) do |stdin, stdout, stderr, wait_thr|  # ok: ruby-dangerous-subshell
    @output = stdout.read
  end
# {/fact}
  "Command logged safely"
end

# Example 10: Using a predefined set of commands
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_10
  action = params[:action]
  commands = {
    "list" => "ls -la",
    "disk" => "df -h",
    "memory" => "free -m"
  }
  
  if commands.key?(action)  # ok: ruby-dangerous-subshell
    result = `#{commands[action]}`
    "Command output: #{result}"
  else
    "Invalid command"
  end
end
# {/fact}

# Example 11: Using system with array arguments in a conditional
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_11
  command = params[:cmd]
  if params[:admin] == "true"
    success = system({"PATH" => "/usr/bin"}, "echo", command)  # ok: ruby-dangerous-subshell
    "Command executed safely with admin privileges: #{success}"
  else
    "Not authorized"
  end
end
# {/fact}

# Example 12: Using exec with array arguments
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_12
  user_command = params[:command]
  exec("echo", user_command)  # ok: ruby-dangerous-subshell
  "Command executed safely"
end
# {/fact}

# Example 13: Using a safe alternative to shell commands
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_13
  filename = params[:filename]
  
  # Using Ruby's File API instead of shell commands
  if File.exist?(filename) && filename.match?(/^[a-zA-Z0-9_\-\.]+$/)  # ok: ruby-dangerous-subshell
    content = File.read(filename)
    "File contents: #{content}"
  else
    "File not found or invalid filename"
  end
end
# {/fact}

# Example 14: Using IO.popen with strict input validation
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_14
  filename = params[:filename]
  
  if filename.match?(/^[a-zA-Z0-9_\-\.]+$/)  # ok: ruby-dangerous-subshell
    IO.popen(["find", "/var/www", "-name", filename, "-type", "f"]) do |io|
      @files = io.read
    end
    "Files found: #{@files}"
  else
    "Invalid filename pattern"
  end
# {/fact}
end

# Example 15: Using system with Shellwords.escape for multiple parameters
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_15
  data = JSON.parse(request.body.read)
  command = data["command"]
  args = data["args"]
  
  safe_command = Shellwords.escape(command)
  safe_args = args.map { |arg| Shellwords.escape(arg) }  # ok: ruby-dangerous-subshell
  
  system("#{safe_command} #{safe_args.join(' ')} > /tmp/output.txt")
  "Command output saved to file"
end
# {/fact}