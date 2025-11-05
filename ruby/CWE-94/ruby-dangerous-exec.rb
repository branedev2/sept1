# Test cases for ruby-dangerous-exec rule
# This rule detects potential command injection vulnerabilities when using exec or spawn with user input

require 'sinatra'
require 'open3'

# True Positive Examples (Vulnerable Code)

# Bad Case 1: Using exec with user input from URL parameter
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_1
  get '/execute' do
    command = params[:cmd]
    # ruleid: ruby-dangerous-exec
    exec(command)
    "Command executed"
  end
# {/fact}
end

# Bad Case 2: Using spawn with user input from form data
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_2
  post '/run_command' do
    user_command = params[:command]
    # ruleid: ruby-dangerous-exec
    spawn(user_command)
    "Command spawned"
  end
# {/fact}
end

# Bad Case 3: Using exec with string interpolation of user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_3
  get '/list_files' do
    directory = params[:dir]
    # ruleid: ruby-dangerous-exec
    exec("ls -la #{directory}")
    "Files listed"
  end
# {/fact}
end

# Bad Case 4: Using exec with concatenated user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_4
  post '/search' do
    term = params[:search_term]
    # ruleid: ruby-dangerous-exec
    exec("grep -r " + term + " /var/log/")
    "Search completed"
  end
# {/fact}
end

# Bad Case 5: Using spawn with user input in an array
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_5
  get '/find_process' do
    process_name = params[:process]
    # ruleid: ruby-dangerous-exec
    spawn(["ps", "aux", "|", "grep", process_name])
    "Process information retrieved"
  end
# {/fact}
end

# Bad Case 6: Using exec with request header as input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_6
  get '/execute_header' do
    cmd = request.env['HTTP_X_CUSTOM_COMMAND']
    # ruleid: ruby-dangerous-exec
    exec(cmd)
    "Command from header executed"
  end
# {/fact}
end

# Bad Case 7: Using exec with user input after minimal processing
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_7
  post '/backup' do
    folder = params[:folder].strip
    # ruleid: ruby-dangerous-exec
    exec("tar -czf backup.tar.gz #{folder}")
    "Backup created"
  end
# {/fact}
end

# Bad Case 8: Using spawn with user input in a conditional
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_8
  get '/conditional_exec' do
    cmd = params[:command]
    if cmd.start_with?("echo")
      # ruleid: ruby-dangerous-exec
      spawn(cmd)
      "Echo command executed"
    else
      "Only echo commands allowed"
    end
  end
# {/fact}
end

# Bad Case 9: Using exec with user input from cookies
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_9
  get '/cookie_exec' do
    command = request.cookies['saved_command']
    # ruleid: ruby-dangerous-exec
    exec(command)
    "Cookie command executed"
  end
# {/fact}
end

# Bad Case 10: Using spawn with user input in a loop
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_10
  post '/batch_commands' do
    commands = params[:commands].split(',')
    commands.each do |cmd|
      # ruleid: ruby-dangerous-exec
      spawn(cmd)
    end
# {/fact}
    "Batch commands executed"
  end
end

# Bad Case 11: Using exec with user input stored in a variable
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_11
  get '/delayed_exec' do
    stored_command = params[:cmd]
    # Some processing...
    sleep(1)
    # ruleid: ruby-dangerous-exec
    exec(stored_command)
    "Command executed after delay"
  end
# {/fact}
end

# Bad Case 12: Using spawn with formatted user input
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_12
  post '/format_exec' do
    input = params[:input]
    formatted_cmd = "echo #{input} >> log.txt"
    # ruleid: ruby-dangerous-exec
    spawn(formatted_cmd)
    "Formatted command executed"
  end
# {/fact}
end

# Bad Case 13: Using exec with multiple user inputs
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_13
  get '/complex_command' do
    source = params[:source]
    destination = params[:destination]
    # ruleid: ruby-dangerous-exec
    exec("cp #{source} #{destination}")
    "File copied"
  end
# {/fact}
end

# Bad Case 14: Using spawn with user input in a hash environment
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_14
  post '/env_command' do
    cmd = params[:command]
    env = {"PATH" => "/usr/bin"}
    # ruleid: ruby-dangerous-exec
    spawn(env, cmd)
    "Command executed with custom environment"
  end
# {/fact}
end

# Bad Case 15: Using exec with user input after transformation
# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_15
  get '/transform_exec' do
    user_input = params[:input]
    transformed = user_input.gsub(" ", "_")
    # ruleid: ruby-dangerous-exec
    exec("echo #{transformed}")
    "Transformed command executed"
  end
# {/fact}
end

# True Negative Examples (Safe Code)

# Good Case 1: Using exec with hardcoded command
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_1
  get '/safe_exec' do
    # ok: ruby-dangerous-exec
    exec("ls -la /tmp")
    "Safe command executed"
  end
# {/fact}
end

# Good Case 2: Using spawn with hardcoded command array
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_2
  post '/safe_spawn' do
    # ok: ruby-dangerous-exec
    spawn(["echo", "Hello World"])
    "Safe spawn executed"
  end
# {/fact}
end

# Good Case 3: Using a safer alternative with user input
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_3
  get '/safe_alternative' do
    directory = params[:dir]
    # ok: ruby-dangerous-exec
    output = `ls -la #{Shellwords.escape(directory)}`
    "Files listed safely: #{output}"
  end
# {/fact}
end

# Good Case 4: Using Open3.capture3 with escaped user input
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_4
  require 'shellwords'
  
  post '/safe_capture' do
    term = params[:search_term]
    # ok: ruby-dangerous-exec
    stdout, stderr, status = Open3.capture3("grep", "-r", term, "/var/log/")
    "Search completed safely: #{stdout}"
  end
# {/fact}
end

# Good Case 5: Using a whitelist for commands
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_5
  get '/whitelist_exec' do
    action = params[:action]
    allowed_actions = {"list" => "ls -la", "disk" => "df -h", "memory" => "free -m"}
    
    if allowed_actions.key?(action)
      # ok: ruby-dangerous-exec
      exec(allowed_actions[action])
      "Whitelisted command executed"
    else
      "Action not allowed"
    end
  end
# {/fact}
end

# Good Case 6: Using system with command array (no shell interpretation)
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_6
  get '/safe_system' do
    file = params[:filename]
    # ok: ruby-dangerous-exec
    system("cat", file)
    "File displayed safely"
  end
# {/fact}
end

# Good Case 7: Using a custom function to validate commands
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_7
  post '/validated_exec' do
    cmd = params[:command]
    
    def is_safe_command?(command)
      safe_patterns = [/^echo\s+"[^"]*"$/, /^date$/, /^uptime$/]
      safe_patterns.any? { |pattern| command.match?(pattern) }
    end
    
    if is_safe_command?(cmd)
      # ok: ruby-dangerous-exec
      exec(cmd)
      "Validated command executed"
    else
      "Unsafe command rejected"
    end
  end
# {/fact}
end

# Good Case 8: Using a safer API for the specific task
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_8
  get '/file_operations' do
    filename = params[:file]
    # ok: ruby-dangerous-exec
    content = File.read(filename) rescue "File not found"
    "File read safely: #{content}"
  end
# {/fact}
end

# Good Case 9: Using Open3.popen3 with command array
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_9
  require 'open3'
  
  post '/safe_popen' do
    query = params[:query]
    # ok: ruby-dangerous-exec
    Open3.popen3("grep", "-i", query, "logfile.txt") do |stdin, stdout, stderr, wait_thr|
      output = stdout.read
      "Search completed safely: #{output}"
    end
# {/fact}
  end
end

# Good Case 10: Using a dedicated library for the task
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_10
  require 'fileutils'
  
  get '/safe_file_copy' do
    source = params[:source]
    destination = params[:destination]
    # ok: ruby-dangerous-exec
    FileUtils.cp(source, destination)
    "File copied safely"
  end
# {/fact}
end

# Good Case 11: Using a constant command with variable arguments
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_11
  post '/safe_args' do
    user_id = params[:user_id].to_i  # Convert to integer to prevent injection
    # ok: ruby-dangerous-exec
    system("id", user_id.to_s)
    "User ID checked safely"
  end
# {/fact}
end

# Good Case 12: Using a command builder pattern
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_12
  get '/command_builder' do
    action = params[:action]
    
    commands = {
      "list_users" => ["cat", "/etc/passwd"],
      "disk_space" => ["df", "-h"],
      "memory_usage" => ["free", "-m"]
    }
    
    if commands.key?(action)
      # ok: ruby-dangerous-exec
      system(*commands[action])
      "Safe command executed via builder pattern"
    else
      "Unknown action"
    end
  end
# {/fact}
end

# Good Case 13: Using Ruby's built-in methods instead of shell commands
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_13
  post '/ruby_methods' do
    directory = params[:dir]
    # ok: ruby-dangerous-exec
    files = Dir.entries(directory)
    "Files listed using Ruby methods: #{files.join(', ')}"
  end
# {/fact}
end

# Good Case 14: Using a dedicated gem for shell operations
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_14
  require 'shellwords'
  
  get '/shell_escape' do
    user_input = params[:input]
    escaped_input = Shellwords.escape(user_input)
    # ok: ruby-dangerous-exec
    system("echo", escaped_input)
    "Input safely echoed"
  end
# {/fact}
end

# Good Case 15: Using a safer subprocess API
# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_15
  require 'open3'
  
  post '/subprocess_api' do
    command = params[:cmd]
    allowed_commands = ["date", "uptime", "whoami"]
    
    if allowed_commands.include?(command)
      # ok: ruby-dangerous-exec
      stdout, stderr, status = Open3.capture3(command)
      "Command executed safely: #{stdout}"
    else
      "Command not allowed"
    end
  end
# {/fact}
end