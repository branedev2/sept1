# This file contains examples of secure and insecure shell command execution in Ruby
# Rule ID: ruby-avoid-tainted-shell-call
# CWE: CWE-78

require 'sinatra'
require 'open3'
require 'shellwords'
require 'cgi'

# TRUE POSITIVES (Vulnerable Code)

# Example 1: Direct use of user input in system call
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_1
  get '/execute' do
    command = params[:cmd]
    # ruleid: ruby-avoid-tainted-shell-call
    system(command)
    "Command executed"
  end
# {/fact}
end

# Example 2: Using backticks with user input
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_2
  get '/run' do
    user_command = params[:command]
    # ruleid: ruby-avoid-tainted-shell-call
    result = `#{user_command}`
    "Result: #{result}"
  end
# {/fact}
end

# Example 3: Using exec with user input
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_3
  get '/exec' do
    cmd = params[:cmd]
    # ruleid: ruby-avoid-tainted-shell-call
    exec(cmd)
  end
# {/fact}
end

# Example 4: Using IO.popen with user input
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_4
  get '/popen' do
    command = params[:command]
    # ruleid: ruby-avoid-tainted-shell-call
    IO.popen(command) do |io|
      io.read
    end
# {/fact}
  end
end

# Example 5: Using Open3.capture2 with user input
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_5
  get '/capture' do
    cmd = params[:cmd]
    # ruleid: ruby-avoid-tainted-shell-call
    stdout, status = Open3.capture2(cmd)
    "Output: #{stdout}"
  end
# {/fact}
end

# Example 6: Using Open3.popen3 with user input
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_6
  get '/popen3' do
    command = params[:command]
    # ruleid: ruby-avoid-tainted-shell-call
    Open3.popen3(command) do |stdin, stdout, stderr, wait_thr|
      "Output: #{stdout.read}"
    end
# {/fact}
  end
end

# Example 7: Using system with string interpolation
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_7
  get '/system_interp' do
    filename = params[:file]
    # ruleid: ruby-avoid-tainted-shell-call
    system("cat #{filename}")
    "File displayed"
  end
# {/fact}
end

# Example 8: Using %x notation with user input
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_8
  get '/x_notation' do
    cmd = params[:cmd]
    # ruleid: ruby-avoid-tainted-shell-call
    result = %x[#{cmd}]
    "Result: #{result}"
  end
# {/fact}
end

# Example 9: Using Kernel.` with user input
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_9
  get '/kernel_backtick' do
    command = params[:command]
    # ruleid: ruby-avoid-tainted-shell-call
    result = Kernel.`(command)
    "Result: #{result}"
  end
# {/fact}
end

# Example 10: Using Open3.capture3 with user input
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_10
  get '/capture3' do
    cmd = params[:cmd]
    # ruleid: ruby-avoid-tainted-shell-call
    stdout, stderr, status = Open3.capture3(cmd)
    "Output: #{stdout}, Errors: #{stderr}"
  end
# {/fact}
end

# Example 11: Using system with multiple arguments but first is tainted
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_11
  get '/system_multi' do
    program = params[:program]
    # ruleid: ruby-avoid-tainted-shell-call
    system(program, "-la")
    "Command executed"
  end
# {/fact}
end

# Example 12: Using user input in shell command with concatenation
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_12
  get '/concat' do
    user_arg = params[:arg]
    cmd = "ls " + user_arg
    # ruleid: ruby-avoid-tainted-shell-call
    result = `#{cmd}`
    "Result: #{result}"
  end
# {/fact}
end

# Example 13: Using user input from headers in shell command
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_13
  get '/header_cmd' do
    cmd = request.env["HTTP_X_CUSTOM_COMMAND"]
    # ruleid: ruby-avoid-tainted-shell-call
    system(cmd)
    "Command from header executed"
  end
# {/fact}
end

# Example 14: Using user input from cookies in shell command
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_14
  get '/cookie_cmd' do
    cmd = request.cookies["command"]
    # ruleid: ruby-avoid-tainted-shell-call
    result = `#{cmd}`
    "Result: #{result}"
  end
# {/fact}
end

# Example 15: Using user input in Open3.pipeline with user input
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_15
  get '/pipeline' do
    cmd1 = params[:cmd1]
    cmd2 = "sort"
    # ruleid: ruby-avoid-tainted-shell-call
    Open3.pipeline(cmd1, cmd2)
    "Pipeline executed"
  end
# {/fact}
end

# TRUE NEGATIVES (Secure Code)

# Example 1: Using system with hardcoded command
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_1
  get '/safe_system' do
    # ok: ruby-avoid-tainted-shell-call
    system("ls -la")
    "Command executed safely"
  end
# {/fact}
end

# Example 2: Using backticks with hardcoded command
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_2
  get '/safe_backticks' do
    # ok: ruby-avoid-tainted-shell-call
    result = `ls -la`
    "Result: #{result}"
  end
# {/fact}
end

# Example 3: Using system with escaped user input
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_3
  get '/escaped_system' do
    filename = params[:file]
    # ok: ruby-avoid-tainted-shell-call
    system("ls", "-la", Shellwords.escape(filename))
    "Command executed safely"
  end
# {/fact}
end

# Example 4: Using backticks with escaped user input
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_4
  get '/escaped_backticks' do
    filename = params[:file]
    escaped_filename = Shellwords.escape(filename)
    # ok: ruby-avoid-tainted-shell-call
    result = `ls -la #{escaped_filename}`
    "Result: #{result}"
  end
# {/fact}
end

# Example 5: Using Open3.capture2 with array form and escaped input
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_5
  get '/safe_capture2' do
    filename = params[:file]
    # ok: ruby-avoid-tainted-shell-call
    stdout, status = Open3.capture2("ls", "-la", Shellwords.escape(filename))
    "Output: #{stdout}"
  end
# {/fact}
end

# Example 6: Using system with array form to avoid shell interpretation
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_6
  get '/array_system' do
    filename = params[:file]
    # ok: ruby-avoid-tainted-shell-call
    system("ls", "-la", filename)
    "Command executed safely using array form"
  end
# {/fact}
end

# Example 7: Using IO.popen with array form
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_7
  get '/safe_popen' do
    filename = params[:file]
    # ok: ruby-avoid-tainted-shell-call
    IO.popen(["ls", "-la", filename]) do |io|
      io.read
    end
# {/fact}
  end
end

# Example 8: Using Open3.capture3 with array form
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_8
  get '/safe_capture3' do
    filename = params[:file]
    # ok: ruby-avoid-tainted-shell-call
    stdout, stderr, status = Open3.capture3("ls", "-la", filename)
    "Output: #{stdout}, Errors: #{stderr}"
  end
# {/fact}
end

# Example 9: Using Open3.popen3 with array form
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_9
  get '/safe_popen3' do
    filename = params[:file]
    # ok: ruby-avoid-tainted-shell-call
    Open3.popen3("ls", "-la", filename) do |stdin, stdout, stderr, wait_thr|
      "Output: #{stdout.read}"
    end
# {/fact}
  end
end

# Example 10: Using system with validated input (whitelist approach)
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_10
  get '/whitelist_system' do
    action = params[:action]
    allowed_actions = ["list", "status", "version"]
    
    if allowed_actions.include?(action)
      command = case action
                when "list" then "ls -la"
                when "status" then "systemctl status apache2"
                when "version" then "ruby --version"
                end
      # ok: ruby-avoid-tainted-shell-call
      system(command)
      "Command executed safely"
    else
      "Invalid action"
    end
# {/fact}
  end
end

# Example 11: Using a safer alternative to shell commands
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_11
  get '/no_shell' do
    filename = params[:file]
    # ok: ruby-avoid-tainted-shell-call
    if File.exist?(filename)
      content = File.read(filename)
      "File content: #{content}"
    else
      "File not found"
    end
  end
# {/fact}
end

# Example 12: Using Open3.pipeline with array form
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_12
  get '/safe_pipeline' do
    filename = params[:file]
    # ok: ruby-avoid-tainted-shell-call
    Open3.pipeline(["grep", "error", filename], ["wc", "-l"])
    "Pipeline executed safely"
  end
# {/fact}
end

# Example 13: Using %x notation with hardcoded command
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_13
  get '/safe_x_notation' do
    # ok: ruby-avoid-tainted-shell-call
    result = %x[ls -la]
    "Result: #{result}"
  end
# {/fact}
end

# Example 14: Using system with sanitized input through regex validation
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_14
  get '/regex_sanitized' do
    filename = params[:file]
    if filename =~ /^[a-zA-Z0-9_\-\.]+$/  # Only allow alphanumeric, underscore, hyphen, and period
      # ok: ruby-avoid-tainted-shell-call
      system("ls", "-la", filename)
      "Command executed safely"
    else
      "Invalid filename"
    end
  end
# {/fact}
end

# Example 15: Using exec with hardcoded command
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_15
  get '/safe_exec' do
    # ok: ruby-avoid-tainted-shell-call
    exec("ls -la")
  end
# {/fact}
end