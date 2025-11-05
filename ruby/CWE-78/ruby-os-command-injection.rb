require 'sinatra'
require 'open3'
require 'shellwords'
require 'cgi'

# True Positive Examples (Vulnerable Code)

# Example 1: Direct command injection through query parameter
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_1
  user_input = params[:command]
  # ruleid: ruby-os-command-injection
  system("echo #{user_input}")
end
# {/fact}

# Example 2: Command injection in backticks
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_2
  user_input = params[:filename]
  # ruleid: ruby-os-command-injection
  result = `ls -la #{user_input}`
  "File listing: #{result}"
end
# {/fact}

# Example 3: Using exec with user input
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_3
  user_input = params[:directory]
  # ruleid: ruby-os-command-injection
  exec("cd #{user_input} && ls -la")
end
# {/fact}

# Example 4: Using IO.popen with user input
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_4
  user_input = request.env['HTTP_X_CUSTOM_HEADER']
  # ruleid: ruby-os-command-injection
  IO.popen("find / -name #{user_input}") do |io|
    io.read
  end
# {/fact}
end

# Example 5: Using Open3.capture2 with user input
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_5
  user_input = params[:search_term]
  # ruleid: ruby-os-command-injection
  stdout, status = Open3.capture2("grep #{user_input} /var/log/system.log")
  stdout
end
# {/fact}

# Example 6: Using Open3.capture3 with user input
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_6
  user_input = request.cookies['preference']
  # ruleid: ruby-os-command-injection
  stdout, stderr, status = Open3.capture3("find /home -user #{user_input}")
  "Results: #{stdout}"
end
# {/fact}

# Example 7: Using %x notation for command execution
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_7
  user_input = params[:query]
  # ruleid: ruby-os-command-injection
  result = %x(grep -r "#{user_input}" /etc/)
  "Search results: #{result}"
end
# {/fact}

# Example 8: Using Open3.popen3 with user input
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_8
  user_input = request.body.read
  # ruleid: ruby-os-command-injection
  Open3.popen3("echo #{user_input} > /tmp/user_data.txt") do |stdin, stdout, stderr, wait_thr|
    stdout.read
  end
# {/fact}
end

# Example 9: Command injection with string interpolation in Kernel.` method
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_9
  user_input = params[:file_type]
  # ruleid: ruby-os-command-injection
  result = Kernel.`("find . -name *.#{user_input}")
  "Found files: #{result}"
end
# {/fact}

# Example 10: Command injection with concatenation
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_10
  user_input = params[:username]
  command = "whoami > /tmp/" + user_input
  # ruleid: ruby-os-command-injection
  system(command)
end
# {/fact}

# Example 11: Command injection with multiple parameters
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_11
  host = params[:host]
  count = params[:count] || "4"
  # ruleid: ruby-os-command-injection
  system("ping -c #{count} #{host}")
end
# {/fact}

# Example 12: Command injection with conditional execution
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_12
  user_input = params[:filename]
  if File.exist?("/tmp")
    # ruleid: ruby-os-command-injection
    system("rm /tmp/#{user_input}")
  end
end
# {/fact}

# Example 13: Command injection with string formatting
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_13
  user_input = params[:command]
  command = "echo %s" % user_input
  # ruleid: ruby-os-command-injection
  system(command)
end
# {/fact}

# Example 14: Command injection with array arguments but containing interpolation
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_14
  user_input = params[:path]
  # ruleid: ruby-os-command-injection
  system("find", "#{user_input}", "-type", "f")
end
# {/fact}

# Example 15: Command injection with partial sanitization but still vulnerable
# {fact rule=os-command-injection@v1.0 defects=1}
def bad_case_15
  user_input = params[:filename].gsub(' ', '_')  # Only replaces spaces
  # ruleid: ruby-os-command-injection
  `cat /var/log/#{user_input}`
end
# {/fact}

# True Negative Examples (Secure Code)

# Example 1: Using shellescape to sanitize user input
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_1
  user_input = params[:command]
  # ok: ruby-os-command-injection
  system("echo #{Shellwords.escape(user_input)}")
end
# {/fact}

# Example 2: Using shellescape with backticks
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_2
  user_input = params[:filename]
  # ok: ruby-os-command-injection
  result = `ls -la #{Shellwords.escape(user_input)}`
  "File listing: #{result}"
end
# {/fact}

# Example 3: Using array form of system which avoids shell interpretation
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_3
  user_input = params[:directory]
  # ok: ruby-os-command-injection
  system("cd", user_input, "&&", "ls", "-la")
end
# {/fact}

# Example 4: Using shellescape with IO.popen
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_4
  user_input = request.env['HTTP_X_CUSTOM_HEADER']
  # ok: ruby-os-command-injection
  IO.popen(["find", "/", "-name", user_input]) do |io|
    io.read
  end
# {/fact}
end

# Example 5: Using array form with Open3.capture2
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_5
  user_input = params[:search_term]
  # ok: ruby-os-command-injection
  stdout, status = Open3.capture2("grep", user_input, "/var/log/system.log")
  stdout
end
# {/fact}

# Example 6: Using shellescape with Open3.capture3
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_6
  user_input = request.cookies['preference']
  # ok: ruby-os-command-injection
  stdout, stderr, status = Open3.capture3("find", "/home", "-user", Shellwords.escape(user_input))
  "Results: #{stdout}"
end
# {/fact}

# Example 7: Using whitelist validation before command execution
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_7
  user_input = params[:query]
  if user_input =~ /\A[a-zA-Z0-9_\-]+\z/
    # ok: ruby-os-command-injection
    result = %x(grep -r "#{user_input}" /etc/)
    "Search results: #{result}"
  else
    "Invalid input"
  end
end
# {/fact}

# Example 8: Using array form with Open3.popen3
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_8
  user_input = request.body.read
  # ok: ruby-os-command-injection
  Open3.popen3({"PATH" => "/usr/bin"}, "echo", user_input) do |stdin, stdout, stderr, wait_thr|
    stdout.read
  end
# {/fact}
end

# Example 9: Using hardcoded commands only
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_9
  # ok: ruby-os-command-injection
  result = Kernel.`("find . -name *.rb")
  "Found Ruby files: #{result}"
end
# {/fact}

# Example 10: Using a safe alternative to command execution
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_10
  user_input = params[:username]
  # ok: ruby-os-command-injection
  File.write("/tmp/#{Shellwords.escape(user_input)}", `whoami`)
end
# {/fact}

# Example 11: Using array form with validated input
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_11
  host = params[:host]
  count = params[:count].to_i.to_s # Ensure it's a clean integer
  if count.match?(/\A\d+\z/) && host.match?(/\A[a-zA-Z0-9\.\-]+\z/)
    # ok: ruby-os-command-injection
    system("ping", "-c", count, host)
  end
end
# {/fact}

# Example 12: Using File operations instead of system commands
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_12
  user_input = params[:filename]
  safe_filename = Shellwords.escape(user_input)
  # ok: ruby-os-command-injection
  File.delete("/tmp/#{safe_filename}") if File.exist?("/tmp/#{safe_filename}")
end
# {/fact}

# Example 13: Using built-in Ruby methods instead of system commands
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_13
  user_input = params[:directory]
  # ok: ruby-os-command-injection
  Dir.entries(user_input).each do |entry|
    puts entry
  end
# {/fact}
end

# Example 14: Using array form of system with separate arguments
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_14
  user_input = params[:path]
  # ok: ruby-os-command-injection
  system("find", user_input, "-type", "f")
end
# {/fact}

# Example 15: Using CGI.escape for user input in a safe context
# {fact rule=os-command-injection@v1.0 defects=0}
def good_case_15
  user_input = params[:query]
  escaped_input = CGI.escape(user_input)
  # ok: ruby-os-command-injection
  system("echo", escaped_input)
end
# {/fact}