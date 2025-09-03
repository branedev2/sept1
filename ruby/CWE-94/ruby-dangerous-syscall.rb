# Examples for ruby-dangerous-syscall rule
# This rule detects direct usage of syscalls in Ruby code which can pose security risks

require 'fiddle'
require 'socket'
require 'open3'
require 'fileutils'
require 'securerandom'
require 'digest'
require 'net/http'
require 'json'

# True Positive Examples (Vulnerable Code)

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_1
  # Using syscall directly to execute a command
  user_input = gets.chomp
  # ruleid: ruby-dangerous-syscall
  syscall(11, "/bin/sh", ["/bin/sh", "-c", "echo #{user_input}"], 0)
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_2
  # Using syscall to open a file with user input
  filename = ARGV[0]
  # ruleid: ruby-dangerous-syscall
  fd = syscall(2, filename, 0) # open syscall
  puts "File opened with descriptor: #{fd}"
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_3
  # Using syscall to execute a command with user input from HTTP
  require 'sinatra'
  get '/execute' do
    command = params[:cmd]
    # ruleid: ruby-dangerous-syscall
    syscall(11, "/bin/sh", ["/bin/sh", "-c", command], 0) # execve syscall
    "Command executed"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_4
  # Using Fiddle to make a direct syscall
  libc = Fiddle.dlopen(nil)
  syscall = Fiddle::Function.new(libc['syscall'], 
                               [Fiddle::TYPE_INT, Fiddle::TYPE_VOIDP], 
                               Fiddle::TYPE_INT)
  # ruleid: ruby-dangerous-syscall
  syscall.call(11, "/bin/ls", ["/bin/ls", "-la"], 0) # execve syscall via Fiddle
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_5
  # Using syscall for file operations with user input
  path = gets.chomp
  mode = 0644
  # ruleid: ruby-dangerous-syscall
  fd = syscall(2, path, 1, mode) # open syscall with write mode
  syscall(4, fd, "Hello, world!\n", 14) # write syscall
  syscall(3, fd) # close syscall
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_6
  # Using syscall for network operations
  # ruleid: ruby-dangerous-syscall
  socket_fd = syscall(41, 2, 1, 0) # socket syscall (AF_INET, SOCK_STREAM, 0)
  puts "Socket created with descriptor: #{socket_fd}"
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_7
  # Using syscall for process manipulation
  target_pid = gets.chomp.to_i
  # ruleid: ruby-dangerous-syscall
  syscall(62, target_pid, 9) # kill syscall with SIGKILL
  puts "Process #{target_pid} terminated"
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_8
  # Using syscall for file permissions
  filename = ARGV[0]
  # ruleid: ruby-dangerous-syscall
  syscall(90, filename, 0777) # chmod syscall
  puts "Changed permissions for #{filename}"
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_9
  # Using syscall for directory operations
  dirname = gets.chomp
  # ruleid: ruby-dangerous-syscall
  syscall(83, dirname, 0755) # mkdir syscall
  puts "Created directory: #{dirname}"
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_10
  # Using syscall with dynamic calculation of syscall number
  operation = gets.chomp
  syscall_num = case operation
                when "read" then 0
                when "write" then 1
                when "open" then 2
                when "close" then 3
                else 11 # execve by default
                end
# {/fact}
  # ruleid: ruby-dangerous-syscall
  syscall(syscall_num, *ARGV)
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_11
  # Using syscall in a loop for multiple operations
  files = Dir.glob("*.txt")
  files.each do |file|
    # ruleid: ruby-dangerous-syscall
    fd = syscall(2, file, 0) # open syscall
    buffer = " " * 1024
    syscall(0, fd, buffer, 1024) # read syscall
    syscall(3, fd) # close syscall
    puts "Read from #{file}: #{buffer.strip}"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_12
  # Using syscall for IPC operations
  # ruleid: ruby-dangerous-syscall
  pipe_fds = [0, 0]
  syscall(22, pipe_fds) # pipe syscall
  puts "Created pipe with descriptors: #{pipe_fds[0]}, #{pipe_fds[1]}"
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_13
  # Using syscall with error handling
  begin
    filename = "/etc/passwd"
    # ruleid: ruby-dangerous-syscall
    fd = syscall(2, filename, 0) # open syscall
    if fd < 0
      puts "Error opening file"
    else
      puts "Successfully opened file with descriptor: #{fd}"
      syscall(3, fd) # close syscall
    end
  rescue => e
    puts "Exception: #{e.message}"
  end
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_14
  # Using syscall for memory operations
  size = 4096
  # ruleid: ruby-dangerous-syscall
  addr = syscall(9, 0, size, 3, 34, -1, 0) # mmap syscall
  puts "Allocated memory at address: #{addr}"
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_15
  # Using syscall with a wrapper function
  def execute_syscall(num, *args)
    # ruleid: ruby-dangerous-syscall
    syscall(num, *args)
  end
  
  execute_syscall(11, "/bin/echo", ["/bin/echo", "Hello World"], 0) # execve syscall
end
# {/fact}

# True Negative Examples (Safe Code)

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_1
  # Using Ruby's built-in system method instead of direct syscall
  user_input = gets.chomp
  sanitized_input = user_input.gsub(/[^a-zA-Z0-9\s]/, '')
  # ok: ruby-dangerous-syscall
  system("echo #{sanitized_input}")
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_2
  # Using File.open instead of syscall for file operations
  filename = ARGV[0]
  # ok: ruby-dangerous-syscall
  File.open(filename, 'r') do |file|
    puts file.read
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_3
  # Using Ruby's built-in methods for command execution in a web context
  require 'sinatra'
  get '/execute' do
    command = params[:cmd]
    if command =~ /^[a-zA-Z0-9\s]+$/
      # ok: ruby-dangerous-syscall
      output = `echo #{command}`
      "Output: #{output}"
    else
      "Invalid command"
    end
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_4
  # Using Ruby's Process module instead of direct syscalls
  # ok: ruby-dangerous-syscall
  pid = Process.spawn("ls -la")
  Process.wait(pid)
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_5
  # Using Ruby's IO methods for file operations
  path = gets.chomp
  # ok: ruby-dangerous-syscall
  File.open(path, 'w') do |file|
    file.write("Hello, world!\n")
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_6
  # Using Ruby's Socket class for network operations
  # ok: ruby-dangerous-syscall
  socket = TCPSocket.new('localhost', 8080)
  socket.puts "Hello, server!"
  response = socket.gets
  socket.close
  puts "Server response: #{response}"
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_7
  # Using Ruby's Process.kill instead of syscall
  target_pid = gets.chomp.to_i
  # ok: ruby-dangerous-syscall
  Process.kill('TERM', target_pid)
  puts "Process #{target_pid} terminated"
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_8
  # Using FileUtils for file permission changes
  filename = ARGV[0]
  # ok: ruby-dangerous-syscall
  FileUtils.chmod(0777, filename)
  puts "Changed permissions for #{filename}"
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_9
  # Using FileUtils for directory operations
  dirname = gets.chomp
  # ok: ruby-dangerous-syscall
  FileUtils.mkdir_p(dirname, mode: 0755)
  puts "Created directory: #{dirname}"
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_10
  # Using appropriate Ruby methods based on operation type
  operation = gets.chomp
  case operation
  when "read"
    # ok: ruby-dangerous-syscall
    content = File.read(ARGV[0])
    puts content
  when "write"
    # ok: ruby-dangerous-syscall
    File.write(ARGV[0], ARGV[1])
  when "execute"
    # ok: ruby-dangerous-syscall
    system(ARGV[0])
  end
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_11
  # Using Ruby's file methods in a loop
  files = Dir.glob("*.txt")
  files.each do |file|
    # ok: ruby-dangerous-syscall
    content = File.read(file)
    puts "Read from #{file}: #{content.strip}"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_12
  # Using Ruby's IO.pipe for IPC operations
  # ok: ruby-dangerous-syscall
  reader, writer = IO.pipe
  writer.puts "Hello, pipe!"
  writer.close
  message = reader.gets
  reader.close
  puts "Read from pipe: #{message}"
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_13
  # Using Ruby's file operations with error handling
  begin
    filename = "/etc/passwd"
    # ok: ruby-dangerous-syscall
    File.open(filename, 'r') do |file|
      puts "Successfully opened file"
      content = file.read
      puts "File content length: #{content.length}"
    end
  rescue => e
    puts "Exception: #{e.message}"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_14
  # Using Ruby's memory management instead of direct syscalls
  # ok: ruby-dangerous-syscall
  buffer = " " * 4096  # Ruby handles memory allocation
  buffer[0] = "H"
  buffer[1] = "i"
  puts "Buffer contains: #{buffer[0..10]}"
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_15
  # Using a wrapper function with proper Ruby methods
  def execute_command(cmd, args)
    # ok: ruby-dangerous-syscall
    Open3.capture3(cmd, *args)
  end
  
  stdout, stderr, status = execute_command("echo", ["Hello World"])
  puts "Output: #{stdout}, Status: #{status.exitstatus}"
end
# {/fact}