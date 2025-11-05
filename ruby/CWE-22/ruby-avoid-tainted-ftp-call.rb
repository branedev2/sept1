require 'net/ftp'
require 'sinatra'
require 'uri'

# True Positive Examples - Vulnerable Code

# Example 1: Basic FTP connection with user-supplied host
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_1
  # User input from request parameters
  host = params[:host]
  
  # ruleid: ruby-avoid-tainted-ftp-call
  ftp = Net::FTP.new(host)
  ftp.login('user', 'password')
  ftp.list
  ftp.close
end
# {/fact}

# Example 2: FTP connection with user-supplied credentials
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_2
  # User input from request parameters
  username = params[:username]
  password = params[:password]
  
  ftp = Net::FTP.new('ftp.example.com')
  # ruleid: ruby-avoid-tainted-ftp-call
  ftp.login(username, password)
  ftp.list
  ftp.close
end
# {/fact}

# Example 3: FTP get operation with user-supplied filename
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_3
  # User input from request parameters
  filename = params[:filename]
  
  ftp = Net::FTP.new('ftp.example.com')
  ftp.login('user', 'password')
  # ruleid: ruby-avoid-tainted-ftp-call
  ftp.get(filename, "downloads/#{filename}")
  ftp.close
end
# {/fact}

# Example 4: FTP put operation with user-supplied path
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_4
  # User input from request parameters
  upload_path = params[:path]
  
  ftp = Net::FTP.new('ftp.example.com')
  ftp.login('user', 'password')
  # ruleid: ruby-avoid-tainted-ftp-call
  ftp.put('local_file.txt', "#{upload_path}/remote_file.txt")
  ftp.close
end
# {/fact}

# Example 5: FTP delete operation with user-supplied filename
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_5
  # User input from request parameters
  filename = params[:filename]
  
  ftp = Net::FTP.new('ftp.example.com')
  ftp.login('user', 'password')
  # ruleid: ruby-avoid-tainted-ftp-call
  ftp.delete(filename)
  ftp.close
end
# {/fact}

# Example 6: FTP mkdir operation with user-supplied directory name
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_6
  # User input from request parameters
  dir_name = params[:directory]
  
  ftp = Net::FTP.new('ftp.example.com')
  ftp.login('user', 'password')
  # ruleid: ruby-avoid-tainted-ftp-call
  ftp.mkdir(dir_name)
  ftp.close
end
# {/fact}

# Example 7: FTP chdir operation with user-supplied path
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_7
  # User input from request parameters
  path = params[:path]
  
  ftp = Net::FTP.new('ftp.example.com')
  ftp.login('user', 'password')
  # ruleid: ruby-avoid-tainted-ftp-call
  ftp.chdir(path)
  ftp.list
  ftp.close
end
# {/fact}

# Example 8: FTP rename operation with user-supplied filenames
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_8
  # User input from request parameters
  old_name = params[:old_name]
  new_name = params[:new_name]
  
  ftp = Net::FTP.new('ftp.example.com')
  ftp.login('user', 'password')
  # ruleid: ruby-avoid-tainted-ftp-call
  ftp.rename(old_name, new_name)
  ftp.close
end
# {/fact}

# Example 9: FTP connection with user-supplied port
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_9
  # User input from request parameters
  port = params[:port].to_i
  
  # ruleid: ruby-avoid-tainted-ftp-call
  ftp = Net::FTP.new('ftp.example.com', port)
  ftp.login('user', 'password')
  ftp.list
  ftp.close
end
# {/fact}

# Example 10: FTP connection with multiple user-supplied parameters
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_10
  # User input from request parameters
  host = params[:host]
  username = params[:username]
  password = params[:password]
  
  # ruleid: ruby-avoid-tainted-ftp-call
  ftp = Net::FTP.new(host)
  ftp.login(username, password)
  ftp.list
  ftp.close
end
# {/fact}

# Example 11: FTP get operation with user-supplied local filename
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_11
  # User input from request parameters
  local_file = params[:local_file]
  
  ftp = Net::FTP.new('ftp.example.com')
  ftp.login('user', 'password')
  # ruleid: ruby-avoid-tainted-ftp-call
  ftp.get('remote_file.txt', local_file)
  ftp.close
end
# {/fact}

# Example 12: FTP rmdir operation with user-supplied directory
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_12
  # User input from request parameters
  dir_name = params[:directory]
  
  ftp = Net::FTP.new('ftp.example.com')
  ftp.login('user', 'password')
  # ruleid: ruby-avoid-tainted-ftp-call
  ftp.rmdir(dir_name)
  ftp.close
end
# {/fact}

# Example 13: FTP getbinaryfile operation with user-supplied parameters
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_13
  # User input from request parameters
  remote_file = params[:remote_file]
  local_file = params[:local_file]
  
  ftp = Net::FTP.new('ftp.example.com')
  ftp.login('user', 'password')
  # ruleid: ruby-avoid-tainted-ftp-call
  ftp.getbinaryfile(remote_file, local_file)
  ftp.close
end
# {/fact}

# Example 14: FTP gettextfile operation with user-supplied parameters
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_14
  # User input from request parameters
  remote_file = params[:remote_file]
  
  ftp = Net::FTP.new('ftp.example.com')
  ftp.login('user', 'password')
  # ruleid: ruby-avoid-tainted-ftp-call
  ftp.gettextfile(remote_file, "downloads/#{remote_file}")
  ftp.close
end
# {/fact}

# Example 15: FTP putbinaryfile operation with user-supplied parameters
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_15
  # User input from request parameters
  remote_path = params[:remote_path]
  
  ftp = Net::FTP.new('ftp.example.com')
  ftp.login('user', 'password')
  # ruleid: ruby-avoid-tainted-ftp-call
  ftp.putbinaryfile('local_file.bin', "#{remote_path}/remote_file.bin")
  ftp.close
end
# {/fact}

# True Negative Examples - Secure Code

# Example 1: FTP connection with hardcoded host
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_1
  # ok: ruby-avoid-tainted-ftp-call
  ftp = Net::FTP.new('ftp.example.com')
  ftp.login('user', 'password')
  ftp.list
  ftp.close
end
# {/fact}

# Example 2: FTP connection with hardcoded credentials
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_2
  ftp = Net::FTP.new('ftp.example.com')
  # ok: ruby-avoid-tainted-ftp-call
  ftp.login('user', 'password')
  ftp.list
  ftp.close
end
# {/fact}

# Example 3: FTP get operation with hardcoded filename
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_3
  ftp = Net::FTP.new('ftp.example.com')
  ftp.login('user', 'password')
  # ok: ruby-avoid-tainted-ftp-call
  ftp.get('remote_file.txt', 'local_file.txt')
  ftp.close
end
# {/fact}

# Example 4: FTP put operation with hardcoded path
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_4
  ftp = Net::FTP.new('ftp.example.com')
  ftp.login('user', 'password')
  # ok: ruby-avoid-tainted-ftp-call
  ftp.put('local_file.txt', 'uploads/remote_file.txt')
  ftp.close
end
# {/fact}

# Example 5: FTP delete operation with hardcoded filename
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_5
  ftp = Net::FTP.new('ftp.example.com')
  ftp.login('user', 'password')
  # ok: ruby-avoid-tainted-ftp-call
  ftp.delete('old_file.txt')
  ftp.close
end
# {/fact}

# Example 6: FTP mkdir operation with hardcoded directory name
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_6
  ftp = Net::FTP.new('ftp.example.com')
  ftp.login('user', 'password')
  # ok: ruby-avoid-tainted-ftp-call
  ftp.mkdir('new_directory')
  ftp.close
end
# {/fact}

# Example 7: FTP chdir operation with hardcoded path
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_7
  ftp = Net::FTP.new('ftp.example.com')
  ftp.login('user', 'password')
  # ok: ruby-avoid-tainted-ftp-call
  ftp.chdir('/public_html')
  ftp.list
  ftp.close
end
# {/fact}

# Example 8: FTP rename operation with hardcoded filenames
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_8
  ftp = Net::FTP.new('ftp.example.com')
  ftp.login('user', 'password')
  # ok: ruby-avoid-tainted-ftp-call
  ftp.rename('old_name.txt', 'new_name.txt')
  ftp.close
end
# {/fact}

# Example 9: FTP connection with validated user input
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_9
  # User input from request parameters
  host = params[:host]
  
  # Validate against a whitelist of allowed hosts
  allowed_hosts = ['ftp.example.com', 'ftp.trusted-site.com', 'ftp.company.com']
  
  if allowed_hosts.include?(host)
    # ok: ruby-avoid-tainted-ftp-call
    ftp = Net::FTP.new(host)
    ftp.login('user', 'password')
    ftp.list
    ftp.close
  else
    raise "Invalid FTP host"
  end
end
# {/fact}

# Example 10: FTP get operation with sanitized filename
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_10
  # User input from request parameters
  filename = params[:filename]
  
  # Sanitize filename to prevent path traversal
  sanitized_filename = File.basename(filename)
  
  ftp = Net::FTP.new('ftp.example.com')
  ftp.login('user', 'password')
  # ok: ruby-avoid-tainted-ftp-call
  ftp.get(sanitized_filename, "downloads/#{sanitized_filename}")
  ftp.close
end
# {/fact}

# Example 11: FTP connection with environment variables
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_11
  # Using environment variables instead of hardcoded or user-supplied values
  host = ENV['FTP_HOST']
  username = ENV['FTP_USERNAME']
  password = ENV['FTP_PASSWORD']
  
  # ok: ruby-avoid-tainted-ftp-call
  ftp = Net::FTP.new(host)
  ftp.login(username, password)
  ftp.list
  ftp.close
end
# {/fact}

# Example 12: FTP put operation with validated path
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_12
  # User input from request parameters
  upload_path = params[:path]
  
  # Validate path against allowed directories
  allowed_dirs = ['uploads', 'public', 'shared']
  
  if allowed_dirs.include?(upload_path)
    ftp = Net::FTP.new('ftp.example.com')
    ftp.login('user', 'password')
    # ok: ruby-avoid-tainted-ftp-call
    ftp.put('local_file.txt', "#{upload_path}/remote_file.txt")
    ftp.close
  else
    raise "Invalid upload directory"
  end
end
# {/fact}

# Example 13: FTP connection with configuration from a secure source
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_13
  # Load configuration from a secure source
  config = YAML.load_file('/etc/app/secure_config.yml')
  
  # ok: ruby-avoid-tainted-ftp-call
  ftp = Net::FTP.new(config['ftp_host'])
  ftp.login(config['ftp_username'], config['ftp_password'])
  ftp.list
  ftp.close
end
# {/fact}

# Example 14: FTP getbinaryfile operation with hardcoded filenames
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_14
  ftp = Net::FTP.new('ftp.example.com')
  ftp.login('user', 'password')
  # ok: ruby-avoid-tainted-ftp-call
  ftp.getbinaryfile('remote_file.bin', 'local_file.bin')
  ftp.close
end
# {/fact}

# Example 15: FTP connection with validated port
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_15
  # User input from request parameters
  port = params[:port].to_i
  
  # Validate port is within allowed range
  if port >= 21 && port <= 22
    # ok: ruby-avoid-tainted-ftp-call
    ftp = Net::FTP.new('ftp.example.com', port)
    ftp.login('user', 'password')
    ftp.list
    ftp.close
  else
    raise "Invalid FTP port"
  end
end
# {/fact}