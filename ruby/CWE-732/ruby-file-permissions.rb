# True Positives (Vulnerable Code)

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_1
  # Creating a file with world-writable permissions
  File.new("sensitive_data.txt", "w", 0777)
  # ruleid: ruby-file-permissions
  File.chmod(0777, "sensitive_data.txt")
end
# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_2
  # Setting read and write permissions for everyone
  file = File.open("config.yml", "w")
  # ruleid: ruby-file-permissions
  file.chmod(0666)
end
# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_3
  # Making a directory world-writable
  Dir.mkdir("secure_folder") unless Dir.exist?("secure_folder")
  # ruleid: ruby-file-permissions
  File.chmod(0777, "secure_folder")
end
# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_4
  # Setting insecure permissions on multiple files
  files = ["passwords.txt", "keys.json", "credentials.yml"]
  files.each do |file|
    File.open(file, "w") {}
    # ruleid: ruby-file-permissions
    File.chmod(0666, file)
  end
# {/fact}
end

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_5
  # Using symbolic permissions to make file world-writable
  require 'fileutils'
  FileUtils.touch("api_keys.txt")
  # ruleid: ruby-file-permissions
  FileUtils.chmod("a+w", "api_keys.txt")
end
# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_6
  # Using octal permissions with variable
  permissions = 0777
  File.open("user_data.json", "w") {}
  # ruleid: ruby-file-permissions
  File.chmod(permissions, "user_data.json")
end
# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_7
  # Using FileUtils to set permissions on multiple files
  require 'fileutils'
  # ruleid: ruby-file-permissions
  FileUtils.chmod(0666, ["config.json", "settings.yml", "database.ini"])
end
# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_8
  # Setting permissions with a calculated value
  base_permission = 0644
  world_write = 0002
  # ruleid: ruby-file-permissions
  File.chmod(base_permission | world_write, "important_file.txt")
end
# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_9
  # Using FileUtils with symbolic mode for group and world write
  require 'fileutils'
  FileUtils.touch("secrets.json")
  # ruleid: ruby-file-permissions
  FileUtils.chmod("go+w", "secrets.json")
end
# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_10
  # Setting permissions with a variable from a calculation
  require 'fileutils'
  permissions = "a+rw"  # all users read and write
  FileUtils.touch("customer_data.csv")
  # ruleid: ruby-file-permissions
  FileUtils.chmod(permissions, "customer_data.csv")
end
# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_11
  # Setting world-readable permissions on a sensitive file
  File.open("private_keys.pem", "w") {}
  # ruleid: ruby-file-permissions
  File.chmod(0644, "private_keys.pem")
end
# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_12
  # Using an array of permissions
  require 'fileutils'
  files = Dir.glob("*.key")
  # ruleid: ruby-file-permissions
  FileUtils.chmod_R(0664, files)
end
# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_13
  # Setting permissions with bitwise operations
  read_for_all = 0444
  write_for_group = 0020
  # ruleid: ruby-file-permissions
  File.chmod(read_for_all | write_for_group, "database_backup.sql")
end
# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_14
  # Using symbolic permissions for group write
  require 'fileutils'
  # ruleid: ruby-file-permissions
  FileUtils.chmod("g+w", "shared_folder")
end
# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=1}
def bad_case_15
  # Setting insecure permissions with a method that returns permissions
  def get_permissions
    0666  # read/write for all
  end
  
  File.open("auth_tokens.txt", "w") {}
  # ruleid: ruby-file-permissions
  File.chmod(get_permissions(), "auth_tokens.txt")
end
# {/fact}

# True Negatives (Secure Code)

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_1
  # Setting secure permissions - owner read/write only
  File.open("sensitive_data.txt", "w") {}
  # ok: ruby-file-permissions
  File.chmod(0600, "sensitive_data.txt")
end
# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_2
  # Using secure permissions for a file
  file = File.open("config.yml", "w")
  # ok: ruby-file-permissions
  file.chmod(0400)  # read-only for owner
end
# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_3
  # Setting secure directory permissions
  Dir.mkdir("secure_folder") unless Dir.exist?("secure_folder")
  # ok: ruby-file-permissions
  File.chmod(0700, "secure_folder")  # owner access only
end
# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_4
  # Setting secure permissions on multiple files
  files = ["passwords.txt", "keys.json", "credentials.yml"]
  files.each do |file|
    File.open(file, "w") {}
    # ok: ruby-file-permissions
    File.chmod(0600, file)  # owner read/write only
  end
# {/fact}
end

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_5
  # Using symbolic permissions securely
  require 'fileutils'
  FileUtils.touch("api_keys.txt")
  # ok: ruby-file-permissions
  FileUtils.chmod("u=rw,go-rwx", "api_keys.txt")  # owner read/write, no access for others
end
# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_6
  # Using octal permissions with variable - secure
  permissions = 0600  # owner read/write only
  File.open("user_data.json", "w") {}
  # ok: ruby-file-permissions
  File.chmod(permissions, "user_data.json")
end
# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_7
  # Using FileUtils to set secure permissions on multiple files
  require 'fileutils'
  # ok: ruby-file-permissions
  FileUtils.chmod(0400, ["config.json", "settings.yml", "database.ini"])  # read-only for owner
end
# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_8
  # Setting permissions with a calculated secure value
  base_permission = 0600  # owner read/write
  # ok: ruby-file-permissions
  File.chmod(base_permission, "important_file.txt")
end
# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_9
  # Using FileUtils with symbolic mode securely
  require 'fileutils'
  FileUtils.touch("secrets.json")
  # ok: ruby-file-permissions
  FileUtils.chmod("u=rw,go=", "secrets.json")  # owner read/write, no access for others
end
# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_10
  # Setting permissions with a secure variable
  require 'fileutils'
  permissions = "u+rw,go-rwx"  # owner read/write, no access for others
  FileUtils.touch("customer_data.csv")
  # ok: ruby-file-permissions
  FileUtils.chmod(permissions, "customer_data.csv")
end
# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_11
  # Setting secure permissions on a sensitive file
  File.open("private_keys.pem", "w") {}
  # ok: ruby-file-permissions
  File.chmod(0400, "private_keys.pem")  # read-only for owner
end
# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_12
  # Using an array of secure permissions
  require 'fileutils'
  files = Dir.glob("*.key")
  # ok: ruby-file-permissions
  FileUtils.chmod_R(0600, files)  # owner read/write only
end
# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_13
  # Setting permissions with secure bitwise operations
  owner_read = 0400
  owner_write = 0200
  # ok: ruby-file-permissions
  File.chmod(owner_read | owner_write, "database_backup.sql")  # owner read/write only
end
# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_14
  # Using symbolic permissions securely
  require 'fileutils'
  # ok: ruby-file-permissions
  FileUtils.chmod("u=rwx,go=", "private_folder")  # owner full access, no access for others
end
# {/fact}

# {fact rule=insecure-file-permissions@v1.0 defects=0}
def good_case_15
  # Setting secure permissions with a method that returns permissions
  def get_secure_permissions
    0600  # read/write for owner only
  end
  
  File.open("auth_tokens.txt", "w") {}
  # ok: ruby-file-permissions
  File.chmod(get_secure_permissions(), "auth_tokens.txt")
end
# {/fact}