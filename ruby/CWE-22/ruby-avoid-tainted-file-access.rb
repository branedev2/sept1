# This file contains examples of secure and insecure file access patterns in Ruby
# focusing on the rule: ruby-avoid-tainted-file-access

require 'sinatra'
require 'fileutils'

# True Positives (Vulnerable Code)

# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_1
  # Reading a file with user input directly in the path
  get '/read_file' do
    filename = params[:filename]
    # ruleid: ruby-avoid-tainted-file-access
    content = File.read(filename)
    return content
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_2
  # Opening a file with user input directly in the path
  get '/open_file' do
    filename = params[:filename]
    # ruleid: ruby-avoid-tainted-file-access
    file = File.open(filename, 'r')
    content = file.read
    file.close
    return content
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_3
  # Checking if a file exists with user input
  get '/file_exists' do
    filename = params[:filename]
    # ruleid: ruby-avoid-tainted-file-access
    if File.exist?(filename)
      return "File exists"
    else
      return "File does not exist"
    end
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_4
  # Writing to a file with user input in the path
  post '/write_file' do
    filename = params[:filename]
    content = params[:content]
    # ruleid: ruby-avoid-tainted-file-access
    File.write(filename, content)
    return "File written successfully"
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_5
  # Deleting a file with user input
  delete '/delete_file' do
    filename = params[:filename]
    # ruleid: ruby-avoid-tainted-file-access
    File.delete(filename)
    return "File deleted successfully"
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_6
  # Using FileUtils to copy a file with user input
  post '/copy_file' do
    source = params[:source]
    destination = params[:destination]
    # ruleid: ruby-avoid-tainted-file-access
    FileUtils.cp(source, destination)
    return "File copied successfully"
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_7
  # Using FileUtils to move a file with user input
  post '/move_file' do
    source = params[:source]
    destination = params[:destination]
    # ruleid: ruby-avoid-tainted-file-access
    FileUtils.mv(source, destination)
    return "File moved successfully"
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_8
  # Reading directory contents with user input
  get '/list_directory' do
    directory = params[:directory]
    # ruleid: ruby-avoid-tainted-file-access
    files = Dir.entries(directory)
    return files.join(", ")
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_9
  # Creating a directory with user input
  post '/create_directory' do
    directory = params[:directory]
    # ruleid: ruby-avoid-tainted-file-access
    Dir.mkdir(directory)
    return "Directory created successfully"
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_10
  # Reading file information with user input
  get '/file_info' do
    filename = params[:filename]
    # ruleid: ruby-avoid-tainted-file-access
    info = File.stat(filename)
    return "File size: #{info.size}, Modified: #{info.mtime}"
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_11
  # Using IO.read with user input
  get '/io_read' do
    filename = params[:filename]
    # ruleid: ruby-avoid-tainted-file-access
    content = IO.read(filename)
    return content
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_12
  # Checking if path is a directory with user input
  get '/is_directory' do
    path = params[:path]
    # ruleid: ruby-avoid-tainted-file-access
    is_dir = File.directory?(path)
    return "Is directory: #{is_dir}"
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_13
  # Changing file permissions with user input
  post '/chmod' do
    filename = params[:filename]
    mode = params[:mode].to_i
    # ruleid: ruby-avoid-tainted-file-access
    File.chmod(mode, filename)
    return "Permissions changed successfully"
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_14
  # Expanding path with user input
  get '/expand_path' do
    path = params[:path]
    # ruleid: ruby-avoid-tainted-file-access
    expanded = File.expand_path(path)
    return expanded
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_15
  # Using File.foreach with user input
  get '/read_lines' do
    filename = params[:filename]
    lines = []
    # ruleid: ruby-avoid-tainted-file-access
    File.foreach(filename) do |line|
      lines << line
    end
# {/fact}
    return lines.join("<br>")
  end
end

# True Negatives (Secure Code)

# {fact rule=path-traversal@v1.0 defects=0}
def good_case_1
  # Reading a file with validated path
  get '/read_file_safe' do
    filename = params[:filename]
    # ok: ruby-avoid-tainted-file-access
    if filename =~ /\A[a-zA-Z0-9_\-\.]+\z/ && File.exist?("safe_directory/#{filename}")
      content = File.read("safe_directory/#{filename}")
      return content
    else
      return "Invalid filename"
    end
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=0}
def good_case_2
  # Opening a file with whitelisted path
  get '/open_file_safe' do
    filename = params[:filename]
    allowed_files = ["config.txt", "data.csv", "info.log"]
    # ok: ruby-avoid-tainted-file-access
    if allowed_files.include?(filename)
      file = File.open("data/#{filename}", 'r')
      content = file.read
      file.close
      return content
    else
      return "Access denied"
    end
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=0}
def good_case_3
  # Checking if a file exists with constrained path
  get '/file_exists_safe' do
    filename = params[:filename]
    # ok: ruby-avoid-tainted-file-access
    safe_path = File.join("public", filename.gsub(/[^a-zA-Z0-9\.\-_]/, ''))
    if File.exist?(safe_path)
      return "File exists"
    else
      return "File does not exist"
    end
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=0}
def good_case_4
  # Writing to a file with validated filename
  post '/write_file_safe' do
    filename = params[:filename]
    content = params[:content]
    # ok: ruby-avoid-tainted-file-access
    if filename =~ /\A[a-zA-Z0-9_\-\.]+\z/
      File.write(File.join("user_files", filename), content)
      return "File written successfully"
    else
      return "Invalid filename"
    end
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=0}
def good_case_5
  # Deleting a file with whitelisted options
  delete '/delete_file_safe' do
    filename = params[:filename]
    allowed_files = ["temp.txt", "cache.tmp", "old_data.bak"]
    # ok: ruby-avoid-tainted-file-access
    if allowed_files.include?(filename)
      File.delete(File.join("temp", filename))
      return "File deleted successfully"
    else
      return "Access denied"
    end
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=0}
def good_case_6
  # Using FileUtils to copy a file with validated paths
  post '/copy_file_safe' do
    source_name = params[:source]
    dest_name = params[:destination]
    # ok: ruby-avoid-tainted-file-access
    if source_name =~ /\A[a-zA-Z0-9_\-\.]+\z/ && dest_name =~ /\A[a-zA-Z0-9_\-\.]+\z/
      source = File.join("source_dir", source_name)
      destination = File.join("dest_dir", dest_name)
      FileUtils.cp(source, destination) if File.exist?(source)
      return "File copied successfully"
    else
      return "Invalid filenames"
    end
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=0}
def good_case_7
  # Using FileUtils to move a file with constrained paths
  post '/move_file_safe' do
    source_name = params[:source]
    dest_name = params[:destination]
    allowed_files = ["report.pdf", "data.xlsx", "image.png"]
    # ok: ruby-avoid-tainted-file-access
    if allowed_files.include?(source_name) && dest_name =~ /\A[a-zA-Z0-9_\-\.]+\z/
      source = File.join("uploads", source_name)
      destination = File.join("archive", dest_name)
      FileUtils.mv(source, destination) if File.exist?(source)
      return "File moved successfully"
    else
      return "Access denied"
    end
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=0}
def good_case_8
  # Reading directory contents with fixed path
  get '/list_directory_safe' do
    # ok: ruby-avoid-tainted-file-access
    files = Dir.entries("public_files")
    return files.join(", ")
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=0}
def good_case_9
  # Creating a directory with validated name
  post '/create_directory_safe' do
    dirname = params[:directory]
    # ok: ruby-avoid-tainted-file-access
    if dirname =~ /\A[a-zA-Z0-9_\-]+\z/
      Dir.mkdir(File.join("user_dirs", dirname)) unless Dir.exist?(File.join("user_dirs", dirname))
      return "Directory created successfully"
    else
      return "Invalid directory name"
    end
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=0}
def good_case_10
  # Reading file information with whitelisted files
  get '/file_info_safe' do
    filename = params[:filename]
    allowed_files = ["system.log", "app.log", "access.log"]
    # ok: ruby-avoid-tainted-file-access
    if allowed_files.include?(filename)
      info = File.stat(File.join("logs", filename))
      return "File size: #{info.size}, Modified: #{info.mtime}"
    else
      return "Access denied"
    end
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=0}
def good_case_11
  # Using IO.read with fixed path
  get '/io_read_safe' do
    # ok: ruby-avoid-tainted-file-access
    content = IO.read("config/settings.yml")
    return content
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=0}
def good_case_12
  # Checking if path is a directory with validated input
  get '/is_directory_safe' do
    path = params[:path]
    valid_dirs = ["uploads", "downloads", "public"]
    # ok: ruby-avoid-tainted-file-access
    if valid_dirs.include?(path)
      is_dir = File.directory?(path)
      return "Is directory: #{is_dir}"
    else
      return "Invalid directory"
    end
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=0}
def good_case_13
  # Changing file permissions with fixed path
  post '/chmod_safe' do
    mode = params[:mode].to_i
    # ok: ruby-avoid-tainted-file-access
    File.chmod(mode, "app/temp/cache.tmp") if mode.between?(0, 0777)
    return "Permissions changed successfully"
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=0}
def good_case_14
  # Expanding path with fixed base
  get '/expand_path_safe' do
    relative_path = params[:path]
    # ok: ruby-avoid-tainted-file-access
    if relative_path =~ /\A[a-zA-Z0-9_\-\.\/]+\z/
      expanded = File.expand_path(relative_path, "/var/www/safe_base")
      # Additional check to ensure we didn't escape the safe base
      if expanded.start_with?("/var/www/safe_base")
        return expanded
      end
    end
    return "Invalid path"
  end
# {/fact}
end

# {fact rule=path-traversal@v1.0 defects=0}
def good_case_15
  # Using File.foreach with hardcoded path
  get '/read_lines_safe' do
    # ok: ruby-avoid-tainted-file-access
    lines = []
    File.foreach("logs/application.log") do |line|
      lines << line
    end
# {/fact}
    return lines.join("<br>")
  end
end