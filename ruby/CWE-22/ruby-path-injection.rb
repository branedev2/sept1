# Path Injection Vulnerability Examples in Ruby

require 'sinatra'
require 'fileutils'
require 'pathname'

# TRUE POSITIVES (Vulnerable Code)

# Example 1: Basic file opening with user input
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_1
  get '/download' do
    filename = params[:filename]
    # ruleid: ruby-path-injection
    content = File.read(filename)
    send_file content
  end
# {/fact}
end

# Example 2: Using File.open with user input
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_2
  get '/view_file' do
    file_path = params[:path]
    # ruleid: ruby-path-injection
    file = File.open(file_path, 'r')
    content = file.read
    file.close
    content
  end
# {/fact}
end

# Example 3: Using IO.read with user input
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_3
  post '/read_data' do
    file_path = request.body.read
    # ruleid: ruby-path-injection
    data = IO.read(file_path)
    "File content: #{data}"
  end
# {/fact}
end

# Example 4: Using File.foreach with user input
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_4
  get '/log_viewer' do
    log_file = params[:log]
    output = ""
    # ruleid: ruby-path-injection
    File.foreach(log_file) do |line|
      output += line
    end
# {/fact}
    output
  end
end

# Example 5: Using File.readlines with user input
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_5
  get '/read_lines' do
    filename = request.cookies["file"]
    # ruleid: ruby-path-injection
    lines = File.readlines(filename)
    lines.join("<br>")
  end
# {/fact}
end

# Example 6: Using File.new with user input
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_6
  get '/file_info' do
    path = params[:path]
    # ruleid: ruby-path-injection
    file = File.new(path, "r")
    info = "File size: #{file.size}"
    file.close
    info
  end
# {/fact}
end

# Example 7: Using FileUtils.touch with user input
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_7
  post '/create_file' do
    filename = request.params["filename"]
    # ruleid: ruby-path-injection
    FileUtils.touch(filename)
    "File created: #{filename}"
  end
# {/fact}
end

# Example 8: Using File.exist? with user input
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_8
  get '/check_file' do
    file_path = request.env["HTTP_X_FILENAME"]
    # ruleid: ruby-path-injection
    if File.exist?(file_path)
      "File exists"
    else
      "File does not exist"
    end
  end
# {/fact}
end

# Example 9: Using Dir.glob with user input
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_9
  get '/search_files' do
    pattern = params[:pattern]
    # ruleid: ruby-path-injection
    files = Dir.glob(pattern)
    "Found files: #{files.join(', ')}"
  end
# {/fact}
end

# Example 10: Using File.delete with user input
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_10
  post '/delete_file' do
    file_to_delete = request.params["file"]
    # ruleid: ruby-path-injection
    File.delete(file_to_delete)
    "File deleted"
  end
# {/fact}
end

# Example 11: Using File.rename with user input
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_11
  post '/rename_file' do
    old_name = params[:old]
    new_name = params[:new]
    # ruleid: ruby-path-injection
    File.rename(old_name, new_name)
    "File renamed"
  end
# {/fact}
end

# Example 12: Using File.chmod with user input
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_12
  post '/change_permissions' do
    file_path = request.body.read.strip
    # ruleid: ruby-path-injection
    File.chmod(0644, file_path)
    "Permissions changed"
  end
# {/fact}
end

# Example 13: Using Dir.entries with user input
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_13
  get '/list_directory' do
    dir_path = params[:dir]
    # ruleid: ruby-path-injection
    entries = Dir.entries(dir_path)
    "Directory contents: #{entries.join(', ')}"
  end
# {/fact}
end

# Example 14: Using File.directory? with user input
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_14
  get '/is_directory' do
    path = request.env["HTTP_X_PATH"]
    # ruleid: ruby-path-injection
    if File.directory?(path)
      "Path is a directory"
    else
      "Path is not a directory"
    end
  end
# {/fact}
end

# Example 15: Using File.expand_path with user input
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_15
  get '/expand_path' do
    rel_path = params[:path]
    # ruleid: ruby-path-injection
    full_path = File.expand_path(rel_path)
    "Full path: #{full_path}"
  end
# {/fact}
end

# TRUE NEGATIVES (Safe Code)

# Example 1: Using basename to sanitize user input
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_1
  get '/download_safe' do
    filename = params[:filename]
    # ok: ruby-path-injection
    safe_filename = File.basename(filename)
    content = File.read(File.join("safe_directory", safe_filename))
    send_file content
  end
# {/fact}
end

# Example 2: Using whitelist for file paths
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_2
  get '/view_file_safe' do
    requested_file = params[:file]
    allowed_files = ["config.txt", "public_info.log", "readme.md"]
    
    if allowed_files.include?(requested_file)
      # ok: ruby-path-injection
      content = File.read(File.join("data_directory", requested_file))
      content
    else
      "Access denied"
    end
  end
# {/fact}
end

# Example 3: Using absolute path with basename
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_3
  post '/read_data_safe' do
    filename = request.body.read
    # ok: ruby-path-injection
    safe_path = File.join("/var/app/safe_files", File.basename(filename))
    data = IO.read(safe_path)
    "File content: #{data}"
  end
# {/fact}
end

# Example 4: Using regex validation for filenames
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_4
  get '/log_viewer_safe' do
    log_file = params[:log]
    
    if log_file =~ /\A[a-zA-Z0-9_-]+\.log\z/
      # ok: ruby-path-injection
      output = File.read(File.join("logs", log_file))
      output
    else
      "Invalid log file name"
    end
  end
# {/fact}
end

# Example 5: Using hardcoded file path
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_5
  get '/read_config' do
    # ok: ruby-path-injection
    config_data = File.read("/etc/app/config.json")
    config_data
  end
# {/fact}
end

# Example 6: Using sanitized path with realpath
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_6
  get '/file_info_safe' do
    filename = params[:filename]
    safe_dir = "/var/app/public"
    safe_path = File.join(safe_dir, File.basename(filename))
    
    # ok: ruby-path-injection
    if File.realpath(safe_path).start_with?(safe_dir)
      file = File.new(safe_path, "r")
      info = "File size: #{file.size}"
      file.close
      info
    else
      "Access denied"
    end
  end
# {/fact}
end

# Example 7: Using Pathname to sanitize paths
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_7
  post '/create_file_safe' do
    filename = request.params["filename"]
    safe_dir = "/var/app/user_files"
    
    # ok: ruby-path-injection
    path = Pathname.new(File.join(safe_dir, File.basename(filename)))
    FileUtils.touch(path)
    "File created: #{path.basename}"
  end
# {/fact}
end

# Example 8: Using constant file path
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_8
  get '/read_terms' do
    # ok: ruby-path-injection
    terms = File.read("./public/terms_of_service.txt")
    terms
  end
# {/fact}
end

# Example 9: Using extension validation
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_9
  get '/view_image' do
    image = params[:image]
    
    if File.extname(image) == ".jpg" || File.extname(image) == ".png"
      # ok: ruby-path-injection
      path = File.join("public/images", File.basename(image))
      send_file path
    else
      "Invalid image format"
    end
  end
# {/fact}
end

# Example 10: Using ID to map to file paths
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_10
  get '/document/:id' do
    doc_id = params[:id].to_i
    doc_map = {
      1 => "/var/app/docs/welcome.txt",
      2 => "/var/app/docs/help.txt",
      3 => "/var/app/docs/contact.txt"
    }
    
    if doc_map.has_key?(doc_id)
      # ok: ruby-path-injection
      content = File.read(doc_map[doc_id])
      content
    else
      "Document not found"
    end
  end
# {/fact}
end

# Example 11: Using sanitized directory listing
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_11
  get '/list_files' do
    dir = "public/downloads"
    # ok: ruby-path-injection
    files = Dir.entries(dir).reject { |f| f.start_with?('.') }
    "Available files: #{files.join(', ')}"
  end
# {/fact}
end

# Example 12: Using path traversal prevention
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_12
  get '/download_file' do
    filename = params[:file]
    base_dir = "/var/www/files"
    
    # ok: ruby-path-injection
    requested_path = File.expand_path(File.join(base_dir, filename))
    if requested_path.start_with?(base_dir)
      send_file requested_path
    else
      "Invalid file path"
    end
  end
# {/fact}
end

# Example 13: Using file ID lookup
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_13
  get '/api/files/:file_id' do
    file_id = params[:file_id]
    
    # Database lookup would happen here to get the real filename
    # This is just a simulation
    file_mapping = {
      "abc123" => "document1.pdf",
      "def456" => "image2.jpg",
      "ghi789" => "spreadsheet3.xlsx"
    }
    
    if file_mapping.has_key?(file_id)
      real_filename = file_mapping[file_id]
      # ok: ruby-path-injection
      content = File.read(File.join("secure_storage", real_filename))
      content
    else
      "File not found"
    end
  end
# {/fact}
end

# Example 14: Using secure temporary file
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_14
  post '/process_upload' do
    # ok: ruby-path-injection
    temp_file = Tempfile.new('upload')
    temp_file.write(request.body.read)
    temp_file.rewind
    
    # Process the file safely
    result = "Processed file with #{temp_file.size} bytes"
    temp_file.close
    temp_file.unlink
    
    result
  end
# {/fact}
end

# Example 15: Using a hash to verify allowed files
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_15
  get '/download_resource' do
    resource_name = params[:resource]
    resource_hash = Digest::MD5.hexdigest(resource_name)
    
    allowed_resources = {
      "5f4dcc3b5aa765d61d8327deb882cf99" => "password.txt",
      "098f6bcd4621d373cade4e832627b4f6" => "test.pdf",
      "d8578edf8458ce06fbc5bb76a58c5ca4" => "sample.doc"
    }
    
    if allowed_resources.has_key?(resource_hash)
      # ok: ruby-path-injection
      content = File.read(File.join("resources", allowed_resources[resource_hash]))
      content
    else
      "Resource not found"
    end
  end
# {/fact}
end