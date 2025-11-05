# File disclosure vulnerabilities in Ruby

require 'sinatra'
require 'rack'
require 'pathname'
require 'fileutils'
require 'securerandom'
require 'uri'
require 'cgi'

# True Positive Examples (Vulnerable Code)

# Example 1: Basic file disclosure through direct path concatenation
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_1
  get '/download' do
    filename = params[:file]
    # ruleid: ruby-file-disclosure
    send_file "./public/#{filename}"
  end
# {/fact}
end

# Example 2: File disclosure through directory traversal
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_2
  get '/assets' do
    asset_path = params[:path]
    # ruleid: ruby-file-disclosure
    File.read(File.join('public/assets', asset_path))
  end
# {/fact}
end

# Example 3: File disclosure through user-controlled file path
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_3
  get '/images' do
    image = params[:name]
    content_type 'image/jpeg'
    # ruleid: ruby-file-disclosure
    File.open("./images/#{image}", 'rb').read
  end
# {/fact}
end

# Example 4: File disclosure through path manipulation with IO.read
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_4
  get '/docs' do
    doc_name = request.params['document']
    # ruleid: ruby-file-disclosure
    content = IO.read("./documents/#{doc_name}")
    content_type 'text/plain'
    content
  end
# {/fact}
end

# Example 5: File disclosure through path manipulation with File.binread
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_5
  get '/download/file' do
    file = params[:filename]
    # ruleid: ruby-file-disclosure
    content = File.binread("./storage/#{file}")
    attachment file
    content
  end
# {/fact}
end

# Example 6: File disclosure through path manipulation with File.foreach
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_6
  get '/logs' do
    log_file = params[:log]
    content = ""
    # ruleid: ruby-file-disclosure
    File.foreach("./logs/#{log_file}") do |line|
      content += line
    end
# {/fact}
    content
  end
end

# Example 7: File disclosure through path manipulation with IO.binread
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_7
  get '/media' do
    media_file = request.params['file']
    # ruleid: ruby-file-disclosure
    data = IO.binread("./media/#{media_file}")
    content_type 'application/octet-stream'
    data
  end
# {/fact}
end

# Example 8: File disclosure through path manipulation with File.readlines
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_8
  get '/config' do
    config_file = params[:name]
    # ruleid: ruby-file-disclosure
    lines = File.readlines("./configs/#{config_file}")
    content_type 'text/plain'
    lines.join
  end
# {/fact}
end

# Example 9: File disclosure through path manipulation with Pathname
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_9
  get '/templates' do
    template = params[:template]
    path = Pathname.new("./templates")
    # ruleid: ruby-file-disclosure
    content = (path + template).read
    content_type 'text/html'
    content
  end
# {/fact}
end

# Example 10: File disclosure through path manipulation with Dir operations
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_10
  get '/browse' do
    directory = params[:dir]
    # ruleid: ruby-file-disclosure
    files = Dir.entries("./public/#{directory}")
    content_type :json
    files.to_json
  end
# {/fact}
end

# Example 11: File disclosure through path manipulation with File.exist? check
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_11
  get '/check_file' do
    filename = params[:file]
    path = "./data/#{filename}"
    
    if File.exist?(path)
      # ruleid: ruby-file-disclosure
      content = File.read(path)
      content_type 'text/plain'
      content
    else
      status 404
      "File not found"
    end
  end
# {/fact}
end

# Example 12: File disclosure through path manipulation with open-uri
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_12
  require 'open-uri'
  
  get '/proxy' do
    file_path = params[:path]
    # ruleid: ruby-file-disclosure
    content = URI.open("file:///var/www/#{file_path}").read
    content_type 'text/plain'
    content
  end
# {/fact}
end

# Example 13: File disclosure through path manipulation with IO.popen
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_13
  get '/view_file' do
    filename = params[:name]
    # ruleid: ruby-file-disclosure
    content = IO.popen("cat ./files/#{filename}").read
    content_type 'text/plain'
    content
  end
# {/fact}
end

# Example 14: File disclosure through path manipulation with FileUtils
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_14
  get '/copy_file' do
    source = params[:source]
    dest = SecureRandom.uuid
    # ruleid: ruby-file-disclosure
    FileUtils.cp("./uploads/#{source}", "./tmp/#{dest}")
    "File copied to #{dest}"
  end
# {/fact}
end

# Example 15: File disclosure through path manipulation with require
# {fact rule=path-traversal@v1.0 defects=1}
def bad_case_15
  get '/load_module' do
    module_name = params[:module]
    begin
      # ruleid: ruby-file-disclosure
      require "./modules/#{module_name}"
      "Module loaded successfully"
    rescue LoadError => e
      "Failed to load module: #{e.message}"
    end
  end
# {/fact}
end

# True Negative Examples (Safe Code)

# Example 1: Safe file access with whitelisting
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_1
  get '/download' do
    filename = params[:file]
    allowed_files = ['report.pdf', 'brochure.pdf', 'catalog.pdf']
    
    if allowed_files.include?(filename)
      # ok: ruby-file-disclosure
      send_file "./public/#{filename}"
    else
      status 403
      "Access denied"
    end
  end
# {/fact}
end

# Example 2: Safe file access with path sanitization
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_2
  get '/assets' do
    asset_path = params[:path]
    sanitized_path = asset_path.gsub(/[^a-zA-Z0-9\-_.]/, '')
    
    # ok: ruby-file-disclosure
    File.read(File.join('public/assets', sanitized_path))
  end
# {/fact}
end

# Example 3: Safe file access with file extension validation
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_3
  get '/images' do
    image = params[:name]
    
    if image =~ /\A[a-zA-Z0-9\-_]+\.(jpg|jpeg|png|gif)\z/
      content_type 'image/jpeg'
      # ok: ruby-file-disclosure
      File.open("./images/#{image}", 'rb').read
    else
      status 400
      "Invalid image name"
    end
  end
# {/fact}
end

# Example 4: Safe file access with absolute path validation
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_4
  get '/docs' do
    doc_name = request.params['document']
    path = File.join('./documents', doc_name)
    
    # Prevent directory traversal
    unless File.expand_path(path).start_with?(File.expand_path('./documents'))
      status 403
      return "Access denied"
    end
    
    # ok: ruby-file-disclosure
    content = IO.read(path)
    content_type 'text/plain'
    content
  end
# {/fact}
end

# Example 5: Safe file access with Pathname realpath validation
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_5
  get '/download/file' do
    file = params[:filename]
    base_dir = Pathname.new('./storage').realpath
    
    begin
      path = Pathname.new(File.join(base_dir, file)).realpath
      
      # Ensure the path is within the base directory
      if path.to_s.start_with?(base_dir.to_s)
        # ok: ruby-file-disclosure
        content = File.binread(path)
        attachment file
        content
      else
        status 403
        "Access denied"
      end
    rescue Errno::ENOENT
      status 404
      "File not found"
    end
  end
# {/fact}
end

# Example 6: Safe file access with regex validation
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_6
  get '/logs' do
    log_file = params[:log]
    
    if log_file =~ /\A[a-zA-Z0-9_\-]+\.log\z/
      content = ""
      # ok: ruby-file-disclosure
      File.foreach("./logs/#{log_file}") do |line|
        content += line
      end
      content
    else
      status 400
      "Invalid log file name"
    end
# {/fact}
  end
end

# Example 7: Safe file access with predefined options
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_7
  get '/media' do
    media_file = request.params['file']
    media_options = {
      'intro' => 'intro.mp4',
      'tutorial' => 'tutorial.mp4',
      'demo' => 'product_demo.mp4'
    }
    
    if media_options.key?(media_file)
      actual_file = media_options[media_file]
      # ok: ruby-file-disclosure
      data = IO.binread("./media/#{actual_file}")
      content_type 'application/octet-stream'
      data
    else
      status 404
      "Media not found"
    end
  end
# {/fact}
end

# Example 8: Safe file access with file existence check and sanitization
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_8
  get '/config' do
    config_file = params[:name]
    sanitized = config_file.gsub(/[^a-zA-Z0-9\-_.]/, '')
    path = "./configs/#{sanitized}"
    
    if File.exist?(path) && !File.directory?(path)
      # ok: ruby-file-disclosure
      lines = File.readlines(path)
      content_type 'text/plain'
      lines.join
    else
      status 404
      "Configuration not found"
    end
  end
# {/fact}
end

# Example 9: Safe file access with template directory restriction
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_9
  get '/templates' do
    template = params[:template]
    
    # Only allow alphanumeric characters, hyphens, and underscores in template names
    if template =~ /\A[a-zA-Z0-9\-_]+\.html\z/
      path = Pathname.new("./templates")
      # ok: ruby-file-disclosure
      content = (path + template).read
      content_type 'text/html'
      content
    else
      status 400
      "Invalid template name"
    end
  end
# {/fact}
end

# Example 10: Safe directory browsing with restricted directories
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_10
  get '/browse' do
    directory = params[:dir]
    allowed_dirs = ['images', 'css', 'js', 'fonts']
    
    if allowed_dirs.include?(directory)
      # ok: ruby-file-disclosure
      files = Dir.entries("./public/#{directory}")
      content_type :json
      files.to_json
    else
      status 403
      "Access denied"
    end
  end
# {/fact}
end

# Example 11: Safe file access with proper path normalization
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_11
  get '/check_file' do
    filename = params[:file]
    
    # Sanitize filename to prevent directory traversal
    sanitized = filename.gsub(/[^a-zA-Z0-9\-_.]/, '')
    path = File.join('./data', sanitized)
    
    # Ensure the path is within the intended directory
    real_path = File.expand_path(path)
    data_dir = File.expand_path('./data')
    
    if real_path.start_with?(data_dir) && File.exist?(real_path)
      # ok: ruby-file-disclosure
      content = File.read(real_path)
      content_type 'text/plain'
      content
    else
      status 404
      "File not found"
    end
  end
# {/fact}
end

# Example 12: Safe file access with content type validation
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_12
  get '/download_image' do
    image = params[:name]
    
    # Validate file extension
    if image =~ /\A[a-zA-Z0-9\-_]+\.(jpg|jpeg|png|gif)\z/
      path = File.join('./images', image)
      
      # Verify file exists and is an image
      if File.exist?(path)
        mime_type = case File.extname(path).downcase
                    when '.jpg', '.jpeg' then 'image/jpeg'
                    when '.png' then 'image/png'
                    when '.gif' then 'image/gif'
                    else 'application/octet-stream'
                    end
        
        content_type mime_type
        # ok: ruby-file-disclosure
        File.binread(path)
      else
        status 404
        "Image not found"
      end
    else
      status 400
      "Invalid image name"
    end
# {/fact}
  end
end

# Example 13: Safe file access with UUID mapping
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_13
  # Simulated UUID to filename mapping (would be stored in database in real app)
  @@file_map = {
    'a1b2c3d4' => 'document1.pdf',
    'e5f6g7h8' => 'document2.pdf',
    'i9j0k1l2' => 'document3.pdf'
  }
  
  get '/secure_download' do
    file_id = params[:id]
    
    if @@file_map.key?(file_id)
      real_filename = @@file_map[file_id]
      # ok: ruby-file-disclosure
      send_file File.join('./secure_files', real_filename)
    else
      status 404
      "File not found"
    end
  end
# {/fact}
end

# Example 14: Safe file access with database lookup
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_14
  get '/protected_file' do
    # Simulate database lookup for file access permissions
    file_id = params[:id]
    
    # In a real app, this would query a database
    authorized = file_id == '12345' && session[:user_id] == 'admin'
    
    if authorized
      # ok: ruby-file-disclosure
      send_file './protected/confidential.pdf'
    else
      status 403
      "Access denied"
    end
  end
# {/fact}
end

# Example 15: Safe file access with proper error handling
# {fact rule=path-traversal@v1.0 defects=0}
def good_case_15
  get '/view_text' do
    filename = params[:name]
    
    # Sanitize and validate filename
    if filename =~ /\A[a-zA-Z0-9\-_]+\.txt\z/
      path = File.join('./text_files', filename)
      
      begin
        # Ensure path is within intended directory
        real_path = File.expand_path(path)
        base_dir = File.expand_path('./text_files')
        
        if real_path.start_with?(base_dir) && File.exist?(real_path)
          content_type 'text/plain'
          # ok: ruby-file-disclosure
          File.read(real_path)
        else
          status 404
          "File not found"
        end
      rescue => e
        status 500
        "Error: #{e.message}"
      end
    else
      status 400
      "Invalid filename"
    end
  end
# {/fact}
end