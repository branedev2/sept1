# Examples for ruby-untrusted-open vulnerability detection

# True Positives (Vulnerable Code)

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_1
  require 'sinatra'
  
  get '/read_file' do
    filename = params['filename']
    # ruleid: ruby-untrusted-open
    file_content = open(filename).read
    return file_content
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_2
  require 'sinatra'
  
  post '/process_file' do
    user_file = params['user_file']
    # ruleid: ruby-untrusted-open
    file_data = open(user_file, 'r').read
    return "File processed: #{file_data}"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_3
  require 'sinatra'
  
  get '/view_log' do
    log_name = request.env['HTTP_X_LOG_NAME']
    log_path = "/var/logs/#{log_name}"
    # ruleid: ruby-untrusted-open
    log_content = open(log_path).read
    return log_content
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_4
  require 'sinatra'
  
  get '/download' do
    file_path = request.cookies['file_path']
    # ruleid: ruby-untrusted-open
    content = open(file_path, 'rb').read
    attachment file_path
    content
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_5
  require 'rack'
  
  class FileViewer
    def call(env)
      request = Rack::Request.new(env)
      filename = request.params['file']
      # ruleid: ruby-untrusted-open
      content = open(filename).read
      [200, {'Content-Type' => 'text/plain'}, [content]]
    end
  end
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_6
  require 'sinatra'
  
  get '/template' do
    template_name = params['template']
    template_path = "./templates/#{template_name}.erb"
    # ruleid: ruby-untrusted-open
    template = open(template_path).read
    erb template
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_7
  require 'sinatra'
  
  post '/save_notes' do
    note_file = params['filename']
    note_content = params['content']
    # ruleid: ruby-untrusted-open
    file = open(note_file, 'w')
    file.write(note_content)
    file.close
    "Note saved to #{note_file}"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_8
  require 'sinatra'
  
  get '/config' do
    config_name = params['config']
    # ruleid: ruby-untrusted-open
    config_data = open("configs/#{config_name}").read
    return config_data
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_9
  require 'sinatra'
  
  get '/image' do
    image_path = params['path']
    # ruleid: ruby-untrusted-open
    img_data = open(image_path, 'rb').read
    content_type 'image/jpeg'
    img_data
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_10
  require 'sinatra'
  
  get '/backup' do
    backup_file = request.env['HTTP_X_BACKUP_FILE']
    # ruleid: ruby-untrusted-open
    backup_data = open("/backups/#{backup_file}").read
    return backup_data
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_11
  require 'webrick'
  
  class FileHandler < WEBrick::HTTPServlet::AbstractServlet
    def do_GET(request, response)
      filename = request.query['file']
      # ruleid: ruby-untrusted-open
      content = open(filename).read
      response.body = content
    end
  end
end
# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_12
  require 'sinatra'
  
  get '/user_file' do
    username = params['username']
    # ruleid: ruby-untrusted-open
    user_data = open("./user_files/#{username}.dat").read
    return user_data
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_13
  require 'sinatra'
  
  post '/append_log' do
    log_file = params['logfile']
    log_entry = params['entry']
    # ruleid: ruby-untrusted-open
    file = open(log_file, 'a')
    file.puts(log_entry)
    file.close
    "Log entry added to #{log_file}"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_14
  require 'sinatra'
  
  get '/dynamic_include' do
    module_name = params['module']
    # ruleid: ruby-untrusted-open
    module_code = open("./modules/#{module_name}.rb").read
    eval(module_code)
    "Module #{module_name} loaded"
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_15
  require 'sinatra'
  
  get '/read_partial' do
    filename = params['file']
    start_pos = params['start'].to_i
    length = params['length'].to_i
    # ruleid: ruby-untrusted-open
    file = open(filename, 'r')
    file.seek(start_pos)
    content = file.read(length)
    file.close
    content
  end
# {/fact}
end

# True Negatives (Safe Code)

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_1
  require 'sinatra'
  
  get '/read_file' do
    # ok: ruby-untrusted-open
    file_content = open("static_file.txt").read
    return file_content
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_2
  require 'sinatra'
  
  get '/read_config' do
    # ok: ruby-untrusted-open
    config = open("/etc/app/config.json").read
    return config
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_3
  require 'sinatra'
  
  get '/user_profile/:id' do
    user_id = params['id'].to_i
    allowed_files = {1 => "user1.txt", 2 => "user2.txt", 3 => "user3.txt"}
    if allowed_files.key?(user_id)
      # ok: ruby-untrusted-open
      profile = open("./profiles/#{allowed_files[user_id]}").read
      return profile
    else
      return "User not found"
    end
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_4
  require 'sinatra'
  
  get '/download/:file_type' do
    file_type = params['file_type']
    allowed_types = ["report", "summary", "details"]
    
    if allowed_types.include?(file_type)
      # ok: ruby-untrusted-open
      content = open("./downloads/#{file_type}.pdf", 'rb').read
      attachment "#{file_type}.pdf"
      content
    else
      "Invalid file type"
    end
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_5
  require 'sinatra'
  
  get '/template/:name' do
    template_name = params['name']
    allowed_templates = ["welcome", "about", "contact"]
    
    if allowed_templates.include?(template_name)
      # ok: ruby-untrusted-open
      template = open("./templates/#{template_name}.erb").read
      erb template
    else
      "Template not found"
    end
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_6
  require 'sinatra'
  
  get '/static_image/:id' do
    image_id = params['id'].to_i
    image_paths = {
      1 => "./images/logo.png",
      2 => "./images/banner.png",
      3 => "./images/icon.png"
    }
    
    if image_paths.key?(image_id)
      # ok: ruby-untrusted-open
      img_data = open(image_paths[image_id], 'rb').read
      content_type 'image/png'
      img_data
    else
      "Image not found"
    end
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_7
  require 'sinatra'
  
  get '/read_file' do
    filename = params['filename']
    # Using File.read instead of open for static files
    # ok: ruby-untrusted-open
    file_content = File.read("./public/#{File.basename(filename)}")
    return file_content
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_8
  require 'sinatra'
  
  get '/documentation/:page' do
    page = params['page']
    valid_pages = ["intro", "guide", "api", "faq"]
    
    if valid_pages.include?(page)
      # ok: ruby-untrusted-open
      content = open("./docs/#{page}.md").read
      markdown content
    else
      "Page not found"
    end
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_9
  require 'sinatra'
  
  get '/logs/:date' do
    date = params['date']
    # Validate date format (YYYY-MM-DD)
    if date =~ /^\d{4}-\d{2}-\d{2}$/
      log_file = "./logs/#{date}.log"
      if File.exist?(log_file)
        # ok: ruby-untrusted-open
        log_content = open(log_file).read
        return log_content
      else
        return "Log not found"
      end
    else
      return "Invalid date format"
    end
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_10
  require 'sinatra'
  
  get '/read_file' do
    filename = params['filename']
    # Using a whitelist approach
    allowed_files = ["report.txt", "summary.txt", "details.txt"]
    
    if allowed_files.include?(filename)
      # ok: ruby-untrusted-open
      file_content = open("./data/#{filename}").read
      return file_content
    else
      return "Access denied"
    end
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_11
  require 'sinatra'
  
  get '/product/:id/spec' do
    product_id = params['id'].to_i
    # Using a database to retrieve the filename
    product = Product.find(product_id)
    if product
      spec_file = product.spec_file_name
      # ok: ruby-untrusted-open
      spec_content = open("./specs/#{spec_file}").read
      return spec_content
    else
      return "Product not found"
    end
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_12
  require 'sinatra'
  
  get '/config/:env' do
    env = params['env']
    allowed_envs = ["dev", "test", "staging"]
    
    if allowed_envs.include?(env)
      # ok: ruby-untrusted-open
      config = open("./config/#{env}.json").read
      return config
    else
      return "Invalid environment"
    end
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_13
  require 'sinatra'
  
  get '/static_resource' do
    resource_type = params['type']
    resource_id = params['id'].to_i
    
    # Using a mapping function to determine the file path
    def get_resource_path(type, id)
      case type
      when "image"
        "./resources/images/img_#{id}.png"
      when "document"
        "./resources/docs/doc_#{id}.pdf"
      else
        nil
      end
    end
    
    path = get_resource_path(resource_type, resource_id)
    if path && File.exist?(path)
      # ok: ruby-untrusted-open
      content = open(path, 'rb').read
      return content
    else
      return "Resource not found"
    end
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_14
  require 'sinatra'
  
  get '/download_report' do
    report_id = params['id']
    # Using a secure helper function to validate and get the path
    def get_report_path(id)
      # Validate ID format (only alphanumeric)
      return nil unless id =~ /^[a-zA-Z0-9]+$/
      
      # Check if report exists in database
      report = Report.find_by(id: id)
      return report ? "./reports/#{report.filename}" : nil
    end
    
    path = get_report_path(report_id)
    if path
      # ok: ruby-untrusted-open
      report_content = open(path).read
      return report_content
    else
      return "Report not found"
    end
  end
# {/fact}
end

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_15
  require 'sinatra'
  
  get '/system_file' do
    # Using a constant for the file path
    SYSTEM_LOG = "/var/log/system.log"
    
    # ok: ruby-untrusted-open
    log_content = open(SYSTEM_LOG).read
    return log_content
  end
# {/fact}
end