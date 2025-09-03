# frozen_string_literal: true

require 'sinatra'
require 'rails'

# BAD EXAMPLES - Vulnerable code that should be detected

# Example 1: Direct use of user input in send_file
# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_1
  get '/download' do
    filename = params[:filename]
    # ruleid: ruby-check-send-file
    send_file(filename)
  end
# {/fact}
end

# Example 2: Using user input with string interpolation
# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_2
  get '/get_file' do
    user_file = params[:file]
    path = "/var/www/files/#{user_file}"
    # ruleid: ruby-check-send-file
    send_file(path)
  end
# {/fact}
end

# Example 3: Using user input with path joining
# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_3
  get '/documents' do
    doc_name = params[:document]
    file_path = File.join('/data/documents', doc_name)
    # ruleid: ruby-check-send-file
    send_file(file_path)
  end
# {/fact}
end

# Example 4: Using user input from request headers
# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_4
  get '/api/file' do
    file_path = request.env['HTTP_X_FILE_PATH']
    # ruleid: ruby-check-send-file
    send_file(file_path)
  end
# {/fact}
end

# Example 5: Using user input from JSON body
# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_5
  post '/download_file' do
    request_payload = JSON.parse(request.body.read)
    file_path = request_payload['file_path']
    # ruleid: ruby-check-send-file
    send_file(file_path)
  end
# {/fact}
end

# Example 6: Using user input with minimal processing
# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_6
  get '/download/file' do
    filename = params[:name].gsub(' ', '_')
    path = "/var/data/#{filename}"
    # ruleid: ruby-check-send-file
    send_file(path)
  end
# {/fact}
end

# Example 7: Using user input with concatenation
# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_7
  get '/images' do
    img = params[:image]
    path = '/var/www/images/' + img
    # ruleid: ruby-check-send-file
    send_file(path)
  end
# {/fact}
end

# Example 8: Using user input from session
# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_8
  get '/user/files' do
    file = session[:last_accessed_file]
    # ruleid: ruby-check-send-file
    send_file(file)
  end
# {/fact}
end

# Example 9: Using user input from cookies
# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_9
  get '/resume' do
    filename = request.cookies['resume_file']
    # ruleid: ruby-check-send-file
    send_file(filename)
  end
# {/fact}
end

# Example 10: Using user input with conditional
# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_10
  get '/download/report' do
    report_name = params[:report]
    if report_name.end_with?('.pdf')
      path = "/reports/#{report_name}"
      # ruleid: ruby-check-send-file
      send_file(path)
    else
      halt 400, "Invalid file format"
    end
  end
# {/fact}
end

# Example 11: Using user input with ternary operator
# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_11
  get '/get_image' do
    is_thumbnail = params[:thumbnail] == 'true'
    image_name = params[:name]
    path = is_thumbnail ? "/thumbnails/#{image_name}" : "/images/#{image_name}"
    # ruleid: ruby-check-send-file
    send_file(path)
  end
# {/fact}
end

# Example 12: Using user input with case statement
# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_12
  get '/download/asset' do
    asset_type = params[:type]
    filename = params[:name]
    
    path = case asset_type
    when 'image'
      "/images/#{filename}"
    when 'document'
      "/documents/#{filename}"
    else
      "/misc/#{filename}"
    end
# {/fact}
    
    # ruleid: ruby-check-send-file
    send_file(path)
  end
end

# Example 13: Using user input with multiple parameters
# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_13
  get '/files/:category/:filename' do
    category = params[:category]
    filename = params[:filename]
    path = "/data/#{category}/#{filename}"
    # ruleid: ruby-check-send-file
    send_file(path)
  end
# {/fact}
end

# Example 14: Using user input with options
# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_14
  get '/download/with_options' do
    file_path = params[:path]
    # ruleid: ruby-check-send-file
    send_file(file_path, disposition: 'attachment', filename: File.basename(file_path))
  end
# {/fact}
end

# Example 15: Using user input with error handling
# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_15
  get '/protected_file' do
    begin
      file = params[:file]
      path = "/protected/#{file}"
      # ruleid: ruby-check-send-file
      send_file(path)
    rescue => e
      halt 500, "Error: #{e.message}"
    end
  end
# {/fact}
end

# GOOD EXAMPLES - Secure code that should not be detected

# Example 1: Using hardcoded path
# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_1
  get '/download/terms' do
    # ok: ruby-check-send-file
    send_file('/app/public/terms_and_conditions.pdf')
  end
# {/fact}
end

# Example 2: Using basename and hardcoded directory
# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_2
  get '/download/user_file' do
    filename = params[:filename]
    safe_filename = File.basename(filename)
    path = File.expand_path(File.join('/safe/directory', safe_filename))
    # Ensure the path is within the intended directory
    if path.start_with?('/safe/directory/')
      # ok: ruby-check-send-file
      send_file(path)
    else
      halt 400, "Invalid file path"
    end
  end
# {/fact}
end

# Example 3: Using whitelist validation
# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_3
  get '/download/report' do
    report_name = params[:report]
    allowed_reports = ['annual.pdf', 'quarterly.pdf', 'summary.pdf']
    
    if allowed_reports.include?(report_name)
      path = File.join('/reports', report_name)
      # ok: ruby-check-send-file
      send_file(path)
    else
      halt 403, "Access denied"
    end
  end
# {/fact}
end

# Example 4: Using ID to lookup file path from database
# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_4
  get '/documents/:id' do
    document_id = params[:id].to_i
    document = Document.find_by(id: document_id)
    
    if document && File.exist?(document.file_path)
      # ok: ruby-check-send-file
      send_file(document.file_path)
    else
      halt 404, "Document not found"
    end
  end
# {/fact}
end

# Example 5: Using constant paths with dynamic selection
# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_5
  get '/download/template' do
    template_type = params[:type]
    
    templates = {
      'invoice' => '/app/templates/invoice.pdf',
      'receipt' => '/app/templates/receipt.pdf',
      'report' => '/app/templates/report.pdf'
    }
    
    if templates.key?(template_type)
      # ok: ruby-check-send-file
      send_file(templates[template_type])
    else
      halt 400, "Invalid template type"
    end
  end
# {/fact}
end

# Example 6: Using basename and checking file existence
# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_6
  get '/images/download' do
    filename = params[:filename]
    safe_filename = File.basename(filename)
    path = File.join('/var/www/images', safe_filename)
    
    if File.exist?(path) && File.file?(path)
      # ok: ruby-check-send-file
      send_file(path)
    else
      halt 404, "Image not found"
    end
  end
# {/fact}
end

# Example 7: Using a UUID to locate file
# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_7
  get '/download/:uuid' do
    uuid = params[:uuid]
    # Validate UUID format
    if uuid =~ /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
      path = File.join('/secure/files', "#{uuid}.pdf")
      # ok: ruby-check-send-file
      send_file(path)
    else
      halt 400, "Invalid UUID format"
    end
  end
# {/fact}
end

# Example 8: Using a numeric ID with string conversion
# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_8
  get '/download/receipt/:id' do
    receipt_id = params[:id].to_i.to_s
    path = File.join('/receipts', "receipt_#{receipt_id}.pdf")
    
    if File.exist?(path)
      # ok: ruby-check-send-file
      send_file(path)
    else
      halt 404, "Receipt not found"
    end
  end
# {/fact}
end

# Example 9: Using a predefined constant
# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_9
  DOWNLOAD_PATH = '/app/public/downloads/user_manual.pdf'
  
  get '/download/manual' do
    # ok: ruby-check-send-file
    send_file(DOWNLOAD_PATH)
  end
# {/fact}
end

# Example 10: Using a method that returns a safe path
# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_10
  def get_public_file_path(filename)
    safe_name = File.basename(filename)
    File.join('/public/files', safe_name)
  end
  
  get '/public_file' do
    filename = params[:name]
    path = get_public_file_path(filename)
    
    if File.exist?(path) && path.start_with?('/public/files/')
      # ok: ruby-check-send-file
      send_file(path)
    else
      halt 404, "File not found"
    end
  end
# {/fact}
end

# Example 11: Using regex validation for filenames
# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_11
  get '/download/asset' do
    filename = params[:name]
    
    if filename =~ /^[a-zA-Z0-9_-]+\.(pdf|jpg|png)$/
      path = File.join('/assets', filename)
      # ok: ruby-check-send-file
      send_file(path)
    else
      halt 400, "Invalid filename format"
    end
  end
# {/fact}
end

# Example 12: Using a hash map for file lookup
# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_12
  FILE_MAP = {
    'terms' => '/legal/terms.pdf',
    'privacy' => '/legal/privacy.pdf',
    'faq' => '/info/faq.pdf'
  }
  
  get '/legal/:document' do
    doc_key = params[:document]
    
    if FILE_MAP.key?(doc_key)
      # ok: ruby-check-send-file
      send_file(FILE_MAP[doc_key])
    else
      halt 404, "Document not found"
    end
  end
# {/fact}
end

# Example 13: Using environment variables for file paths
# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_13
  get '/system/config' do
    config_path = ENV['CONFIG_FILE_PATH']
    
    if config_path && File.exist?(config_path)
      # ok: ruby-check-send-file
      send_file(config_path)
    else
      halt 500, "Configuration file not found"
    end
  end
# {/fact}
end

# Example 14: Using a database to validate file access
# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_14
  get '/user/:user_id/files/:file_id' do
    user_id = params[:user_id].to_i
    file_id = params[:file_id].to_i
    
    user = User.find_by(id: user_id)
    file = UserFile.find_by(id: file_id, user_id: user_id)
    
    if user && file && current_user.id == user.id
      # ok: ruby-check-send-file
      send_file(file.storage_path)
    else
      halt 403, "Access denied"
    end
  end
# {/fact}
end

# Example 15: Using a secure temporary file
# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_15
  get '/export/data' do
    require 'tempfile'
    
    temp_file = Tempfile.new(['export', '.csv'])
    begin
      # Generate export data
      temp_file.write("data,export,content")
      temp_file.close
      
      # ok: ruby-check-send-file
      send_file(temp_file.path, filename: "export_#{Time.now.to_i}.csv")
    ensure
      temp_file.unlink
    end
  end
# {/fact}
end