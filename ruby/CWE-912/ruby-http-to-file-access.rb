require 'net/http'
require 'uri'
require 'open-uri'
require 'fileutils'
require 'tempfile'

# True Positive Examples (Vulnerable Code)

# {fact rule=hidden-functionality@v1.0 defects=1}
def bad_case_1
  # Download content from a URL and write directly to a file
  url = URI.parse('http://example.com/potentially-malicious-file.txt')
  response = Net::HTTP.get_response(url)
  
  # ruleid: ruby-http-to-file-access
  File.write('downloaded_file.txt', response.body)
end
# {/fact}

# {fact rule=hidden-functionality@v1.0 defects=1}
def bad_case_2
  # Using open-uri to fetch content and write to file
  url = 'https://example.com/script.rb'
  content = URI.open(url).read
  
  # ruleid: ruby-http-to-file-access
  File.open('local_script.rb', 'w') do |file|
    file.write(content)
  end
# {/fact}
end

# {fact rule=hidden-functionality@v1.0 defects=1}
def bad_case_3
  # Fetching content from user-provided URL and saving to file
  url = URI.parse('http://attacker-controlled-site.com/payload.txt')
  http = Net::HTTP.new(url.host, url.port)
  request = Net::HTTP::Get.new(url.request_uri)
  response = http.request(request)
  
  # ruleid: ruby-http-to-file-access
  IO.write('/var/www/html/user_content.txt', response.body)
end
# {/fact}

# {fact rule=hidden-functionality@v1.0 defects=1}
def bad_case_4
  # Download and execute content from remote URL
  url = 'https://example.com/remote_code.rb'
  response = Net::HTTP.get(URI(url))
  
  temp_file = Tempfile.new(['downloaded_code', '.rb'])
  # ruleid: ruby-http-to-file-access
  temp_file.write(response)
  temp_file.close
  
  # This could execute malicious code
  load temp_file.path
  temp_file.unlink
end
# {/fact}

# {fact rule=hidden-functionality@v1.0 defects=1}
def bad_case_5
  # Downloading binary content and saving to file
  url = URI.parse('http://example.com/binary_file.bin')
  response = Net::HTTP.get_response(url)
  
  # ruleid: ruby-http-to-file-access
  File.binwrite('local_binary.bin', response.body)
end
# {/fact}

# {fact rule=hidden-functionality@v1.0 defects=1}
def bad_case_6
  # Fetching content with custom headers and saving to file
  uri = URI('https://api.example.com/data')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  
  request = Net::HTTP::Get.new(uri)
  request['Authorization'] = 'Bearer token123'
  response = http.request(request)
  
  # ruleid: ruby-http-to-file-access
  File.open('api_response.json', 'w') do |file|
    file.puts response.body
  end
# {/fact}
end

# {fact rule=hidden-functionality@v1.0 defects=1}
def bad_case_7
  # Downloading file with redirect following
  url = 'http://example.com/redirecting_file'
  uri = URI(url)
  
  response = nil
  Net::HTTP.start(uri.host, uri.port) do |http|
    response = http.get(uri.path)
    if response.code == '302'
      redirect_uri = URI(response['location'])
      response = Net::HTTP.get_response(redirect_uri)
    end
  end
# {/fact}
  
  # ruleid: ruby-http-to-file-access
  File.write('followed_redirect_file.txt', response.body)
end

# {fact rule=hidden-functionality@v1.0 defects=1}
def bad_case_8
  # Downloading and appending to existing file
  url = URI.parse('https://example.com/additional_content.txt')
  response = Net::HTTP.get_response(url)
  
  # ruleid: ruby-http-to-file-access
  File.open('growing_file.txt', 'a') do |file|
    file.write(response.body)
  end
# {/fact}
end

# {fact rule=hidden-functionality@v1.0 defects=1}
def bad_case_9
  # Using open-uri with options and writing to file
  url = 'https://example.com/protected_resource.txt'
  content = URI.open(
    url,
    'User-Agent' => 'MyApp/1.0',
    http_basic_authentication: ['username', 'password']
  ).read
  
  # ruleid: ruby-http-to-file-access
  File.write('protected_content.txt', content)
end
# {/fact}

# {fact rule=hidden-functionality@v1.0 defects=1}
def bad_case_10
  # Downloading file and setting permissions
  url = URI('https://example.com/script.sh')
  response = Net::HTTP.get_response(url)
  
  filename = 'downloaded_script.sh'
  # ruleid: ruby-http-to-file-access
  File.write(filename, response.body)
  FileUtils.chmod(0755, filename) # Making it executable
end
# {/fact}

# {fact rule=hidden-functionality@v1.0 defects=1}
def bad_case_11
  # Downloading multiple files from a list of URLs
  urls = [
    'http://example.com/file1.txt',
    'http://example.com/file2.txt'
  ]
  
  urls.each_with_index do |url, index|
    response = Net::HTTP.get_response(URI(url))
    # ruleid: ruby-http-to-file-access
    File.write("downloaded_file_#{index}.txt", response.body)
  end
# {/fact}
end

# {fact rule=hidden-functionality@v1.0 defects=1}
def bad_case_12
  # Downloading file with error handling
  url = URI('https://example.com/important_file.txt')
  begin
    response = Net::HTTP.get_response(url)
    if response.is_a?(Net::HTTPSuccess)
      # ruleid: ruby-http-to-file-access
      File.write('important_file.txt', response.body)
    end
  rescue => e
    puts "Error downloading file: #{e.message}"
  end
end
# {/fact}

# {fact rule=hidden-functionality@v1.0 defects=1}
def bad_case_13
  # Using POST request to get content and saving to file
  uri = URI('https://api.example.com/data')
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = (uri.scheme == 'https')
  
  request = Net::HTTP::Post.new(uri)
  request.set_form_data('param1' => 'value1', 'param2' => 'value2')
  response = http.request(request)
  
  # ruleid: ruby-http-to-file-access
  File.open('post_response.txt', 'w') { |f| f.write(response.body) }
end
# {/fact}

# {fact rule=hidden-functionality@v1.0 defects=1}
def bad_case_14
  # Downloading file and processing line by line
  url = URI('https://example.com/large_file.txt')
  response = Net::HTTP.get_response(url)
  
  # ruleid: ruby-http-to-file-access
  File.open('processed_file.txt', 'w') do |file|
    response.body.each_line do |line|
      # Process each line
      processed_line = line.strip.upcase
      file.puts processed_line
    end
# {/fact}
  end
end

# {fact rule=hidden-functionality@v1.0 defects=1}
def bad_case_15
  # Downloading JSON, parsing it, and saving specific fields
  url = URI('https://api.example.com/users.json')
  response = Net::HTTP.get_response(url)
  
  require 'json'
  users = JSON.parse(response.body)
  
  # ruleid: ruby-http-to-file-access
  File.open('user_emails.txt', 'w') do |file|
    users.each do |user|
      file.puts user['email']
    end
# {/fact}
  end
end

# True Negative Examples (Safe Code)

# {fact rule=hidden-functionality@v1.0 defects=0}
def good_case_1
  # Reading from a local file instead of downloading
  # ok: ruby-http-to-file-access
  content = File.read('local_file.txt')
  puts content
end
# {/fact}

# {fact rule=hidden-functionality@v1.0 defects=0}
def good_case_2
  # Processing HTTP content in memory without writing to file
  url = URI.parse('https://example.com/data.json')
  response = Net::HTTP.get_response(url)
  
  # ok: ruby-http-to-file-access
  data = JSON.parse(response.body)
  puts "Received #{data.size} items"
end
# {/fact}

# {fact rule=hidden-functionality@v1.0 defects=0}
def good_case_3
  # Validating and sanitizing content before writing to file
  url = URI('https://trusted-source.com/safe_data.txt')
  response = Net::HTTP.get_response(url)
  
  # Validate content is safe (e.g., checking format, scanning for malicious patterns)
  content = response.body
  if content.match?(/^[a-zA-Z0-9\s.,!?]+$/) && content.length < 1000
    # ok: ruby-http-to-file-access
    File.write('validated_content.txt', "SAFE CONTENT: #{content}")
  else
    puts "Content failed validation"
  end
end
# {/fact}

# {fact rule=hidden-functionality@v1.0 defects=0}
def good_case_4
  # Using a hash to verify file integrity before using
  url = URI('https://example.com/file.txt')
  response = Net::HTTP.get_response(url)
  
  expected_hash = '5eb63bbbe01eeed093cb22bb8f5acdc3'
  
  require 'digest/md5'
  actual_hash = Digest::MD5.hexdigest(response.body)
  
  if actual_hash == expected_hash
    # ok: ruby-http-to-file-access
    puts "File verified, hash: #{actual_hash}"
    # Process content in memory
    processed_data = response.body.upcase
  else
    puts "File integrity check failed"
  end
end
# {/fact}

# {fact rule=hidden-functionality@v1.0 defects=0}
def good_case_5
  # Writing static content to file (not from HTTP)
  static_content = "This is safe static content"
  
  # ok: ruby-http-to-file-access
  File.write('static_file.txt', static_content)
end
# {/fact}

# {fact rule=hidden-functionality@v1.0 defects=0}
def good_case_6
  # Using HTTP content for display only, not writing to file
  url = URI('https://example.com/news.txt')
  response = Net::HTTP.get_response(url)
  
  # ok: ruby-http-to-file-access
  puts "Latest news: #{response.body}"
end
# {/fact}

# {fact rule=hidden-functionality@v1.0 defects=0}
def good_case_7
  # Downloading file to memory and processing without saving
  url = URI('https://example.com/data.csv')
  response = Net::HTTP.get_response(url)
  
  # ok: ruby-http-to-file-access
  rows = response.body.split("\n").map { |line| line.split(',') }
  sum = rows.sum { |row| row[0].to_i }
  puts "Sum of first column: #{sum}"
end
# {/fact}

# {fact rule=hidden-functionality@v1.0 defects=0}
def good_case_8
  # Writing to a file from a trusted local source
  local_data = "This is data from a trusted local source"
  
  # ok: ruby-http-to-file-access
  File.write('trusted_data.txt', local_data)
end
# {/fact}

# {fact rule=hidden-functionality@v1.0 defects=0}
def good_case_9
  # Logging HTTP request metadata without saving the content
  url = URI('https://example.com/api/status')
  response = Net::HTTP.get_response(url)
  
  # ok: ruby-http-to-file-access
  log_entry = "#{Time.now} - API Status: #{response.code}"
  File.open('api_log.txt', 'a') { |f| f.puts log_entry }
end
# {/fact}

# {fact rule=hidden-functionality@v1.0 defects=0}
def good_case_10
  # Using a memory buffer instead of a file
  url = URI('https://example.com/large_data.bin')
  response = Net::HTTP.get_response(url)
  
  # ok: ruby-http-to-file-access
  buffer = StringIO.new(response.body)
  first_byte = buffer.getbyte
  puts "First byte: #{first_byte}"
end
# {/fact}

# {fact rule=hidden-functionality@v1.0 defects=0}
def good_case_11
  # Extracting metadata from HTTP response without saving content
  url = URI('https://example.com/document.pdf')
  response = Net::HTTP.get_response(url)
  
  # ok: ruby-http-to-file-access
  content_type = response['Content-Type']
  content_length = response['Content-Length']
  puts "Document type: #{content_type}, size: #{content_length} bytes"
end
# {/fact}

# {fact rule=hidden-functionality@v1.0 defects=0}
def good_case_12
  # Using HTTP content to update a database, not a file
  url = URI('https://api.example.com/prices.json')
  response = Net::HTTP.get_response(url)
  
  # ok: ruby-http-to-file-access
  prices = JSON.parse(response.body)
  # In a real app, this would update a database
  puts "Updated #{prices.size} prices in database"
end
# {/fact}

# {fact rule=hidden-functionality@v1.0 defects=0}
def good_case_13
  # Comparing HTTP content with local file without writing
  url = URI('https://example.com/version.txt')
  response = Net::HTTP.get_response(url)
  
  # ok: ruby-http-to-file-access
  local_version = File.read('current_version.txt').strip
  remote_version = response.body.strip
  
  if remote_version > local_version
    puts "Update available: #{remote_version}"
  else
    puts "Already up to date"
  end
end
# {/fact}

# {fact rule=hidden-functionality@v1.0 defects=0}
def good_case_14
  # Processing HTTP content in chunks without saving to file
  url = URI('https://example.com/large_data.txt')
  
  # ok: ruby-http-to-file-access
  Net::HTTP.start(url.host, url.port, use_ssl: url.scheme == 'https') do |http|
    request = Net::HTTP::Get.new(url)
    
    http.request(request) do |response|
      total = 0
      response.read_body do |chunk|
        # Process each chunk in memory
        total += chunk.length
      end
# {/fact}
      puts "Processed #{total} bytes"
    end
  end
end

# {fact rule=hidden-functionality@v1.0 defects=0}
def good_case_15
  # Using HTTP content to generate a report in memory
  url = URI('https://api.example.com/stats.json')
  response = Net::HTTP.get_response(url)
  
  # ok: ruby-http-to-file-access
  stats = JSON.parse(response.body)
  report = "Report generated at #{Time.now}\n"
  report += "Total users: #{stats['users']}\n"
  report += "Active sessions: #{stats['sessions']}\n"
  
  puts report
end
# {/fact}