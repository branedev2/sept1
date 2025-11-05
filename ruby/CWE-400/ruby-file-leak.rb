# File: ruby_file_leak_examples.rb

# True Positive Examples (Vulnerable Code)

# {fact rule=resource-leak@v1.0 defects=1}
def bad_case_1
  # Opening a file and assigning to a variable without closing it
  # ruleid: ruby-file-leak
  file = File.open("data.txt", "r")
  content = file.read
  puts "File content: #{content}"
  # No file.close, causing a resource leak
end
# {/fact}

# {fact rule=resource-leak@v1.0 defects=1}
def bad_case_2
  begin
    # ruleid: ruby-file-leak
    log_file = File.open("logs/application.log", "a")
    log_file.puts("Application started at #{Time.now}")
    # File remains open after function exits
  rescue => e
    puts "Error: #{e.message}"
  end
end
# {/fact}

# {fact rule=resource-leak@v1.0 defects=1}
def bad_case_3
  if File.exist?("config.json")
    # ruleid: ruby-file-leak
    config = File.open("config.json")
    json_data = JSON.parse(config.read)
    puts "Configuration loaded: #{json_data}"
    # Missing config.close
  else
    puts "Config file not found"
  end
end
# {/fact}

# {fact rule=resource-leak@v1.0 defects=1}
def bad_case_4
  # Multiple file handles left open
  # ruleid: ruby-file-leak
  input = File.open("input.txt", "r")
  # ruleid: ruby-file-leak
  output = File.open("output.txt", "w")
  
  while line = input.gets
    output.puts line.upcase
  end
  # Both files left open
end
# {/fact}

# {fact rule=resource-leak@v1.0 defects=1}
def bad_case_5
  files = Dir.glob("*.csv")
  files.each do |file_path|
    # ruleid: ruby-file-leak
    csv_file = File.open(file_path, "r")
    csv_content = csv_file.read
    process_csv(csv_content)
    # No csv_file.close
  end
# {/fact}
end

# {fact rule=resource-leak@v1.0 defects=1}
def bad_case_6
  def process_user_data(user_id)
    # ruleid: ruby-file-leak
    user_file = File.open("users/#{user_id}.dat", "r+")
    user_data = user_file.read
    updated_data = update_user_info(user_data)
    user_file.rewind
    user_file.write(updated_data)
    # Missing user_file.close
  end
  
  process_user_data(123)
end
# {/fact}

# {fact rule=resource-leak@v1.0 defects=1}
def bad_case_7
  # Conditional paths with file leak
  path = get_file_path()
  if File.exist?(path)
    # ruleid: ruby-file-leak
    f = File.open(path)
    if f.size > 1000
      process_large_file(f)
    else
      process_small_file(f)
    end
    # f is not closed in either branch
  end
end
# {/fact}

# {fact rule=resource-leak@v1.0 defects=1}
def bad_case_8
  begin
    # ruleid: ruby-file-leak
    data_file = File.open("large_dataset.bin", "rb")
    header = data_file.read(16)
    if valid_header?(header)
      process_data_file(data_file)
    end
    # data_file not closed even if exception occurs
  rescue => e
    log_error(e)
    # Missing data_file.close in rescue block
  end
end
# {/fact}

# {fact rule=resource-leak@v1.0 defects=1}
def bad_case_9
  # File leak in a loop
  10.times do |i|
    filename = "chunk_#{i}.dat"
    # ruleid: ruby-file-leak
    chunk = File.open(filename, "wb")
    chunk.write(generate_data(i))
    # No chunk.close inside loop
  end
# {/fact}
end

# {fact rule=resource-leak@v1.0 defects=1}
def bad_case_10
  # Multiple exit points without closing file
  def analyze_log(log_path)
    # ruleid: ruby-file-leak
    log = File.open(log_path, "r")
    
    header = log.readline
    return nil unless valid_header?(header)
    
    content = log.read
    return process_content(content) if content.size > 0
    
    # log is not closed in any return path
  end
  
  analyze_log("system.log")
end
# {/fact}

# {fact rule=resource-leak@v1.0 defects=1}
def bad_case_11
  # File leak with error handling
  # ruleid: ruby-file-leak
  report = File.open("report.txt", "w")
  begin
    data = fetch_data_from_api()
    report.puts("API Data: #{data}")
    if data.empty?
      puts "No data received"
      return
    end
    # report not closed if early return happens
  rescue => e
    report.puts("Error: #{e.message}")
    # report not closed in exception handler
  end
end
# {/fact}

# {fact rule=resource-leak@v1.0 defects=1}
def bad_case_12
  # Nested conditionals with file leak
  user_type = get_user_type()
  
  if user_type == "admin"
    # ruleid: ruby-file-leak
    admin_log = File.open("admin_actions.log", "a")
    admin_log.puts("Admin action at #{Time.now}")
    if current_action == "backup"
      admin_log.puts("Backup initiated")
      perform_backup()
    end
    # admin_log not closed
  end
end
# {/fact}

# {fact rule=resource-leak@v1.0 defects=1}
def bad_case_13
  # File leak in a method with multiple responsibilities
  def export_user_data(user_id, format)
    user = find_user(user_id)
    return nil unless user
    
    if format == "csv"
      # ruleid: ruby-file-leak
      csv_file = File.open("exports/#{user_id}.csv", "w")
      csv_file.puts(user.to_csv)
      # csv_file not closed
    elsif format == "json"
      # ruleid: ruby-file-leak
      json_file = File.open("exports/#{user_id}.json", "w")
      json_file.puts(user.to_json)
      # json_file not closed
    end
    
    return true
  end
  
  export_user_data(123, "json")
end
# {/fact}

# {fact rule=resource-leak@v1.0 defects=1}
def bad_case_14
  # File leak with complex processing
  # ruleid: ruby-file-leak
  source = File.open("source.dat", "rb")
  # ruleid: ruby-file-leak
  target = File.open("target.dat", "wb")
  
  while !source.eof?
    chunk = source.read(1024)
    processed = process_chunk(chunk)
    target.write(processed)
  end
  
  # Neither source nor target are closed
end
# {/fact}

# {fact rule=resource-leak@v1.0 defects=1}
def bad_case_15
  # File leak with threading
  threads = []
  
  5.times do |i|
    threads << Thread.new do
      # ruleid: ruby-file-leak
      thread_log = File.open("thread_#{i}.log", "w")
      thread_log.puts("Thread #{i} started")
      perform_work(i)
      thread_log.puts("Thread #{i} completed")
      # thread_log not closed
    end
# {/fact}
  end
  
  threads.each(&:join)
end

# True Negative Examples (Safe Code)

# {fact rule=resource-leak@v1.0 defects=0}
def good_case_1
  # Using block form ensures file is closed
  # ok: ruby-file-leak
  File.open("data.txt", "r") do |file|
    content = file.read
    puts "File content: #{content}"
  end # File automatically closed here
end
# {/fact}

# {fact rule=resource-leak@v1.0 defects=0}
def good_case_2
  begin
    # ok: ruby-file-leak
    File.open("logs/application.log", "a") do |log_file|
      log_file.puts("Application started at #{Time.now}")
    end # log_file automatically closed
  rescue => e
    puts "Error: #{e.message}"
  end
end
# {/fact}

# {fact rule=resource-leak@v1.0 defects=0}
def good_case_3
  if File.exist?("config.json")
    # ok: ruby-file-leak
    File.open("config.json") do |config|
      json_data = JSON.parse(config.read)
      puts "Configuration loaded: #{json_data}"
    end # config automatically closed
  else
    puts "Config file not found"
  end
end
# {/fact}

# {fact rule=resource-leak@v1.0 defects=0}
def good_case_4
  # Properly closing multiple files with blocks
  # ok: ruby-file-leak
  File.open("input.txt", "r") do |input|
    # ok: ruby-file-leak
    File.open("output.txt", "w") do |output|
      while line = input.gets
        output.puts line.upcase
      end
    end # output automatically closed
  end # input automatically closed
end
# {/fact}

# {fact rule=resource-leak@v1.0 defects=0}
def good_case_5
  files = Dir.glob("*.csv")
  files.each do |file_path|
    # ok: ruby-file-leak
    File.open(file_path, "r") do |csv_file|
      csv_content = csv_file.read
      process_csv(csv_content)
    end # csv_file automatically closed
  end
# {/fact}
end

# {fact rule=resource-leak@v1.0 defects=0}
def good_case_6
  def process_user_data(user_id)
    # ok: ruby-file-leak
    File.open("users/#{user_id}.dat", "r+") do |user_file|
      user_data = user_file.read
      updated_data = update_user_info(user_data)
      user_file.rewind
      user_file.write(updated_data)
    end # user_file automatically closed
  end
  
  process_user_data(123)
end
# {/fact}

# {fact rule=resource-leak@v1.0 defects=0}
def good_case_7
  # Conditional paths with proper file handling
  path = get_file_path()
  if File.exist?(path)
    # ok: ruby-file-leak
    File.open(path) do |f|
      if f.size > 1000
        process_large_file(f)
      else
        process_small_file(f)
      end
    end # f automatically closed
  end
end
# {/fact}

# {fact rule=resource-leak@v1.0 defects=0}
def good_case_8
  begin
    # ok: ruby-file-leak
    File.open("large_dataset.bin", "rb") do |data_file|
      header = data_file.read(16)
      if valid_header?(header)
        process_data_file(data_file)
      end
    end # data_file automatically closed
  rescue => e
    log_error(e)
  end
end
# {/fact}

# {fact rule=resource-leak@v1.0 defects=0}
def good_case_9
  # Proper file handling in a loop
  10.times do |i|
    filename = "chunk_#{i}.dat"
    # ok: ruby-file-leak
    File.open(filename, "wb") do |chunk|
      chunk.write(generate_data(i))
    end # chunk automatically closed
  end
# {/fact}
end

# {fact rule=resource-leak@v1.0 defects=0}
def good_case_10
  # Multiple exit points with proper file handling
  def analyze_log(log_path)
    # ok: ruby-file-leak
    File.open(log_path, "r") do |log|
      header = log.readline
      return nil unless valid_header?(header)
      
      content = log.read
      return process_content(content) if content.size > 0
      
      return nil
    end # log automatically closed regardless of return path
  end
  
  analyze_log("system.log")
end
# {/fact}

# {fact rule=resource-leak@v1.0 defects=0}
def good_case_11
  # Proper file handling with error handling
  # ok: ruby-file-leak
  File.open("report.txt", "w") do |report|
    begin
      data = fetch_data_from_api()
      report.puts("API Data: #{data}")
      if data.empty?
        puts "No data received"
        return
      end
    rescue => e
      report.puts("Error: #{e.message}")
    end
  end # report automatically closed
end
# {/fact}

# {fact rule=resource-leak@v1.0 defects=0}
def good_case_12
  # Nested conditionals with proper file handling
  user_type = get_user_type()
  
  if user_type == "admin"
    # ok: ruby-file-leak
    File.open("admin_actions.log", "a") do |admin_log|
      admin_log.puts("Admin action at #{Time.now}")
      if current_action == "backup"
        admin_log.puts("Backup initiated")
        perform_backup()
      end
    end # admin_log automatically closed
  end
end
# {/fact}

# {fact rule=resource-leak@v1.0 defects=0}
def good_case_13
  # Proper file handling in a method with multiple responsibilities
  def export_user_data(user_id, format)
    user = find_user(user_id)
    return nil unless user
    
    if format == "csv"
      # ok: ruby-file-leak
      File.open("exports/#{user_id}.csv", "w") do |csv_file|
        csv_file.puts(user.to_csv)
      end # csv_file automatically closed
    elsif format == "json"
      # ok: ruby-file-leak
      File.open("exports/#{user_id}.json", "w") do |json_file|
        json_file.puts(user.to_json)
      end # json_file automatically closed
    end
    
    return true
  end
  
  export_user_data(123, "json")
end
# {/fact}

# {fact rule=resource-leak@v1.0 defects=0}
def good_case_14
  # Proper file handling with complex processing
  # ok: ruby-file-leak
  File.open("source.dat", "rb") do |source|
    # ok: ruby-file-leak
    File.open("target.dat", "wb") do |target|
      while !source.eof?
        chunk = source.read(1024)
        processed = process_chunk(chunk)
        target.write(processed)
      end
    end # target automatically closed
  end # source automatically closed
end
# {/fact}

# {fact rule=resource-leak@v1.0 defects=0}
def good_case_15
  # Proper file handling with threading
  threads = []
  
  5.times do |i|
    threads << Thread.new do
      # ok: ruby-file-leak
      File.open("thread_#{i}.log", "w") do |thread_log|
        thread_log.puts("Thread #{i} started")
        perform_work(i)
        thread_log.puts("Thread #{i} completed")
      end # thread_log automatically closed
    end
# {/fact}
  end
  
  threads.each(&:join)
end

# Helper methods to make the examples work
def process_csv(content)
  # Process CSV content
end

def update_user_info(data)
  # Update user information
  data + " updated"
end

def get_file_path
  "example.txt"
end

def valid_header?(header)
  !header.nil?
end

def process_large_file(file)
  # Process large file
end

def process_small_file(file)
  # Process small file
end

def process_data_file(file)
  # Process data file
end

def generate_data(index)
  "Data for chunk #{index}"
end

def process_content(content)
  # Process content
  content
end

def fetch_data_from_api
  "Sample API data"
end

def log_error(error)
  puts "Error: #{error.message}"
end

def get_user_type
  "admin"
end

def current_action
  "backup"
end

def perform_backup
  # Perform backup
end

def find_user(user_id)
  OpenStruct.new(
    to_csv: "user data in CSV",
    to_json: "user data in JSON"
  )
end

def perform_work(index)
  # Perform work for thread
end