require 'aws-sdk-s3'

# True Positives (Vulnerable Code)

# {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
def bad_case_1
  s3 = Aws::S3::Client.new(region: 'us-west-2')
  
  # ruleid: ruby-missing-pagination
  resp = s3.list_objects(bucket: 'my-bucket')
  resp.contents.each do |object|
    puts "#{object.key} => #{object.size} bytes"
  end
# {/fact}
end

# {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
def bad_case_2
  s3 = Aws::S3::Client.new(region: 'us-west-2')
  
  # ruleid: ruby-missing-pagination
  objects = s3.list_objects_v2(bucket: 'my-bucket').contents
  objects.each do |object|
    puts "#{object.key} => #{object.etag}"
  end
# {/fact}
end

# {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
def bad_case_3
  s3_client = Aws::S3::Client.new(region: 'us-east-1')
  
  # ruleid: ruby-missing-pagination
  response = s3_client.list_objects_v2(
    bucket: 'my-bucket',
    prefix: 'logs/'
  )
  
  response.contents.each do |item|
    puts "Processing #{item.key}"
    s3_client.get_object(bucket: 'my-bucket', key: item.key)
  end
# {/fact}
end

# {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
def bad_case_4
  s3 = Aws::S3::Client.new(region: 'us-west-2')
  
  # ruleid: ruby-missing-pagination
  result = s3.list_objects(bucket: 'my-bucket', prefix: 'documents/')
  
  total_size = 0
  result.contents.each do |object|
    total_size += object.size
  end
# {/fact}
  
  puts "Total size: #{total_size} bytes"
end

# {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
def bad_case_5
  s3 = Aws::S3::Resource.new(region: 'us-west-2')
  bucket = s3.bucket('my-bucket')
  
  # ruleid: ruby-missing-pagination
  objects = bucket.objects(prefix: 'images/').collect(&:key)
  objects.each do |key|
    puts "Found object: #{key}"
  end
# {/fact}
end

# {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
def bad_case_6
  s3 = Aws::S3::Client.new(region: 'us-west-2')
  
  # ruleid: ruby-missing-pagination
  response = s3.list_objects_v2(bucket: 'my-bucket', max_keys: 500)
  
  response.contents.each do |object|
    if object.size > 1_000_000
      puts "Large file found: #{object.key}"
    end
  end
# {/fact}
end

# {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
def bad_case_7
  s3_client = Aws::S3::Client.new(region: 'us-west-2')
  
  # ruleid: ruby-missing-pagination
  objects = s3_client.list_objects(
    bucket: 'my-bucket',
    prefix: 'backups/',
    delimiter: '/'
  ).contents
  
  objects.map(&:key)
end
# {/fact}

# {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
def bad_case_8
  s3 = Aws::S3::Client.new(region: 'us-west-2')
  
  # ruleid: ruby-missing-pagination
  response = s3.list_objects_v2(bucket: 'my-bucket')
  
  if response.contents.any?
    latest_object = response.contents.sort_by(&:last_modified).last
    puts "Latest object: #{latest_object.key}"
  end
end
# {/fact}

# {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
def bad_case_9
  s3 = Aws::S3::Resource.new(region: 'us-west-2')
  
  # ruleid: ruby-missing-pagination
  objects = s3.bucket('my-bucket').objects(prefix: 'uploads/').limit(100)
  
  objects.each do |object|
    puts "Processing #{object.key}"
  end
# {/fact}
end

# {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
def bad_case_10
  s3 = Aws::S3::Client.new(region: 'us-west-2')
  
  # ruleid: ruby-missing-pagination
  versions = s3.list_object_versions(bucket: 'my-bucket').versions
  
  versions.each do |version|
    puts "Version: #{version.version_id} for #{version.key}"
  end
# {/fact}
end

# {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
def bad_case_11
  s3 = Aws::S3::Client.new(region: 'us-west-2')
  
  # ruleid: ruby-missing-pagination
  multipart_uploads = s3.list_multipart_uploads(bucket: 'my-bucket').uploads
  
  multipart_uploads.each do |upload|
    puts "Upload ID: #{upload.upload_id} for #{upload.key}"
  end
# {/fact}
end

# {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
def bad_case_12
  s3 = Aws::S3::Client.new(region: 'us-west-2')
  
  # ruleid: ruby-missing-pagination
  buckets = s3.list_buckets.buckets
  
  buckets.each do |bucket|
    puts "Bucket: #{bucket.name}"
    objects = s3.list_objects_v2(bucket: bucket.name).contents
    puts "Object count: #{objects.count}"
  end
# {/fact}
end

# {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
def bad_case_13
  s3 = Aws::S3::Client.new(region: 'us-west-2')
  
  # ruleid: ruby-missing-pagination
  response = s3.list_objects_v2(bucket: 'my-bucket')
  
  csv_objects = response.contents.select { |obj| obj.key.end_with?('.csv') }
  csv_objects.each do |obj|
    puts "CSV file: #{obj.key}"
  end
# {/fact}
end

# {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
def bad_case_14
  s3 = Aws::S3::Client.new(region: 'us-west-2')
  
  # ruleid: ruby-missing-pagination
  common_prefixes = s3.list_objects_v2(
    bucket: 'my-bucket',
    delimiter: '/',
    prefix: 'users/'
  ).common_prefixes
  
  common_prefixes.each do |prefix|
    puts "Prefix: #{prefix.prefix}"
  end
# {/fact}
end

# {fact rule=avoid-reset-exception-rule@v1.0 defects=1}
def bad_case_15
  s3 = Aws::S3::Client.new(region: 'us-west-2')
  
  # ruleid: ruby-missing-pagination
  response = s3.list_objects_v2(bucket: 'my-bucket')
  
  if response.key_count > 0
    keys = response.contents.map(&:key)
    s3.delete_objects(
      bucket: 'my-bucket',
      delete: { objects: keys.map { |k| { key: k } } }
    )
  end
end
# {/fact}

# True Negatives (Secure Code)

# {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
def good_case_1
  s3 = Aws::S3::Client.new(region: 'us-west-2')
  
  # ok: ruby-missing-pagination
  s3.list_objects_v2(bucket: 'my-bucket').each do |response|
    response.contents.each do |object|
      puts "#{object.key} => #{object.size} bytes"
    end
# {/fact}
  end
end

# {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
def good_case_2
  s3 = Aws::S3::Client.new(region: 'us-west-2')
  
  # ok: ruby-missing-pagination
  s3.list_objects(bucket: 'my-bucket').each do |response|
    response.contents.each do |object|
      puts "#{object.key} => #{object.etag}"
    end
# {/fact}
  end
end

# {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
def good_case_3
  s3_client = Aws::S3::Client.new(region: 'us-east-1')
  
  # ok: ruby-missing-pagination
  s3_client.list_objects_v2(bucket: 'my-bucket', prefix: 'logs/').each do |response|
    response.contents.each do |item|
      puts "Processing #{item.key}"
      s3_client.get_object(bucket: 'my-bucket', key: item.key)
    end
# {/fact}
  end
end

# {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
def good_case_4
  s3 = Aws::S3::Client.new(region: 'us-west-2')
  
  total_size = 0
  
  # ok: ruby-missing-pagination
  s3.list_objects(bucket: 'my-bucket', prefix: 'documents/').each do |response|
    response.contents.each do |object|
      total_size += object.size
    end
# {/fact}
  end
  
  puts "Total size: #{total_size} bytes"
end

# {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
def good_case_5
  s3 = Aws::S3::Resource.new(region: 'us-west-2')
  bucket = s3.bucket('my-bucket')
  
  objects = []
  
  # ok: ruby-missing-pagination
  bucket.objects(prefix: 'images/').each do |object|
    objects << object.key
  end
# {/fact}
  
  objects.each do |key|
    puts "Found object: #{key}"
  end
end

# {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
def good_case_6
  s3 = Aws::S3::Client.new(region: 'us-west-2')
  
  large_files = []
  
  # ok: ruby-missing-pagination
  s3.list_objects_v2(bucket: 'my-bucket', max_keys: 500).each do |response|
    response.contents.each do |object|
      if object.size > 1_000_000
        large_files << object.key
      end
    end
# {/fact}
  end
  
  large_files.each { |file| puts "Large file found: #{file}" }
end

# {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
def good_case_7
  s3_client = Aws::S3::Client.new(region: 'us-west-2')
  
  objects = []
  
  # ok: ruby-missing-pagination
  s3_client.list_objects(
    bucket: 'my-bucket',
    prefix: 'backups/',
    delimiter: '/'
  ).each do |response|
    objects.concat(response.contents.map(&:key))
  end
# {/fact}
  
  objects
end

# {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
def good_case_8
  s3 = Aws::S3::Client.new(region: 'us-west-2')
  
  all_objects = []
  
  # ok: ruby-missing-pagination
  s3.list_objects_v2(bucket: 'my-bucket').each do |response|
    all_objects.concat(response.contents)
  end
# {/fact}
  
  if all_objects.any?
    latest_object = all_objects.sort_by(&:last_modified).last
    puts "Latest object: #{latest_object.key}"
  end
end

# {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
def good_case_9
  s3 = Aws::S3::Resource.new(region: 'us-west-2')
  
  # ok: ruby-missing-pagination
  s3.bucket('my-bucket').objects(prefix: 'uploads/').each do |object|
    puts "Processing #{object.key}"
  end
# {/fact}
end

# {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
def good_case_10
  s3 = Aws::S3::Client.new(region: 'us-west-2')
  
  # ok: ruby-missing-pagination
  s3.list_object_versions(bucket: 'my-bucket').each do |response|
    response.versions.each do |version|
      puts "Version: #{version.version_id} for #{version.key}"
    end
# {/fact}
  end
end

# {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
def good_case_11
  s3 = Aws::S3::Client.new(region: 'us-west-2')
  
  # ok: ruby-missing-pagination
  s3.list_multipart_uploads(bucket: 'my-bucket').each do |response|
    response.uploads.each do |upload|
      puts "Upload ID: #{upload.upload_id} for #{upload.key}"
    end
# {/fact}
  end
end

# {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
def good_case_12
  s3 = Aws::S3::Client.new(region: 'us-west-2')
  
  s3.list_buckets.buckets.each do |bucket|
    puts "Bucket: #{bucket.name}"
    object_count = 0
    
    # ok: ruby-missing-pagination
    s3.list_objects_v2(bucket: bucket.name).each do |response|
      object_count += response.contents.count
    end
# {/fact}
    
    puts "Object count: #{object_count}"
  end
end

# {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
def good_case_13
  s3 = Aws::S3::Client.new(region: 'us-west-2')
  
  csv_objects = []
  
  # ok: ruby-missing-pagination
  s3.list_objects_v2(bucket: 'my-bucket').each do |response|
    csv_objects.concat(response.contents.select { |obj| obj.key.end_with?('.csv') })
  end
# {/fact}
  
  csv_objects.each do |obj|
    puts "CSV file: #{obj.key}"
  end
end

# {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
def good_case_14
  s3 = Aws::S3::Client.new(region: 'us-west-2')
  
  all_prefixes = []
  
  # ok: ruby-missing-pagination
  s3.list_objects_v2(
    bucket: 'my-bucket',
    delimiter: '/',
    prefix: 'users/'
  ).each do |response|
    all_prefixes.concat(response.common_prefixes)
  end
# {/fact}
  
  all_prefixes.each do |prefix|
    puts "Prefix: #{prefix.prefix}"
  end
end

# {fact rule=avoid-reset-exception-rule@v1.0 defects=0}
def good_case_15
  s3 = Aws::S3::Client.new(region: 'us-west-2')
  
  all_keys = []
  
  # ok: ruby-missing-pagination
  s3.list_objects_v2(bucket: 'my-bucket').each do |response|
    all_keys.concat(response.contents.map(&:key))
  end
# {/fact}
  
  if all_keys.any?
    s3.delete_objects(
      bucket: 'my-bucket',
      delete: { objects: all_keys.map { |k| { key: k } } }
    )
  end
end