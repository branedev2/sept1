# Ruby Regex Validation Test Cases
# This file contains examples of proper and improper regex bounds in Rails validations

# Common imports for Rails models
require 'active_record'

# True Positive Examples (Vulnerable Code)

class User1 < ActiveRecord::Base
  # ruleid: ruby-regex-validation
  validates_format_of :email, with: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}/
end

class User2 < ActiveRecord::Base
  # ruleid: ruby-regex-validation
  validates_format_of :username, with: /^[a-zA-Z0-9_]+$/
end

class User3 < ActiveRecord::Base
  # ruleid: ruby-regex-validation
  validates :password, format: { with: /[a-zA-Z0-9]{8,}/ }
end

class User4 < ActiveRecord::Base
  # ruleid: ruby-regex-validation
  validates :phone, format: { with: /^\d{3}-\d{3}-\d{4}$/ }
end

class User5 < ActiveRecord::Base
  # ruleid: ruby-regex-validation
  validates :website, format: { with: /https?:\/\/[\w\-\.]+\.\w{2,}/ }
end

class Product1 < ActiveRecord::Base
  # ruleid: ruby-regex-validation
  validates_format_of :sku, with: /[A-Z]{2}\d{6}/
end

class Product2 < ActiveRecord::Base
  # ruleid: ruby-regex-validation
  validates :color_code, format: { with: /^#[0-9a-fA-F]{6}$/ }
end

class Address1 < ActiveRecord::Base
  # ruleid: ruby-regex-validation
  validates :zip_code, format: { with: /\d{5}(-\d{4})?/ }
end

class CreditCard1 < ActiveRecord::Base
  # ruleid: ruby-regex-validation
  validates_format_of :number, with: /\d{4}-\d{4}-\d{4}-\d{4}/
end

class Post1 < ActiveRecord::Base
  # ruleid: ruby-regex-validation
  validates :slug, format: { with: /[a-z0-9-]+/ }
end

class Comment1 < ActiveRecord::Base
  # ruleid: ruby-regex-validation
  validates :content, format: { with: /^.{10,500}$/ }
end

class Event1 < ActiveRecord::Base
  # ruleid: ruby-regex-validation
  validates_format_of :date_string, with: /\d{2}\/\d{2}\/\d{4}/
end

class Tag1 < ActiveRecord::Base
  # ruleid: ruby-regex-validation
  validates :name, format: { with: /^[a-z\-]+$/ }
end

class Profile1 < ActiveRecord::Base
  # ruleid: ruby-regex-validation
  validates :twitter_handle, format: { with: /@[a-zA-Z0-9_]{1,15}/ }
end

class Document1 < ActiveRecord::Base
  # ruleid: ruby-regex-validation
  validates_format_of :file_extension, with: /\.(jpg|png|pdf|doc)$/i
end

# True Negative Examples (Secure Code)

class User6 < ActiveRecord::Base
  # ok: ruby-regex-validation
  validates_format_of :email, with: /\A[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}\z/
end

class User7 < ActiveRecord::Base
  # ok: ruby-regex-validation
  validates_format_of :username, with: /\A[a-zA-Z0-9_]+\z/
end

class User8 < ActiveRecord::Base
  # ok: ruby-regex-validation
  validates :password, format: { with: /\A[a-zA-Z0-9]{8,}\z/ }
end

class User9 < ActiveRecord::Base
  # ok: ruby-regex-validation
  validates :phone, format: { with: /\A\d{3}-\d{3}-\d{4}\z/ }
end

class User10 < ActiveRecord::Base
  # ok: ruby-regex-validation
  validates :website, format: { with: /\Ahttps?:\/\/[\w\-\.]+\.\w{2,}\z/ }
end

class Product3 < ActiveRecord::Base
  # ok: ruby-regex-validation
  validates_format_of :sku, with: /\A[A-Z]{2}\d{6}\z/
end

class Product4 < ActiveRecord::Base
  # ok: ruby-regex-validation
  validates :color_code, format: { with: /\A#[0-9a-fA-F]{6}\z/ }
end

class Address2 < ActiveRecord::Base
  # ok: ruby-regex-validation
  validates :zip_code, format: { with: /\A\d{5}(-\d{4})?\z/ }
end

class CreditCard2 < ActiveRecord::Base
  # ok: ruby-regex-validation
  validates_format_of :number, with: /\A\d{4}-\d{4}-\d{4}-\d{4}\z/
end

class Post2 < ActiveRecord::Base
  # ok: ruby-regex-validation
  validates :slug, format: { with: /\A[a-z0-9-]+\z/ }
end

class Comment2 < ActiveRecord::Base
  # ok: ruby-regex-validation
  validates :content, format: { with: /\A.{10,500}\z/ }
end

class Event2 < ActiveRecord::Base
  # ok: ruby-regex-validation
  validates_format_of :date_string, with: /\A\d{2}\/\d{2}\/\d{4}\z/
end

class Tag2 < ActiveRecord::Base
  # ok: ruby-regex-validation
  validates :name, format: { with: /\A[a-z\-]+\z/ }
end

class Profile2 < ActiveRecord::Base
  # ok: ruby-regex-validation
  validates :twitter_handle, format: { with: /\A@[a-zA-Z0-9_]{1,15}\z/ }
end

class Document2 < ActiveRecord::Base
  # ok: ruby-regex-validation
  validates_format_of :file_extension, with: /\A.*\.(jpg|png|pdf|doc)\z/i
end