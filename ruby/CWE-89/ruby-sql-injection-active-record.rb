# frozen_string_literal: true
require 'sinatra'
require 'active_record'
require 'rails'

# Setup database connection for examples
ActiveRecord::Base.establish_connection(
  adapter: 'sqlite3',
  database: ':memory:'
)

# Define a User model for examples
class User < ActiveRecord::Base
  # Assume this model has id, username, email, and password fields
end

# Define a Product model for examples
class Product < ActiveRecord::Base
  # Assume this model has id, name, price, and category fields
end

# TRUE POSITIVES - Vulnerable code examples

# Example 1: Direct interpolation of user input in where clause
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_1
  get '/users' do
    username = params[:username]
    # ruleid: ruby-sql-injection-active-record
    users = User.where("username = '#{username}'")
    users.to_json
  end
# {/fact}
end

# Example 2: Using raw SQL with user input in find_by_sql
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_2
  post '/search_products' do
    search_term = params[:q]
    # ruleid: ruby-sql-injection-active-record
    products = Product.find_by_sql("SELECT * FROM products WHERE name LIKE '%#{search_term}%'")
    products.to_json
  end
# {/fact}
end

# Example 3: Using connection.execute with interpolated user input
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_3
  get '/user_orders' do
    user_id = params[:id]
    # ruleid: ruby-sql-injection-active-record
    results = ActiveRecord::Base.connection.execute("SELECT * FROM orders WHERE user_id = #{user_id}")
    results.to_json
  end
# {/fact}
end

# Example 4: Using select with interpolated user input
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_4
  get '/filtered_products' do
    category = params[:category]
    # ruleid: ruby-sql-injection-active-record
    products = Product.select("id, name, price, category").where("category = '#{category}'")
    products.to_json
  end
# {/fact}
end

# Example 5: Using order with interpolated user input
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_5
  get '/sorted_users' do
    sort_column = params[:sort]
    # ruleid: ruby-sql-injection-active-record
    users = User.order("#{sort_column} ASC")
    users.to_json
  end
# {/fact}
end

# Example 6: Using group with interpolated user input
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_6
  get '/product_stats' do
    group_by = params[:group]
    # ruleid: ruby-sql-injection-active-record
    stats = Product.group("#{group_by}").count
    stats.to_json
  end
# {/fact}
end

# Example 7: Using having with interpolated user input
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_7
  get '/product_categories' do
    min_count = params[:min]
    # ruleid: ruby-sql-injection-active-record
    categories = Product.group(:category).having("COUNT(*) > #{min_count}")
    categories.to_json
  end
# {/fact}
end

# Example 8: Using joins with interpolated user input
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_8
  get '/user_products' do
    join_condition = params[:condition]
    # ruleid: ruby-sql-injection-active-record
    results = User.joins("JOIN orders ON orders.user_id = users.id AND #{join_condition}")
    results.to_json
  end
# {/fact}
end

# Example 9: Using update_all with interpolated user input
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_9
  post '/update_products' do
    category = params[:category]
    new_price = params[:price]
    # ruleid: ruby-sql-injection-active-record
    Product.where("category = '#{category}'").update_all("price = #{new_price}")
    redirect '/products'
  end
# {/fact}
end

# Example 10: Using delete_all with interpolated user input
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_10
  post '/delete_products' do
    condition = params[:condition]
    # ruleid: ruby-sql-injection-active-record
    Product.where("#{condition}").delete_all
    redirect '/products'
  end
# {/fact}
end

# Example 11: Using from with interpolated user input
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_11
  get '/custom_table' do
    table_name = params[:table]
    # ruleid: ruby-sql-injection-active-record
    results = User.from("#{table_name}")
    results.to_json
  end
# {/fact}
end

# Example 12: Using pluck with interpolated user input
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_12
  get '/product_attributes' do
    attribute = params[:attr]
    # ruleid: ruby-sql-injection-active-record
    values = Product.pluck("#{attribute}")
    values.to_json
  end
# {/fact}
end

# Example 13: Using lock with interpolated user input
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_13
  post '/update_inventory' do
    lock_type = params[:lock_type]
    # ruleid: ruby-sql-injection-active-record
    Product.transaction do
      products = Product.lock("#{lock_type}").where(in_stock: true)
      products.update_all(in_stock: false)
    end
# {/fact}
    redirect '/inventory'
  end
end

# Example 14: Using calculate with interpolated user input
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_14
  get '/product_calculation' do
    operation = params[:operation]
    field = params[:field]
    # ruleid: ruby-sql-injection-active-record
    result = Product.calculate("#{operation}", "#{field}")
    { result: result }.to_json
  end
# {/fact}
end

# Example 15: Using exec_query with interpolated user input
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_15
  get '/custom_query' do
    query_param = params[:query]
    # ruleid: ruby-sql-injection-active-record
    results = ActiveRecord::Base.connection.exec_query("SELECT * FROM users WHERE #{query_param}")
    results.to_json
  end
# {/fact}
end

# TRUE NEGATIVES - Safe code examples

# Example 1: Using parameterized query with where
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_1
  get '/users' do
    username = params[:username]
    # ok: ruby-sql-injection-active-record
    users = User.where(username: username)
    users.to_json
  end
# {/fact}
end

# Example 2: Using find method safely
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_2
  get '/user' do
    user_id = params[:id]
    # ok: ruby-sql-injection-active-record
    user = User.find(user_id)
    user.to_json
  end
# {/fact}
end

# Example 3: Using find_by safely
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_3
  get '/find_product' do
    name = params[:name]
    # ok: ruby-sql-injection-active-record
    product = Product.find_by(name: name)
    product.to_json
  end
# {/fact}
end

# Example 4: Using where with array syntax for conditions
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_4
  get '/search_products' do
    search_term = params[:q]
    # ok: ruby-sql-injection-active-record
    products = Product.where("name LIKE ?", "%#{search_term}%")
    products.to_json
  end
# {/fact}
end

# Example 5: Using order safely with hash syntax
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_5
  get '/sorted_users' do
    sort_column = params[:sort].to_sym
    # Validate column name to prevent injection
    valid_columns = [:id, :username, :email, :created_at]
    sort_column = :id unless valid_columns.include?(sort_column)
    
    # ok: ruby-sql-injection-active-record
    users = User.order(sort_column => :asc)
    users.to_json
  end
# {/fact}
end

# Example 6: Using group safely with symbol
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_6
  get '/product_stats' do
    group_by = params[:group].to_sym
    # Validate column name
    valid_columns = [:category, :price]
    group_by = :category unless valid_columns.include?(group_by)
    
    # ok: ruby-sql-injection-active-record
    stats = Product.group(group_by).count
    stats.to_json
  end
# {/fact}
end

# Example 7: Using having with array syntax
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_7
  get '/product_categories' do
    min_count = params[:min]
    # ok: ruby-sql-injection-active-record
    categories = Product.group(:category).having("COUNT(*) > ?", min_count)
    categories.to_json
  end
# {/fact}
end

# Example 8: Using joins safely with symbols
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_8
  get '/user_orders' do
    # ok: ruby-sql-injection-active-record
    results = User.joins(:orders)
    results.to_json
  end
# {/fact}
end

# Example 9: Using update_all safely with hash syntax
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_9
  post '/update_products' do
    category = params[:category]
    new_price = params[:price]
    # ok: ruby-sql-injection-active-record
    Product.where(category: category).update_all(price: new_price)
    redirect '/products'
  end
# {/fact}
end

# Example 10: Using delete_all safely with hash conditions
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_10
  post '/delete_products' do
    category = params[:category]
    # ok: ruby-sql-injection-active-record
    Product.where(category: category).delete_all
    redirect '/products'
  end
# {/fact}
end

# Example 11: Using from safely with validated input
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_11
  get '/custom_table' do
    table_name = params[:table]
    # Whitelist allowed tables
    allowed_tables = ['users', 'products', 'orders']
    table_name = 'users' unless allowed_tables.include?(table_name)
    
    # ok: ruby-sql-injection-active-record
    results = User.from(table_name)
    results.to_json
  end
# {/fact}
end

# Example 12: Using pluck safely with symbol
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_12
  get '/product_attributes' do
    attribute = params[:attr].to_sym
    # Validate attribute name
    valid_attributes = [:id, :name, :price, :category]
    attribute = :name unless valid_attributes.include?(attribute)
    
    # ok: ruby-sql-injection-active-record
    values = Product.pluck(attribute)
    values.to_json
  end
# {/fact}
end

# Example 13: Using lock safely with symbol
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_13
  post '/update_inventory' do
    # ok: ruby-sql-injection-active-record
    Product.transaction do
      products = Product.lock.where(in_stock: true)
      products.update_all(in_stock: false)
    end
# {/fact}
    redirect '/inventory'
  end
end

# Example 14: Using calculate safely with symbols
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_14
  get '/product_calculation' do
    operation = params[:operation].to_sym
    field = params[:field].to_sym
    
    # Validate operation and field
    valid_operations = [:sum, :average, :minimum, :maximum, :count]
    valid_fields = [:price, :stock_quantity]
    
    operation = :sum unless valid_operations.include?(operation)
    field = :price unless valid_fields.include?(field)
    
    # ok: ruby-sql-injection-active-record
    result = Product.calculate(operation, field)
    { result: result }.to_json
  end
# {/fact}
end

# Example 15: Using sanitize_sql_array for complex queries
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_15
  get '/custom_query' do
    min_price = params[:min_price]
    max_price = params[:max_price]
    
    # ok: ruby-sql-injection-active-record
    query = ActiveRecord::Base.sanitize_sql_array(["SELECT * FROM products WHERE price BETWEEN ? AND ?", min_price, max_price])
    results = ActiveRecord::Base.connection.exec_query(query)
    results.to_json
  end
# {/fact}
end