require 'sinatra'
require 'sqlite3'
require 'active_record'
require 'pg'
require 'mysql2'

# True Positive Cases (Vulnerable)

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_1
  # Direct string interpolation in SQL query
  user_id = params[:id]
  db = SQLite3::Database.new('users.db')
  
  # ruleid: ruby-sql-injection
  result = db.execute("SELECT * FROM users WHERE id = #{user_id}")
  
  return result
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_2
  # Using string concatenation with user input
  username = request.params['username']
  db = PG.connect(dbname: 'app_database')
  
  query = "SELECT * FROM users WHERE username = '" + username + "'"
  # ruleid: ruby-sql-injection
  results = db.exec(query)
  
  return results
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_3
  # Using string interpolation in ActiveRecord find_by_sql
  search_term = params[:search]
  
  # ruleid: ruby-sql-injection
  users = User.find_by_sql("SELECT * FROM users WHERE name LIKE '%#{search_term}%'")
  
  return users
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_4
  # Using string interpolation with multiple parameters
  min_age = params[:min_age]
  max_age = params[:max_age]
  client = Mysql2::Client.new(host: "localhost", username: "user", password: "password", database: "mydb")
  
  # ruleid: ruby-sql-injection
  result = client.query("SELECT * FROM users WHERE age >= #{min_age} AND age <= #{max_age}")
  
  return result
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_5
  # Using string interpolation in a complex query
  table = params[:table]
  column = params[:column]
  value = params[:value]
  db = SQLite3::Database.new('app.db')
  
  # ruleid: ruby-sql-injection
  result = db.execute("SELECT * FROM #{table} WHERE #{column} = '#{value}'")
  
  return result
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_6
  # Using string interpolation in an UPDATE statement
  user_id = params[:id]
  new_status = params[:status]
  db = SQLite3::Database.new('users.db')
  
  # ruleid: ruby-sql-injection
  db.execute("UPDATE users SET status = '#{new_status}' WHERE id = #{user_id}")
  
  return "User updated"
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_7
  # Using string interpolation in a DELETE statement
  user_id = request.params['id']
  db = PG.connect(dbname: 'app_database')
  
  # ruleid: ruby-sql-injection
  db.exec("DELETE FROM users WHERE id = #{user_id}")
  
  return "User deleted"
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_8
  # Using string interpolation in a JOIN query
  product_id = params[:product_id]
  client = Mysql2::Client.new(host: "localhost", username: "user", password: "password", database: "mydb")
  
  # ruleid: ruby-sql-injection
  result = client.query("SELECT p.*, c.name FROM products p JOIN categories c ON p.category_id = c.id WHERE p.id = #{product_id}")
  
  return result
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_9
  # Using string interpolation in an ORDER BY clause
  sort_column = params[:sort]
  db = SQLite3::Database.new('products.db')
  
  # ruleid: ruby-sql-injection
  result = db.execute("SELECT * FROM products ORDER BY #{sort_column}")
  
  return result
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_10
  # Using string interpolation in a GROUP BY clause
  group_field = params[:group]
  db = PG.connect(dbname: 'app_database')
  
  # ruleid: ruby-sql-injection
  result = db.exec("SELECT #{group_field}, COUNT(*) FROM orders GROUP BY #{group_field}")
  
  return result
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_11
  # Using string interpolation in a HAVING clause
  min_count = params[:min]
  db = SQLite3::Database.new('sales.db')
  
  # ruleid: ruby-sql-injection
  result = db.execute("SELECT product_id, COUNT(*) FROM sales GROUP BY product_id HAVING COUNT(*) > #{min_count}")
  
  return result
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_12
  # Using string interpolation in a subquery
  department = request.params['dept']
  client = Mysql2::Client.new(host: "localhost", username: "user", password: "password", database: "mydb")
  
  # ruleid: ruby-sql-injection
  result = client.query("SELECT * FROM employees WHERE department_id IN (SELECT id FROM departments WHERE name = '#{department}')")
  
  return result
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_13
  # Using string interpolation with LIMIT and OFFSET
  limit = params[:limit]
  offset = params[:offset]
  db = SQLite3::Database.new('products.db')
  
  # ruleid: ruby-sql-injection
  result = db.execute("SELECT * FROM products LIMIT #{limit} OFFSET #{offset}")
  
  return result
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_14
  # Using string interpolation in a complex condition
  status = params[:status]
  category = params[:category]
  db = PG.connect(dbname: 'app_database')
  
  # ruleid: ruby-sql-injection
  result = db.exec("SELECT * FROM orders WHERE status = '#{status}' AND category = '#{category}'")
  
  return result
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_15
  # Using string interpolation in a raw SQL with ActiveRecord
  search = params[:q]
  
  # ruleid: ruby-sql-injection
  results = ActiveRecord::Base.connection.execute("SELECT * FROM products WHERE name LIKE '%#{search}%' OR description LIKE '%#{search}%'")
  
  return results
end
# {/fact}

# True Negative Cases (Safe)

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_1
  # Using parameterized query with placeholders
  user_id = params[:id]
  db = SQLite3::Database.new('users.db')
  
  # ok: ruby-sql-injection
  result = db.execute("SELECT * FROM users WHERE id = ?", user_id)
  
  return result
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_2
  # Using parameterized query with named parameters
  username = request.params['username']
  db = PG.connect(dbname: 'app_database')
  
  # ok: ruby-sql-injection
  results = db.exec_params("SELECT * FROM users WHERE username = $1", [username])
  
  return results
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_3
  # Using ActiveRecord's find method
  user_id = params[:id]
  
  # ok: ruby-sql-injection
  user = User.find(user_id)
  
  return user
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_4
  # Using ActiveRecord's where method with hash
  min_age = params[:min_age]
  max_age = params[:max_age]
  
  # ok: ruby-sql-injection
  users = User.where("age >= ? AND age <= ?", min_age, max_age)
  
  return users
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_5
  # Using ActiveRecord's find_by method
  username = params[:username]
  
  # ok: ruby-sql-injection
  user = User.find_by(username: username)
  
  return user
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_6
  # Using parameterized query for UPDATE
  user_id = params[:id]
  new_status = params[:status]
  db = SQLite3::Database.new('users.db')
  
  # ok: ruby-sql-injection
  db.execute("UPDATE users SET status = ? WHERE id = ?", [new_status, user_id])
  
  return "User updated"
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_7
  # Using parameterized query for DELETE
  user_id = request.params['id']
  db = PG.connect(dbname: 'app_database')
  
  # ok: ruby-sql-injection
  db.exec_params("DELETE FROM users WHERE id = $1", [user_id])
  
  return "User deleted"
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_8
  # Using ActiveRecord for JOIN queries
  product_id = params[:product_id]
  
  # ok: ruby-sql-injection
  product = Product.joins(:category).where(id: product_id).select('products.*, categories.name')
  
  return product
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_9
  # Safe handling of ORDER BY with whitelist
  sort_column = params[:sort]
  allowed_columns = ['name', 'price', 'created_at']
  
  if allowed_columns.include?(sort_column)
    db = SQLite3::Database.new('products.db')
    # ok: ruby-sql-injection
    result = db.execute("SELECT * FROM products ORDER BY #{sort_column}")
    return result
  else
    return "Invalid sort parameter"
  end
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_10
  # Using parameterized query for GROUP BY
  group_field = params[:group]
  allowed_fields = ['category', 'date', 'status']
  
  if allowed_fields.include?(group_field)
    db = PG.connect(dbname: 'app_database')
    # ok: ruby-sql-injection
    result = db.exec("SELECT #{group_field}, COUNT(*) FROM orders GROUP BY #{group_field}")
    return result
  else
    return "Invalid group parameter"
  end
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_11
  # Using parameterized query for HAVING clause
  min_count = params[:min]
  db = SQLite3::Database.new('sales.db')
  
  # ok: ruby-sql-injection
  result = db.execute("SELECT product_id, COUNT(*) FROM sales GROUP BY product_id HAVING COUNT(*) > ?", min_count)
  
  return result
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_12
  # Using ActiveRecord for subqueries
  department = request.params['dept']
  
  # ok: ruby-sql-injection
  employees = Employee.where(department_id: Department.where(name: department).select(:id))
  
  return employees
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_13
  # Using parameterized query with LIMIT and OFFSET
  limit = params[:limit].to_i
  offset = params[:offset].to_i
  
  # Validate input
  limit = [limit, 100].min if limit > 0
  offset = [offset, 0].max
  
  db = SQLite3::Database.new('products.db')
  
  # ok: ruby-sql-injection
  result = db.execute("SELECT * FROM products LIMIT ? OFFSET ?", [limit, offset])
  
  return result
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_14
  # Using ActiveRecord's where method with multiple conditions
  status = params[:status]
  category = params[:category]
  
  # ok: ruby-sql-injection
  orders = Order.where(status: status, category: category)
  
  return orders
end
# {/fact}

# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_15
  # Using parameterized query for complex search
  search = params[:q]
  
  # ok: ruby-sql-injection
  results = ActiveRecord::Base.connection.exec_query(
    "SELECT * FROM products WHERE name LIKE ? OR description LIKE ?", 
    "Products Search", 
    ["%#{search}%", "%#{search}%"]
  )
  
  return results
end
# {/fact}