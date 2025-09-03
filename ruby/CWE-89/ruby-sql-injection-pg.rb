require 'pg'
require 'sinatra'

# True Positive Examples (Vulnerable Code)

# Example 1: Basic SQL injection in a direct query
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_1
  conn = PG.connect(dbname: 'test')
  user_id = params[:id]
  
  # ruleid: ruby-sql-injection-pg
  result = conn.exec("SELECT * FROM users WHERE id = #{user_id}")
  
  conn.close
  result.to_a.to_json
end
# {/fact}

# Example 2: SQL injection in an UPDATE statement
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_2
  conn = PG.connect(dbname: 'test')
  user_name = request.params['name']
  user_id = request.params['id']
  
  # ruleid: ruby-sql-injection-pg
  conn.exec("UPDATE users SET status = 'active' WHERE username = '#{user_name}' AND id = #{user_id}")
  
  conn.close
  "User updated"
end
# {/fact}

# Example 3: SQL injection in a DELETE statement
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_3
  conn = PG.connect(dbname: 'test')
  email = request.params['email']
  
  # ruleid: ruby-sql-injection-pg
  conn.exec("DELETE FROM users WHERE email = '#{email}'")
  
  conn.close
  "User deleted"
end
# {/fact}

# Example 4: SQL injection with string interpolation in a complex query
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_4
  conn = PG.connect(dbname: 'test')
  search = request.params['search']
  category = request.params['category']
  
  query = "SELECT p.id, p.name, p.price FROM products p " \
          "JOIN categories c ON p.category_id = c.id " \
          "WHERE p.name LIKE '%#{search}%' AND c.name = '#{category}'"
  
  # ruleid: ruby-sql-injection-pg
  result = conn.exec(query)
  
  conn.close
  result.to_a.to_json
end
# {/fact}

# Example 5: SQL injection with minimal processing
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_5
  conn = PG.connect(dbname: 'test')
  sort_field = request.params['sort']
  sort_direction = request.params['direction']
  
  # ruleid: ruby-sql-injection-pg
  result = conn.exec("SELECT * FROM products ORDER BY #{sort_field} #{sort_direction}")
  
  conn.close
  result.to_a.to_json
end
# {/fact}

# Example 6: SQL injection in a prepared statement with string interpolation
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_6
  conn = PG.connect(dbname: 'test')
  user_input = request.params['filter']
  
  # ruleid: ruby-sql-injection-pg
  conn.prepare('query', "SELECT * FROM products WHERE category = '#{user_input}'")
  result = conn.exec_prepared('query')
  
  conn.close
  result.to_a.to_json
end
# {/fact}

# Example 7: SQL injection with multiple user inputs
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_7
  conn = PG.connect(dbname: 'test')
  min_price = request.params['min_price']
  max_price = request.params['max_price']
  category = request.params['category']
  
  query = "SELECT * FROM products WHERE price >= #{min_price} " \
          "AND price <= #{max_price} AND category = '#{category}'"
  
  # ruleid: ruby-sql-injection-pg
  result = conn.exec(query)
  
  conn.close
  result.to_a.to_json
end
# {/fact}

# Example 8: SQL injection in a subquery
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_8
  conn = PG.connect(dbname: 'test')
  department = request.params['department']
  
  query = "SELECT * FROM employees WHERE department_id IN " \
          "(SELECT id FROM departments WHERE name = '#{department}')"
  
  # ruleid: ruby-sql-injection-pg
  result = conn.exec(query)
  
  conn.close
  result.to_a.to_json
end
# {/fact}

# Example 9: SQL injection with string concatenation
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_9
  conn = PG.connect(dbname: 'test')
  status = request.params['status']
  
  query = "SELECT * FROM orders WHERE status = '" + status + "'"
  
  # ruleid: ruby-sql-injection-pg
  result = conn.exec(query)
  
  conn.close
  result.to_a.to_json
end
# {/fact}

# Example 10: SQL injection in an INSERT statement
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_10
  conn = PG.connect(dbname: 'test')
  username = request.params['username']
  email = request.params['email']
  
  # ruleid: ruby-sql-injection-pg
  conn.exec("INSERT INTO users (username, email) VALUES ('#{username}', '#{email}')")
  
  conn.close
  "User created"
end
# {/fact}

# Example 11: SQL injection with exec_params but string interpolation in query
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_11
  conn = PG.connect(dbname: 'test')
  table_name = request.params['table']
  
  # ruleid: ruby-sql-injection-pg
  result = conn.exec_params("SELECT * FROM #{table_name} WHERE active = $1", [true])
  
  conn.close
  result.to_a.to_json
end
# {/fact}

# Example 12: SQL injection with conditional query building
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_12
  conn = PG.connect(dbname: 'test')
  search_term = request.params['search']
  
  query = "SELECT * FROM products"
  if search_term && !search_term.empty?
    query += " WHERE name LIKE '%#{search_term}%'"
  end
  
  # ruleid: ruby-sql-injection-pg
  result = conn.exec(query)
  
  conn.close
  result.to_a.to_json
end
# {/fact}

# Example 13: SQL injection with exec_params but interpolated table name
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_13
  conn = PG.connect(dbname: 'test')
  table = request.params['table']
  id = request.params['id']
  
  # ruleid: ruby-sql-injection-pg
  result = conn.exec_params("SELECT * FROM #{table} WHERE id = $1", [id])
  
  conn.close
  result.to_a.to_json
end
# {/fact}

# Example 14: SQL injection with string formatting
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_14
  conn = PG.connect(dbname: 'test')
  user_id = request.params['id']
  
  query = format("SELECT * FROM users WHERE id = %s", user_id)
  
  # ruleid: ruby-sql-injection-pg
  result = conn.exec(query)
  
  conn.close
  result.to_a.to_json
end
# {/fact}

# Example 15: SQL injection with minimal sanitization attempt
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_15
  conn = PG.connect(dbname: 'test')
  user_input = request.params['input']
  
  # This is not proper sanitization
  sanitized = user_input.gsub("'", "''")
  
  # ruleid: ruby-sql-injection-pg
  result = conn.exec("SELECT * FROM users WHERE name = '#{sanitized}'")
  
  conn.close
  result.to_a.to_json
end
# {/fact}

# True Negative Examples (Safe Code)

# Example 1: Using parameterized queries with exec_params
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_1
  conn = PG.connect(dbname: 'test')
  user_id = params[:id]
  
  # ok: ruby-sql-injection-pg
  result = conn.exec_params("SELECT * FROM users WHERE id = $1", [user_id])
  
  conn.close
  result.to_a.to_json
end
# {/fact}

# Example 2: Using parameterized queries for UPDATE
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_2
  conn = PG.connect(dbname: 'test')
  user_name = request.params['name']
  user_id = request.params['id']
  
  # ok: ruby-sql-injection-pg
  conn.exec_params("UPDATE users SET status = 'active' WHERE username = $1 AND id = $2", 
                  [user_name, user_id])
  
  conn.close
  "User updated"
end
# {/fact}

# Example 3: Using parameterized queries for DELETE
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_3
  conn = PG.connect(dbname: 'test')
  email = request.params['email']
  
  # ok: ruby-sql-injection-pg
  conn.exec_params("DELETE FROM users WHERE email = $1", [email])
  
  conn.close
  "User deleted"
end
# {/fact}

# Example 4: Using parameterized queries in a complex query
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_4
  conn = PG.connect(dbname: 'test')
  search = request.params['search']
  category = request.params['category']
  
  query = "SELECT p.id, p.name, p.price FROM products p " \
          "JOIN categories c ON p.category_id = c.id " \
          "WHERE p.name LIKE $1 AND c.name = $2"
  
  # ok: ruby-sql-injection-pg
  result = conn.exec_params(query, ["%#{search}%", category])
  
  conn.close
  result.to_a.to_json
end
# {/fact}

# Example 5: Using parameterized queries with proper validation
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_5
  conn = PG.connect(dbname: 'test')
  sort_field = request.params['sort']
  sort_direction = request.params['direction']
  
  # Validate sort field against allowed columns
  allowed_columns = ['name', 'price', 'created_at']
  sort_field = 'name' unless allowed_columns.include?(sort_field)
  
  # Validate sort direction
  sort_direction = sort_direction == 'DESC' ? 'DESC' : 'ASC'
  
  # ok: ruby-sql-injection-pg
  result = conn.exec_params("SELECT * FROM products ORDER BY #{sort_field} #{sort_direction}")
  
  conn.close
  result.to_a.to_json
end
# {/fact}

# Example 6: Using proper prepared statements
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_6
  conn = PG.connect(dbname: 'test')
  user_input = request.params['filter']
  
  # ok: ruby-sql-injection-pg
  conn.prepare('query', "SELECT * FROM products WHERE category = $1")
  result = conn.exec_prepared('query', [user_input])
  
  conn.close
  result.to_a.to_json
end
# {/fact}

# Example 7: Using parameterized queries with multiple parameters
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_7
  conn = PG.connect(dbname: 'test')
  min_price = request.params['min_price']
  max_price = request.params['max_price']
  category = request.params['category']
  
  query = "SELECT * FROM products WHERE price >= $1 " \
          "AND price <= $2 AND category = $3"
  
  # ok: ruby-sql-injection-pg
  result = conn.exec_params(query, [min_price, max_price, category])
  
  conn.close
  result.to_a.to_json
end
# {/fact}

# Example 8: Using parameterized queries in a subquery
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_8
  conn = PG.connect(dbname: 'test')
  department = request.params['department']
  
  query = "SELECT * FROM employees WHERE department_id IN " \
          "(SELECT id FROM departments WHERE name = $1)"
  
  # ok: ruby-sql-injection-pg
  result = conn.exec_params(query, [department])
  
  conn.close
  result.to_a.to_json
end
# {/fact}

# Example 9: Using parameterized queries with array parameters
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_9
  conn = PG.connect(dbname: 'test')
  statuses = request.params['statuses'].split(',')
  
  placeholders = statuses.each_with_index.map { |_, i| "$#{i+1}" }.join(', ')
  query = "SELECT * FROM orders WHERE status IN (#{placeholders})"
  
  # ok: ruby-sql-injection-pg
  result = conn.exec_params(query, statuses)
  
  conn.close
  result.to_a.to_json
end
# {/fact}

# Example 10: Using parameterized queries for INSERT
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_10
  conn = PG.connect(dbname: 'test')
  username = request.params['username']
  email = request.params['email']
  
  # ok: ruby-sql-injection-pg
  conn.exec_params("INSERT INTO users (username, email) VALUES ($1, $2)", 
                  [username, email])
  
  conn.close
  "User created"
end
# {/fact}

# Example 11: Using a whitelist for table names
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_11
  conn = PG.connect(dbname: 'test')
  table_name = request.params['table']
  
  # Whitelist of allowed tables
  allowed_tables = ['products', 'categories', 'public_data']
  
  if allowed_tables.include?(table_name)
    # ok: ruby-sql-injection-pg
    result = conn.exec("SELECT * FROM #{table_name} WHERE active = true")
  else
    result = conn.exec("SELECT * FROM products WHERE active = true") # Default table
  end
  
  conn.close
  result.to_a.to_json
end
# {/fact}

# Example 12: Using parameterized queries with conditional query building
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_12
  conn = PG.connect(dbname: 'test')
  search_term = request.params['search']
  
  if search_term && !search_term.empty?
    # ok: ruby-sql-injection-pg
    result = conn.exec_params("SELECT * FROM products WHERE name LIKE $1", ["%#{search_term}%"])
  else
    result = conn.exec("SELECT * FROM products")
  end
  
  conn.close
  result.to_a.to_json
end
# {/fact}

# Example 13: Using ORM to avoid SQL injection
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_13
  require 'sequel'
  
  DB = Sequel.postgres('test')
  
  user_id = request.params['id']
  
  # ok: ruby-sql-injection-pg
  result = DB[:users].where(id: user_id).all
  
  result.to_json
end
# {/fact}

# Example 14: Using type casting for numeric values
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_14
  conn = PG.connect(dbname: 'test')
  user_id = request.params['id']
  
  # Ensure user_id is an integer
  user_id = user_id.to_i
  
  # ok: ruby-sql-injection-pg
  result = conn.exec("SELECT * FROM users WHERE id = #{user_id}")
  
  conn.close
  result.to_a.to_json
end
# {/fact}

# Example 15: Using a query builder with proper escaping
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_15
  conn = PG.connect(dbname: 'test')
  
  # Simple query builder with escaping
  class QueryBuilder
    def initialize(conn)
      @conn = conn
      @conditions = []
      @params = []
    end
    
    def add_condition(field, value)
      @params << value
      @conditions << "#{field} = $#{@params.length}"
      self
    end
    
    def execute(table)
      query = "SELECT * FROM #{table}"
      query += " WHERE " + @conditions.join(" AND ") unless @conditions.empty?
      @conn.exec_params(query, @params)
    end
  end
  
  builder = QueryBuilder.new(conn)
  
  # ok: ruby-sql-injection-pg
  result = builder
    .add_condition('status', request.params['status'])
    .add_condition('category', request.params['category'])
    .execute('products')
  
  conn.close
  result.to_a.to_json
end
# {/fact}