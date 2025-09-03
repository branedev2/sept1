require 'sequel'
require 'sinatra'

# Database connection setup
DB = Sequel.connect('postgres://user:password@localhost/mydb')

# True Positive Examples (Vulnerable Code)

# Bad case 1: Direct interpolation of user input in SQL query
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_1
  user_id = params[:id]
  # ruleid: ruby-sql-injection-sequel
  users = DB["SELECT * FROM users WHERE id = #{user_id}"].all
  return users.to_json
end
# {/fact}

# Bad case 2: Using string concatenation with user input
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_2
  username = request.params['username']
  # ruleid: ruby-sql-injection-sequel
  result = DB.fetch("SELECT * FROM users WHERE username = '" + username + "'").all
  return result
end
# {/fact}

# Bad case 3: Using string interpolation in a where clause
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_3
  search_term = params[:search]
  # ruleid: ruby-sql-injection-sequel
  products = DB[:products].where("name LIKE '%#{search_term}%'").all
  return products.to_json
end
# {/fact}

# Bad case 4: Using exec_sql with string interpolation
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_4
  user_email = request.params['email']
  # ruleid: ruby-sql-injection-sequel
  DB.execute("UPDATE users SET active = true WHERE email = '#{user_email}'")
  return "User activated"
end
# {/fact}

# Bad case 5: Using run with string interpolation
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_5
  table_name = params[:table]
  # ruleid: ruby-sql-injection-sequel
  DB.run("DROP TABLE IF EXISTS #{table_name}")
  return "Table dropped"
end
# {/fact}

# Bad case 6: Using fetch with string interpolation in complex query
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_6
  min_price = params[:min_price]
  category = params[:category]
  # ruleid: ruby-sql-injection-sequel
  results = DB.fetch("SELECT * FROM products WHERE price > #{min_price} AND category = '#{category}'").all
  return results.to_json
end
# {/fact}

# Bad case 7: Using literal SQL in order clause
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_7
  sort_column = params[:sort]
  # ruleid: ruby-sql-injection-sequel
  users = DB[:users].order(Sequel.lit("#{sort_column} ASC")).all
  return users.to_json
end
# {/fact}

# Bad case 8: Using string interpolation with multiple parameters
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_8
  start_date = params[:start_date]
  end_date = params[:end_date]
  # ruleid: ruby-sql-injection-sequel
  orders = DB.fetch("SELECT * FROM orders WHERE order_date BETWEEN '#{start_date}' AND '#{end_date}'").all
  return orders.to_json
end
# {/fact}

# Bad case 9: Using string interpolation in a join condition
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_9
  user_role = request.params['role']
  # ruleid: ruby-sql-injection-sequel
  results = DB.fetch("SELECT users.name, roles.name FROM users JOIN roles ON roles.id = users.role_id WHERE roles.name = '#{user_role}'").all
  return results.to_json
end
# {/fact}

# Bad case 10: Using string interpolation in a group by clause
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_10
  group_field = params[:group_by]
  # ruleid: ruby-sql-injection-sequel
  stats = DB.fetch("SELECT #{group_field}, COUNT(*) FROM orders GROUP BY #{group_field}").all
  return stats.to_json
end
# {/fact}

# Bad case 11: Using string interpolation in a having clause
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_11
  min_count = params[:min]
  # ruleid: ruby-sql-injection-sequel
  results = DB.fetch("SELECT category, COUNT(*) FROM products GROUP BY category HAVING COUNT(*) > #{min_count}").all
  return results.to_json
end
# {/fact}

# Bad case 12: Using string interpolation in a complex where condition
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_12
  status = request.params['status']
  # ruleid: ruby-sql-injection-sequel
  DB["UPDATE orders SET processed = true WHERE status = '#{status}' AND processed = false"].update
  return "Orders updated"
end
# {/fact}

# Bad case 13: Using string interpolation in a limit clause
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_13
  limit_val = params[:limit]
  # ruleid: ruby-sql-injection-sequel
  users = DB.fetch("SELECT * FROM users LIMIT #{limit_val}").all
  return users.to_json
end
# {/fact}

# Bad case 14: Using string interpolation in an offset clause
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_14
  page = params[:page].to_i
  page_size = params[:page_size].to_i
  offset_val = page * page_size
  # ruleid: ruby-sql-injection-sequel
  products = DB.fetch("SELECT * FROM products LIMIT 10 OFFSET #{offset_val}").all
  return products.to_json
end
# {/fact}

# Bad case 15: Using string interpolation in a complex query with subquery
# {fact rule=cross-site-scripting@v1.0 defects=1}
def bad_case_15
  department = request.params['department']
  # ruleid: ruby-sql-injection-sequel
  employees = DB.fetch("SELECT * FROM employees WHERE department_id IN (SELECT id FROM departments WHERE name = '#{department}')").all
  return employees.to_json
end
# {/fact}

# True Negative Examples (Safe Code)

# Good case 1: Using parameterized queries with placeholders
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_1
  user_id = params[:id]
  # ok: ruby-sql-injection-sequel
  users = DB["SELECT * FROM users WHERE id = ?", user_id].all
  return users.to_json
end
# {/fact}

# Good case 2: Using named parameters
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_2
  username = request.params['username']
  # ok: ruby-sql-injection-sequel
  result = DB["SELECT * FROM users WHERE username = :username", username: username].all
  return result
end
# {/fact}

# Good case 3: Using the Sequel DSL for queries
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_3
  search_term = params[:search]
  # ok: ruby-sql-injection-sequel
  products = DB[:products].where(Sequel.like(:name, "%#{search_term}%")).all
  return products.to_json
end
# {/fact}

# Good case 4: Using hash conditions in where clause
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_4
  user_email = request.params['email']
  # ok: ruby-sql-injection-sequel
  DB[:users].where(email: user_email).update(active: true)
  return "User activated"
end
# {/fact}

# Good case 5: Using symbols for table names
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_5
  table_name = params[:table].to_sym
  # Validation to prevent arbitrary table access
  allowed_tables = [:temp_data, :cache_items, :logs]
  if allowed_tables.include?(table_name)
    # ok: ruby-sql-injection-sequel
    DB.drop_table?(table_name)
    return "Table dropped"
  else
    return "Operation not allowed"
  end
end
# {/fact}

# Good case 6: Using parameterized queries with multiple parameters
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_6
  min_price = params[:min_price]
  category = params[:category]
  # ok: ruby-sql-injection-sequel
  results = DB["SELECT * FROM products WHERE price > ? AND category = ?", min_price, category].all
  return results.to_json
end
# {/fact}

# Good case 7: Using the Sequel DSL for ordering
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_7
  sort_column = params[:sort]
  # Validate sort column to prevent injection
  allowed_columns = ['name', 'created_at', 'email']
  if allowed_columns.include?(sort_column)
    # ok: ruby-sql-injection-sequel
    users = DB[:users].order(sort_column.to_sym).all
    return users.to_json
  else
    return "Invalid sort parameter"
  end
end
# {/fact}

# Good case 8: Using the Sequel DSL with date objects
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_8
  start_date = Date.parse(params[:start_date])
  end_date = Date.parse(params[:end_date])
  # ok: ruby-sql-injection-sequel
  orders = DB[:orders].where(order_date: start_date..end_date).all
  return orders.to_json
end
# {/fact}

# Good case 9: Using the Sequel DSL for joins
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_9
  user_role = request.params['role']
  # ok: ruby-sql-injection-sequel
  results = DB[:users].join(:roles, id: :role_id).where(roles__name: user_role).select_all(:users).select_append(:roles__name).all
  return results.to_json
end
# {/fact}

# Good case 10: Using the Sequel DSL for group by
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_10
  group_field = params[:group_by]
  # Validate group field to prevent injection
  allowed_fields = ['category', 'status', 'date']
  if allowed_fields.include?(group_field)
    # ok: ruby-sql-injection-sequel
    stats = DB[:orders].group(group_field.to_sym).select(group_field.to_sym, Sequel.function(:count, '*')).all
    return stats.to_json
  else
    return "Invalid group parameter"
  end
end
# {/fact}

# Good case 11: Using the Sequel DSL for having clause
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_11
  min_count = params[:min].to_i
  # ok: ruby-sql-injection-sequel
  results = DB[:products].group(:category).having { count(:*) > min_count }.select(:category, Sequel.function(:count, '*')).all
  return results.to_json
end
# {/fact}

# Good case 12: Using the Sequel DSL for complex where conditions
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_12
  status = request.params['status']
  # ok: ruby-sql-injection-sequel
  DB[:orders].where(status: status, processed: false).update(processed: true)
  return "Orders updated"
end
# {/fact}

# Good case 13: Using the Sequel DSL for limit
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_13
  limit_val = params[:limit].to_i
  # Validate limit to prevent abuse
  limit_val = [limit_val, 100].min if limit_val > 0
  # ok: ruby-sql-injection-sequel
  users = DB[:users].limit(limit_val).all
  return users.to_json
end
# {/fact}

# Good case 14: Using the Sequel DSL for pagination
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_14
  page = params[:page].to_i
  page_size = params[:page_size].to_i
  # Validate pagination parameters
  page = 1 if page < 1
  page_size = [page_size, 50].min if page_size > 0
  # ok: ruby-sql-injection-sequel
  products = DB[:products].limit(page_size, (page - 1) * page_size).all
  return products.to_json
end
# {/fact}

# Good case 15: Using the Sequel DSL for subqueries
# {fact rule=cross-site-scripting@v1.0 defects=0}
def good_case_15
  department = request.params['department']
  # ok: ruby-sql-injection-sequel
  employees = DB[:employees].where(department_id: DB[:departments].where(name: department).select(:id)).all
  return employees.to_json
end
# {/fact}