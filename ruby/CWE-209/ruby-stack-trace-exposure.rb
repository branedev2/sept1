require 'sinatra'
require 'rack'
require 'rails'
require 'json'

# True Positive Examples (Vulnerable Code)

# Example 1: Directly exposing exception details in Sinatra
# {fact rule=stack-trace-exposure@v1.0 defects=1}
def bad_case_1
  begin
    # Some code that might raise an exception
    result = 10 / 0
    "Result: #{result}"
  rescue => e
    # ruleid: ruby-stack-trace-exposure
    return e.backtrace.join("\n")
  end
end
# {/fact}

# Example 2: Exposing exception in Rails controller
# {fact rule=stack-trace-exposure@v1.0 defects=1}
def bad_case_2
  begin
    # Some operation that might fail
    user = User.find(params[:id])
    render json: user
  rescue ActiveRecord::RecordNotFound => e
    # ruleid: ruby-stack-trace-exposure
    render json: { error: e.message, backtrace: e.backtrace }
  end
end
# {/fact}

# Example 3: Logging to response in Rack application
# {fact rule=stack-trace-exposure@v1.0 defects=1}
def bad_case_3
  begin
    # Process some data
    data = JSON.parse(request.body.read)
    [200, {'Content-Type' => 'application/json'}, [data.to_json]]
  rescue JSON::ParserError => e
    # ruleid: ruby-stack-trace-exposure
    [500, {'Content-Type' => 'text/plain'}, [e.full_message]]
  end
end
# {/fact}

# Example 4: Exposing stack trace in API error response
# {fact rule=stack-trace-exposure@v1.0 defects=1}
def bad_case_4
  begin
    # API operation
    response = some_api_call(params[:query])
    { status: 'success', data: response }
  rescue => e
    # ruleid: ruby-stack-trace-exposure
    { status: 'error', message: e.message, debug_info: e.backtrace }
  end
end
# {/fact}

# Example 5: Directly rendering exception in view
# {fact rule=stack-trace-exposure@v1.0 defects=1}
def bad_case_5
  begin
    # Database operation
    records = Database.query(params[:query])
    render :index, locals: { records: records }
  rescue => e
    # ruleid: ruby-stack-trace-exposure
    render inline: "<h1>Error</h1><pre>#{e.backtrace.join('<br>')}</pre>"
  end
end
# {/fact}

# Example 6: Exposing exception in JSON API
# {fact rule=stack-trace-exposure@v1.0 defects=1}
def bad_case_6
  begin
    # Process request
    result = process_data(params[:data])
    render json: { success: true, result: result }
  rescue => e
    # ruleid: ruby-stack-trace-exposure
    render json: { 
      success: false, 
      error: e.message,
      stack: e.backtrace.first(10)
    }
  end
end
# {/fact}

# Example 7: Exposing stack trace in HTML comment
# {fact rule=stack-trace-exposure@v1.0 defects=1}
def bad_case_7
  begin
    # Some operation
    calculate_result(params[:input])
  rescue => e
    # ruleid: ruby-stack-trace-exposure
    response.body = "An error occurred. <!-- Debug info: #{e.backtrace.join('\n')} -->"
  end
end
# {/fact}

# Example 8: Exposing exception details in XML response
# {fact rule=stack-trace-exposure@v1.0 defects=1}
def bad_case_8
  begin
    # XML processing
    doc = process_xml_document(request.body.read)
    render xml: doc
  rescue => e
    # ruleid: ruby-stack-trace-exposure
    render xml: { error: { message: e.message, stack_trace: e.backtrace } }
  end
end
# {/fact}

# Example 9: Exposing exception in custom error page
# {fact rule=stack-trace-exposure@v1.0 defects=1}
def bad_case_9
  begin
    # Some operation
    result = complex_calculation(params[:values])
    render json: result
  rescue => e
    # ruleid: ruby-stack-trace-exposure
    render html: <<~HTML
      <html>
        <body>
          <h1>Error occurred</h1>
          <div class="error-details">
            <p>#{e.message}</p>
            <pre>#{e.backtrace.join("\n")}</pre>
          </div>
        </body>
      </html>
    HTML
  end
end
# {/fact}

# Example 10: Exposing stack trace in text response
# {fact rule=stack-trace-exposure@v1.0 defects=1}
def bad_case_10
  begin
    # File operation
    content = File.read(params[:filename])
    [200, {'Content-Type' => 'text/plain'}, [content]]
  rescue => e
    # ruleid: ruby-stack-trace-exposure
    [500, {'Content-Type' => 'text/plain'}, ["Error details:\n#{e.class}: #{e.message}\n#{e.backtrace.join("\n")}"]]
  end
end
# {/fact}

# Example 11: Exposing exception in debug mode
# {fact rule=stack-trace-exposure@v1.0 defects=1}
def bad_case_11
  begin
    # Some operation
    result = calculate_statistics(params[:dataset])
    { status: 'ok', data: result }
  rescue => e
    if params[:debug] == 'true'
      # ruleid: ruby-stack-trace-exposure
      { status: 'error', debug: { message: e.message, trace: e.backtrace } }
    else
      { status: 'error', message: 'An error occurred' }
    end
  end
end
# {/fact}

# Example 12: Exposing stack trace in development environment
# {fact rule=stack-trace-exposure@v1.0 defects=1}
def bad_case_12
  begin
    # Database query
    results = db.execute(params[:query])
    render json: results
  rescue => e
    if Rails.env.development?
      # ruleid: ruby-stack-trace-exposure
      render plain: "Development Error:\n#{e.full_message}"
    else
      render plain: "An error occurred"
    end
  end
end
# {/fact}

# Example 13: Exposing exception in webhook response
# {fact rule=stack-trace-exposure@v1.0 defects=1}
def bad_case_13
  begin
    # Process webhook
    payload = JSON.parse(request.body.read)
    process_webhook(payload)
    [200, {'Content-Type' => 'application/json'}, [{ success: true }.to_json]]
  rescue => e
    # ruleid: ruby-stack-trace-exposure
    [500, {'Content-Type' => 'application/json'}, [{ 
      success: false, 
      error: e.message,
      trace: e.backtrace 
    }.to_json]]
  end
end
# {/fact}

# Example 14: Exposing exception in error log sent to client
# {fact rule=stack-trace-exposure@v1.0 defects=1}
def bad_case_14
  begin
    # Process form data
    process_form(params[:form_data])
    redirect_to success_path
  rescue => e
    error_log = "Error processing form:\n#{e.message}\n#{e.backtrace.join("\n")}"
    # ruleid: ruby-stack-trace-exposure
    render plain: "Error occurred. Please send this to support:\n#{error_log}"
  end
end
# {/fact}

# Example 15: Exposing exception in API debug endpoint
# {fact rule=stack-trace-exposure@v1.0 defects=1}
def bad_case_15
  if params[:action] == 'debug_last_error'
    begin
      raise @last_error if @last_error
      "No errors recorded"
    rescue => e
      # ruleid: ruby-stack-trace-exposure
      "Last error: #{e.class.name}\n#{e.message}\n#{e.backtrace.join("\n")}"
    end
  else
    begin
      # Normal operation
      result = perform_operation(params[:input])
      "Operation completed: #{result}"
    rescue => e
      @last_error = e
      "An error occurred"
    end
  end
end
# {/fact}

# True Negative Examples (Secure Code)

# Example 1: Proper error handling in Sinatra
# {fact rule=stack-trace-exposure@v1.0 defects=0}
def good_case_1
  begin
    # Some code that might raise an exception
    result = 10 / 0
    "Result: #{result}"
  rescue => e
    # ok: ruby-stack-trace-exposure
    logger.error("Error occurred: #{e.message}\n#{e.backtrace.join("\n")}")
    return "An error occurred. Please contact support."
  end
end
# {/fact}

# Example 2: Secure exception handling in Rails controller
# {fact rule=stack-trace-exposure@v1.0 defects=0}
def good_case_2
  begin
    # Some operation that might fail
    user = User.find(params[:id])
    render json: user
  rescue ActiveRecord::RecordNotFound => e
    # ok: ruby-stack-trace-exposure
    logger.error("Record not found: #{e.message}\n#{e.backtrace.join("\n")}")
    render json: { error: "User not found" }, status: :not_found
  end
end
# {/fact}

# Example 3: Proper error handling in Rack application
# {fact rule=stack-trace-exposure@v1.0 defects=0}
def good_case_3
  begin
    # Process some data
    data = JSON.parse(request.body.read)
    [200, {'Content-Type' => 'application/json'}, [data.to_json]]
  rescue JSON::ParserError => e
    # Log the full error internally
    logger.error("JSON parse error: #{e.message}\n#{e.backtrace.join("\n")}")
    # ok: ruby-stack-trace-exposure
    [400, {'Content-Type' => 'application/json'}, [{ error: "Invalid JSON format" }.to_json]]
  end
end
# {/fact}

# Example 4: Secure API error response
# {fact rule=stack-trace-exposure@v1.0 defects=0}
def good_case_4
  begin
    # API operation
    response = some_api_call(params[:query])
    { status: 'success', data: response }
  rescue => e
    # Log the error with stack trace
    Rails.logger.error("API error: #{e.message}\n#{e.backtrace.join("\n")}")
    # ok: ruby-stack-trace-exposure
    { status: 'error', message: "An error occurred processing your request" }
  end
end
# {/fact}

# Example 5: Secure error rendering in view
# {fact rule=stack-trace-exposure@v1.0 defects=0}
def good_case_5
  begin
    # Database operation
    records = Database.query(params[:query])
    render :index, locals: { records: records }
  rescue => e
    # Log the error with details
    logger.error("Database query error: #{e.message}\n#{e.backtrace.join("\n")}")
    # ok: ruby-stack-trace-exposure
    render :error, locals: { message: "We couldn't process your request" }
  end
end
# {/fact}

# Example 6: Secure JSON API error handling
# {fact rule=stack-trace-exposure@v1.0 defects=0}
def good_case_6
  begin
    # Process request
    result = process_data(params[:data])
    render json: { success: true, result: result }
  rescue => e
    # Log the full error
    Rails.logger.error("Data processing error: #{e.full_message}")
    # ok: ruby-stack-trace-exposure
    render json: { 
      success: false, 
      error: "An error occurred while processing your data"
    }, status: :internal_server_error
  end
end
# {/fact}

# Example 7: Secure error handling with error codes
# {fact rule=stack-trace-exposure@v1.0 defects=0}
def good_case_7
  begin
    # Some operation
    calculate_result(params[:input])
  rescue ArgumentError => e
    logger.error("Calculation error: #{e.message}\n#{e.backtrace.join("\n")}")
    # ok: ruby-stack-trace-exposure
    response.body = "Invalid input parameters (Error code: E1001)"
  rescue => e
    logger.error("Unexpected error: #{e.message}\n#{e.backtrace.join("\n")}")
    # ok: ruby-stack-trace-exposure
    response.body = "An unexpected error occurred (Error code: E9999)"
  end
end
# {/fact}

# Example 8: Secure XML error response
# {fact rule=stack-trace-exposure@v1.0 defects=0}
def good_case_8
  begin
    # XML processing
    doc = process_xml_document(request.body.read)
    render xml: doc
  rescue => e
    # Log the full error details
    logger.error("XML processing error: #{e.message}\n#{e.backtrace.join("\n")}")
    # ok: ruby-stack-trace-exposure
    render xml: { error: { code: "XML_PROCESSING_ERROR", message: "Could not process XML document" } }
  end
end
# {/fact}

# Example 9: Secure custom error page
# {fact rule=stack-trace-exposure@v1.0 defects=0}
def good_case_9
  begin
    # Some operation
    result = complex_calculation(params[:values])
    render json: result
  rescue => e
    # Log the error with stack trace
    Rails.logger.error("Calculation error: #{e.message}\n#{e.backtrace.join("\n")}")
    # ok: ruby-stack-trace-exposure
    render html: <<~HTML
      <html>
        <body>
          <h1>Error occurred</h1>
          <div class="error-details">
            <p>We couldn't complete your calculation. Please check your input values.</p>
            <p>Reference ID: #{SecureRandom.hex(8)}</p>
          </div>
        </body>
      </html>
    HTML
  end
end
# {/fact}

# Example 10: Secure text response with error reference
# {fact rule=stack-trace-exposure@v1.0 defects=0}
def good_case_10
  begin
    # File operation
    content = File.read(params[:filename])
    [200, {'Content-Type' => 'text/plain'}, [content]]
  rescue => e
    error_id = SecureRandom.uuid
    logger.error("File read error [#{error_id}]: #{e.message}\n#{e.backtrace.join("\n")}")
    # ok: ruby-stack-trace-exposure
    [500, {'Content-Type' => 'text/plain'}, ["Error reading file. Reference ID: #{error_id}"]]
  end
end
# {/fact}

# Example 11: Secure debug mode handling
# {fact rule=stack-trace-exposure@v1.0 defects=0}
def good_case_11
  begin
    # Some operation
    result = calculate_statistics(params[:dataset])
    { status: 'ok', data: result }
  rescue => e
    error_id = "ERR-#{Time.now.to_i}"
    logger.error("#{error_id}: #{e.message}\n#{e.backtrace.join("\n")}")
    
    if params[:debug] == 'true' && authorized_admin?
      # ok: ruby-stack-trace-exposure
      { status: 'error', message: "Error calculating statistics", error_id: error_id }
    else
      { status: 'error', message: "An error occurred" }
    end
  end
end
# {/fact}

# Example 12: Secure development environment handling
# {fact rule=stack-trace-exposure@v1.0 defects=0}
def good_case_12
  begin
    # Database query
    results = db.execute(params[:query])
    render json: results
  rescue => e
    logger.error("Database error: #{e.message}\n#{e.backtrace.join("\n")}")
    
    if Rails.env.development?
      # ok: ruby-stack-trace-exposure
      render plain: "Database query error. Check server logs for details."
    else
      render plain: "An error occurred"
    end
  end
end
# {/fact}

# Example 13: Secure webhook error response
# {fact rule=stack-trace-exposure@v1.0 defects=0}
def good_case_13
  begin
    # Process webhook
    payload = JSON.parse(request.body.read)
    process_webhook(payload)
    [200, {'Content-Type' => 'application/json'}, [{ success: true }.to_json]]
  rescue => e
    logger.error("Webhook processing error: #{e.message}\n#{e.backtrace.join("\n")}")
    # ok: ruby-stack-trace-exposure
    [500, {'Content-Type' => 'application/json'}, [{ 
      success: false, 
      error: "Failed to process webhook",
      error_code: "WEBHOOK_PROCESSING_ERROR"
    }.to_json]]
  end
end
# {/fact}

# Example 14: Secure error reporting to client
# {fact rule=stack-trace-exposure@v1.0 defects=0}
def good_case_14
  begin
    # Process form data
    process_form(params[:form_data])
    redirect_to success_path
  rescue => e
    error_id = "FORM-#{SecureRandom.hex(6)}"
    logger.error("Form processing error [#{error_id}]: #{e.message}\n#{e.backtrace.join("\n")}")
    # ok: ruby-stack-trace-exposure
    render plain: "Error processing form. Please contact support with this reference: #{error_id}"
  end
end
# {/fact}

# Example 15: Secure API debug endpoint
# {fact rule=stack-trace-exposure@v1.0 defects=0}
def good_case_15
  if params[:action] == 'debug_last_error' && current_user.admin?
    if @last_error_id
      # ok: ruby-stack-trace-exposure
      "Last error ID: #{@last_error_id}. Check logs for details."
    else
      "No errors recorded"
    end
  else
    begin
      # Normal operation
      result = perform_operation(params[:input])
      "Operation completed: #{result}"
    rescue => e
      @last_error_id = "ERR-#{Time.now.to_i}"
      logger.error("#{@last_error_id}: #{e.message}\n#{e.backtrace.join("\n")}")
      "An error occurred. Reference: #{@last_error_id}"
    end
  end
end
# {/fact}