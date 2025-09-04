from flask import *
import re
app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <link href="https://fonts.googleapis.com/css2?family=VT323&family=IBM+Plex+Mono:wght@400&display=swap" rel="stylesheet">
    <title>SSTI LAB</title>
    <style>
      body {
        background-color: black; 
        background: url("https://media3.giphy.com/media/v1.Y2lkPTc5MGI3NjExeDg1eGlvYXlyaTU4dWxmbnhhejJmNXF5bWhscHhrcHV6aWpyazI0aSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/WoD6JZnwap6s8/giphy.gif")
          repeat;
        background-size: 400px 400px;
        color: #00ff00;
        font-family: "VT323", "IBM Plex Mono", monospace;
        text-align: center;
        padding-top: 50px;
      }

      h1 {
        font-size: 40px;
        text-shadow: 0 0 10px #00ff00;
      }

      form {
        margin-top: 20px;
      }

      input[type="text"] {
        background-color: black;
        border: 2px solid #00ff00;
        color: #00ff00;
        padding: 15px;
        font-size: 24px;
        width: 350px;
        font-family: "VT323", monospace;
      }

      input:focus {
        outline: none;
        box-shadow: none;
      }

      input[type="submit"] {
        background-color: black;
        border: 2px solid #00ff00;
        color: #00ff00;
        padding: 15px 25px;
        font-size: 24px;
        cursor: pointer;
        font-family: "VT323", monospace;
        margin-top: 10px;
      }

      input[type="submit"]:hover {
        background-color: #00ff00;
        color: black;
      }

      p {
        margin-top: 20px;
        font-size: 32px;
        text-shadow: 0 0 8px #00ff00;
      }
    </style>
  </head>
  <body>
    <h1>Can u exploit SSTI?</h1>
    <form action="/endpoint" method="post">
      <input type="text" name="name" placeholder="Enter your name..."  autocomplete="off"/>
      <input type="submit" value="Submit" />
    </form>
    <p>{{name}}</p>
  </body>
</html>

"""

HOME_TEMPLATE =  """
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <link href="https://fonts.googleapis.com/css2?family=VT323&family=IBM+Plex+Mono:wght@400&display=swap" rel="stylesheet">
        <title>SSTI Challenge Hub</title>
        <style>
          body {
            background-color: black; 
            background: url("https://media3.giphy.com/media/v1.Y2lkPTc5MGI3NjExeDg1eGlvYXlyaTU4dWxmbnhhejJmNXF5bWhscHhrcHV6aWpyazI0aSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/WoD6JZnwap6s8/giphy.gif")
              repeat;
            background-size: 400px 400px;
            color: #00ff00;
            font-family: "VT323", "IBM Plex Mono", monospace;
            text-align: center;
            padding-top: 50px;
          }

          h1 {
            font-size: 40px;
            text-shadow: 0 0 10px #00ff00;
          }

          .challenge-links {
            margin-top: 30px;
          }

          a {
            display: block;
            font-size: 28px;
            color: #00ff00;
            text-decoration: none;
            padding: 10px;
            border: 2px solid #00ff00;
            margin: 10px auto;
            width: 200px;
            transition: 0.3s;
          }

          a:hover {
            background-color: #00ff00;
            color: black;
          }
        </style>
      </head>
      <body>
        <h1>SSTI Challenges</h1>
        <div class="challenge-links">
          <a href="/level1">Level 1</a>
          <a href="/level2">Level 2</a>
          <a href="/level3">Level 3</a>
        </div>
      </body>
    </html>
"""

@app.route("/")
def index():
  return render_template_string(HOME_TEMPLATE)

@app.route("/level1" , methods=["GET", "POST"])
def level1():
  level1_template = TEMPLATE.replace("/endpoint" , "/level1")
  if request.method == "GET":
    return render_template_string(level1_template)
  name = request.form.get("name" , "")
  vulnerable_template = level1_template.replace("{{name}}" , name)

  return render_template_string(vulnerable_template)


@app.route("/level2" , methods=["GET", "POST"])
def level2():
  level2_template = TEMPLATE.replace("/endpoint", "/level2")

  if request.method == "GET":
    return render_template_string(level2_template)
  
  name = request.form.get("name" , "")

  blocked_words = [
        "request", "self", "class", "__", "mro", "base", "globals", "builtins",
        "os", "subprocess", "eval", "exec", "import", "sys", "join", "format",
        "getattr", "setattr", "compile", "execfile", "open", "read", "write"
    ]
    
  if "()" in name:
    return render_template_string(level2_template.replace("{{name}}", "Malicious input detected"))

  for word in blocked_words:
    if re.search(rf"\b{word}\b", name):
      return render_template_string(level2_template.replace("{{name}}", "Malicious input detected"))

  return render_template_string(level2_template.replace("{{name}}" , name))



@app.route("/level3" , methods=["GET","POST"])
def level3():
  level3_template = TEMPLATE.replace("/endpoint", "/level3")

  if request.method == "GET": 
    return render_template_string(level3_template)
  
  name = request.form.get("name" , "")
  if re.search(r"\{\{|\}\}", name):
    return render_template_string(level3_template.replace("{{name}}", "Malicious input detected"))
  
  return render_template_string(level3_template.replace("{{name}}", name))

  


if __name__ == "__main__":
  app.secret_key = 'super secret key'
  app.run(host="0.0.0.0", port=8080, debug=True)