
import urllib
from django.db.models import Q
from django.auth import User
from django.http import HttpResponse, HttpResponseBadRequest
from django.utils.translation import ugettext as _

from org import engines, manageNoEngine, genericApiException

import html
import re
from flask import Flask, request, render_template_string, Response, make_response, render_template
from django.http import HttpResponse
from django.utils.html import escape as django_escape
from markupsafe import Markup, escape as markupsafe_escape
import bleach
from werkzeug.utils import escape as werkzeug_escape
from fastapi import FastAPI, Query
from starlette.responses import HTMLResponse

app = Flask(__name__)
django_app = FastAPI()

# True Positive Examples (Vulnerable Code)

def bad_case_1():
    # Direct insertion of user input into HTML response
    user_input = request.args.get('name', '')
    # ruleid: python-cross-site-scripting-ide
    return f"<div>Hello, {user_input}!</div>"

def bad_case_2():
    # Using Flask's render_template_string with unescaped user input
    user_input = request.form.get('comment', '')
    template = f"<p>Your comment: {user_input}</p>"
    # ruleid: python-cross-site-scripting-ide
    return render_template_string(template)

def bad_case_3():
    # Using Django's HttpResponse with unescaped user input
    user_input = request.GET.get('search', '')
    # ruleid: python-cross-site-scripting-ide
    return HttpResponse(f"<div>Search results for: {user_input}</div>")

def bad_case_4():
    # Using Flask with Markup to explicitly mark as safe (bypassing escaping)
    user_input = request.args.get('content', '')
    # ruleid: python-cross-site-scripting-ide
    return f"<div>{Markup(user_input)}</div>"

def bad_case_5():
    # Using string concatenation with user input
    username = request.cookies.get('username', '')
    html_content = "<div>Welcome back, " + username + "!</div>"
    # ruleid: python-cross-site-scripting-ide
    return html_content