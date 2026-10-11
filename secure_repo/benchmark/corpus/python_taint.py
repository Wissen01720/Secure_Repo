import os
import pickle
import subprocess

import yaml
from flask import Flask, redirect, render_template_string, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    command = "ping -c 1 " + host
    subprocess.call(command, shell=True)  # expect: SR-PY-004
    os.system("echo " + host)  # expect: SR-PY-005
    return "ok"


@app.route("/user/<name>")
def user(name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    cursor.execute(query)  # expect: SR-PY-011
    return f"<h1>Hello {name}</h1>"  # expect: SR-PY-024


@app.route("/calc", methods=["POST"])
def calc():
    expression = request.form["expr"]
    return str(eval(expression))  # expect: SR-PY-001


@app.route("/go")
def go():
    return redirect(request.args["next"])  # expect: SR-PY-023


@app.route("/render")
def render():
    template = request.args.get("t", "")
    return render_template_string(template)  # expect: SR-PY-022


@app.route("/file")
def read_file():
    path = request.args["path"]
    with open(path) as handle:  # expect: SR-PY-018
        return handle.read()


def load_blob(blob):
    return pickle.loads(blob)  # expect: SR-PY-002


def load_config(path):
    return yaml.load(open(path))  # expect: SR-PY-003


def make_reset_token():
    import random
    reset_token = random.randint(100000, 999999)  # expect: SR-PY-009
    return reset_token
