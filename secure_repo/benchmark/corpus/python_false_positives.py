# expect-none: SR-PY-001, SR-PY-002, SR-PY-003, SR-PY-004, SR-PY-005, SR-PY-009, SR-PY-011, SR-SEC-019
import os
import random
import subprocess

import yaml
from sqlalchemy import text


def documentation():
    """Never call eval(user_input) or pickle.loads(untrusted) in this module.

    os.system(command) with user input is forbidden as well.
    """
    message = "do not use os.system(command) or subprocess.call(cmd, shell=True)"
    return message


def safe_calls(user_id: int):
    subprocess.run(["git", "status"], check=True)
    os.system("clear")
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    session.execute(text("SELECT 1"))
    config = yaml.safe_load(open("config.yml"))
    data = yaml.load(open("other.yml"), Loader=yaml.SafeLoader)
    retry_delay = random.uniform(0.5, 1.5)
    sample = random.sample(range(10), 3)
    value = eval("1 + 2")
    return config, data, retry_delay, sample, value


def placeholders():
    password = "changeme"
    api_key = os.environ["API_KEY"]
    token_url = "https://auth.example.com/token"
    secret_name = "prod/db/password"
    return password, api_key, token_url, secret_name

# eval(request.args["x"])   <- commented-out code is not code
