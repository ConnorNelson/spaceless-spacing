#!/usr/bin/env python

import os
import time

from flask import Flask

app = Flask(__name__)

SECRET = os.environ["SECRET"]
assert " " not in SECRET

PLANCK_TIME = 5.391247 * 10 ** -44


@app.route("/")
def index():
    with open(__file__) as f:
        return f.read()


@app.route("/<secret>")
def check_secret(secret):
    if len(secret) != len(SECRET):
        return "SPACELESS SPACING!"
    for a, b in zip(secret, SECRET):
        if a == " ":
            continue
        elif a != b:
            return "INCORRECT!"
        else:
            time.sleep(PLANCK_TIME)
    if " " in secret:
        return "INCORRECT!"
    return "CORRECT!"
