from __future__ import print_function
from os import popen, environ
from flask import Flask, request, Response, jsonify, redirect
from flasgger import Swagger
from types import SimpleNamespace as Namespace
import json

try:
    import creds as creds
except:
    print("not using creds.py (not existing)")

# Get ip from env or creds file
try:
    ip = creds.ip
except Exception as e:
    ip = environ["IP"]

# Get token from env or creds file
try:
    token = creds.token
except Exception as e:
    token = environ["TOKEN"]

supportedCommandsList = popen("miiocli dreamevacuum --help").read()
print(supportedCommandsList)

supportedCommands = []
for cmd_description_pair in supportedCommandsList.split("Commands:\n")[1].split("\n"):
    cmd = cmd_description_pair.strip().partition(" ")[0]
    if cmd != "":
        supportedCommands.append(cmd)

# TODO: fix about:blank link in url:
template = {
    "securityDefinitions": {"Bearer": {"type": "apiKey", "name": "Authorization", "in": "header"}},
    "swagger": "2.0",
    "info": {
        "title": "Xiaomi vacuum control API",
        "description": "API to control Xiaomi robot vacuums via http requests.",
        "contact": {
            "name": "DoganM95",
            "url": "github.com/DoganM95",
        },
        "license": {"name": "Apache 2.0", "url": "https://www.apache.org/licenses/LICENSE-2.0.html"},
        "version": "0.0.1",
    },
    "schemes": ["http", "https"],
    "consumes": [
        "application/json",
    ],
    "produces": [
        "application/json",
    ],
}

app = Flask(__name__)
swagger = Swagger(app, template=template)


@app.route("/")
def redirectRootToDocs():
    return redirect("/apidocs", code=302)


@app.before_request
def commonRoutine():
    for command in supportedCommands:
        if request.path.find(command) != -1:

            # 401
            try:
                request.headers["Authorization"]
            except:
                return Response(response="No token was entered", status=401, mimetype="text/plain")
            if request.headers["Authorization"] != creds.token:
                return Response(response="Invalid Token", status=401, mimetype="text/plain")
            break


# TODO
@app.route("/call_action/", methods=["POST"])
def action(call_action):
    """Call an action by a name in the mapping
    This is using docstrings for specifications.
    ---
    deprecated: true
    parameters:
      - name: action
        in: path
        type: string
        required: true
        default: some_command
    definitions:
      action:
        type: string
        properties:
          action_name:
            type: array
            items:
              $ref: '#/definitions/Color'
      Color:
        type: string
    responses:
        '200':
          description: A JSON array of user names
          content:
            application/json:
              schema:
                type: array
                items:
                  type: string
    """
    all_colors = {"cmyk": ["cyan", "magenta", "yellow", "black"], "rgb": ["red", "green", "blue"]}
    if action == "all":
        result = all_colors
    else:
        result = {action: all_colors.get(action)}

    return jsonify(result)


# TODO
@app.route("/call_action_by/")
def call_action_by(action):
    """Call an action
    This is using docstrings for specifications.
    ---
    deprecated: true
    parameters:
      - name: action
        in: path
        type: string
        required: true
        default: something
    definitions:
      action:
        type: object
        properties:
          action_name:
            type: array
            items:
              $ref: '#/definitions/Color'
      Color:
        type: string
    responses:
      200:
        description: A list of colors (may be filtered by action)
        schema:
          $ref: '#/definitions/action'
        examples:
          rgb: ['red', 'green', 'blue']
      400:
        description: A list of colors (may be filtered by action)
        schema:
          $ref: '#/definitions/action'
        examples:
          rgb: ['red', 'green', 'blue']
    """
    all_colors = {"cmyk": ["cyan", "magenta", "yellow", "black"], "rgb": ["red", "green", "blue"]}
    if action == "all":
        result = all_colors
    else:
        result = {action: all_colors.get(action)}

    return jsonify(result)


# Not supported by my vacuum
@app.get("/fan_speed/")
def fan_speed(action):
    """Return fan speed
    This is using docstrings for specifications.
    ---
    deprecated: true
    """


@app.get("/fan_speed_presets/")
def get_fan_speed_presets():
    """Return dictionary containing supported fan speeds
    This is using docstrings for specifications.
    ---
    definitions:
      fan_speeds:
        type: object
        properties:
          Quiet:
            type: integer
          Default:
            type: integer
          Medium:
            type: integer
          Strong:
            type: integer
      bad_request:
        type:
    security:
      - Bearer: []
    responses:
      200:
        description: OK
        schema:
          $ref: '#/definitions/fan_speeds'
      400:
        description: Bad Request
      401:
        description: Unauthorized
    """
    consoleOutput = (
        popen("miiocli dreamevacuum --ip " + creds.ip + " --token " + creds.token + " fan_speed_presets")
        .read()
        .strip()
        .rstrip("\n")
    )

    # 400
    if consoleOutput.find("Error") != -1:
        return Response(response=consoleOutput.rstrip("\n"), status=400, mimetype="text/plain")

    # 200
    result = consoleOutput.partition("fan_speed_presets")[2]
    if result.find("{") != -1:
        return Response(response=result.replace("'", '"'), status=200, mimetype="application/json")


@app.post("/forward/")
def post_forward():
    """Move forward
    This is using docstrings for specifications.
    ---
    definitions:
      forward:
        type: object
        properties:
          move:
            type: string
    security:
      - Bearer: []
    responses:
      200:
        description: OK
        schema:
          $ref: '#/definitions/forward'
      400:
        description: Bad Request
      401:
        description: Unauthorized
    """
    consoleOutput = (
        popen("miiocli dreamevacuum --ip " + creds.ip + " --token " + creds.token + " forward")
        .read()
        .strip()
        .rstrip("\n")
    )

    # 400
    if consoleOutput.find("Error") != -1:
        return Response(response=consoleOutput.rstrip("\n"), status=400, mimetype="text/plain")

    # 200
    result = consoleOutput.partition("forward")[2]
    if result.find("None") != -1:
        return Response(response='{"move":"forward"}', status=200, mimetype="application/json")


# TODO
@app.route("/get_property_by/")
def get_property_by(action):
    """Get a single property (siid/piid)
    This is using docstrings for specifications.
    ---
    deprecated: true
    parameters:
      - name: action
        in: path
        type: string
        required: true
        default: something
    definitions:
      action:
        type: object
        properties:
          action_name:
            type: array
            items:
              $ref: '#/definitions/Color'
      Color:
        type: string
    responses:
      200:
        description: A list of colors (may be filtered by action)
        schema:
          $ref: '#/definitions/action'
        examples:
          rgb: ['red', 'green', 'blue']
      400:
        description: A list of colors (may be filtered by action)
        schema:
          $ref: '#/definitions/action'
        examples:
          rgb: ['red', 'green', 'blue']
    """
    all_colors = {"cmyk": ["cyan", "magenta", "yellow", "black"], "rgb": ["red", "green", "blue"]}
    if action == "all":
        result = all_colors
    else:
        result = {action: all_colors.get(action)}

    return jsonify(result)


@app.post("/home/")
def home():
    """Return to home
    This is using docstrings for specifications.
    ---
    definitions:
      home:
        type: object
        properties:
          did:
            type: string
          siid:
            type: integer
          aiid:
            type: integer
          code:
            type: integer
          out:
            type: array
            items: {}
    security:
      - Bearer: []
    responses:
      200:
        description: OK
        schema:
          $ref: '#/definitions/home'
      400:
        description: Bad Request
      401:
        description: Unauthorized
    """
    consoleOutput = (
        popen("miiocli dreamevacuum --ip " + creds.ip + " --token " + creds.token + " home").read().strip().rstrip("\n")
    )

    # 400
    if consoleOutput.find("Error") != -1:
        return Response(response=consoleOutput.rstrip("\n"), status=400, mimetype="text/plain")

    # 200
    result = consoleOutput.partition("\n")[2]
    print(result)
    if result.find("{'did'") != -1:
        return Response(response=result.replace("'", '"'), status=200, mimetype="application/json")


@app.post("/identify/")
def identify():
    """Locate the device (i am here)
    This is using docstrings for specifications.
    ---
    definitions:
      identify:
        type: object
        properties:
          did:
            type: string
          siid:
            type: integer
          aiid:
            type: integer
          code:
            type: integer
          out:
            type: array
            items: {}
    security:
      - Bearer: []
    responses:
      200:
        description: OK
        schema:
          $ref: '#/definitions/identify'
      400:
        description: Bad Request
      401:
        description: Unauthorized
    """
    consoleOutput = (
        popen("miiocli dreamevacuum --ip " + creds.ip + " --token " + creds.token + " identify")
        .read()
        .strip()
        .rstrip("\n")
    )

    # 400
    if consoleOutput.find("Error") != -1:
        return Response(response=consoleOutput.rstrip("\n"), status=400, mimetype="text/plain")

    # 200
    result = consoleOutput.partition("\n")[2]
    print(result)
    if result.find("{'did'") != -1:
        return Response(response=result.replace("'", '"'), status=200, mimetype="application/json")


@app.get("/info/")
def info():
    """Get (and cache) miIO protocol information from...
    This is using docstrings for specifications.
    ---
    definitions:
      info:
        type: object
        properties:
          Model:
            type: string
          Hardware version:
            type: string
          Software version:
            type: string
    security:
      - Bearer: []
    responses:
      200:
        description: OK
        schema:
          $ref: '#/definitions/info'
      400:
        description: Bad Request
      401:
        description: Unauthorized
    """
    consoleOutput = (
        popen("miiocli dreamevacuum --ip " + creds.ip + " --token " + creds.token + " info").read().strip().rstrip("\n")
    )

    # 400
    if consoleOutput.find("Error") != -1:
        return Response(response=consoleOutput.rstrip("\n"), status=400, mimetype="text/plain")

    # 200
    if consoleOutput.find("Model:") != -1:
        rawResultList = consoleOutput.split("\n")  # In case more info gets added some time
        resultList = []
        for line in rawResultList:
            keySeperatorValue = line.partition(": ")
            resultList.append(
                '"' + keySeperatorValue[0] + '"' + keySeperatorValue[1] + '"' + keySeperatorValue[2] + '"'
            )

        resultJson = "{"
        for line in resultList:
            resultJson += line + ","
        resultJson = resultJson.rstrip(",")
        resultJson += "}"

        return Response(response=resultJson, status=200, mimetype="application/json")


@app.post("/play_sound/")
def play_sound():
    """Play sound
    This is using docstrings for specifications.
    ---
    definitions:
      play_sound:
        type: object
        properties:
          did:
            type: string
          siid:
            type: integer
          aiid:
            type: integer
          code:
            type: integer
          out:
            type: array
            items: {}
    security:
      - Bearer: []
    responses:
      200:
        description: OK
        schema:
          $ref: '#/definitions/play_sound'
      400:
        description: Bad Request
      401:
        description: Unauthorized
    """
    consoleOutput = (
        popen("miiocli dreamevacuum --ip " + creds.ip + " --token " + creds.token + " play_sound")
        .read()
        .strip()
        .rstrip("\n")
    )

    # 400
    if consoleOutput.find("Error") != -1:
        return Response(response=consoleOutput.rstrip("\n"), status=400, mimetype="text/plain")

    # 200
    result = consoleOutput.partition("\n")[2]
    print(result)
    if result.find("{'did'") != -1:
        return Response(response=result.replace("'", '"'), status=200, mimetype="application/json")


# TODO
@app.route("/raw_command/")
def raw_command(action):
    """Send a raw command to the device
    This is using docstrings for specifications.
    ---
    deprecated: true
    parameters:
      - name: action
        in: path
        type: string
        required: true
        default: something
    definitions:
      action:
        type: object
        properties:
          action_name:
            type: array
            items:
              $ref: '#/definitions/Color'
      Color:
        type: string
    responses:
      200:
        description: A list of colors (may be filtered by action)
        schema:
          $ref: '#/definitions/action'
        examples:
          rgb: ['red', 'green', 'blue']
      400:
        description: A list of colors (may be filtered by action)
        schema:
          $ref: '#/definitions/action'
        examples:
          rgb: ['red', 'green', 'blue']
    """
    all_colors = {"cmyk": ["cyan", "magenta", "yellow", "black"], "rgb": ["red", "green", "blue"]}
    if action == "all":
        result = all_colors
    else:
        result = {action: all_colors.get(action)}

    return jsonify(result)


# won't implement, as i cannot test it without actually resetting
@app.route("/reset_filter_life/")
def reset_filter_life(action):
    """Reset filter life
    This is using docstrings for specifications.
    ---
    deprecated: true
    """


# won't implement, as i cannot test it without actually resetting
@app.route("/reset_mainbrush_life/")
def reset_mainbrush_life(action):
    """Reset main brush life
    This is using docstrings for specifications.
    ---
    deprecated: true
    """


# won't implement, as i cannot test it without actually resetting
@app.route("/reset_sidebrush_life/")
def reset_sidebrush_life(action):
    """Reset side brush life
    This is using docstrings for specifications.
    ---
    deprecated: true
    """


# WIP - waiting for issue to be answered
@app.put("/rotate/")
def rotate(action):
    """Rotate vacuum
    This is using docstrings for specifications.
    ---
    consumes:
      - application/json
    parameters:
      - name: rotation
        in: body
        schema:
          type: object
          properties:
            direction:
              type: string
            degrees:
              type: integer
          required:
            - rotation
    security:
      - Bearer: []
    definitions:
      rotate:
        type: array
        items:
          type: object
          properties:
            did:
              type: string
            siid:
              type: integer
            piid:
              type: integer
            code:
              type: integer
    responses:
      200:
        description: OK
        schema:
          $ref: '#/definitions/rotate'
      400:
        description: Bad Request
      401:
        description: Unauthorized
    """

    # 400 - malformed request body
    try:
        jsonObject = json.loads(request.data, object_hook=lambda d: Namespace(**d))
        requestedFanSpeed = jsonObject.direction
    except Exception as e:
        return Response(response="Malformed request body\n" + str(e), status=400, mimetype="text/plain")

    consoleOutput = (
        popen(
            "miiocli dreamevacuum --ip "
            + creds.ip
            + " --token "
            + creds.token
            + " set_fan_speed "
            + str(requestedFanSpeed)
        )
        .read()
        .strip()
        .rstrip("\n")
    )

    # 400 - unsupported value
    if consoleOutput.find("Error") != -1:
        return Response(response=consoleOutput.rstrip("\n"), status=400, mimetype="text/plain")

    # 200
    result = "[{" + consoleOutput.partition("\n")[2].partition("[{")[2]
    if result.find("'did'") != -1:
        return Response(response=result.replace("'", '"'), status=200, mimetype="application/json")


@app.put("/set_fan_speed/")
def set_fan_speed():
    """Set fan speed
    This is using docstrings for specifications.
    ---
    consumes:
      - application/json
    parameters:
      - name: speed
        in: body
        schema:
          type: object
          properties:
            fan_speed:
              type: integer
          required:
            - fan_speed
    security:
      - Bearer: []
    definitions:
      set_fan_speed:
        type: array
        items:
          type: object
          properties:
            did:
              type: string
            siid:
              type: integer
            piid:
              type: integer
            code:
              type: integer
    responses:
      200:
        description: OK
        schema:
          $ref: '#/definitions/set_fan_speed'
      400:
        description: Bad Request
    """

    # 400 - malformed request body
    try:
        jsonObject = json.loads(request.data, object_hook=lambda d: Namespace(**d))
        requestedFanSpeed = jsonObject.fan_speed
    except Exception as e:
        return Response(response="Malformed request body\n" + str(e), status=400, mimetype="text/plain")

    consoleOutput = (
        popen(
            "miiocli dreamevacuum --ip "
            + creds.ip
            + " --token "
            + creds.token
            + " set_fan_speed "
            + str(requestedFanSpeed)
        )
        .read()
        .strip()
        .rstrip("\n")
    )

    # 400 - unsupported value
    if consoleOutput.find("Error") != -1:
        return Response(response=consoleOutput.rstrip("\n"), status=400, mimetype="text/plain")

    # 200
    result = "[{" + consoleOutput.partition("\n")[2].partition("[{")[2]
    if result.find("'did'") != -1:
        return Response(response=result.replace("'", '"'), status=200, mimetype="application/json")


# TODO
@app.route("/set_property_by/")
def set_property_by(action):
    """Set a single property (siid/piid) to given value
    This is using docstrings for specifications.
    ---
    deprecated: true
    parameters:
      - name: action
        in: path
        type: string
        required: true
        default: something
    definitions:
      action:
        type: object
        properties:
          action_name:
            type: array
            items:
              $ref: '#/definitions/Color'
      Color:
        type: string
    responses:
      200:
        description: A list of colors (may be filtered by action)
        schema:
          $ref: '#/definitions/action'
        examples:
          rgb: ['red', 'green', 'blue']
      400:
        description: A list of colors (may be filtered by action)
        schema:
          $ref: '#/definitions/action'
        examples:
          rgb: ['red', 'green', 'blue']
    """
    all_colors = {"cmyk": ["cyan", "magenta", "yellow", "black"], "rgb": ["red", "green", "blue"]}
    if action == "all":
        result = all_colors
    else:
        result = {action: all_colors.get(action)}

    return jsonify(result)


# not working for my vacuum
@app.route("/set_waterflow/")
def set_waterflow():
    """Set water flow
    This is using docstrings for specifications.
    ---
    deprecated: true
    """


@app.route("/start/")
def start():
    """Start cleaning
    This is using docstrings for specifications.
    ---
    definitions:
      stop:
        type: object
        properties:
          did:
            type: string
          siid:
            type: integer
          aiid:
            type: integer
          code:
            type: integer
          out:
            type: array
            items: {}
    security:
      - Bearer: []
    responses:
      200:
        description: OK
        schema:
          $ref: '#/definitions/stop'
      400:
        description: Bad Request
      401:
        description: Unauthorized
    """
    consoleOutput = (
        popen("miiocli dreamevacuum --ip " + creds.ip + " --token " + creds.token + " start")
        .read()
        .strip()
        .rstrip("\n")
    )

    # 400
    if consoleOutput.find("Error") != -1:
        return Response(response=consoleOutput.rstrip("\n"), status=400, mimetype="text/plain")

    # 200
    result = consoleOutput.partition("\n")[2]
    print(result)
    if result.find("{'did'") != -1:
        return Response(response=result.replace("'", '"'), status=200, mimetype="application/json")


# Not working for my vacuum
@app.route("/status/")
def status():
    """State of the vacuum
    This is using docstrings for specifications.
    ---
    deprecated: true
    """


@app.post("/stop/")
def stop():
    """Stop cleaning
    This is using docstrings for specifications.
    ---
    definitions:
      stop:
        type: object
        properties:
          did:
            type: string
          siid:
            type: integer
          aiid:
            type: integer
          code:
            type: integer
          out:
            type: array
            items: {}
    security:
      - Bearer: []
    responses:
      200:
        description: OK
        schema:
          $ref: '#/definitions/stop'
      400:
        description: Bad Request
      401:
        description: Unauthorized
    """
    consoleOutput = (
        popen("miiocli dreamevacuum --ip " + creds.ip + " --token " + creds.token + " play_sound")
        .read()
        .strip()
        .rstrip("\n")
    )

    # 400
    if consoleOutput.find("Error") != -1:
        return Response(response=consoleOutput.rstrip("\n"), status=400, mimetype="text/plain")

    # 200
    result = consoleOutput.partition("\n")[2]
    print(result)
    if result.find("{'did'") != -1:
        return Response(response=result.replace("'", '"'), status=200, mimetype="application/json")


# TODO
@app.route("/test_properties/")
def test_properties(action):
    """Helper to test device properties
    This is using docstrings for specifications.
    ---
    deprecated: true
    parameters:
      - name: action
        in: path
        type: string
        required: true
        default: something
    definitions:
      action:
        type: object
        properties:
          action_name:
            type: array
            items:
              $ref: '#/definitions/Color'
      Color:
        type: string
    responses:
      200:
        description: A list of colors (may be filtered by action)
        schema:
          $ref: '#/definitions/action'
        examples:
          rgb: ['red', 'green', 'blue']
      400:
        description: A list of colors (may be filtered by action)
        schema:
          $ref: '#/definitions/action'
        examples:
          rgb: ['red', 'green', 'blue']
    """
    all_colors = {"cmyk": ["cyan", "magenta", "yellow", "black"], "rgb": ["red", "green", "blue"]}
    if action == "all":
        result = all_colors
    else:
        result = {action: all_colors.get(action)}

    return jsonify(result)


# not working for my vacuum
@app.route("/waterflow/")
def waterflow():
    """Get water flow setting
    This is using docstrings for specifications.
    ---
    deprecated: true
    """


# not working for my vacuum (empty json object as response)
@app.route("/waterflow_presets/")
def waterflow_presets():
    """Return dictionary containing supported water flow
    This is using docstrings for specifications.
    ---
    deprecated: true
    """


app.run(host="0.0.0.0", debug=True, port=5000)
