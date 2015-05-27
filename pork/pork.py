# -*- coding: utf-8 -*-
"""
    Pork
    ----

    Pork is a microservice REST interface for SpamAssassin (and maybe others?).
    It accepts MIME, and provides the SpamAssassin result in JSON format.

    Pork probably should not be used in production environments. Performance
    has not been evaluated.
"""

from flask import Flask, request, jsonify
from lib.spamassassin import client


app = Flask(__name__)

# define the SpamAssassin server and port here
app.config.update(dict(
    SPAMD_SERVER="127.0.0.1",
    SPAMD_PORT=783
))


@app.route('/v0/scan', methods=['POST'])
def scan_mime():
    # obtain the mime
    mime = request.json.get("mime", None)

    # get spamassassin config, if present
    spamassassin_config = request.json.get("spamassassin", None)

    # obtain the command, if none, default to verbose REPORT
    if spamassassin_config:
        spamassassin_command = spamassassin_config.get("command")
    else:
        spamassassin_command = "REPORT"

    # if no mime, return 400 error. must have the mimes.
    if not mime:
        response = jsonify({"result": "MIME required!"})
        response.status_code = 400
        return response

    # initiate scan
    raw_scan_result = client.request(app.config["SPAMD_SERVER"],
                                     app.config["SPAMD_PORT"],
                                     spamassassin_command,
                                     mime)

    # process the result, if REPORT or SYMBOLS command
    if spamassassin_command in ["REPORT", "SYMBOLS"]:
        # parse the scan_result
        parsed_scan_result = client.parse(spamassassin_command, raw_scan_result)
        # jsonify it
        response = jsonify({"spamassassin": parsed_scan_result})
    else:
        # jsonify the raw result
        response = jsonify({"spamassassin": {"raw": raw_scan_result}})

    # 200, oh yeah!
    response.status_code = 200

    # return the result, woo.
    return response


@app.route('/v0/ham', methods=['POST'])
def mime_is_ham():
    response = jsonify({"error": "Not implemented yet!"})
    response.status_code = 400
    return response


@app.route('/v0/spam', methods=['POST'])
def mime_is_spam():
    response = jsonify({"error": "Not implemented yet!"})
    response.status_code = 400
    return response

app.run(debug=True)
