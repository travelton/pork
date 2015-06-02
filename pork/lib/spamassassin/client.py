# -*- coding: utf-8 -*-
import re
import socket

from definitions import definitions


TEMPLATE = '%s SPAMC/1.5\r\nContent-length: %s\r\n\r\n%s\r\n\r\n'


def request(server, port, command, mime):
    """
    Constructs and processes a request to the Spam Assassin
    server. Returns the raw reply.

    :param server: the server running the Spam Assassin daemon
    :param port: the listening port of the Spam Assassin server
    :param command: the command for protocol 1.5. one of 'CHECK',
                    'SYMBOLS', 'REPORT', 'REPORT_IFSPAM', 'SKIP',
                    'PING', 'PROCESS', 'TELL', 'HEADERS'.
    :param mime: the mime to be submitted with the request
    """
    # construct payload from template
    payload = TEMPLATE % (command, len(mime) + 2, mime)

    # return the response
    return _process_request(server, port, payload)


def _process_request(server, port, payload):
    """
    Internal function for processing a request.
    """
    try:
        # create a socket for communication
        spamd_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # set the timeout to 5 seconds
        spamd_socket.settimeout(10)

        # connect to the spamd instance
        spamd_socket.connect((server, port))

        # send the payload
        spamd_socket.sendall(payload)

        # get the result
        result = spamd_socket.recv(1024)

        while True:
            data = spamd_socket.recv(1024)
            if data:
                result += data
            else:
                break

        # return the result
        return result
    except:
        return None
    finally:
        if spamd_socket:
            # close the socket
            spamd_socket.close()


def parse(report_type, scan_result):
    """
    Parses the result of the raw Spam Assassin
    reply. A bunch of regex mess, but gets the job done!

    :param report_type: the type of report to parse. one of 'REPORT',
                        'SYMBOLS'.
    :param scan_result: the raw result from the scan.
    """
    # capture content length
    content_length_re = re.compile(r'Content-length: ([0-9]{1,10})')
    content_length = re.search(content_length_re, scan_result).group(1)
    content_length = int(content_length) if content_length else None

    # capture spam result
    spam_result_re = re.compile(
        r'Spam: (True|False) ; (-?[0-9]{0,3}\.[0-9]{0,1}) \/ ([0-9]{0,3}\.[0-9]{0,1})')
    spam_result = _cast_bool(re.search(spam_result_re, scan_result).group(1))

    spam_score_actual = re.search(spam_result_re, scan_result).group(2)
    spam_score_actual = float(spam_score_actual) if spam_score_actual else None

    spam_score_required = re.search(spam_result_re, scan_result).group(3)
    spam_score_required = float(spam_score_required) if spam_score_required else None

    if report_type == "REPORT":
        # capture rules the spam message violated
        rule_re = re.compile(r'\n ?(-?[0-9]{0,2}\.[0-9]{0,2}) ([A-Z_0-9]+) (.*)')
        rule_results = re.findall(rule_re, scan_result)

    if report_type == "SYMBOLS":
        # capture rules the spam message violated
        rule_re = re.compile(r'\r\n\r\n(.*)')
        rule_results = re.search(rule_re, scan_result).group(1)
        rule_results = [(None, rule) for rule in rule_results.split(",")]

    # construct an array of rule violations
    rule_violations = []
    for rule_tuple in rule_results:
        rule_violations.append({
            "rule": rule_tuple[1],
            "score": float(rule_tuple[0]) if rule_tuple[0] else None,
            # use the override definition file, or get straight results
            "description": definitions.get(rule_tuple[1]) if definitions.get(rule_tuple[1], None) else rule_tuple[2]
        })

    # sort the rule violations
    rule_violations = sorted(rule_violations,
                             key=lambda k: k['score'],
                             reverse=True)

    # craft response
    response = {
        "parsed": {
            "content_length": content_length,
            "spam": spam_result,
            "actual_score": spam_score_actual,
            "required_score": spam_score_required,
            "rule_violations": rule_violations,
        },
        "raw": scan_result
    }

    return response


def _cast_bool(string):
    if string in ["True", "true"]:
        return True
    else:
        return False
