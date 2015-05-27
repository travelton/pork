Pork
============

**What is Pork?**
The culinary name for Pig Meat... Also, Pork is a simple Python Flask microservice API for SpamAssassin (and maybe others?). It accepts MIME, and provides the SpamAssassin result in JSON format.

**Why Pork?**
Spam has such a bad name. The poor product... But, did you know, Spam is really just Pork? True story, http://en.wikipedia.org/wiki/Spam_%28food%29.


The API is as follows: 

####Scan MIME body

```
POST /v0/scan
```
Content-Type: application/json 

| Parameter Name         | Description                                        |
|------------------------|----------------------------------------------------|
| mime                   | The raw mime body from an email message            |
| spamassassin           | A dictionary containing configuration parameters   |
| spamassassin.command   | One of "REPORT" or "SYMBOLS"                       |

Sample CURL Command:

```bash
curl -X POST -H "Content-Type: application/json" -d '{
    "mime": "<MIME BODY HERE>",
    "spamassassin": {
        "command": "<REPORT|SYMBOLS>"
    }
}' http://127.0.0.1:5000/scan
```

JSON Result:

```json
{
  "spamassassin": {
    "parsed": {
      "actual_score": "15.1", 
      "content_length": "2055", 
      "required_score": "5.0", 
      "rule_violations": [
        {
          "description": "Received via a relay in Spamhaus PBL", 
          "rule": "RCVD_IN_PBL", 
          "score": "3.6"
        }, 
        {
          "description": "Contains an URL listed in the DBL blocklist", 
          "rule": "URIBL_DBL_SPAM", 
          "score": "2.5"
        }, 
        {
          "description": "Contains an URL listed in the JP SURBL blocklist", 
          "rule": "URIBL_JP_SURBL", 
          "score": "1.9"
        }, 
        {
          "description": "Contains an URL listed in the WS SURBL blocklist", 
          "rule": "URIBL_WS_SURBL", 
          "score": "1.7"
        }
      ], 
      "spam": "True"
    }, 
    "raw": "SPAMD/1.1 0 EX_OK\r\nContent-length: 2055\r\nSpam: True ; 15.1 / 5.0\r\n\r\nSpam detection software, running on the system \"cloud-server-01\", has\nidentified this incoming email as possible spam.  The original message\nhas been attached to this so you can view it (if it isn't spam) or label\nsimilar future email.  If you have any questions, see\nthe administrator of that system for details.\n\nContent preview:  so hard. t\u00c5\u00a7Hello there my adult mas\u0651t\u0361er\u036f! I\u0651t's m\u0326e,\n   Lavina!!Argued abby cried the window. Suggested abby trying not getting married.\n   [...Truncated]"
  }
}
```
