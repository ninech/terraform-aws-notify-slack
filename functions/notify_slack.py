from __future__ import print_function
import os, boto3, json, base64
import urllib.request, urllib.parse
import logging


# Decrypt encrypted URL with KMS
def decrypt(encrypted_url):
    region = os.environ['AWS_REGION']
    try:
        kms = boto3.client('kms', region_name=region)
        plaintext = kms.decrypt(CiphertextBlob=base64.b64decode(encrypted_url))['Plaintext']
        return plaintext.decode()
    except Exception:
        logging.exception("Failed to decrypt URL with KMS")


def cloudwatch_notification(message, region):
    states = {'OK': 'good', 'INSUFFICIENT_DATA': 'warning', 'ALARM': 'danger'}

    return {
            "color": states[message['NewStateValue']],
            "fallback": "Alarm {} triggered".format(message['AlarmName']),
            "fields": [
                { "title": "Alarm Name", "value": message['AlarmName'], "short": True },
                { "title": "Alarm Description", "value": message['AlarmDescription'], "short": False},
                { "title": "Alarm reason", "value": message['NewStateReason'], "short": False},
                { "title": "Old State", "value": message['OldStateValue'], "short": True },
                { "title": "Current State", "value": message['NewStateValue'], "short": True },
                {
                    "title": "Link to Alarm",
                    "value": "https://console.aws.amazon.com/cloudwatch/home?region=" + region + "#alarm:alarmFilter=ANY;name=" + urllib.parse.quote_plus(message['AlarmName']),
                    "short": False
                }
            ]
        }

def ses_bounce_notification(message, region):
    states = {'Transient': 'warning', 'Undetermined': 'warning', 'Permanent': 'danger'}
    color = states[message['bounce']['bounceType']]

    bounces = [{
        "color": color,
        "title": "Mail from {}".format(message['mail']['source']),
        "fields": [
            {"title":"Date", "value": message['mail']['timestamp'], "short": True},
            {"title":"Source IP", "value": message['mail']['sourceIp'], "short": True}
        ]
    }]

    for recv in message["bounce"]["bouncedRecipients"]:
        bounces.append({
            "color": color,
            "title": "Recipient Address: {}".format(recv["emailAddress"]),
            "fields": [
                { "title": "Status Code", "value": recv["status"], "short": True },
                { "title": "Diagnostic", "value": recv["diagnosticCode"], "short": True },
            ],
        })
    return bounces

def ses_complaint_notification(message, region):
    bounces = [{
        "color": "danger",
        "title": "Mail from {} classified as {}".format(message['mail']['source'], message['complaint']['complaintFeedbackType']),
        "fields": [
            {"title":"Date", "value": message['mail']['timestamp'], "short": True},
            {"title":"Source IP", "value": message['mail']['sourceIp'], "short": True},
            {"title":"Recipients", "value": message['mail']['destination'].join(', '), "short": False}
        ]
    }]
    return bounces

def default_notification(message):
    return {
            "fallback": "A new message",
            "fields": [{"title": "Message", "value": json.dumps(message), "short": False}]
        }


# Send a message to a slack channel
def notify_slack(message, region):
    slack_url = os.environ['SLACK_WEBHOOK_URL']
    if not slack_url.startswith("http"):
        slack_url = decrypt(slack_url)

    slack_channel = os.environ['SLACK_CHANNEL']
    slack_username = os.environ['SLACK_USERNAME']
    slack_emoji = os.environ['SLACK_EMOJI']

    payload = {
        "channel": slack_channel,
        "username": slack_username,
        "icon_emoji": slack_emoji,
        "attachments": []
    }
    if "AlarmName" in message:
        notification = cloudwatch_notification(message, region)
        payload['text'] = "AWS CloudWatch notification - " + message["AlarmName"]
        payload['attachments'].append(notification)
    elif "notificationType" in message and message["notificationType"] == "Bounce":
        payload['text'] = "AWS SES Bounce notification - " + message["bounce"]["bounceType"] + " - " + message["bounce"]["bounceSubType"]
        payload['attachments'] + ses_bounce_notification(message, region)
    elif "notificationType" in message and message["notificationType"] == "Complaint":
        payload['text'] = "AWS SES Complaint notification"
        payload['attachments'] + ses_complaint_notification(message, region)
    else:
        payload['text'] = "AWS notification"
        payload['attachments'].append(default_notification(message))

    data = urllib.parse.urlencode({"payload": json.dumps(payload)}).encode("utf-8")
    req = urllib.request.Request(slack_url)
    urllib.request.urlopen(req, data)


def lambda_handler(event, context):
    message = json.loads(event['Records'][0]['Sns']['Message'])
    region = event['Records'][0]['Sns']['TopicArn'].split(":")[3]
    notify_slack(message, region)

    return message

#notify_slack({"AlarmName":"Example","AlarmDescription":"Example alarm description.","AWSAccountId":"000000000000","NewStateValue":"ALARM","NewStateReason":"Threshold Crossed","StateChangeTime":"2017-01-12T16:30:42.236+0000","Region":"EU - Ireland","OldStateValue":"OK"}, "eu-west-1")
