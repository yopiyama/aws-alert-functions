import json
import gzip
import base64
import io
import logging
import os
import requests

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def load_subscription_filter_logs(event):
    """Subscription filter からのログを Python で使える状態に加工する関数

    Args:
        event (dict): handler が取得した event データ

    Returns:
        dict: Subscription filter のログ本体
    """
    encoded_data = event['awslogs']['data']
    gzip_data = base64.b64decode(encoded_data)
    file_object = io.BytesIO(gzip_data)
    with gzip.GzipFile(fileobj=file_object, mode='r') as f:
        decoded_data = f.read()
    file_object.close()
    data = json.loads(decoded_data)
    logger.info(data)

    if data['messageType'] == 'CONTROL_MESSAGE':
        return 'Control Message'

    message_data = []
    for log in data['logEvents']:
        message_data.append(json.loads(log['message']))
    return message_data

def make_login_alert_message(log):
    user_name = log['userIdentity']['userName']
    user_type = log['userIdentity']['type']
    stats_message = f'`{user_name}` ({user_type})'
    if log['responseElements']['ConsoleLogin'] == 'Success':
        stats_message = ':mega:' + stats_message
        stats_message += ' logged in to the AWS Console'
    else:
        error_message = log['errorMessage']
        stats_message = ':rotating-light-red:' + stats_message
        stats_message += f'failed to login.\nError Message {error_message}'

    event_time = log['eventTime']
    source_ip = log['sourceIPAddress']
    aws_id = log['userIdentity']['accountId']
    aws_region = log['awsRegion']
    fields_messages = [
        {'type': 'mrkdwn', 'text': f'Event Time: {event_time}'},
        {'type': 'mrkdwn', 'text': f'Source IP: {source_ip}'},
        {'type': 'mrkdwn', 'text': f'AWS ID/Region: {aws_id}/{aws_region}'}
    ]

    send_message = {
        'type': 'section',
        'text': {'type': 'mrkdwn', 'text': stats_message},
        'fields': fields_messages
    }
    return send_message


def transform_to_slack_payloads(data):
    blocks = []
    for log in data:
        if log['eventType'] == 'AwsConsoleSignIn':
            blocks.append(make_login_alert_message(log))
        else:
            blocks.append({
                'type': 'section',
                'text': {'type': 'mrkdwn', 'text': 'not login event'}
            })

    payloads = {'text': 'AWS Audit Alert'}
    payloads['blocks'] = blocks
    return payloads


def send_to_slack(data):
    """payload に格納されているデータを Slack へ送信する

    Args:
        paylaod (dict): Slack の Webhook 用にフォーマットを整えてある dict
    """
    webhook_url = os.environ.get('SLACK_WEBHOOK_URL')
    headers = {'Content-type': 'application/json'}
    payloads = json.dumps(data)
    logger.info(payloads)
    response = requests.post(webhook_url, data=payloads,headers=headers)
    logger.info(response)

def lambda_handler(event, context):
    logger.info(event)
    log_events = load_subscription_filter_logs(event)
    logger.info(log_events)
    transformed_data = transform_to_slack_payloads(log_events)
    send_to_slack(transformed_data)
