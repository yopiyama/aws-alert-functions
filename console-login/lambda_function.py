import json
import gzip
import base64
import io
import logging
import os
import requests

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DESTINATION = os.getenv('DESTINATION', 'slack').lower()
WEBHOOK_URL = os.getenv('WEBHOOK_URL')


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


def transform_to_discord_payloads(data):
    embeds = []
    payloads = {
        'username': 'AWS Audit',
        # 'avatar_url' : 'icon url'
        'content': 'AWS Audit Alert',
        'embeds': embeds
    }

    # color : https://www.mathsisfun.com/hexadecimal-decimal-colors.html
    warning_color = 16732215
    caution_color = 16766559
    attention_color = 3124810

    for log in data:
        if log['eventType'] == 'AwsConsoleSignIn':
            color = 0
            description = ''
            fields = []
            user_name = log['userIdentity']['userName']
            user_type = log['userIdentity']['type']
            event_time = log['eventTime']
            source_ip = log['sourceIPAddress']
            aws_id = log['userIdentity']['accountId']
            aws_region = log['awsRegion']

            if log['responseElements']['ConsoleLogin'] == 'Success':
                color = caution_color
                description += f'`{user_name} ({user_type})` logged in to the AWS Console.\n'
            else:
                color = warning_color
                error_message = log['errorMessage']
                description += f'`{user_name} ({user_type})` failed to login.\n'
                description += f'Error message : {error_message}\n'

            fields = [
                {
                    'name': 'Event time',
                    'value': event_time,
                    'inline': True
                },
                {
                    'name': 'Source IP',
                    'value': source_ip,
                    'inline': True
                },
                {
                    'name': 'AWS ID/Region',
                    'value': f'{aws_id}/{aws_region}',
                    'inline': False
                }
            ]

            embeds.append({
                'color': color,
                'title': 'Login alert',
                'description': description,
                'fields': fields
            })
        else:
            embeds.append({
                'color': attention_color,
                'description': 'not login event'
            })

    payloads['embeds'] = embeds
    return payloads


def send_to_destination(data):
    """payload に格納されているデータを Slack へ送信する

    Args:
        paylaod (dict): Destinatino の Webhook 用にフォーマットを整えてある dict
    """
    headers = {'Content-Type': 'application/json'}

    payloads = json.dumps(data)
    logger.info(payloads)
    response = requests.post(WEBHOOK_URL, data=payloads, headers=headers)

    if response.status_code != requests.codes.ok:
        logger.error(response.status_code)
        logger.error(response.text)


def lambda_handler(event, context):
    logger.debug(event)

    log_events = load_subscription_filter_logs(event)
    logger.info(log_events)

    logger.info(f'Destination : {DESTINATION}')
    if DESTINATION == 'slack':
        transformed_data = transform_to_slack_payloads(log_events)
    elif DESTINATION == 'discord':
        transformed_data = transform_to_discord_payloads(log_events)
    else:
        logger.error('Invalid Destination.')
        raise Exception

    send_to_destination(transformed_data)
