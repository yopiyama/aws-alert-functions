# aws_cloudtrail_alert

CloudTrail → CWL → サブスクリプションフィルタ(Lambda) → Slack という経路で CloudTrail ログのアラーティングを行うスクリプト

## Installation

1. CloudTrail ログを CloudWatch Logs へ出力する設定を有効化する
2. このスクリプトを Lambda へデプロイ
   1. 以下の環境変数を設定する
      1. SLACK_WEBHOOK_URL
3. CloudWatch Logs のロググループでサブスクリプションフィルタの設定を行う
   1. Lambda のサブスクリプションフィルタを選択
   2. フィルタは任意の物を設定する
      1. ログインのアラーティングを行いたい場合 : `{$.eventName = "ConsoleLogin"}`
