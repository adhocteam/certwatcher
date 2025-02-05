
# upload lambda zip to S3
resource "aws_s3_bucket_object" "lambda-storage" {
  bucket = var.s3_bucket
  key    = var.s3_object
  source = var.lambda_local_path
  etag   = filemd5(var.lambda_local_path)
}

# lambda function
resource "aws_lambda_function" "certwatcher" {
  function_name = "certwatcher"
  handler       = "main"
  role          = aws_iam_role.certwatcher-role.arn
  description   = "Checks certificate expiration"
  runtime       = "go1.x"
  memory_size   = "128"
  timeout       = "5"
  s3_bucket     = var.s3_bucket
  s3_key        = var.s3_object
}

# lambda role / policy
resource "aws_iam_role_policy_attachment" "certwatcher" {
  role       = aws_iam_role.certwatcher-role.name
  policy_arn = aws_iam_policy.policy.arn
}

resource "aws_iam_role" "certwatcher-role" {
  name_prefix        = "certwatcher-role-"
  assume_role_policy = jsonencode(
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
})
}

resource "aws_iam_policy" "lambda-policy" {
  name        = "certwatcher-exec"
  path        = "/"
  description = "Policy to allow certwatcher to "
  policy = jsonencode(
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Action": [
                "sns:Publish"
            ],
            "Resource": "*"
        }
    ]
})
}

# associate AWS's default Lambda role
resource "aws_iam_role_policy_attachment" "default-lambda" {
  role       = aws_iam_role.certwatcher_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_cloudwatch_log_group" "logs" {
  name              = "/aws/lambda/${aws_lambda_function.certwatcher.function_name}"
  retention_in_days = var.log_retention
}

# sns topic for notifications
resource "aws_sns_topic" "certwatcher" {
  name              = "certwatcher"
  display_name      = "certwatcher"
  kms_master_key_id = "alias/aws/sns"
}

# cloudwatch rule to trigger the lambda
resource "aws_cloudwatch_event_rule" "event-rule" {
  name_prefix         = "scheduled-certwatcher"
  description         = "Invoke the certwatcher lambda"
  schedule_expression = var.interval
}

resource "aws_lambda_permission" "allow-cloudwatch-exec" {
  statement_id_prefix = "AllowCloudWatchExecution-"
  action              = "lambda:InvokeFunction"
  principal           = "events.amazonaws.com"
  function_name       = aws_lambda_function.certwatcher.name
  source_arn          = aws_cloudwatch_event_rule.event-rule.arn
}

resource "aws_cloudwatch_event_target" "lambda-target" {
  rule = aws_cloudwatch_event_rule.event-rule.id
  arn  = aws_lambda_function.certwatcher.arn
  input = jsonencode(merge(cfg, {"topic" : aws_sns_topic.certwatcher.arn}))
}
