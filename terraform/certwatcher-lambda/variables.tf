variable "s3_bucket" {
  description = "S3 bucket that holds the certwatcher application code"
}

variable "s3_object" {
  default = "certwatcher-lambda.zip"
}

variable "cfg" {
  description = "variables to be passed into the lambda function"
  type = object({
    urls    = string
    days    = number
    verbose = bool
  })
  default = {
    urls    = []
    days    = 30
    verbose = false
  }
}

variable "lambda_local_path" {
  description = "path to zipped lambda function on local filesystem"
  default     = "certwatcher-lambda.zip"
}

variable "interval" {
  description = "how often to invoke the function.  ex rate(1 day) or cron (* 5 * * *)"
  default     = "1 day"
}

variable "log_retention" {
  description = "how long to retain lambda execution log data in cloudwatch logs"
  default     = 30
}


