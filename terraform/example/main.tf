module "certwatcher" {
  s3_bucket = "lambda-storage"
  cfg = {
    urls    = []
    days    = 30
    verbose = false
  }
}

