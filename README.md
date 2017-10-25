# certwatcher
utility to monitor the certificates in use by a host and alert if they're expiring soon


## Usage

1. Create a list of URLs in a CSV file. Format is: `host,description`. The description is optional. Comments can be added by prepending a line with `#`. For example:
```
# Company websites
adhocteam.us,Ad Hoc homepage

# Third party
www.google.com,Google
example.com,
```
2. Add SMTP config values to `config.ini`
3. Run the app
```
$ $ ./certwatcher -urls urls.csv -days 90
2017/05/12 12:56:30 check: reddit.com - certificate is ok
2017/05/12 12:56:30 check: wikipedia.org - certificate is ok
2017/05/12 12:56:30 check: www.facebook.com - certificate is ok
2017/05/12 12:56:30 check: amazon.com - certificate is ok
2017/05/12 12:56:30 check: adhocteam.us - certificate is ok
2017/05/12 12:56:30 check: twitter.com - certificate is ok
2017/05/12 12:56:30 check: instagram.com - certificate is ok
2017/05/12 12:56:30 check: whitehouse.gov - certificate is ok
2017/05/12 12:56:30 check: live.com - certificate is ok
2017/05/12 12:56:30 check: yahoo.com - certificate is ok
2017/05/12 12:56:31 main: sent notification for host youtube.com - expiring soon
```
4. Relax and/or start renewing your certificates.
