# certwatcher
utility to monitor the certificates in use by a host and alert if they're expiring soon


## Usage

1. Create a list of URLs in a CSV file. Format is: host,descrption. For example:
```
www.google.com,Google
adhocteam.us,Ad Hoc homepage
```
2. Add SMTP config values to `config.ini`
3. Run the app
```
$ ./certwatcher
2017/05/08 09:25:35 check: host: adhocteam.us
2017/05/08 09:25:35 check: host: www.google.com
```
4. Relax and/or start renewing your certificates.