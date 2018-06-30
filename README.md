# **BasicAuthManager**
BasicAuthManager is a small web GUI written in Flask for managing HTTP basic authentication. It uses [`passlib`](http://passlib.readthedocs.io/en/stable/#) password hashing library to create/update Htpasswd file which can later be used by either NGINX or Apache for enabling basic authentication for desired sites.

The resulting Htpasswd file has [`bcrypt`](http://passlib.readthedocs.io/en/stable/lib/passlib.hash.bcrypt.html) encrypted passwords.

## **Requirements**
BasicAuthManager requires Python 2.7.x.

## **Installing and Running**
Install python, virtualenv, supervisor and apache2-utils packages:
```console
# apt-get install python python-virtualenv supervisor
```
Create a user:
```console
# groupadd bam
# useradd -d /home/bam -g bam
```
As the new user, clone the repo:
```console
$ git clone https://github.com/NIXKnight/BasicAuthManager.git
```
Create a python virtual environment and install application requirements:
```console
$ virtualenv ~/venv
$ pip install ~/BasicAuthManager/requirements.txt
```
Create a configuration file `~/BasicAuthManager/config.cfg` as follows:
```python
SECRET_KEY = "Random Key String"
ADMIN_USER = "admin"
HTPASSWD_FILE = "/path/to/htpasswd_file"
SMTP_FROM = "from email address"
SMTP_SERVER = "SMTPHOST"
SMTP_TRANSPORT = "STARTTLS"
SMTP_PORT = "587"
SMTP_USERNAME = "from email address"
SMTP_PASSWORD = "password"
```
Note that you can use either `STARTTLS` or `SSL` in `SMTP_TRANSPORT`. Ensure that you use the proper port in `SMTP_PORT`.

Create an Htpasswd file (with `-B` option for bcrypt encryption) having an admin user as in the `config.cfg`:
```console
$ htpasswd -B -c /path/to/htpasswd_file admin
```
Create a supervisor configuration file /etc/supervisor/conf.d/BasicAuthManager.conf with following parameters:
```ini
user = bam
directory = /home/bam/BasicAuthManager
command = /home/bam/venv/bin/gunicorn BasicAuthManager:app -w 4 -b 127.0.0.1:8000
environment = PRODUCTION=1
redirect_stderr = True
autorestart = True
stdout_logfile = /var/log/supervisor/BasicAuthManager_stdout.log
stderr_logfile = /var/log/supervisor/BasicAuthManager_stderr.log
```
Create NGINX server block as follows:
```conf
server {
  listen 80;
  server_name this.bam.local;
  autoindex off;

  location / {
    proxy_set_header X-Forward-For $proxy_add_x_forwarded_for;
    proxy_pass http://127.0.0.1:8000;
  }

  location /static {
    alias /home/bam/BasicAuthManager/static/;
  }

  access_log /var/log/nginx/BasicAuthManager-access.log;
  error_log /var/log/nginx/BasicAuthManager-error.log;
}
```

## **Use Ansible Role**
If you don't want to go through the hassle of manual setup, you can use the Ansible role [Ansible-BasicAuthManager](https://github.com/NIXKnight/Ansible-BasicAuthManager) for the purpose of setting up BasicAuthManager.

## **Contributing**
If you want to contribute to BasicAuthManager and make it better, your help is very welcome. Note that I am not a Python/Flask developer.

You could send make a pull request. Just do let me know how does your pull request makes the application better. I will do my best to understand and merge the code.

## **Why Did I Write This Code?**
I wanted to learn bits of how to code a web application. In trying to do so, I wrote BasicAuthManager to fullfil my need. I hate logging in to the server to update htpasswd files everytime I have to create a user.

## **License**
This Ansible role is licensed under MIT License.

## **Author**
[Saad Ali](https://github.com/nixknight)