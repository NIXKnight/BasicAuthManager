import os
from functools import wraps
from flask import Flask, render_template, url_for, redirect, request, Response, abort
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, validators
from wtforms.fields.html5 import EmailField
from passlib.apache import HtpasswdFile
from passlib.hash import bcrypt
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText

app = Flask(__name__)

def auth_required(f):
  @wraps(f)
  def authen(*args, **kwargs):
    auth = request.authorization
    if not auth or not check_user_auth(auth.username, auth.password):
      return authenticate()
    return f(*args, **kwargs)
  return authen

def check_user_auth(username, password):
  if verify_passwd_hash(username, password):
    return True
  else:
    return not_authenticated()

def verify_passwd_hash(username, password):
  htContent = HtpasswdFile(app.config['HTPASSWD_FILE'], default_scheme='bcrypt')
  passwdHash = htContent.get_hash(username)
  try:
    hashMatch = bcrypt.verify(password, passwdHash)
    if hashMatch:
      return True
  except ValueError:
    return False
  except TypeError:
    return False

def verify_admin(username):
  if str(username) != str(app.config['ADMIN_USER']):
    return not_authenticated()

def authenticate():
  pagename = "Need Proper Authentication"
  return Response(render_template("401.html.j2", pagename=pagename), 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

def not_authenticated():
  abort(401)

def get_users(htPasswdFile):
  htContent = HtpasswdFile(htPasswdFile)
  return htContent.users()

def create_user(username, password):
  htContent = HtpasswdFile(app.config['HTPASSWD_FILE'], default_scheme='bcrypt')
  htContent.set_password(username, password)
  htContent.save()

def rm_user(username):
  htcontent = HtpasswdFile(app.config['HTPASSWD_FILE'])
  htcontent.delete(username)
  htcontent.save()

def send_mail(username, password, email):
  msg = MIMEMultipart()
  msg['From'] = app.config['SMTP_FROM']
  msg['To'] = email
  msg['Subject'] = "Access for " + username
  body = "Password for your username " + username + " is set to " + password
  msg.attach(MIMEText(body, 'plain'))
  if app.config['SMTP_TRANSPORT'] == "STARTTLS":
    smtp = smtplib.SMTP(app.config['SMTP_SERVER'], app.config['SMTP_PORT'])
    smtp.ehlo()
    smtp.starttls()
  if app.config['SMTP_TRANSPORT'] == "SSL":
    smtp = smtplib.SMTP_SSL(app.config['SMTP_SERVER'], app.config['SMTP_PORT'])
  smtp.login(app.config['SMTP_USERNAME'], app.config['SMTP_PASSWORD'])
  text = msg.as_string()
  smtp.sendmail(app.config['SMTP_FROM'], email, text)
  smtp.quit()

class change_password_form(FlaskForm):
  password = PasswordField('', [validators.DataRequired()])
  confimPassword = PasswordField('', [validators.DataRequired(), validators.EqualTo('password', message='Passwords must match')])

class new_user_form(FlaskForm):
  username = StringField('', [validators.DataRequired()])
  email = EmailField('', [validators.DataRequired(), validators.Email()])
  password = PasswordField('', [validators.DataRequired()])
  confimPassword = PasswordField('', [validators.DataRequired(), validators.EqualTo('password', message='Passwords must match')])

class edit_user_form(FlaskForm):
  email = EmailField('', [validators.DataRequired(), validators.Email()])
  password = PasswordField('', [validators.DataRequired()])
  confimPassword = PasswordField('', [validators.DataRequired(), validators.EqualTo('password', message='Passwords must match')])

@app.route('/', methods=['GET'])
@auth_required
def root_uri():
  if str(request.authorization['username']) == str(app.config['ADMIN_USER']):
    return redirect(url_for('admin'))
  else:
    return redirect(url_for('change_password'))

@app.route('/change-password', methods=['GET', 'POST'])
@auth_required
def change_password():
  pagename = "Change Password"
  form = change_password_form()
  if form.validate_on_submit():
    password = form.password.data
    form.password.data = ''
    return redirect(url_for('change_password'))
  return render_template("change_password.html.j2", form=form, pagename=pagename)

@app.route('/admin/add', methods=['GET', 'POST'])
def add_user():
  pagename = "Add User"
  username = None
  email = None
  password = None
  form = new_user_form()
  if form.validate_on_submit():
    username = form.username.data
    email = form.email.data
    password = form.password.data
    form.username.data = ''
    form.email.data = ''
    form.password.data = ''
    create_user(username, password)
    send_mail(username, password, email)
    return redirect(url_for('admin'))
  return render_template("adduser.html.j2", form=form, username=username, email=email, password=password, pagename=pagename)

@app.route('/admin', methods=['GET'])
@auth_required
def admin():
  pagename = "Admin"
  verify_admin(request.authorization['username'])
  users = get_users(app.config['HTPASSWD_FILE'])
  return render_template("admin.html.j2", users=users, pagename=pagename)

@app.route('/admin/edit/<username>', methods=['GET', 'POST'])
@auth_required
def edit_user(username):
  pagename = "Edit User"
  email = None
  password = None
  form = edit_user_form()
  if form.validate_on_submit():
    email = form.email.data
    password = form.password.data
    form.email.data = ''
    form.password.data = ''
    form.confimPassword.data = ''
    create_user(username, password)
    send_mail(username, password, email)
    return redirect(url_for('admin'))
  return render_template("edituser.html.j2", form=form, username=username, email=email, password=password, pagename=pagename)

@app.route('/admin/remove/<username>', methods=['GET', 'POST'])
@auth_required
def remove_user(username):
  rm_user(username)
  return redirect(url_for('admin'))

@app.errorhandler(401)
def custom_401(error):
    pagename = "Need Proper Authentication"
    return Response(render_template("401.html.j2", pagename=pagename), 401, {'WWWAuthenticate':'Basic realm="Login Required"'})

if __name__ == '__main__':
  if os.path.exists('config.cfg'):
    app.config.from_pyfile('config.cfg')
    if not os.path.exists(app.config['HTPASSWD_FILE']):
      from getpass import getpass
      htContent = HtpasswdFile(app.config['HTPASSWD_FILE'], new=True, default_scheme='bcrypt')
      passwordPrompt = lambda: (getpass(prompt='Enter Password for ' + app.config['ADMIN_USER'] + ": "), getpass('Confirm password: '))
      adminPassword, adminPassword2 = passwordPrompt()
      while adminPassword != adminPassword2:
        print('Passwords do not match! Try again!')
        adminPassword, adminPassword2 = passwordPrompt()
      htContent.set_password(app.config['ADMIN_USER'], adminPassword)
      htContent.save()
  else:
    print "Create a config file 1st"
    raise SystemExit
  app.run()