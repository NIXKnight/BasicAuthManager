import os
from flask import Flask, render_template, url_for, redirect
from flask_wtf import FlaskForm
from wtforms import PasswordField, validators
from passlib.apache import HtpasswdFile
from passlib.hash import bcrypt

app = Flask(__name__)

def get_users(htPasswdFile):
  htContent = HtpasswdFile(htPasswdFile)
  return htContent.users()

class change_password_form(FlaskForm):
  password = PasswordField('', [validators.DataRequired()])
  confimPassword = PasswordField('', [validators.DataRequired(), validators.EqualTo('password', message='Passwords must match')])

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
  form = change_password_form()
  if form.validate_on_submit():
    password = form.password.data
    form.password.data = ''
    return redirect(url_for('change_password'))
  return render_template("change_password.html.j2", form=form)

@app.route('/admin/add', methods=['GET', 'POST'])
def add_user():
  return render_template("adduser.html.j2")

@app.route('/admin', methods=['GET', 'POST'])
def admin():
  users = get_users(app.config['HTPASSWD_FILE'])
  return render_template("admin.html.j2", users=users)

@app.route('/admin/edit', methods=['GET', 'POST'])
def edit_user():
  return render_template("edituser.html.j2")

@app.route('/admin/remove', methods=['GET', 'POST'])
def remove_user():
  return redirect(url_for('admin'))

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