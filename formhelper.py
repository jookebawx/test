from wtforms import Form, StringField, DecimalField, IntegerField, TextAreaField,SelectField, PasswordField, validators

class RegisterForm(Form):
    first_name= StringField('first_name', [validators.Length(min=1, max=50)])
    last_name = StringField('last_name', [validators.Length(min=1, max=50)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    auth_type = SelectField('auth_type',choices=[('auth', 'Authenticator'),  ('regular', 'Regular User')])
    password = PasswordField('password',[validators.DataRequired(),validators.EqualTo('confirm', message='Password Do not match')])
    confirm = PasswordField('confirm password')

class SendMoneyForm(Form):
    receiver = StringField('address', [validators.Length(min=1, max=100)])
    amount = StringField('amount',[validators.Length(min=1, max=100)])