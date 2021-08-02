from flask import Flask, render_template, request, redirect, url_for, session, g
from flask_sqlalchemy import SQLAlchemy 
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_httpauth import HTTPBasicAuth


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'

auth = HTTPBasicAuth()
bootstrap = Bootstrap(app)

#database
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#Forms
class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password',validators=[InputRequired(), Length(min=8, max=20)])
    remember = BooleanField('remember me')
 

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


#create database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    status = db.Column(db.Boolean)
    username = db.column(db.String(15), db.ForeignKey(User.id))


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if user.password == form.password.data:
                return redirect(url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'

    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        #hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=form.password.data)
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New user has been created!</h1>'
    return render_template('signup.html', form=form)



@app.route('/dashboard')
def dashboard():
    # show all todos

    todo_list = Todo.query.all()
    return render_template('dashboard.html', todo_list=todo_list)

@app.route('/add',methods=["POST"])
def add():
    #add new todo
    title = request.form.get("title")
    new_todo = Todo(title=title, status= False)
    db.session.add(new_todo)
    db.session.commit()
    return redirect(url_for("dashboard"))
    
@app.route('/update/<int:todo_id>')
def update(todo_id):
    #update todo
    todo = Todo.query.filter_by(id=todo_id).first()
    todo.status = not todo.status
    db.session.commit()
    return redirect(url_for("dashboard"))


@app.route('/delete/<int:todo_id>')
def delete(todo_id):
    #delete todo
    todo = Todo.query.filter_by(id=todo_id).first()
    db.session.delete(todo)
    db.session.commit()
    return redirect(url_for("dashboard"))



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == "__main__" :
    db.create_all()

    app.run(debug=True) 