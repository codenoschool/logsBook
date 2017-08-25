from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import InputRequired, Length, Email
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_required, login_user, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash

import os

dbdir = "sqlite:///" + os.path.abspath(os.getcwd()) + "/database.db"

app = Flask(__name__)
app.config["SECRET_KEY"] = "superSecret"
app.config["SQLALCHEMY_DATABASE_URI"] = dbdir
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "signin"

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)

db = SQLAlchemy(app)

class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    content = db.Column(db.String(1000))
    author = db.Column(db.String(50))

class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=6, max=50)])
    email = StringField("Email", validators=[InputRequired(), Length(min=6, max=50), Email()])
    password = PasswordField("Password", validators=[InputRequired(), Length(max=80, message="Máx 80.")])
    submit = SubmitField("Sign Up")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Length(max=50, message="Máx 50."), Email()])
    password = PasswordField("Password", validators=[InputRequired(), Length(max=80, message="Máx 80.")])
    remember = BooleanField("Remember me")
    submit = SubmitField("Log In")

@app.route("/")
def posts():
    posts = Posts.query.all()

    return render_template("posts.html", posts=posts)

@app.route("/log/<int:id>")
def post(id):
    post = Posts.query.get(id)

    return render_template("post.html", post=post)

@app.route("/new/log", methods=["GET", "POST"])
@login_required
def newPost():

    if request.method == "POST":
        new_post = Posts(title=request.form["title"], content=request.form["content"], author=current_user.username)
        db.session.add(new_post)
        db.session.commit()
        flash("The log was created successfully.")
        return redirect(url_for("posts"))

    return render_template("newPost.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        ccu = bool(Users.query.filter_by(username=form.username.data).first())
        cee = bool(Users.query.filter_by(email=form.email.data).first())
        
        if ccu == True:
            return "The username was taken by someone else. Try again with a new one."
        elif cee == True:
            return "A user with this email already exists. Try again with a new one."
        else:
            hashed_pw = generate_password_hash(form.password.data)
            new_user = Users(username=form.username.data, email=form.email.data, password=hashed_pw)
            db.session.add(new_user)
            db.session.commit()
            flash("You've been registered successfully")
            return redirect(url_for("signin"))

    return render_template("signup.html", form=form)

@app.route("/signin", methods=["GET", "POST"])
def signin():
    form = LoginForm()

    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()

        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember)
            return redirect(url_for("newPost"))
        return "Your credentials are invalid. Double check and try again."
    
    return render_template("signin.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You've logged out correctly.")
    
    return redirect(url_for("index"))

@app.errorhandler(400)
def page_not_found(error):
    return render_template("page_not_found.html"), 400

if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
