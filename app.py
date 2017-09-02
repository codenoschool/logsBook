from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import InputRequired, Length, Email
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import update
from flask_login import UserMixin, LoginManager, login_required, login_user, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash

import os
import hashlib, urllib.parse

dbdir = "sqlite:///" + os.path.abspath(os.getcwd()) + "/database.db"

app = Flask(__name__)
app.config["SECRET_KEY"] = "superSecret"
app.config["SQLALCHEMY_DATABASE_URI"] = dbdir
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "signin"
login_manager.login_message_category = "alert-primary"

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)

class Base(db.Model):
    __abstract__ = True

    id = db.Column(db.Integer, primary_key=True)
    date_created = db.Column(db.DateTime, default=db.func.current_timestamp())
    date_modified = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

class Posts(Base):

    # Based on Base Class

    title = db.Column(db.String(150))
    content = db.Column(db.Text(length=None))
    author = db.Column(db.String(50))
    status = db.Column(db.SmallInteger, nullable=False, default=1)

    def __init__(self, title, content, author):
        self.title = title
        self.content = content
        self.author = author

    def __repr__(self):
        return "<Log %r>" % (self.title)

class Users(UserMixin, Base):

    # Based on Base Class.

    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    name = db.Column(db.String(50))
    description = db.Column(db.String(300))
    contact = db.Column(db.String(50))
    web = db.Column(db.String(50))
    profile_url = db.Column(db.String(100))
    role = db.Column(db.SmallInteger, nullable=False, default=1)
    status = db.Column(db.SmallInteger, nullable=False, default=1)

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password
    
    def __repr__(self):
        return "<User %r>" % (self.email)

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
    posts = Posts.query.order_by(Posts.date_modified).limit(100).all()

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
        flash("The log was created successfully.", "alert-success")
        return redirect(url_for("posts"))

    return render_template("new_post.html")

@app.route("/edit/log/<int:log_id>/", methods=["GET", "POST"])
@login_required
def edit_log(log_id):
    log = Posts.query.filter_by(id=log_id).first()

    if log.author == current_user.username:
        if request.method == "POST":
            log.title = request.form["title"]
            log.content = request.form["content"]
            db.session.commit()
            flash("The log has been updated successfully.", "alert-success")
            return redirect(url_for("post", id=log.id))

        return render_template("edit_log.html", log=log)

    flash("You are not the author of that log.", "alert-danger")
    return redirect(url_for("posts"))

@app.route("/search")
def search():
    posts = Posts.query.filter_by(title=request.args.get("query")).all()

    return render_template("posts.html", posts=posts)

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if not current_user.is_authenticated:
        form = RegisterForm()

        if form.validate_on_submit():
            # ceu = Check Existent User
            # cee = Check Existent Email
            ceu = bool(Users.query.filter_by(username=form.username.data).first())
            cee = bool(Users.query.filter_by(email=form.email.data).first())
            
            if ceu == True:
                flash("The username was taken by someone else. Try again with a new one.", "alert-dark")
            elif cee == True:
                flash("A user with this email already exists. Try again with a new one.", "alert-warning")
            else:
                hashed_pw = generate_password_hash(form.password.data, method="sha256")
                new_user = Users(username=form.username.data, email=form.email.data, password=hashed_pw)
                db.session.add(new_user)
                db.session.commit()
                flash("You've been registered successfully", "alert-success")
                return redirect(url_for("signin"))

        return render_template("signup.html", form=form)

    flash("You are already logged in.", "alert-primary")
    return redirect(url_for("posts"))

@app.route("/signin", methods=["GET", "POST"])
def signin():
    if not current_user.is_authenticated:
        form = LoginForm()

        if form.validate_on_submit():
            user = Users.query.filter_by(email=form.email.data).first()

            if user and check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember)
                return redirect(url_for("posts"))
            flash("Your credentials are invalid. Double check and try again.", "alert-warning")
    
        return render_template("signin.html", form=form)

    flash("You are already logged in.", "alert-primary")
    return redirect(url_for("posts"))

@app.route("/settings/profile", methods=["GET", "POST"])
@login_required
def settings_profile():
    user = Users.query.filter_by(username=current_user.username).first()

    if request.method == "POST":
        user.name = request.form["name"]
        user.description = request.form["description"]
        user.contact = request.form["contact"]
        user.web = request.form["web"]
        user.profile_url = request.form["profile_url"]
        db.session.commit()
        flash("You've updated your profile successfully.", "alert-success")
        return redirect(url_for("profile", username=current_user.username))

    if user:
        email = user.email.encode("utf-8")
        if user.profile_url:
            image = user.profile_url
        else:
            image = "http://kappaincor.16mb.com/img/carita.png"
        size = 400
        gravatar_url = "https://www.gravatar.com/avatar/" + hashlib.md5(email.lower()).hexdigest() + "?"
        gravatar_url += urllib.parse.urlencode({'d':image, 's':str(size)})
        return render_template("edit_profile.html", user=user, posts=posts, gravatar_url=gravatar_url)

    return render_template("edit_profile.html")

@app.route("/profile/<string:username>/")
def profile(username):
    user = Users.query.filter_by(username=username).first()
    if user:
        posts = Posts.query.filter_by(author=username).order_by(Posts.date_modified).limit(10).all()
        email = user.email.encode("utf-8")
        if user.profile_url:
            image = user.profile_url
        else:
            image = "http://kappaincor.16mb.com/img/carita.png"
        size = 400
        gravatar_url = "https://www.gravatar.com/avatar/" + hashlib.md5(email.lower()).hexdigest() + "?"
        gravatar_url += urllib.parse.urlencode({'d':image, 's':str(size)})
        return render_template("user_profile.html", user=user, posts=posts, gravatar_url=gravatar_url)
        
    return render_template("page_not_found.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You've logged out correctly.", "alert-secondary")
    
    return redirect(url_for("posts"))

@app.errorhandler(404)
def page_not_found(error):
    return render_template("page_not_found.html"), 404

if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
