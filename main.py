import sqlalchemy.exc
from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, ForeignKey
from sqlalchemy import Column, String, Integer, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_wtf import FlaskForm
from flask_gravatar import Gravatar
from functools import wraps
from flask_ckeditor import CKEditor, CKEditorField
from flask_gravatar import Gravatar
import os
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
gravatar = Gravatar(app, size=100, rating='g', default='retro', base_url=None)

login = LoginManager()

login.init_app(app)

engine = create_engine(SQLALCHEMY_DATABASE_URI, connect_args={'check_same_thread': False})
Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///blog.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False



##CONFIGURE TABLES

# Parent
class User(Base, UserMixin):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False, unique=True)
    email = Column(String(100), nullable=False, unique=True)
    password = Column(String(250), nullable=False)
    posts = relationship('BlogPost', back_populates='author')
    comments = relationship("Comment", back_populates="comment_author")


# Child
class BlogPost(Base):
    __tablename__ = "blog_posts"
    id = Column(Integer, primary_key=True)
    author_id = Column(Integer, ForeignKey('users.id'))
    author = relationship('User', back_populates='posts')
    title = Column(String(250), unique=True, nullable=False)
    subtitle = Column(String(250), nullable=False)
    date = Column(String(250), nullable=False)
    body = Column(String, nullable=False)
    img_url = Column(String(250), nullable=False)
    comments = relationship('Comment', back_populates='parent_post')


class Comment(Base):
    __tablename__ = 'comments'
    id = Column(Integer, primary_key=True)
    text = Column(String(250), unique=True)
    author_id = Column(Integer, ForeignKey("users.id"))
    comment_author = relationship('User', back_populates='comments')
    post_id = Column(Integer, ForeignKey('blog_posts.id'))
    parent_post = relationship('BlogPost', back_populates='comments')



Base.metadata.create_all(engine)

# ORM Mapper
local = Session(bind=engine)


# Login Loader

@login.user_loader
def load_user(user_id):
    user_id = local.query(User).filter(User.id == user_id).first()
    return user_id


##CONFIGURE WTFFORM

class CommentForm(FlaskForm):
    comment = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField('Submit Comment')


class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    author = StringField("Your Name", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class LoginForm(FlaskForm):
    email = StringField("Email")
    password = PasswordField("Password")
    submit = SubmitField("Let me in!")


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password")
    name = StringField("Name")
    submit = SubmitField("Sign me up!")


@app.route('/')
def get_all_posts():
    posts = local.query(BlogPost).all()
    return render_template("index.html", all_posts=posts, admin_id=request.args.get('admin_id'))


@app.route('/login', methods=['POST', 'GET'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user = local.query(User).filter(User.email == login_form.data.get('email')).first()
        if user is None:
            flash("That email does not exist, Please try again")
            return redirect(url_for('login'))
        if check_password_hash(user.password, login_form.data.get('password')):
            login_user(user)
            return redirect(url_for('get_all_posts', user=user.is_authenticated, admin_id=user.id))
        else:
            flash("Password incorrect, Please try again")
            return redirect(url_for('login'))
    return render_template("login.html", form=login_form)


def admin_only(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return func(*args, **kwargs)

    return wrapper


@app.route('/register', methods=['POST', 'GET'])
def register():
    local = Session(bind=engine)
    form = RegisterForm()
    if form.validate_on_submit():
        new_user = User()
        new_user_id = local.query(User).order_by(User.id.desc()).first()
        if new_user_id is None:
            new_user.id = 1
        else:
            new_user.id = new_user_id.id + 1
        new_user.email = form.data.get('email')
        new_user.name = form.data.get('name')
        new_user.password = form.data.get('password')
        # Hashing and salting the password using Werkzueg
        new_user.password = generate_password_hash(new_user.password, method="pbkdf2:sha256", salt_length=8)
        local.add(new_user)
        try:
            local.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
        except sqlalchemy.exc.IntegrityError:
            flash("You've already signed up with that email, please Log-in instead!")
            return redirect(url_for('login'))
    return render_template("register.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>/", methods=['POST', 'GET'])
def show_post(post_id):
    form = CommentForm()
    all_comments = local.query(Comment).all()
    all_posts = local.query(BlogPost).all()
    requested_post = None
    for blog_post in all_posts:
        if blog_post.id == post_id:
            requested_post = blog_post
    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(text=form.data.get('comment'),
                                  post_id=post_id,
                                  author_id=current_user.id)
            local.add(new_comment)
            local.commit()

            return redirect(url_for("show_post", post_id=post_id, comment_author=requested_post.author.name))
        else:
            flash('You need to login or register to comment')
            return redirect(url_for('login'))

    return render_template("post.html", post=requested_post, admin=request.args.get('admin'), comment_text=all_comments,
                           comment=form)

    # id = Column(Integer, primary_key=True)
    # text = Column(String(250), unique=True)
    # author_id = Column(Integer, ForeignKey("users.id"))
    # post_id = Column(Integer, ForeignKey('blog_posts.id'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['POST', 'GET'])
@admin_only
def create_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(title=form.title.data,
                            subtitle=form.subtitle.data,
                            author=current_user,
                            img_url=form.img_url.data,
                            date=date.today().strftime("%B %d, %Y"),
                            body=form.body.data)
        local.add(new_post)
        local.commit()
        return redirect(url_for("get_all_posts"))
    return render_template('make-post.html', form=form, user=current_user.is_authenticated)


@app.route('/edit-post/<int:post_id>', methods=['POST', 'GET'])
@admin_only
def edit_post(post_id):
    local = Session(bind=engine)
    post = local.query(BlogPost).filter(post_id == BlogPost.id).first()
    edit_form = CreatePostForm(title=post.title,
                               subtitle=post.subtitle,
                               img_url=post.img_url,
                               author=current_user,
                               body=post.body)
    if edit_form.validate_on_submit():
        local = Session(bind=engine)
        blog_to_update = local.query(BlogPost).filter(BlogPost.id == post_id).first()
        blog_to_update.title = edit_form.title.data
        blog_to_update.author = edit_form.author.data
        blog_to_update.subtitle = edit_form.subtitle.data
        blog_to_update.img_url = edit_form.img_url.data
        blog_to_update.body = edit_form.body.data
        local.commit()

        return redirect(url_for("show_post", index=post_id))

    return render_template('make-post.html', form=edit_form, edit=True, current_user=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    local = Session(bind=engine)
    blog_to_delete = local.query(BlogPost).filter(BlogPost.id == post_id).first()
    local.delete(blog_to_delete)
    local.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
