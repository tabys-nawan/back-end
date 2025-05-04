from flask import Flask, render_template, request, redirect, url_for, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, decode_token, jwt_required, get_jwt_identity, unset_jwt_cookies
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import timedelta, datetime
import uuid
import os

UPLOAD_FOLDER = 'static/uploads/avatars'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = 'secretkey'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)

db = SQLAlchemy(app)
jwt = JWTManager(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    posts = db.relationship('Post', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)
    avatar = db.Column(db.String(200), default='default.png')

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', backref='post', lazy=True, cascade="all, delete-orphan")

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_approved = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

# Routes
@app.route('/')
def index():
    q = request.args.get('q', '').strip()
    filter_title = request.args.get('filter_title')
    filter_username = request.args.get('filter_username')

    posts = Post.query
    if q:
        if filter_title and filter_username:
            posts = posts.join(User).filter(
                db.or_(
                    Post.title.ilike(f"%{q}%"),
                    User.username.ilike(f"%{q}%")
                )
            )
        elif filter_title:
            posts = posts.filter(Post.title.ilike(f"%{q}%"))
        elif filter_username:
            posts = posts.join(User).filter(User.username.ilike(f"%{q}%"))

    posts = posts.order_by(Post.id.desc()).all()
    user = get_current_user_optional()

    return render_template('index.html', posts=posts, user=user)


@app.route('/register', methods=['GET', 'POST'])
def register():
    user = get_current_user_optional()
    if user:
        return redirect(url_for('profile'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))

        user = User(public_id=str(uuid.uuid4()), username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    user = get_current_user_optional()
    if user:
        return redirect(url_for('profile'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            flash('Invalid credentials.', 'danger')
            return redirect(url_for('login'))

        access_token = create_access_token(identity=user.public_id)
        resp = make_response(redirect(url_for('index')))
        resp.set_cookie('access_token_cookie', access_token, httponly=True)
        return resp
    return render_template('login.html')

@app.route('/logout')
@jwt_required()
def logout():
    resp = make_response(redirect(url_for('index')))
    unset_jwt_cookies(resp)
    flash('Logged out successfully.', 'success')
    return resp

@app.route('/profile')
@jwt_required()
def profile():
    user_id = get_jwt_identity()
    user = User.query.filter_by(public_id=user_id).first()
    return render_template('profile.html', user=user)

@app.route('/about_us')
def about_us():
    return render_template('about_us.html')

@app.route('/edit_profile', methods=['GET', 'POST'])
@jwt_required()
def edit_profile():
    user_id = get_jwt_identity()
    user = User.query.filter_by(public_id=user_id).first()

    if request.method == 'POST':
        file = request.files.get('avatar')
        new_username = request.form['username']
        new_password = request.form['new_password']

        if new_username and new_username != user.username:
            if User.query.filter_by(username=new_username).first():
                flash('Username already taken.', 'warning')
                return redirect(url_for('edit_profile'))
            user.username = new_username

        if new_password:
            user.password = generate_password_hash(new_password)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            ext = filename.rsplit('.', 1)[1]
            unique_filename = f"{uuid.uuid4()}.{ext}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))

            if user.avatar and user.avatar != 'default.png':
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], user.avatar))
                except Exception:
                    pass

            user.avatar = unique_filename

        db.session.commit()
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('profile'))

    return render_template('edit_profile.html', user=user)

@app.route('/create_post', methods=['GET', 'POST'])
@jwt_required()
def create_post():
    user_id = get_jwt_identity()
    user = User.query.filter_by(public_id=user_id).first()
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        post = Post(title=title, content=content, author=user)
        db.session.add(post)
        db.session.commit()
        flash('Post created.', 'success')
        return redirect(url_for('profile'))
    return render_template('create_post.html')

@app.route('/posts/<int:post_id>')
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    user = get_current_user_optional()

    if user and post.author == user:
        comments = Comment.query.filter_by(post_id=post.id).all()  # Показываем все
    else:
        comments = Comment.query.filter_by(post_id=post.id, is_approved=True).all()

    return render_template('view_post.html', post=post, comments=comments, user=user)


@app.route('/posts/<int:post_id>/comment', methods=['POST'])
@jwt_required()
def comment(post_id):
    user_id = get_jwt_identity()
    user = User.query.filter_by(public_id=user_id).first()
    content = request.form['content']
    comment = Comment(content=content, post_id=post_id, user_id=user.id)
    db.session.add(comment)
    db.session.commit()
    flash('Comment submitted for approval.', 'info')
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@jwt_required()
def edit_post(post_id):
    user_id = get_jwt_identity()
    user = User.query.filter_by(public_id=user_id).first()
    post = Post.query.get_or_404(post_id)

    if post.author != user:
        flash("You can only edit your own posts.", 'warning')
        return redirect(url_for('profile'))

    if request.method == 'POST':
        post.title = request.form['title']
        post.content = request.form['content']
        db.session.commit()
        flash('Post updated.', 'success')
        return redirect(url_for('profile'))

    return render_template('edit_post.html', post=post, user=user)

@app.route('/delete_post/<int:post_id>')
@jwt_required()
def delete_post(post_id):
    user_id = get_jwt_identity()
    user = User.query.filter_by(public_id=user_id).first()
    post = Post.query.get_or_404(post_id)

    if post.author != user:
        flash("You can only delete your own posts.", 'warning')
        return redirect(url_for('profile'))

    db.session.delete(post)
    db.session.commit()
    flash('Post deleted.', 'success')
    return redirect(url_for('profile'))

@app.route('/delete_comment/<int:comment_id>')
@jwt_required()
def delete_comment(comment_id):
    user_id = get_jwt_identity()
    user = User.query.filter_by(public_id=user_id).first()
    comment = Comment.query.get_or_404(comment_id)
    post = Post.query.get(comment.post_id)

    if comment.author != user and post.author != user:
        flash("You can only delete your own comments or comments on your own posts.", 'warning')
        return redirect(url_for('profile'))

    db.session.delete(comment)
    db.session.commit()
    flash('Comment deleted.', 'success')
    return redirect(url_for('view_post', post_id=comment.post_id))

@app.route('/moderate_comments/<int:post_id>')
@jwt_required()
def moderate_comments(post_id):
    user_id = get_jwt_identity()
    user = User.query.filter_by(public_id=user_id).first()
    post = Post.query.get_or_404(post_id)

    if post.author != user:
        flash("You can only moderate your own posts.", "warning")
        return redirect(url_for('index'))

    pending_comments = Comment.query.filter_by(post_id=post.id, is_approved=False).all()
    return render_template('moderate_comments.html', post=post, comments=pending_comments, user=user)

@app.route('/approve_comment/<int:comment_id>')
@jwt_required()
def approve_comment(comment_id):
    user_id = get_jwt_identity()
    user = User.query.filter_by(public_id=user_id).first()
    comment = Comment.query.get_or_404(comment_id)
    post = comment.post

    if post.author != user:
        flash("You can't approve comments on others' posts.", "danger")
        return redirect(url_for('index'))

    comment.is_approved = True
    db.session.commit()
    flash("Comment approved.", "success")
    return redirect(url_for('moderate_comments', post_id=post.id))

@app.route('/reject_comment/<int:comment_id>')
@jwt_required()
def reject_comment(comment_id):
    user_id = get_jwt_identity()
    user = User.query.filter_by(public_id=user_id).first()
    comment = Comment.query.get_or_404(comment_id)
    post = comment.post

    if post.author != user:
        flash("You can't reject comments on others' posts.", "danger")
        return redirect(url_for('index'))

    db.session.delete(comment)
    db.session.commit()
    flash("Comment rejected and deleted.", "info")
    return redirect(url_for('moderate_comments', post_id=post.id))



def get_current_user_optional():
    token = request.cookies.get('access_token_cookie')
    if not token:
        return None
    try:
        decoded = decode_token(token)
        identity = decoded.get('sub')
        return User.query.filter_by(public_id=identity).first()
    except Exception:
        return None

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@jwt.unauthorized_loader
def custom_unauthorized_response(err_str):
    flash("You must be logged in to access this page.", 'danger')
    return redirect(url_for('login'))

@jwt.invalid_token_loader
def custom_invalid_token_response(err_str):
    flash("Invalid or expired session. Please log in again.", 'warning')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run()
