from flask import Blueprint, flash, g, redirect, render_template, request, url_for, jsonify, session
from .auth import login_required
from sqlalchemy import func, or_
from .models import User, Post, Tag, PostTag, Comment  
from .dbase import db
from werkzeug.utils import secure_filename
import re
import os
from datetime import datetime

bp = Blueprint('blog', __name__, url_prefix='/blog')

@bp.route('/')
def index():
    """Returns the home page"""
    posts = (
        db.session.query(
            Post.id, Post.title, Post.body, Post.created, Post.author_id, User.username,
            db.func.group_concat(Tag.name).label('tags'), Post.image
        )
        .join(User, Post.author_id == User.id)
        .outerjoin(PostTag, Post.id == PostTag.post_id)
        .outerjoin(Tag, PostTag.tag_id == Tag.id)
        .filter(Post.status == 'published')
        .group_by(Post.id)
        .order_by(Post.created.desc())
        .all()
    )
    return render_template('blog/index.html', posts=posts)

@bp.route('/create', methods=('GET', 'POST'))
@login_required
def create():
    """Create a new post"""
    # Query all tags from the database
    tags = Tag.query.all()

    if request.method == 'POST':
        title = request.form['title']
        body = request.form['body']
        selected_tags = request.form.getlist('tags')
        new_tag_name = request.form.get('newTag')
        image = request.files.get('image')
        action = request.form['action']
        created = datetime.now()
        error = None

        if not title:
            error = 'Title is required.'

        if error is not None:
            flash(error)
        else:
            if g.user is None:
                flash('You need to be logged in to create a post.')
                return redirect(url_for('auth.login'))

            status = 'published' if action == 'Publish' else 'draft'
            post = Post(title=title, body=body, author_id=g.user.id, status=status)
            db.session.add(post)
            db.session.commit()

            if image:
                filename = secure_filename(image.filename)
                image.save(os.path.join('/home/tau_rai/try/blogA/static/public/', filename))
                post.image = 'public/' + filename

            if selected_tags:
                for tag_name in selected_tags:
                    tag = Tag.query.filter_by(name=tag_name).first()
                    if tag:
                        post_tag = PostTag(post_id=post.id, tag_id=tag.id)
                        print(post_tag)
                        db.session.add(post_tag)
                        db.session.commit()

            # if new_tag_name:  # Check if 'newTag' field is not empty
            #     existing_tag = Tag.query.filter_by(name=new_tag_name).first()
            #     if not existing_tag:
            #         new_tag = Tag(name=new_tag_name)
            #         db.session.add(new_tag)
            #         db.session.commit()
            #         post_tag = PostTag(post_id=post.id, tag_id=new_tag.id)
            #     else:
            #         post_tag = PostTag(post_id=post.id, tag_id=existing_tag.id)
            #     db.session.add(post_tag)

            db.session.commit()

            if action == 'Publish':
                return redirect(url_for('blog.index'))
            else:
                return redirect(url_for('blog.profile'))

    # Pass the tags to the template
    return render_template('blog/create.html', tags=tags)


@login_required
@bp.route('/<int:id>/update', methods=('GET', 'POST'))
def update(id):
    """Updates a post"""
    post = Post.query.get(id)

    if request.method == 'POST':
        title = request.form['title']
        body = request.form['body']
        image = request.files['image']
        error = None

        if not title:
            error = 'Title is required.'

        if error is not None:
            flash(error)
        else:
            if image:
                filename = secure_filename(image.filename)
                image.save(os.path.join('/home/tau_rai/try/blogA/static/public/', filename))
                post.image = 'public/' + filename
            post.title = title
            post.body = body
            post.status = 'published'
            db.session.commit()
            return redirect(url_for('blog.index'))

    return render_template('blog/update.html', post=post)

@login_required
@bp.route('/<int:id>/delete', methods=('POST',))
def delete(id):
    """Deletes a post"""
    post = Post.query.get(id)
    if post:
        db.session.delete(post)
        db.session.commit()
    return redirect(url_for('blog.index'))

@bp.route('/<int:id>/post_detail', methods=('GET',))
def post_detail(id):
    """Shows post details"""
    post = Post.query.get(id)
    comments = Comment.query.filter_by(post_id=id).all()
    tags = [tag.name for tag in post.tags]
    like_count = post.like_count
    return render_template('blog/post_detail.html', post=post, comments=comments, tags=tags, like_count=like_count)

@bp.route('/<int:id>/comment', methods=('GET', 'POST'))
def comment(id):
    """Create a new comment"""
    if request.method == 'POST':
        body = request.form['body']
        error = None

        if not body:
            error = 'Comment body is required.'

        if g.user is None:
            error = 'You must be logged in to add a comment.'

        if error is not None:
            flash(error, 'error')
        else:
            # Create a new Comment object
            comment = Comment(post_id=id, body=body, author_id=g.user.id)

            # Add the new comment to the session
            db.session.add(comment)

            # Commit the session to save the changes in the database
            db.session.commit()

            return redirect(url_for('blog.detail', id=id))
        
    return render_template('blog/comment.html')

@bp.route('/tags/<tag_name>')
def tag(tag_name):
    """Shows tags"""
    posts = (
        db.session.query(Post.id, Post.title)
        .join(PostTag, Post.id == PostTag.post_id)
        .join(Tag, PostTag.tag_id == Tag.id)
        .filter(Tag.name == tag_name)
        .all()
    )
    return render_template('blog/tag.html', posts=posts, tag_name=tag_name)

@bp.route('/search')
def search():
    """Searches for posts or categories"""
    query = request.args.get('q', '').strip()
    if query == '':
        return render_template('blog/search.html', posts=[])
    else:
        posts = (
            db.session.query(
                Post.id, Post.title, Post.body, Post.created, Post.author_id, User.username,
                db.func.group_concat(Tag.name).label('tags'), Post.image
            )
            .join(User, Post.author_id == User.id)
            .outerjoin(PostTag, Post.id == PostTag.post_id)
            .outerjoin(Tag, PostTag.tag_id == Tag.id)
            .filter(
                db.or_(
                    Post.title.like('%' + query + '%'),
                    Post.body.like('%' + query + '%'),
                    Tag.name.like('%' + query + '%')
                )
            )
            .group_by(Post.id)
            .order_by(Post.created.desc())
            .all()
        )
        return render_template('blog/search.html', posts=posts)

# Regular expression for validating an Email
email_regex = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

@bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """Updates user profile"""
    user = g.user  # Fetch the current logged-in user object
    posts = Post.query.filter_by(author_id=user.id, status='published').all()  # Fetch user's published posts
    drafts = Post.query.filter_by(author_id=user.id, status='draft').all()  # Fetch user's draft posts

    if request.method == 'POST':
        # Fetch form data
        user.first_name = request.form.get('first_name')
        user.last_name = request.form.get('last_name')
        user.date_of_birth = request.form.get('date_of_birth')
        user.bio = request.form.get('bio')
        user.email = request.form.get('email')

        # Fetch profile picture
        avatar = request.files.get('avatar')
        if avatar:
            filename = secure_filename(avatar.filename)
            avatar.save(os.path.join('/home/tau_rai/try/blogA/static/public', filename))
            user.avatar = 'public/' + filename  # Update the user's avatar path

        # Validate email format
        if not re.fullmatch(email_regex, user.email):
            flash('Invalid email address.')
        else:
            # Check if email already exists in the database
            existing_user = User.query.filter(User.email == user.email, User.id != user.id).first()
            if existing_user:
                flash('Email address already in use.')
            else:
                try:
                    # Update user details in the database
                    db.session.commit()
                    flash('Profile updated successfully!')
                except Exception as e:
                    db.session.rollback()
                    flash('An error occurred while updating the profile.')

    return render_template('blog/profile.html', user=user, posts=posts, drafts=drafts)


@bp.route('/privacy-policy')
def privacy():
    """Shows site privacy policy"""
    return render_template('blog/privacy.html')

@bp.route('/terms-of-service')
def terms_of_service():
    """Shows site terms of service"""
    return render_template('blog/terms_of_service.html')

@bp.route('/about')
def about_us():
    """Shows the site about us section"""
    return render_template('blog/about_us.html')

@bp.route('/contact-us')
def contact_us():
    """Shows the site about us section"""
    return render_template('blog/contact_us.html')

@bp.route('/like_post/<int:id>', methods=['POST'])
def like_post(id):
    """Enables users to like posts"""
    post = Post.query.get(id)
    post.like_count += 1
    db.session.commit()
    return jsonify({'like_count': post.like_count})

from . import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)