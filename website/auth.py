from cmath import e
from flask import Blueprint, flash, render_template, request, redirect , url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
from sqlalchemy.exc import IntegrityError
from werkzeug.utils import secure_filename

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Log In successfully!!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, please try again', category='error')
        else:
            flash('Email does not exist.', category='error')


    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        last_name = request.form.get('lastName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')cache/

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        if len(email) < 4:
            flash('email must be greater than 3 character.', category='error')
        elif len(first_name) < 2:
            flash('First Name must be greater than 1 character.', category='error')
        elif len(last_name) < 2:
            flash('Last Name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('password don\'t match.', category='error')
        elif len(password1) < 8:
            flash('password must be at least 8 character', category='error')
        else:
            add_user = User(email=email, first_name=first_name, last_name=last_name ,password=generate_password_hash(password1, method='sha256'))  
            db.session.add(add_user)
            db.session.commit()
        try:
            db.session.flush()
        except IntegrityError:
            db.session.rollback()

            login_user(user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)

