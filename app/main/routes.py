from flask import Blueprint, render_template, session

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def home():
    user_info = session.get('user_info')
    return render_template('home.html', user_info=user_info)
