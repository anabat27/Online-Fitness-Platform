from flask_login import UserMixin
from __init__ import db
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import TextAreaField, SubmitField
from wtforms.validators import DataRequired

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'user', 'coach', 'admin'
    suspended = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    specialization = db.Column(db.String(100))

    # Relationships
    workout_logs = db.relationship('WorkoutLog', backref='user', lazy=True)
    meal_logs = db.relationship('MealLog', backref='user', lazy=True)
    created_plans = db.relationship('WorkoutPlan', foreign_keys='WorkoutPlan.coach_id', backref='coach', lazy=True)
    received_plans = db.relationship('WorkoutPlan', foreign_keys='WorkoutPlan.user_id', backref='user', lazy=True)
    given_feedbacks = db.relationship('Feedback', foreign_keys='Feedback.coach_id', backref='coach', lazy=True)
    received_feedbacks = db.relationship('Feedback', foreign_keys='Feedback.user_id', backref='user_feedback', lazy=True)
    sent_requests = db.relationship('CoachRequest', foreign_keys='CoachRequest.user_id', backref='requester', lazy=True)
    received_requests = db.relationship('CoachRequest', foreign_keys='CoachRequest.coach_id', backref='requested_coach', lazy=True)
    forum_posts = db.relationship('ForumPost', backref='author', lazy=True)
    forum_replies = db.relationship('ForumReply', backref='author', lazy=True)
    forum_reports = db.relationship('ForumReport', backref='reporter', lazy=True)

class WorkoutLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    exercise = db.Column(db.String(100), nullable=False)
    duration = db.Column(db.String(50), nullable=False)
    notes = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class WorkoutPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    completed = db.Column(db.Boolean, default=False)

class MealLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    food = db.Column(db.String(100), nullable=False)
    calories = db.Column(db.Integer, nullable=False)
    notes = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class CoachRequest(db.Model):
    __tablename__ = 'coach_requests'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    coach_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'accepted', 'rejected'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    
    user = db.relationship('User', foreign_keys=[user_id], backref='coach_requests_sent')
    coach = db.relationship('User', foreign_keys=[coach_id], backref='coach_requests_received')

class FeedbackForm(FlaskForm):
    content = TextAreaField('Your Feedback', validators=[DataRequired()])
    submit = SubmitField('Send Feedback')

class ForumPost(db.Model):
    __tablename__ = 'forum_posts'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    replies = db.relationship('ForumReply', backref='post', cascade='all, delete', lazy=True)
    reports = db.relationship('ForumReport', backref='post', lazy=True, cascade="all, delete")

class ForumReply(db.Model):
    __tablename__ = 'forum_replies'
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('forum_posts.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class ForumReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('forum_posts.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reason = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
