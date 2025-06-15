from __init__ import create_app, db, bcrypt
from flask import render_template, request, redirect, url_for, flash
from models import User, WorkoutLog, WorkoutPlan, MealLog, Feedback, FeedbackForm, CoachRequest, ForumPost, ForumReply, ForumReport
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
import io
import base64
import matplotlib.pyplot as plt

app = create_app()

# --- AUTH ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        specialization = request.form.get('specialization')
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(name=name, email=email, password=hashed_pw, role=role,
                        specialization=specialization if role == 'coach' else None)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            if user.suspended:
                return "Your account has been suspended. Please contact admin.", 403
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            return "Invalid email or password", 401
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
def home():
    return render_template('home.html')


# --- REQUEST COACH FEATURE ---
@app.route('/request_coach/<int:coach_id>', methods=['POST'])
@login_required
def request_coach(coach_id):
    if current_user.role != 'user':
        flash("Only regular users can request coaches.")
        return redirect(url_for('find_coach'))
    coach = User.query.get_or_404(coach_id)
    if coach.role != 'coach':
        flash("Selected user is not a coach.")
        return redirect(url_for('find_coach'))

    existing_accepted = CoachRequest.query.filter_by(user_id=current_user.id, status='accepted').first()
    if existing_accepted:
        flash("You already have an accepted coach. You can't request another.")
        return redirect(url_for('find_coach'))

    existing = CoachRequest.query.filter_by(user_id=current_user.id, coach_id=coach_id).first()
    if existing:
        flash("You have already requested this coach.")
        return redirect(url_for('find_coach'))

    new_request = CoachRequest(user_id=current_user.id, coach_id=coach_id)
    db.session.add(new_request)
    db.session.commit()
    flash("Coach request sent successfully!")
    return redirect(url_for('find_coach'))

# --- DASHBOARD ---
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'user':
        accepted_request = CoachRequest.query.filter_by(user_id=current_user.id, status='accepted').first()
        return render_template('user_home.html', accepted_request=accepted_request)
    elif current_user.role == 'coach':
        return render_template('coach_home.html')
    elif current_user.role == 'admin':
        return render_template('admin_home.html')
    else:
        return "<h3>Unknown role – contact support.</h3>"

# --- FEEDBACK ---
@app.route('/send_feedback/<int:user_id>', methods=['GET', 'POST'])
@login_required
def send_feedback(user_id):
    if current_user.role != 'coach':
        return "Access denied", 403
    user = User.query.get_or_404(user_id)
    form = FeedbackForm()
    if form.validate_on_submit():
        feedback = Feedback(coach_id=current_user.id, user_id=user.id, content=form.content.data)
        db.session.add(feedback)
        db.session.commit()
        flash('Feedback sent successfully!', 'success')
        return redirect(url_for('coach_dashboard'))
    return render_template('send_feedback.html', user=user, form=form)

@app.route('/my_feedback')
@login_required
def my_feedback():
    feedbacks = Feedback.query.filter_by(user_id=current_user.id).order_by(Feedback.timestamp.desc()).all()
    return render_template('my_feedback.html', feedbacks=feedbacks)

# --- COACH TOOLS ---

@app.route('/assign_plan', methods=['POST'])
@login_required
def assign_plan():
    if current_user.role != 'coach':
        return "Access denied", 403
    user_id = request.form['user_id']
    title = request.form['title']
    description = request.form['description']
    plan = WorkoutPlan(coach_id=current_user.id, user_id=user_id, title=title, description=description)
    db.session.add(plan)
    db.session.commit()
    return redirect(url_for('coach_dashboard'))

@app.route('/my_plans')
@login_required
def my_plans():
    if current_user.role != 'coach':
        return "Access denied", 403
    plans = WorkoutPlan.query.filter_by(coach_id=current_user.id).all()
    return render_template('my_plans.html', plans=plans)

# --- USER FEATURES ---
@app.route('/assigned_plans')
@login_required
def assigned_plans():
    if current_user.role != 'user':
        return "Access denied", 403
    plans = WorkoutPlan.query.filter_by(user_id=current_user.id).all()
    return render_template('assigned_plans.html', plans=plans)

@app.route('/complete_plan/<int:plan_id>')
@login_required
def complete_plan(plan_id):
    plan = WorkoutPlan.query.get_or_404(plan_id)
    if current_user.id != plan.user_id:
        return "Unauthorized", 403
    plan.completed = True
    db.session.commit()
    return redirect(url_for('assigned_plans'))

@app.route('/log_workout', methods=['GET', 'POST'])
@login_required
def log_workout():
    if request.method == 'POST':
        workout = WorkoutLog(
            user_id=current_user.id,
            exercise=request.form['exercise'],
            duration=request.form['duration'],
            notes=request.form['notes']
        )
        db.session.add(workout)
        db.session.commit()
        return redirect(url_for('view_workouts'))
    return render_template('log_workout.html')

@app.route('/my_workouts')
@login_required
def view_workouts():
    workouts = WorkoutLog.query.filter_by(user_id=current_user.id).all()
    return render_template('view_workouts.html', workouts=workouts)

@app.route('/edit_workout/<int:workout_id>', methods=['GET', 'POST'])
@login_required
def edit_workout(workout_id):
    workout = WorkoutLog.query.get_or_404(workout_id)
    if workout.user_id != current_user.id:
        return "Unauthorized", 403
    if request.method == 'POST':
        workout.exercise = request.form['exercise']
        workout.duration = request.form['duration']
        workout.notes = request.form['notes']
        db.session.commit()
        return redirect(url_for('view_workouts'))
    return render_template('edit_workout.html', workout=workout)

@app.route('/delete_workout/<int:workout_id>')
@login_required
def delete_workout(workout_id):
    workout = WorkoutLog.query.get_or_404(workout_id)
    if workout.user_id != current_user.id:
        return "Unauthorized", 403
    db.session.delete(workout)
    db.session.commit()
    return redirect(url_for('view_workouts'))


@app.route('/weekly_report')
@login_required
def weekly_report():
    now = datetime.utcnow()
    one_week_ago = now - timedelta(days=7)
    workouts = WorkoutLog.query.filter(
        WorkoutLog.user_id == current_user.id,
        WorkoutLog.timestamp >= one_week_ago
    ).all()
    completed_plans = WorkoutPlan.query.filter_by(user_id=current_user.id, completed=True).count()
    active_plans = WorkoutPlan.query.filter_by(user_id=current_user.id, completed=False).all()
    return render_template('weekly_report.html',
                           workouts=workouts,
                           completed_count=completed_plans,
                           active_plans=active_plans,
                           week_start=one_week_ago.date(),
                           week_end=now.date())

@app.route('/log_meal', methods=['GET', 'POST'])
@login_required
def log_meal():
    if request.method == 'POST':
        meal = MealLog(
            user_id=current_user.id,
            food=request.form['food'],
            calories=int(request.form['calories']),
            notes=request.form['notes']
        )
        db.session.add(meal)
        db.session.commit()
        return redirect(url_for('my_meals'))
    return render_template('log_meal.html')

@app.route('/my_meals')
@login_required
def my_meals():
    meals = MealLog.query.filter_by(user_id=current_user.id).order_by(MealLog.timestamp.desc()).all()
    total = sum(m.calories for m in meals)
    return render_template('my_meals.html', meals=meals, total=total)

@app.route('/my_requests')
@login_required
def my_requests():
    if current_user.role != 'user':
        return "Access denied", 403
    requests = CoachRequest.query.filter_by(user_id=current_user.id).order_by(CoachRequest.timestamp.desc()).all()
    return render_template('my_requests.html', requests=requests)

@app.route('/coach_requests')
@login_required
def coach_requests():
    if current_user.role != 'coach':
        return "Access denied", 403

    requests = CoachRequest.query.filter_by(
        coach_id=current_user.id
    ).order_by(CoachRequest.timestamp.desc()).all()

    return render_template('coach_requests.html', requests=requests)


# --- ADMIN TOOLS ---
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return "Access denied", 403
    users = User.query.filter(User.role != 'admin').all()
    return render_template('admin_dashboard.html', users=users)

@app.route('/suspend_user/<int:user_id>')
@login_required
def suspend_user(user_id):
    if current_user.role != 'admin':
        return "Access denied", 403
    user = User.query.get_or_404(user_id)
    user.suspended = True
    db.session.commit()
    flash('User suspended.', 'warning')
    return redirect(url_for('admin_dashboard'))

@app.route('/reactivate_user/<int:user_id>')
@login_required
def reactivate_user(user_id):
    if current_user.role != 'admin':
        return "Access denied", 403
    user = User.query.get_or_404(user_id)
    user.suspended = False
    db.session.commit()
    flash('User reactivated.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        return "Access denied", 403

    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        return "You can't delete another admin", 403

    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/verify_coach/<int:user_id>')
@login_required
def verify_coach(user_id):
    if current_user.role != 'admin':
        return "Access denied", 403
    user = User.query.get_or_404(user_id)
    if user.role != 'coach':
        return "Only coaches can be verified", 400
    user.is_verified = True
    db.session.commit()
    flash('Coach verified.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/unverify/<int:user_id>')
@login_required
def unverify_coach(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'coach':
        user.is_verified = False
        db.session.commit()
        flash(f"Coach {user.name} has been unverified.", "info")
    return redirect(url_for('admin_dashboard'))

@app.route('/find_coach')
@login_required
def find_coach():
    if current_user.role != 'user':
        return "Only users can find coaches.", 403
    search = request.args.get('search')
    specialization = request.args.get('specialization')
    query = User.query.filter_by(role='coach', is_verified=True)
    if search:
        query = query.filter(User.name.ilike(f"%{search}%"))
    if specialization:
        query = query.filter(User.specialization.ilike(f"%{specialization}%"))
    coaches = query.all()
    return render_template('find_coach.html', coaches=coaches, search=search, specialization=specialization)

@app.route('/coach_dashboard')
@login_required
def coach_dashboard():
    if current_user.role != 'coach':
        return redirect(url_for('dashboard'))

    # Fetch accepted requests only
    accepted_requests = CoachRequest.query.filter_by(
        coach_id=current_user.id,
        status='accepted'
    ).all()

    # Get the actual client User objects from the accepted requests
    users = [req.user for req in accepted_requests]

    return render_template('coach_dashboard.html', users=users)



@app.route('/respond_request/<int:request_id>/<string:action>', methods=['POST'])
@login_required
def respond_request(request_id, action):
    if current_user.role != 'coach':
        return "Access denied", 403
    req = CoachRequest.query.get_or_404(request_id)
    if req.coach_id != current_user.id:
        return "Unauthorized", 403

    if action == 'accept':
        req.status = 'accepted'
        # Reject all other pending requests for this user
        other_pending = CoachRequest.query.filter(
            CoachRequest.user_id == req.user_id,
            CoachRequest.status == 'pending',
            CoachRequest.id != req.id
        ).all()
        for r in other_pending:
            r.status = 'rejected'
        flash("You accepted the request. Other pending requests were rejected.")
    elif action == 'reject':
        req.status = 'rejected'
        flash("You rejected the request.")
    else:
        return "Invalid action", 400

    db.session.commit()
    return redirect(url_for('coach_requests'))
# --- COMMUNITY FORUM ---

@app.route('/forum', methods=['GET', 'POST'])
@login_required
def forum():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        post = ForumPost(user_id=current_user.id, title=title, content=content)
        db.session.add(post)
        db.session.commit()
        flash("Your post has been added.")
        return redirect(url_for('forum'))

    posts = ForumPost.query.order_by(ForumPost.timestamp.desc()).all()
    return render_template('forum.html', posts=posts)

@app.route('/reply/<int:post_id>', methods=['POST'])
@login_required
def reply(post_id):
    post = ForumPost.query.get_or_404(post_id)
    content = request.form['reply_content']
    reply = ForumReply(post_id=post.id, user_id=current_user.id, content=content)
    db.session.add(reply)
    db.session.commit()
    flash("Reply posted.")
    return redirect(url_for('forum'))

@app.route('/delete_post/<int:post_id>')
@login_required
def delete_post(post_id):
    if current_user.role != 'admin':
        return "Access denied", 403
    post = ForumPost.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    flash("Post deleted.")
    return redirect(url_for('forum'))

@app.route('/delete_reply/<int:reply_id>')
@login_required
def delete_reply(reply_id):
    if current_user.role != 'admin':
        return "Access denied", 403
    reply = ForumReply.query.get_or_404(reply_id)
    db.session.delete(reply)
    db.session.commit()
    flash("Reply deleted.")
    return redirect(url_for('forum'))

@app.route('/report_post/<int:post_id>', methods=['POST'])
@login_required
def report_post(post_id):
    post = ForumPost.query.get_or_404(post_id)

    if post.user_id == current_user.id:
        flash("You cannot report your own post.")
        return redirect(url_for('forum'))

    existing = ForumReport.query.filter_by(post_id=post_id, user_id=current_user.id).first()
    if existing:
        flash("You already reported this post.")
        return redirect(url_for('forum'))

    reason = request.form.get('reason', '').strip()
    report = ForumReport(post_id=post_id, user_id=current_user.id, reason=reason)
    db.session.add(report)
    db.session.commit()
    flash("Post reported to admin.")
    return redirect(url_for('forum'))


@app.route('/reported_posts')
@login_required
def reported_posts():
    if current_user.role != 'admin':
        return "Access denied", 403

    reports = ForumReport.query.order_by(ForumReport.timestamp.desc()).all()
    return render_template('reported_posts.html', reports=reports)

@app.route('/delete_report/<int:report_id>')
@login_required
def delete_report(report_id):
    if current_user.role != 'admin':
        return "Access denied", 403
    report = ForumReport.query.get_or_404(report_id)
    db.session.delete(report)
    db.session.commit()
    flash("Report removed.")
    return redirect(url_for('reported_posts'))

@app.route('/admin_stats')
@login_required
def admin_stats():
    if current_user.role != 'admin':
        return "Access denied", 403

    user_count = User.query.filter(User.role == 'user').count()
    coach_count = User.query.filter(User.role == 'coach').count()
    verified_coaches = User.query.filter_by(role='coach', is_verified=True).count()
    suspended_count = User.query.filter_by(suspended=True).count()

    post_count = ForumPost.query.count()
    report_count = ForumReport.query.count()

    return render_template('admin_stats.html',
                           user_count=user_count,
                           coach_count=coach_count,
                           verified_coaches=verified_coaches,
                           suspended_count=suspended_count,
                           post_count=post_count,
                           report_count=report_count)



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)