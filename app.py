from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisissecret'

db = SQLAlchemy(app)


class JWTToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(80), unique=True, nullable=False)
    token = db.Column(db.String(255))


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    weight = db.Column(db.Integer, nullable=True)

    def to_dict(self):
        return {
            'name': self.name,
            'weight': self.weight
        }


class Exercises(db.Model):
    __tablename__ = 'exercises'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)
    description = db.Column(db.String(255))
    instruction = db.Column(db.String(255))
    target_muscles = db.Column(db.String(100))

    def to_dict(self):
        return {
            'name': self.name,
            'description': self.description,
            'instruction': self.instruction,
            'target_muscles': self.target_muscles
        }


class WorkoutPlans(db.Model):
    __tablename__ = 'workout_plans'
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(50))
    exercise_name = db.Column(db.String(255))
    frequency = db.Column(db.Integer)
    goals = db.Column(db.String(255))
    exercise_type = db.Column(db.String(100))
    daily_session_duration = db.Column(db.Integer)

    def to_dict(self):
        return {
            'user_name': self.user_name,
            'exercise_name': self.exercise_name,
            'frequency': self.frequency,
            'goals': self.goals,
            'exercise_type': self.exercise_type,
            'daily_session_duration': self.daily_session_duration,
        }


@app.route('/user_plans', methods=['POST'])
def add_user_plan():
    token = request.headers['x-access-token']
    if not token:
        return make_response({'message': 'Not authenticated'}, 200)
    data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    user = data['name']

    data = request.get_json()
    exercise_name = data['exercise_name']
    frequency = data['frequency']
    goals = data['goals']
    exercise_type = data['exercise_type']
    daily_session_duration = data['daily_session_duration']

    user_plan = WorkoutPlans(
        user_name=user,
        exercise_name=exercise_name,
        frequency=frequency,
        goals=goals,
        exercise_type=exercise_type,
        daily_session_duration=daily_session_duration)
    db.session.add(user_plan)
    db.session.commit()

    return jsonify({"message": "Successfully added"})


@app.route('/get_plans', methods=['GET'])
def get_plans():
    token = request.headers['x-access-token']
    if not token:
        return make_response({'message': 'Not authenticated'}, 200)
    data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    user = data['name']

    user_plans = [plan.to_dict() for plan in WorkoutPlans.query.filter_by(user_name=user)]
    return user_plans


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    username = data['username']
    password = data['password']
    weight = data['weight']
    if username and password:
        hashed_password = generate_password_hash(password)
        new_user = User(name=username, password=hashed_password, weight=weight)
        db.session.add(new_user)
        db.session.commit()
        return make_response("User registered successfully!", 200)

    return make_response("Could not verify!", 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    username = data['username']
    password = data['password']

    user = User.query.filter_by(name=username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user.password, password):
        token = jwt.encode(
            {'name': user.name, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
            app.config['SECRET_KEY'])

        db.session.add(JWTToken(user=username, token=token))
        db.session.commit()
        return jsonify({'token': token})

    return make_response('Could not verify 2', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


@app.route('/logout', methods=['POST'])
def logout():
    token = request.headers['x-access-token']
    if not token:
        return make_response({'message': 'Not authenticated'}, 200)
    payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    user = User.query.filter_by(name=payload['name']).first()

    del_data = JWTToken.query.filter_by(user=user.name).first()
    db.session.delete(del_data)
    db.session.commit()

    return jsonify({'message': 'You have been logged out'})


@app.route('/user', methods=['GET'])
def get_user():
    token = request.headers['x-access-token']
    if not token:
        return make_response({'message': 'Not authenticated'}, 200)
    data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    user = User.query.filter_by(name=data['name']).first()
    return make_response({'m': user.name}, 200)


@app.route('/exercises', methods=['GET'])
def get_exercises():
    exercises = [exercise.to_dict() for exercise in Exercises.query.all()]

    return exercises, 200


@app.route('/tracker', methods=['GET'])
def get_tracker():
    token = request.headers['x-access-token']
    if not token:
        return make_response({'message': 'Not authenticated'}, 200)
    payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    user = User.query.filter_by(name=payload['name']).first()
    data = request.get_json()

    weight_now = data['weight_now']

    if weight_now < user.weight:
        difference = user.weight - weight_now
        user.weight = weight_now
        db.session.commit()
        return make_response({'message': f'You have lost weight {difference} kg'})

    elif weight_now == user.weight:
        user.weight = weight_now
        db.session.commit()
        return make_response({'message': "You are same weight as you were!"})

    else:
        difference = weight_now - user.weight
        user.weight = weight_now
        db.session.commit()
        return make_response({'message': f"You are fatter than you were! You gained {difference} kg"})


with app.app_context():
    db.create_all()
    app.run(debug=True)
