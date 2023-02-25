from flask import jsonify, request, session, Blueprint
from marshmallow import ValidationError
from flask_restful import Api, Resource
from flask_bcrypt import bcrypt
from models import *
from item import StreaksSchema, UserSchema, WorkoutSchema, PaymetSchema, SubscriptionSchema, VideoSchema
import re

USER_NOT_FOUND = "User not found."
WORKOUT_NOT_FOUND = "Workout not found."
PAYMENT_NOT_FOUND = "Payment not found."
SUBSCRIPTION_NOT_FOUND = "Subscription not found."
VIDEO_NOT_FOUND = "Video not found."

# Initialize schema
user_schema = UserSchema()
users_schema = UserSchema(many=True)

# Initialize schema
workout_schema = WorkoutSchema()
workouts_schema = WorkoutSchema(many=True)

# Initialize schema
payment_schema = PaymetSchema()
payments_schema = PaymetSchema(many=True)

# Initialize schema
subscription_schema = SubscriptionSchema()
subscriptions_schema = SubscriptionSchema(many=True)

# Initialize schema
video_schema = VideoSchema()
videos_schema = VideoSchema(many=True)

#initialize schema
streak_schema = StreaksSchema()
streaks_schema = StreaksSchema(many=True)

api_bp = Blueprint('api', __name__,url_prefix='/api')
api = Api(api_bp)

@api.resource("/users", "/users/<int:id>")
class UsersList(Resource):
	def get(self):
		return users_schema.dump(User.find_all()), 200

	def put(self, id):
		user_json = request.get_json()
		if not user_json:
			return {'message': "No input data provided"}, 400
		try:
			user_data = user_schema.load(user_json)
			if not re.match(r'[^@]+@[^@]+\.[^@]+', user_data.email):
				return 'Invalid email', 400
		except ValidationError as err:
			return err.messages, 422
		user = User.find_by_id(id)
		if not user:
			return {'message': USER_NOT_FOUND}, 404
		user.email = user_data.email
		user.fullname = user_data.fullname
		user.phoneNumber = user_data.phoneNumber
		user.password = bcrypt.hashpw(user_data.password.encode('utf-8'), bcrypt.gensalt())
		user.save_to_db()
		return user_schema.dump(user), 200

	def delete(self, id):
		users_to_delete = User.find_by_id(id)
		users_to_delete.delete_from_db()
		return jsonify({"message": "User Deleted Successfully"}), 204


@api.resource("/user", "/user/<int:id>")
class Users(Resource):
	def post(self):
		user_json = request.get_json()
		if not user_json:
			return {'message': 'No input data provided'}, 400
		# Validate and deserialize input
		try:
			user_data = user_schema.load(user_json)
		except ValidationError as err:
			return err.messages, 422
		hashed_password = bcrypt.hashpw(user_data.password.encode('utf-8'), bcrypt.gensalt())
		user = User(fullname=user_data.fullname, email=user_data.email, phoneNumber=user_data.phoneNumber,
		            password=hashed_password)
		user.save_to_db()
		return user_schema.dump(user), 201

	def get(self, id):
		user_data = User.find_by_id(id)
		if user_data:
			return user_schema.dump(user_data)
		return {'message': USER_NOT_FOUND}, 404

	def put(self):
		user_json = request.get_json()
		if not user_json:
			return {'message': "No input data provided"}, 400
		try:
			user_data = user_schema.load(user_json)
			if not re.match(r'[^@]+@[^@]+\.[^@]+', user_data.email):
				return 'Invalid email', 400
		except ValidationError as err:
			return err.messages, 422
		hashed_password = bcrypt.hashpw(user_data.password.encode('utf-8'), bcrypt.gensalt())
		user = User(fullname=user_data.fullname, email=user_data.email, phoneNumber=user_data.phoneNumber,
		            password=hashed_password)
		user.save_to_db()
		return user_schema.dump(user), 200

	def delete(self, id):
		users_to_delete = User.find_by_id(id)
		users_to_delete.delete_from_db()
		return jsonify({"message": "User Deleted Successfully"}), 204


# @api.resource("/user/login")
# class Login(Resource):
#
#     def post(self):
#         data = request.get_json()
#         try:
#             result = user_schema.load(data)
#         except ValidationError as err:
#             print(err.messages)
#             return err.messages, 422

#         hashed_password = bcrypt.hashpw(result.password.encode('utf-8'), bcrypt.gensalt())
#         user = User.query.filter_by(email=result.email, password=hashed_password).first()

#         if not user:
#             return {'message': 'Invalid email or password'}, 401

#         # Create a JWT token for the user
#         token = jwt.encode({
#             'sub': user.id,
#             'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
#         }, app.config['SECRET_KEY'])

#         return {'token': token.decode('UTF-8')}, 200


@api.resource("/workouts", "/workouts/<id>")
class Workouts(Resource):
	def get(self, id):
		workout = Workout.find_by_id(id)
		if not workout:
			return {'message': 'workout not found'}, 404
		return workout_schema.dump(workout)

	# (Workout.find_all()), 200

	def post(self):
		workout_json = request.get_json()
		workout_data = workout_schema.load(workout_json)
		workout_data.save_to_db()
		return workout_schema.dump(workout_data), 200

	def delete(self, id):
		workout_data = Workout.find_by_id(id)
		if workout_data:
			workout_data.delete_from_db()
			return {'message': "Workout Deleted successfully"}, 200
		return {'status': WORKOUT_NOT_FOUND}

	def put(self, id):
		workout_data = request.get_json()
		if not workout_data:
			return {'message': "No input data provided"}, 400
		try:
			workout = Workout.find_by_id(id)
			if not workout:
				return {'message': WORKOUT_NOT_FOUND}, 404
			workout_data = workout_schema.load(workout_data)
			workout.title = workout_data.title
			workout.description = workout_data.description
			workout.duration = workout_data.duration
			workout.save_to_db()
			return workout_schema.dump(workout), 200
		except ValidationError as err:
			return err.messages, 422


@api.resource("/payment")
class Payments(Resource):
	def get(self, id):
		payment = Payment.find_by_id(id)
		if not payment:
			return {'message': 'Payment not found'}, 404
		return payment_schema.dump(payment), 200

	def post(self):
		payment_json = request.get_json()
		payment_data = payment_schema.load(payment_json)
		payment_data.save_to_db()
		return payment_schema.dump(payment_data), 200

	def put(self):
		payment_json = request.get_json()
		payment_data = payment_schema.load(payment_json)
		payment = Payment.find_by_id(payment_data.id)
		if not payment:
			return {'message': 'Payment not found'}, 404
		payment.save_to_db()
		return payment_schema.dump(payment_data), 200

	def delete(self, id):
		payment_to_delete = Payment.find_by_id(id)
		payment_to_delete.delete_from_db()
		return jsonify({"message": "Payment Deleted Successfully"}), 204


@api.resource("/subscription")
class Subscriptions(Resource):
	def get(self, id):
		subscription = Subscription.find_by_id(id)
		if not subscription:
			return {'message': 'Subscription not found'}, 404
		return subscription_schema.dump(subscription), 200

	def post(self):
		subscription_json = request.get_json()
		subscription_data = subscription_schema.load(subscription_json)
		subscription_data.save_to_db()
		return subscription_schema.dump(subscription_data), 200

	def put(self):
		subscription_json = request.get_json()
		subscription_data = subscription_schema.load(subscription_json)
		subscription = Subscription.find_by_id(subscription_data.id)
		if not subscription:
			return {'message': 'Subscription not found'}, 404
		subscription.save_to_db()
		return subscription_schema.dump(subscription_data), 200

	def delete(self, id):
		subscription_to_delete = Subscription.find_by_id(id)
		subscription_to_delete.delete_from_db()
		return jsonify({"message": "Subscription Deleted Successfully"}), 204


@api.resource("/video")
class Videos(Resource):
	def get(self, id):
		video = Video.find_by_id(id)
		if not video:
			return {'message': 'Video not found'}, 404
		return video_schema.dump(video), 200

	def post(self):
		video_json = request.get_json()
		video_data = video_schema.load(video_json)
		video_data.save_to_db()
		return video_schema.dump(video_data), 200

	def put(self):
		video_json = request.get_json()
		video_data = video_schema.load(video_json)
		video = Video.find_by_id(video_data.id)
		if not video:
			return {'message': 'Video not found'}, 404
		video.save_to_db()
		return video_schema.dump(video_data), 200

	def delete(self, id):
		video_to_delete = Video.find_by_id(id)
		video_to_delete.delete_from_db()
		return jsonify({"message": "Video Deleted Successfully"}), 204


# @app.route("/login", methods=['POST'])
# def login():
#     email = request.json['email']
#     password = request.json['password']
#     user = User.find_by_email(email=email)

#     if user and bcrypt.check_password_hash(user.password, password):
#         return jsonify({'user': user_schema.dump(user)})
#     else:
#         return jsonify({'error': 'Invalid email or password'}), 401

# @app.route("/subscribe", methods=['POST'])
# def subscribe():
#     data = request.get_json()
#     user_id = data['user_id']
#     workout_id = data['workout_id']
#     payment_info = data['payment_info']
#     # Validate user's subscription
#     user = User.query.filter_by(id=user_id).first()
#     # user_schema = UserSchema()
#     user = user_schema.load(user)

#     if user is None:
#         return jsonify({'error': 'User not found'}), 404

#     # Check if the user has an active subscription
#     active_subscription = False
#     for payment in user.payments:
#         if payment.end_time > datetime.now():
#             active_subscription = True
#             break

#     if not active_subscription:
#         return jsonify({'error': 'Please subscribe to access the workout'}), 401

#     # Get workout details
#     workout = Workout.query.filter_by(workout_id=workout_id).first()
#     # workout_schema = WorkoutSchema()
#     workout = workout_schema.load(workout)

#     if workout is None:
#         return jsonify({'error': 'Workout not found'}), 404

#     # Allow user to watch the workout
#     return jsonify({'message': 'Access granted', 'workout': workout_schema.dump(workout)})

# @app.route("/watch-video/<int:video_id>", methods=["GET"])
# def watch_video(video_id):
#     user = User.find_by_id()
#     # get_jwt_identity()
#     if not user.has_valid_subscription():
#         return jsonify({"error": "You must have a valid subscription to watch this video"}), 401
#     # continue with serving the video

@api.resource('/streaks')
class Streaks(Resource):
	def get(self):
		return streaks_schema.dump(Streak.find_all()), 200

	def post(self):
		streak_json = request.get_json()
		streak_data = streak_schema.load(streak_json)
		streak_data.save_to_db()
		return streak_schema.dump(streak_data), 200

	def delete(self):
		Streak.delete_all()
		return jsonify({"message": "All St"})

# def post(self):
#     json_data = request.get_json()
#     data, errors = streak_schema.load(json_data)
#     if errors:
#         return errors, 422
#     user_id = json_data.get("user_id")
#     date = data.get("date")
#     # Save the date to the database for the given user
#     date.save_to_db()
#     user_id.save_to_db()
#     # save_date_to_db(user_id, date)
#     # Fetch the dates from the database for the given user
#     dates = user_id.find_all()
#     # dates = get_dates_from_db(user_id)
#     # Sort the dates in chronological order
#     dates.sort()
#     streak = 0
#     current_streak = 0
#     for i in range(len(dates)):
#         if i == 0:
#             current_streak += 1
#         else:
#             previous_date = dates[i-1]
#             current_date = dates[i]
#             if (current_date - previous_date).days == 1:
#                 current_streak += 1
#             else:
#                 streak = max(streak, current_streak)
#                 current_streak = 0
#     return {"streak": max(streak, current_streak)}

# def save_date_to_db(user_id, date):
# Save the date to the database for the given user
# pass

# def get_dates_from_db(user_id):
# Fetch the dates from the database for the given user
# Example: dates = [datetime(2022, 1, 1), datetime(2022, 1, 2), datetime(2022, 1, 3)]
# return dates
