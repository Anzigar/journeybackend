from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import backref
import uuid

db = SQLAlchemy()

def generate_uuid():
    return str(uuid.uuid4())

#many to many relation ship between user and video
user_video = db.Table(
    'user_video',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id')),
    db.Column('video_id', db.Integer, db.ForeignKey('videos.id')))

# user_streaks = db.Table('user_streak',
#                 db.Column('user_ids', db.Integer, db.Foreignkey('users.id')),
#                 db.Column('streak_id'), db.Integer, db.ForeignKey('streaks.id'))

#user class model
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True, autoincrement= True)
    fullname = db.Column(db.String(255), nullable = False)
    email = db.Column(db.String(255), nullable = False)
    phoneNumber = db.Column(db.String(20),nullable =False )
    password = db.Column(db.String(), nullable = False)
    workouts = db.relationship('Workout', backref=backref('users'))
    payment = db.relationship('Payment', backref=backref('users'))
        
    def __repr__(self):
        return f"<{self.id}>"

    @classmethod
    def find_by_email(cls, email):
        return cls.query.filter_by(email=email).first()

    @classmethod
    def find_all(cls):
        return cls.query.all()

    @classmethod
    def find_by_id(cls, id):
        return cls.query.filter_by(id=id).first()
    
    def save_to_db(self):
        db.session.add(self)
        db.session.commit()
    
    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

#workout class model
class Workout(db.Model):
    __tablename__ = "workouts"

    workout_id = db.Column(db.Integer , primary_key=True, autoincrement= True)
    total_time = db.Column(db.Time, unique=True, nullable=False)
    username_id = db.Column(db.String(255), unique=True, nullable=False)
    calories = db.Column(db.String(255), unique=True, nullable=False)
    strikes = db.Column(db.Integer, unique=True, nullable=False)
    #one to many relation ship
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    def __repr__(self):
        return f"<{self.workout_id}>"

    @classmethod
    def find_by_name(cls, username_id):
        return cls.query.filter_by(username_id=username_id).first()

    @classmethod
    def find_all(cls):
        return cls.query.all()

    @classmethod
    def find_by_id(cls, workout_id):
        return cls.query.filter_by(workout_id=workout_id).first()
    
    def save_to_db(self):
        db.session.add(self)
        db.session.commit()
    
    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

#subscription class model
class Subscription(db.Model):
    __tablename__ = "subscriptions"

    Subscription_id = db.Column(db.Integer, primary_key=True, autoincrement= True)
    Subscription_name = db.Column(db.String(255), unique=True, nullable=False)
    payment_id = db.Column(db.Integer, db.ForeignKey('payments.payment_id'))

    # subscription = db.relationship("Payment", uselist=False, backref='subscriptions')
    def __rpr__(self):
        return f"<{self.Subscription_id}>"

    @classmethod
    def has_valid_subscription(self):
        now = datetime.now()
        valid_payments = Payment.query.filter(
            Payment.payment_user_id == self.id,
            Payment.start_time <= now,
            Payment.end_time >= now
        ).all()
        return valid_payments != []

    @classmethod
    def find_by_name(cls, Subscription_name):
        return cls.query.filter_by(Subscription_name=Subscription_name).first()

    @classmethod
    def find_by_user_id(cls,user_id):
        return cls.query.filter_by(user_id=user_id).all()

    @classmethod
    def find_all(cls):
        return cls.query.all()

    @classmethod
    def find_by_id(cls, id):
        return cls.query.filter_by(id=id).first()
    
    def save_to_db(self):
        db.session.add(self)
        db.session.commit()
    
    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()
        


#payment class model
class Payment(db.Model):
    __tablename__ = "payments"

    payment_id = db.Column(db.Integer, primary_key=True , autoincrement= True)
    payment_user_id = db.Column(db.String(255), unique=True, nullable=False)
    Ammount = db.Column(db.Float, nullable= False)
    Startime = db.Column(db.DateTime, nullable= False, default=datetime.utcnow)
    Endtime = db.Column(db.DateTime, nullable= False)

    #one to one relationship
    # payment_id = db.Column(db.Integer, db.ForeignKey('subscriptions.Subscription_id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    def __repr__(self):
        return f"<{self.payment_id}>"

    @classmethod
    def find_by_name(cls, payment_user_id):
        return cls.query.filter_by(payment_user_id=payment_user_id).first()

    @classmethod
    def find_all(cls):
        return cls.query.all()

    def find_by_user_id(cls,user_id):
        return cls.query.filter_by(user_id=user_id).all()

    @classmethod
    def find_by_id(cls, id):
        return cls.query.filter_by(id=id).first()
    
    def save_to_db(self):
        db.session.add(self)
        db.session.commit()
    
    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

#video class model
class Video(db.Model):
    __tablename__ = "videos"

    id = db.Column(db.Integer, primary_key=True, autoincrement= True)
    video_path = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f"<{self.id}>"

    @classmethod
    def find_all(cls):
        return cls.query.all()

    @classmethod
    def find_by_id(cls, id):
        return cls.query.filter_by(id=id).first()
    
    def save_to_db(self):
        db.session.add(self)
        db.session.commit()
    
    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

class Streaks(db.Model):
    __tablename__ = "streaks"

    id = db.Column(db.Integer, primary_key=True, autoincrement= True)
    date = db.Column(db.DateTime, nullable= False)

    def __repr__(self) -> str:
        return f"<{self.id}>"

    @classmethod
    def find_all(cls):
        return cls.query.all()

    @classmethod
    def find_by_id(cls, id):
        return cls.query.filter_by(id=id).first()

    
    def save_to_db(self):
        db.session.add(self)
        db.session.commit()
    
    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()
