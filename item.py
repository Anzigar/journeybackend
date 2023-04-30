from marshmallow import fields
from flask_marshmallow import Marshmallow
from models import *

ma = Marshmallow()

#User-schema
class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User
        include_fk = True
        load_instance = True
        id = fields.Integer(dump_only=True)
        fullname = fields.String(required=False)
        email = fields.String(required=True)
        phoneNumber = fields.String(required=False)
        password =fields.String(required=True)       
        
#workout-schema
class WorkoutSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Workout
        include_fk = True
        load_instance = True
        total_time = fields.Time(format='%H:%M:%S')

# payment schema
class PaymetSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Payment
        include_fk = True
        load_instance = True
        payment_id = fields.Integer(dump_only=True)
        Ammount = fields.Float(required=True)
        Startime = fields.DateTime(required=True)
        Endtime = fields.DateTime(required=True)
        user_id = fields.Integer(required=True)

# #substcription schema
class SubscriptionSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Subscription
        include_fk = True
        load_instance = True

#video schema
class VideoSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Video
        include_fk = True
        load_instance = True

#Streaks schema
class StreaksSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Streaks
        include_fk = True
        load_instance = True

class OTPSchema (ma.SQLAlchemyAutoSchema):
    class Meta:
        model = OTP
        include_fk = True
        load_instance = True