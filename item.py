from flask_marshmallow import Marshmallow
from models import *

ma = Marshmallow()

#User-schema
class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User
        include_fk = True
        load_instance = True
        
        
#workout-schema
class WorkoutSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Workout
        include_fk = True
        load_instance = True

# payment schema
class PaymetSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Payment
        include_fk = True
        load_instance = True

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






