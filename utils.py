from accounts.models import *
import jwt 
from django.conf import settings
import pytz 
from datetime import datetime, timedelta
import json
from werkzeug.utils import secure_filename
import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
# from rest_framework.request import Request
import secrets 
import bcrypt

secret_key = settings.SECRET_KEY




def generate_jwt_token(user):
    expiration_time = current_pst_to_utc() + timedelta(hours=12)
    payload = {
        'user_id': user.user_id,
        # 'role_id': user.role_id,
        'exp': expiration_time
    }
    token = jwt.encode(payload, secret_key, algorithm='HS256')
    return token

def generate_secure_token(user_id):
    token = secrets.token_hex(32)
    expires_at = current_pst_to_utc() + timedelta(hours=48)
    token_record = Token(token=token, user_id=user_id, expires_at=expires_at)
    token_record.save()
    return token


def decode_jwt_token(token):
    token = token.replace("Bearer ", "").strip()
    try:
        decode_payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        return decode_payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired") 
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")  


def generate_presigned_S3_url(object_name):
    # Example logic to generate presigned URL for S3 object with `object_name`
    presigned_url = f"https://your-bucket-name.s3.amazonaws.com/{object_name}"
    return presigned_url


def is_token_valid(token):
    token_record = Token.objects.filter(token=token).first()
    if not token_record:
        return False, "Invalid token"  
    if get_current_pst_time() > token_record.expires_at:
        return False, "Expired token"  
    if token_record.used:
        return False, "Used token"  
    return True, None  


def get_user_by_token(token):
    token_record = Token.objects.filter(token=token).first()
    if not token_record:
        return None
    user = Users.objects.get(token_record.user_id)
    return user


def update_user_password(token, new_password): 
    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    user = get_user_by_token(token)
    user.password = hashed_password
   
def reset_password_token(token):
    token_record = Token.objects.filter(token=token).first()
    token_record.used = True


# def generate_presigned_S3_url(bucket_name, object_name, expiration=3600):
#     """
#     Generate a presigned URL to share an S3 object
#     :param bucket_name: string
#     :param object_name: string
#     :param expiration: Time in seconds for the presigned URL to remain valid
#     :return: Presigned URL as string. If error, returns None.
#     """
#     s3_client = boto3.client('s3')
#     try:
#         response = s3_client.generate_presigned_url('get_object',
#                                                     Params={'Bucket': bucket_name,
#                                                             'Key': object_name},
#                                                     ExpiresIn=expiration)
#     except (NoCredentialsError, PartialCredentialsError) as e:
#         print(f"Credentials error: {e}")
#         return None
#     except Exception as e:
#         print(f"An error occurred: {e}")
#         return None
#     return response


# def get_latest_user_subscription(user_id):
#     # from models import UserSubscriptions
#     return UserSubscriptions.objects.filter(user_id=user_id, is_deleted=False) \
#                                     .order_by('user_id').first()

#     # return UserSubscriptions.objects.filter(user_id=user_id, is_deleted=False) \
#                                 #    .order_by(UserSubscriptions.user_subscriptions_id).first()    


# def get_latest_user_subscription(user_id):
#     try:
#         latest_subscription = UserSubscriptions.objects.filter(user_id=user_id, is_deleted=False) \
#                                                     .order_by('-user_subscriptions_id').first()
#         return latest_subscription
#     except UserSubscriptions.DoesNotExist:
#         return None


# def get_subscription_name(user_id):
#             # from models import SubscriptionPlans
#             latest_user_subscription = get_latest_user_subscription(user_id)
#             plan_name = SubscriptionPlans.objects.get(latest_user_subscription.plan_id).subscription_name if latest_user_subscription else "No active plan"
#             return plan_name




def get_current_pst_time():
    """Returns the current time in Pacific Standard Time (PST)."""

    pst_timezone = pytz.timezone('US/Pacific')

    current_time_utc = datetime.now(pytz.utc)

    current_time_pst = current_time_utc.astimezone(pst_timezone)
    
    return current_time_pst

def upload_file_to_s3(file, bucket_name, s3):

    if not file or not file.filename:
        return None
    filename = secure_filename(file.filename)
    try:
        s3.upload_fileobj(file, bucket_name, filename)
        return filename
    except Exception:
        return None

def parse_json(input_data):
    if isinstance(input_data, str):
        try:
            return json.loads(input_data)
        except json.JSONDecodeError:
            return []
    else:
        return input_data    
    

# from datetime import datetime
# import pytz

# def pst_to_utc(pst_time_str):
#     """
#     Convert PST time to UTC.

#     Args:
#     pst_time_str (str): Time in PST as a string in the format 'YYYY-MM-DD HH:MM:SS'

#     Returns:
#     str: Time in UTC as a string in the format 'YYYY-MM-DD HH:MM:SS'
#     """
#     pst_zone = pytz.timezone('US/Pacific')
#     utc_zone = pytz.timezone('UTC')

#     naive_pst_time = datetime.strptime(pst_time_str, '%Y-%m-%d %H:%M:%S')

#     localized_pst_time = pst_zone.localize(naive_pst_time)

#     utc_time = localized_pst_time.astimezone(utc_zone)
    
#     return utc_time.strftime('%Y-%m-%d %H:%M:%S')

def pst_to_utc(pst_time):
    """
    Convert PST time to UTC.

    Args:
    pst_time (str or datetime): Time in PST either as a string in the format 'YYYY-MM-DD HH:MM:SS' 
                                or as a datetime object.

    Returns:
    datetime: Time in UTC as a datetime object
    """
    if pst_time is None:
        return None
    pst_zone = pytz.timezone('US/Pacific')
    utc_zone = pytz.timezone('UTC')

    if isinstance(pst_time, str):
        # Parse the input string into a naive datetime object
        naive_pst_time = datetime.strptime(pst_time, '%Y-%m-%d %H:%M:%S')
    elif isinstance(pst_time, datetime):
        # Use the datetime object directly
        naive_pst_time = pst_time
    else:
        raise ValueError("Input must be a string or a datetime object")

    # Localize the naive datetime object to PST
    localized_pst_time = pst_zone.localize(naive_pst_time)

    # Convert the localized datetime to UTC
    utc_time = localized_pst_time.astimezone(utc_zone)
    
    return utc_time

# def utc_to_pst(utc_time):
#     """
#     Convert UTC time to PST.

#     Args:
#     utc_time (datetime): Time in UTC as a datetime object

#     Returns:
#     datetime: Time in PST as a datetime object
#     """
#     if utc_time is None:
#         return None

#     utc_zone = pytz.timezone('UTC')
#     pst_zone = pytz.timezone('US/Pacific')

#     # Ensure the input time is timezone-aware
#     if utc_time.tzinfo is None:
#         localized_utc_time = utc_zone.localize(utc_time)
#     else:
#         localized_utc_time = utc_time.astimezone(utc_zone)

#     pst_time = localized_utc_time.astimezone(pst_zone)
    
#     # return pst_time.strftime('%Y-%m-%d %H:%M:%S')
#     return pst_time

# def utc_to_pst(utc_time):
#     """
#     Convert UTC time to PST.

#     Args:
#     utc_time (datetime): Time in UTC as a datetime object

#     Returns:
#     str: Time in PST as a string in the format 'YYYY-MM-DD HH:MM:SS'
#     """
#     utc_zone = pytz.timezone('UTC')
#     pst_zone = pytz.timezone('US/Pacific')

#     if isinstance(utc_time, str):
#         # Parse the input string into a naive datetime object
#         naive_utc_time = datetime.strptime(utc_time, '%Y-%m-%d %H:%M:%S')
#         # Localize the naive datetime object to UTC
#         localized_utc_time = utc_zone.localize(naive_utc_time)
#     elif isinstance(utc_time, datetime):
#         if utc_time.tzinfo is None:
#             # If the datetime object is naive, localize it to UTC
#             localized_utc_time = utc_zone.localize(utc_time)
#         else:
#             # If the datetime object is already timezone-aware, ensure it's in UTC
#             localized_utc_time = utc_time.astimezone(utc_zone)
#     else:
#         raise ValueError("Input must be a string or a datetime object")

#     # Convert the localized UTC time to PST
#     pst_time = localized_utc_time.astimezone(pst_zone)
    
#     return pst_time

def utc_to_pst(utc_time):
    """
    Convert UTC time to PST.

    Args:
    utc_time (datetime or str): Time in UTC as a datetime object or string in the format 
                                'YYYY-MM-DD HH:MM:SS' or 'YYYY-MM-DD HH:MM:SS.ssssss+00:00'

    Returns:
    datetime: Time in PST as a datetime object
    """
    if utc_time is None:
        return None
    
    utc_zone = pytz.timezone('UTC')
    pst_zone = pytz.timezone('US/Pacific')

    if isinstance(utc_time, str):
        try:
            # Try parsing with microseconds and timezone information
            naive_utc_time = datetime.strptime(utc_time, '%Y-%m-%d %H:%M:%S.%f%z')
        except ValueError:
            try:
                # Fallback to parsing without microseconds but with timezone
                naive_utc_time = datetime.strptime(utc_time, '%Y-%m-%d %H:%M:%S%z')
            except ValueError:
                # Fallback to parsing without timezone
                naive_utc_time = datetime.strptime(utc_time, '%Y-%m-%d %H:%M:%S')
                # Localize the naive datetime object to UTC
                localized_utc_time = utc_zone.localize(naive_utc_time)
            else:
                localized_utc_time = naive_utc_time.astimezone(utc_zone)
        else:
            localized_utc_time = naive_utc_time.astimezone(utc_zone)
    elif isinstance(utc_time, datetime):
        if utc_time.tzinfo is None:
            # If the datetime object is naive, localize it to UTC
            localized_utc_time = utc_zone.localize(utc_time)
        else:
            # If the datetime object is already timezone-aware, ensure it's in UTC
            localized_utc_time = utc_time.astimezone(utc_zone)
    else:
        raise ValueError("Input must be a string or a datetime object")

    # Convert the localized UTC time to PST
    pst_time = localized_utc_time.astimezone(pst_zone)
    
    return pst_time





def current_pst_to_utc():
    """
    Convert the current PST time to UTC.

    Returns:
    str: Current time in UTC as a string in the format 'YYYY-MM-DD HH:MM:SS'
    """
    pst_zone = pytz.timezone('US/Pacific')
    utc_zone = pytz.timezone('UTC')

    current_pst_time = datetime.now(pst_zone)

    utc_time = current_pst_time.astimezone(utc_zone)
    
    return utc_time


def current_pst_to_utc_date():
    """
    Convert the current PST time to UTC.

    Returns:
    str: Current time in UTC as a string in the format 'YYYY-MM-DD HH:MM:SS'
    """
    pst_zone = pytz.timezone('US/Pacific')
    # utc_zone = pytz.timezone('UTC')

    current_pst_time = datetime.now(pst_zone)

    # utc_time = current_pst_time.astimezone(utc_zone)
    
    return current_pst_time