from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.exceptions import ValidationError
from .models import Users
import bcrypt
import json
from .models import Users, Record
from utils import *
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login


@csrf_exempt  # Use this if you are not using CSRF tokens for your requests
def signup(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)

            name = data.get('name')
            email = data.get('email', '').lower()
            password = data.get('password')

            if not email:
                return JsonResponse({"error": "Email is required"}, status=400)

            existing_user = Users.objects.filter(email=email).first()
            if existing_user:
                return JsonResponse({'message': 'Email already registered.'}, status=400)

            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            new_user = Users(
                name=name,
                email=email,
                password=hashed_password,
                created_by=email,
                created_on = current_pst_to_utc(),
            )
            new_user.save()

            # send_verification_email(new_user)

            return JsonResponse({"message": "User registered."}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({'message': 'Invalid JSON format.'}, status=400)
        except ValidationError as error:
            return JsonResponse({'message': 'Validation failed.', 'errors': error.message_dict}, status=400)
        except Exception as e:
            return JsonResponse({'message': 'An error occurred while registering user.', 'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid HTTP method. Please use POST.'}, status=405)


@csrf_exempt  
def login(request):
    if request.method == 'POST':
        try:
            # Parse the JSON data from the request body
            data = json.loads(request.body)

            # Extract and validate email and password
            email = data.get('email', '').lower()
            password = data.get('password')

            if not email or not password:
                return JsonResponse({'message': 'Email and password are required.'}, status=400)

            try:
                user = Users.objects.get(email=email)
            except Users.DoesNotExist:
                return JsonResponse({'message': 'Sorry, no account found. Please check your credentials or sign up to create an account.'}, status=404)

            if user.is_deleted:
                return JsonResponse({'message': 'Your account has been Deactivated. To reactivate, please contact the administrator at hello@heyloops.com.'}, status=401)

            # Check the provided password against the stored hash
            provided_password_bytes = password.encode('utf-8')
            if bcrypt.checkpw(provided_password_bytes, user.password.encode('utf-8')):
                # if user.verified:
                    # Generate JWT token and save it in the session
                access_token = generate_jwt_token(user)
                request.session['jwt_token'] = access_token

                    # Prepare the response data
                response_data = {
                    'access_token': access_token,
                    'name': user.name,
                    'email': user.email,
                    'data': 'Login Successful'
                }
                return JsonResponse({'response': response_data}, status=200)
            else:
                return JsonResponse({'message': 'Invalid credentials. Please check and try again.'}, status=401)
          

        except json.JSONDecodeError:
            return JsonResponse({'message': 'Invalid JSON format.'}, status=400)
        except Exception as e:
            return JsonResponse({'message': 'An error occurred during login.', 'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid HTTP method. Please use POST.'}, status=405)


@csrf_exempt 
def add_record(request):
    # if request.user.is_authenticated:
        if request.method == "POST":
            try:
                # Parse JSON data from the request body
                data = json.loads(request.body)

                # Assuming the fields in the incoming data
                first_name = data.get('first_name')
                last_name = data.get('last_name')
                rec_email = data.get('rec_email')
                city = data.get('city')
                
                # Add more fields as necessary based on your model

                # Perform any validation needed
                if not first_name or not last_name:
                    return JsonResponse({'error': 'Details are required.'}, status=400)

                # Create and save the record
                new_record = Record(first_name=first_name, last_name=last_name, rec_email=rec_email, city=city) 
                new_record.save()

                messages.success(request, "Record Added...")
                return JsonResponse({'message': 'Record added successfully!'}, status=201)

            except json.JSONDecodeError:
                return JsonResponse({'error': 'Invalid JSON.'}, status=400)

            except Exception as e:
                return JsonResponse({'error': str(e)}, status=500)

    # else:
    #     messages.success(request, "You Must Be Logged In...")
    #     return JsonResponse({'error': 'Unauthorized'}, status=401)


def get_records(request):
    records = Record.objects.all().values('first_name', 'last_name', 'rec_email', 'city', 'created_at', 'id')
    records_list = list(records)  # Convert QuerySet to list
    return JsonResponse(records_list, safe=False) 


def customer_detail(request, pk):
    customer_record = get_object_or_404(Record, id=pk)

    # Prepare the data to return as JSON
    data = {
        'id': customer_record.id,
        'first_name': customer_record.first_name,
        'last_name': customer_record.last_name,
        'rec_email': customer_record.rec_email,
        'city': customer_record.city,
        'created_at': customer_record.created_at.isoformat()  # Format date to string
    }

    return JsonResponse(data) 
        

@csrf_exempt
def update_record(request, pk):
        # if request.user.is_authenticated:
            current_record = get_object_or_404(Record, id=pk)
            try:
                data = json.loads(request.body)
                current_record.first_name = data.get('first_name', current_record.first_name)
                current_record.last_name = data.get('last_name', current_record.last_name)
                current_record.rec_email = data.get('rec_email', current_record.rec_email)
                current_record.city = data.get('city', current_record.city)

                current_record.save()

                return JsonResponse({'message': 'Record updated successfully!'}, status=200)
            except Exception as e:
                return JsonResponse({'message': 'Error updating record: ' + str(e)}, status=400)
        
  

def delete_record(request, pk):
    # if request.user.is_authenticated:
            # Fetch the record or return a 404 error if it does not exist
        record = get_object_or_404(Record, id=pk)
        record.delete()  # Delete the record
        return JsonResponse({'message': 'Record Deleted Successfully...'}, status=200)
    # else:
    #     return JsonResponse({'error': 'You Must Be Logged In To Do That...'}, status=403)
    


def signup_page(request):
    return render(request, 'signup.html')

def login_page(request):
    return render(request, 'login.html')                

def home(request):
    records = Record.objects.all()
    return render(request, 'home.html', {'records':records})

def addrecord_page(request):
    return render(request, 'add_record.html')    

def customer_record(request, pk):
    customer_record = get_object_or_404(Record, id=pk)
    return render(request, 'record.html', {'customer_record': customer_record})    


def update_record_page(request, pk):
    record = get_object_or_404(Record, id=pk)
    return render(request, 'update_record.html', {'record': record})

def delete(request, pk):
    record = get_object_or_404(Record, id=pk)
    record.delete() 
    return render(request, 'home.html') 



@csrf_exempt
def logout(request):
    if request.user.is_authenticated:
        logout(request)
        response_data = {
            "message": "You have been logged out successfully.",
            "success": True
        }
    else:
        response_data = {
            "message": "You are not logged in.",
            "success": False
        }
    return JsonResponse(response_data)


    # logout(request)
    # response_data = {
    #     "message": "You have been logged out successfully.",
    #     "success": True
    # }
    # return render(request, 'login.html')

   

# def login_view(request):
#     if request.method == 'POST':
#         email = request.POST['email']
#         password = request.POST['password']
#         user = authenticate(request, email=email, password=password)
#         if user is not None:
#             login(request, user)
#             return JsonResponse({'success': True})  # Return a success response for AJAX
#         else:
#             return JsonResponse({'success': False, 'message': 'Invalid username or password.'}, status=400)

#     return render(request, 'login.html')

#     #         return redirect('records')  # Redirect to records page after login
#     # return render(request, 'login.html')