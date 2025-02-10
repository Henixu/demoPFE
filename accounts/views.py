from django.shortcuts import render
from django.contrib.auth import authenticate, login
from django.http import JsonResponse
from django.utils import timezone
from .models import Employees, History
from django.contrib.auth.models import User
import json
from .utils import get_client_ip
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def register(request):
    if request.method == 'POST':
        try:
            # Parse JSON data from the request body
            data = json.loads(request.body)
            first_name = data.get('first_name')
            last_name = data.get('last_name')
            email = data.get('email')
            password = data.get('password')
            username = email  # Use email as the username

            # Validate required fields
            if not all([first_name, last_name, email, password]):
                return JsonResponse({'error': 'All fields are required.'}, status=400)

            # Check if email already exists
            if User.objects.filter(email=email).exists():
                return JsonResponse({'error': 'Email already registered.'}, status=400)

            # Create the user
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name
            )

            # Optionally log in the user after registration
            login(request, user)

            return JsonResponse({'message': 'User registered successfully.'}, status=201)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method.'}, status=405)

@csrf_exempt
def user_login(request):
    if request.method == 'POST':
        try:
            # Parse JSON data from the request body
            data = json.loads(request.body)
            email = data.get('email')
            password = data.get('password')

            # Validate required fields
            if not all([email, password]):
                return JsonResponse({'error': 'Email and password are required.'}, status=400)

            # Get the IP address of the client
            ip_address = get_client_ip(request)

            # Check if IP is banned
            history, created = History.objects.get_or_create(ip_address=ip_address)
            if history.is_banned and (timezone.now() - history.timestamp).total_seconds() < 180:
                return JsonResponse({
                    'error': 'Too many failed login attempts. Your IP is banned for 3 minutes.'
                }, status=403)

            # Authenticate user
            user = authenticate(request, username=email, password=password)
            if user is not None:
                # Successful login, reset failed attempts
                history.attempt_count = 0
                history.is_banned = False
                history.save()

                # Log in the user
                login(request, user)
                return JsonResponse({'message': 'Login successful.'}, status=200)
            else:
                # Failed login, increment attempt count
                history.attempt_count += 1

                if history.attempt_count >= 3:
                    history.is_banned = True
                    history.timestamp = timezone.now()  # Update ban timestamp
                    history.save()  # Ensure ban status is saved before returning response

                    return JsonResponse({
                        'error': 'Too many failed attempts. Your IP is temporarily banned for 3 minutes.'
                    }, status=403)

                history.save()  # Save attempt count before returning incorrect password message
                return JsonResponse({'error': 'Incorrect password. Please try again.'}, status=401)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method.'}, status=405)
