import os
import requests
import traceback
from decouple import config

from utils.email import send_email

from .models import User
from .serializers import UserSerializer

from django.shortcuts import render
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import make_password
from django.utils.crypto import constant_time_compare
from django.db import transaction
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode

from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.exceptions import APIException
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework_simplejwt.tokens import OutstandingToken, BlacklistedToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.reverse import reverse
from rest_framework.response import Response



class RegisterAPIView(APIView):
    """
        API view for user registration.

        This view handles user registration by saving the user and custom user data in the database.

        Inputs:
        - request: The HTTP request object containing user data in the request body.

        Outputs:
        - Response:
            - 201: User registered successfully. Returns user data.
            - 400: Bad request. Invalid data provided in the request body.
            - 500: Internal server error.
    """
    authentication_classes = [SessionAuthentication]
    permission_classes = [AllowAny]
    
    def post(self, request):
        try:
            with transaction.atomic():
                # Serialize the User data
                user_serializer = UserSerializer(data=request.data)
                
                if user_serializer.is_valid():
                    user_serializer.save()
                    return Response(user_serializer.data, status=status.HTTP_201_CREATED)
                else:
                    return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception:  
            return Response({'error': traceback.format_exc()}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
register_view = RegisterAPIView.as_view()


#TODO: implement later for suggestions
class UserListApiView(generics.ListAPIView):
    serializer_class = UserSerializer

    def get_queryset(self):
        queryset = User.objects.all()

        # Check if request contains parameters
        if self.request.query_params:
            conditions = {}

            level_num = self.request.query_params.get('levelNum')
            if level_num:
                conditions['levelNum__lte'] = level_num

            # Example condition: isCompleted = True
            is_completed = self.request.query_params.get('isCompleted')
            if is_completed:
                conditions['completedProfile'] = is_completed

            # Filter queryset based on conditions
            if conditions:
                queryset = queryset.filter(**conditions)
        
        return queryset

user_list_view = UserListApiView.as_view()


class EmailVerificationAPIView(APIView):
    """
        API view for sending email verification.

        This view sends an email verification link to the provided email address.

        Inputs:
        - request: The HTTP request object containing the email address in the request data.

        Outputs:
        - Response:
            - 200: Email verification email sent successfully.
            - 400: Bad request. User with the provided email does not exist.
            - 500: Internal server error.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            email = request.data.get('email')
            if email:
                user = User.objects.filter(email=email).first()
                user_serializer = UserSerializer(instance=user, data=request.data)
                if user_serializer.is_valid():                    
                    uid = urlsafe_base64_encode(force_bytes(user.id))
                    verification_url = reverse('email_confirm', kwargs={'uidb64': uid}, request=request)
                    send_email(
                        [email],
                        'test.dummy@gmail.com',
                        'Email Verification',
                        f'Please click the link below to verify your email address: {verification_url}',
                        fail_silently=False,
                    )
                    return Response({'message': 'Email verification email sent', 'url':verification_url}, status=status.HTTP_200_OK)
            return Response({'error': 'User with this email does not exist'}, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception:
            return Response({'error': traceback.format_exc()}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

verify_email_view = EmailVerificationAPIView.as_view()


class EmailVerificationConfirmAPIView(generics.GenericAPIView):
    """
        API view for confirming email verification.

        This view confirms email verification for a user by decoding the uidb64 parameter,
        fetching the user and custom user instances, and updating their email confirmation status.

        Inputs:
        - request: The HTTP request object.
        - uidb64: The base64 encoded user ID.

        Outputs:
        - Response:
            - 200: Email verification successful.
            - 500: Internal server error.
    """
    permission_classes = [AllowAny]

    def get(self, request, uidb64):
        try:
            # Decoding the uidb64 to get the user ID
            user_id = urlsafe_base64_decode(uidb64).decode()
            
            # Fetching the user and customuser instances
            user_instance = User.objects.get(id=user_id)
            
            # Creating serializers for instances
            user_serializer = UserSerializer(instance=user_instance, data=request.data, partial=True)
            
            # Performing database operations synchroniously
            with transaction.atomic():
                
                # Validating serializers and updating email confirmation status
                if user_serializer.is_valid():
                    user_serializer.validated_data['emailConfirmed'] = True
                    user_serializer.save()
                    
            # Responding with success message    
            return Response({'message': 'Email verification successful'}, status=status.HTTP_200_OK)
        
        except Exception:
            # Handling exceptions and responding with error message
            return Response({'error': traceback.format_exc()}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

email_confirm_view = EmailVerificationConfirmAPIView.as_view()


class UserLoginAPIVIew(ObtainAuthToken):
    """
        authentication view for obtaining JWT tokens.
        
        This view checks:
        - Verify user credentials (email and password).
        - Check if the user's email is confirmed.
        - Obtain JWT tokens for authenticated users.
        
        Inputs:
        - request: The request object containing user credentials (email and password).
        - *args: Additional positional arguments.
        - **kwargs: Additional keyword arguments.
        
        Outputs:
        - Response: 
                200: OK.
                400: Credentials invalids.
                401: Email not confirmed.
                404: User not found.
                500: Internal errors.
    """
    authentication_classes = [SessionAuthentication]
    
    def post(self, request, *args, **kwargs):
        try:
            # get login informations
            data = request.data.copy()
            email = data.get('email')
            password = data.get('password')
            data['username'] = email
            
            # handle errors
            if not email or not password:
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
            
            if not constant_time_compare(user.password, make_password(password=password, salt=user.salt, hasher=os.environ.get('HASHER'))):
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)
            
            # if not user.emailConfirmed:
            #     return Response({'error': 'email not confirmed'}, status=status.HTTP_401_UNAUTHORIZED)
            
            # validate request data and get token
            serializer = self.serializer_class(data=data, context={'request': request})
            if serializer.is_valid():
                user_infos = UserSerializer(user).data
                response_data = {'user': user_infos}
                url = reverse('token_obtain_pair', request=request)
                response = requests.post(url, data=data)
                if response.status_code != 200:
                    return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)
                response_data.update(response.json())
                return Response(response_data, status=status.HTTP_200_OK)
            
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception:
            return Response({'error': traceback.format_exc()}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
login_view = UserLoginAPIVIew.as_view()


class CustomTokenRefreshView(APIView):
    """
    Custom view for token refresh.
    """
    permission_classes = [AllowAny]
    def post(self, request, *args, **kwargs):
        try:
            refresh_token = request.data.get('refresh')
            if not refresh_token:
                return Response({'error': 'Refresh token is required'}, status=status.HTTP_400_BAD_REQUEST)

            token = RefreshToken(refresh_token)
            access_token = str(token.access_token)

            return Response({'access': access_token}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
refresh_view = CustomTokenRefreshView.as_view()

class CustomTokenVerifyView(APIView):
    """
    Custom view for token verification.
    """

    def post(self, request, *args, **kwargs):
        try:
            token = request.data.get('token')
            if not token:
                return Response({'error': 'Token is required'}, status=status.HTTP_400_BAD_REQUEST)

            RefreshToken(token).blacklist()

            return Response({'message': 'Token is valid'}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

verify_view = CustomTokenVerifyView.as_view()
class UserUpdateApiView(generics.UpdateAPIView):
    """
        API view for updating user information.

        This view updates the user and custom user instances with the provided data.

        Inputs:
        - request: The HTTP request object containing user data in the request body.

        Outputs:
        - Response:
            - 200: Updates made successfully.
            - 404: user not found
            - 400: validation errors
            - 500: Internal server error.
    """

    def update(self, request, *args, **kwargs):
        try:
            # get instances
            if ('id' in request.data or 'email' in request.data):
                raise APIException('Cannot update email or id', code=status.HTTP_400_BAD_REQUEST)
            user_id = request.user.id
            print(request.user)
            if not user_id:
                raise APIException('No user id provided', code=status.HTTP_404_NOT_FOUND)
            user_instance = User.objects.get(id=user_id)
            if not user_instance:
                raise APIException('User not found', code=status.HTTP_400_BAD_REQUEST)
            
            # default values
            user_instance.is_active = True
            user_instance.is_staff = False
            user_instance.is_superuser = False
            
            # Update user fields if provided in request data
            user_serializer = UserSerializer(instance=user_instance, data=request.data, partial=True)
            
            # Validate request data with serializers
            user_serializer.is_valid(raise_exception=True)

            # make updates
            with transaction.atomic():
                if 'password' in request.data:                        
                    new_password = request.data['password']
                    salt = user_instance.salt
                    user_serializer.validated_data['password'] = make_password(password=new_password, salt=salt, hasher=os.environ.get('HASHER'))
                user_serializer.save()
        
                return Response({'message': 'Updates made successfully', "id": user_id}, status=status.HTTP_200_OK)
        
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        except ValidationError:
            return Response({'error': traceback.format_exc()}, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception:
            return Response({'error': traceback.format_exc()}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

user_update_view = UserUpdateApiView.as_view()


class UserDetailApiView(generics.RetrieveAPIView):
    """
        API view for retrieving details of a user.

        This view retrieves details of a user based on the provided user ID.

        Inputs:
        - id: The user ID used to retrieve user details.

        Outputs:
        - Response:
            - 200: User details retrieved successfully.
            - 404: Not found. User with the provided ID does not exist.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    lookup_field = 'id'

user_detail_view = UserDetailApiView.as_view()


class UserDeleteApiView(generics.DestroyAPIView):
    """
        API view for deleting a user.

        This view deletes a user based on the provided user ID.

        Inputs:
        - id: The user ID used to delete the user.

        Outputs:
        - Response:
            - 204: No content. User deleted successfully.
            - 404: Not found. User with the provided ID does not exist.
            - 500: Internal server error.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    lookup_field = 'id'
    
    def perform_destroy(self, instance):
        try:
            return super().perform_destroy(instance)
        
        except Exception:
            return Response({'error': traceback.format_exc()}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


user_delete_view = UserDeleteApiView.as_view()


class PasswordResetAPIView(APIView):
    """
        API view for sending password reset emails.

        This view sends a password reset email to the provided email address.

        Inputs:
        - request: The HTTP request object containing the email address in the request body.

        Outputs:
        - Response:
            - 200: Password reset email sent successfully.
            - 400: Bad request. User with the provided email does not exist.
            - 500: Internal server error.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            email = request.data.get('email')
            if email:
                user = User.objects.filter(email=email).first()
                if user:
                    uid = urlsafe_base64_encode(force_bytes(user.id))
                    reset_url = reverse('password_reset_confirm', kwargs={'uidb64': uid}, request=request)
                    #TODO: implement later
                    # send_email(
                    #     'Password Reset Request',
                    #     f'Please click the link below to reset your password: {reset_url}',
                    #     'from@example.com',
                    #     [email],
                    #     fail_silently=False,
                    # )
                    return Response({'message': 'Password reset email sent', 'url':reset_url}, status=status.HTTP_200_OK)
            
            return Response({'error': 'User with this email does not exist'}, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception:
            return Response({'error': traceback.format_exc()}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

password_reset_view = PasswordResetAPIView.as_view()


class PasswordResetConfirmAPIView(APIView):
    """
        API view for confirming password reset.

        This view confirms the password reset request and updates the user's password.

        Inputs:
        - request: The HTTP request object containing the new password in the request data.
        - uidb64: The base64 encoded user ID used to identify the user.

        Outputs:
        - Response:
            - 200: Password reset successful.
            - 400: Bad request. New password is required.
            - 500: Internal server error.
    """
    permission_classes = [AllowAny]
    
    def get(self, request, uidb64):
        #TODO: need a redirect
        return Response({'message': 'can reset password', 'uidb64': uidb64}, status=status.HTTP_200_OK)
    
    def post(self, request, uidb64):
        try:
            id = urlsafe_base64_decode(uidb64).decode()
            user_instance = User.objects.get(id=id)
            user_serializer = UserSerializer(instance=user_instance, data=request.data, partial=True)

            with transaction.atomic():
                new_password = request.data.get('password')
                salt = user_instance.salt
                if user_serializer.is_valid():
                    if new_password:
                        user_serializer.validated_data['password'] = make_password(password=new_password, salt=salt, hasher=os.environ.get('HASHER'))
                        user_serializer.save()
                        return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)
                    else:
                        raise APIException({'error': 'New password is required'}, code=status.HTTP_400_BAD_REQUEST)
        except Exception:
            return Response({'error': traceback.format_exc()}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

password_reset_confirm_view = PasswordResetConfirmAPIView.as_view()


class LogoutAPIView(APIView):
    """
        API view for user logout.

        This view blacklists the refresh token to invalidate it, effectively logging out the user.

        Inputs:
        - request: The HTTP request object containing the refresh token in the request data.

        Outputs:
        - Response:
            - 205: Reset content. Logout successful.
            - 400: Invalid token
            - 500: Bad request. Error occurred during logout process.
    """
    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response(status=status.HTTP_205_RESET_CONTENT)
        
        except TokenError:
            return Response({"error": "invalid token"},status=status.HTTP_400_BAD_REQUEST)
            
        except Exception:
            return Response({"error": traceback.format_exc()},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
logout_view = LogoutAPIView.as_view()


# class LogoutAllView(APIView):

#     def post(self, request):
#         tokens = OutstandingToken.objects.filter(id=request.data['id'])
#         for token in tokens:
#             t, _ = BlacklistedToken.objects.get_or_create(token=token)

#         return Response(status=status.HTTP_205_RESET_CONTENT)
