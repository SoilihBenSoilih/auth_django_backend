from utils.hashers import generate_salt
from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from .models import User
import uuid
from .validators import CustomValidators
from decouple import config
from utils.uuid import is_valid_uuid



class UserSerializer(serializers.ModelSerializer):
    
    customValidators = CustomValidators()
    
    class Meta:
        model = User
        lookup_field = "id"
        fields = "__all__"
        
        extra_kwargs = {
            'email': {'required': True},
            'password': {'required': False, 'write_only': True},
            'groups': {'write_only': True},
            'user_permissions': {'write_only': True},
            'is_superuser': {'write_only': True},
            'is_staff': {'write_only': True},
            'is_active': {'write_only': True},
            'is_superuser': {'write_only': True},
            'date_joined': {'write_only': True},
            'id': {'required': False}
        }
    
    # validators        
    def validate_password(self, value):
        return self.customValidators.validate_password(value)


    # create
    def create(self, validated_data):
        if not validated_data.get('password'):
            raise serializers.ValidationError("password required!!")
        
        # hash password
        salt = generate_salt()
        password = make_password(password=validated_data['password'], salt=salt, hasher=config('HASHER'))     
        validated_data['password'] = password
        validated_data['salt'] = salt
        
        # Set default values
        validated_data.update({
            'is_active': True,
            'is_staff': False,
            'is_superuser': False,
            'emailConfirmed': False,
        })

        
        # make id
        user_id = validated_data.get('userID')
        user_id = is_valid_uuid(user_id)
        if not user_id:
            user_id = str(uuid.uuid4())
            while User.objects.filter(id=user_id).exists():
                user_id = str(uuid.uuid4())
            validated_data['id'] = user_id
        
        return super().create(validated_data)
