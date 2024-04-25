from rest_framework import serializers
import re



class CustomValidators():
        
        
    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("password must be at least 8 characters!!")

        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError("password must contain a capital letter!!")

        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError("password must contain a letter!!")

        if not re.search(r'[0-9]', value):
            raise serializers.ValidationError("password must contain at least one digit!!")

        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise serializers.ValidationError("password must contain at least one special character!!")

        return value
