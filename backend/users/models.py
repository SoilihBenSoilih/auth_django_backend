from django.db import models
from django.contrib.auth.models import UserManager, AbstractBaseUser, PermissionsMixin
from django.utils import timezone



class BaseUser(models.Model):
    
    id = models.CharField(max_length=100, primary_key=True)
    firstName = models.CharField(max_length=150, null=True, blank=True)
    lastName = models.CharField(max_length=150, null=True, blank=True)
    email = models.EmailField(max_length=255, null=True, default='', blank=True, unique=True)
    password = models.CharField(max_length=255, null=True, default='', blank=True)
    roles = models.TextField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    is_superuser = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    last_login = models.DateTimeField(blank=True, null=True)
    salt = models.CharField(max_length=255, null=True, default='', blank=True)
    emailConfirmed = models.BooleanField(null=True, blank=True)
    
    class Meta:
        abstract = True


class User(AbstractBaseUser, PermissionsMixin, BaseUser):

    objects = UserManager()
    USERNAME_FIELD = 'email'
    EMAIL_FIELD = 'email'
    REQUIRED_FIELDS = [] 
