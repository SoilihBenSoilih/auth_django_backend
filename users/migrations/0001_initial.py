# Generated by Django 5.0.2 on 2024-04-20 22:01

import django.contrib.auth.models
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='CustomUser',
            fields=[
                ('id', models.CharField(max_length=100, primary_key=True, serialize=False)),
                ('firstName', models.CharField(blank=True, max_length=150, null=True)),
                ('lastName', models.CharField(blank=True, max_length=150, null=True)),
                ('email', models.EmailField(blank=True, default='', max_length=255, null=True, unique=True)),
                ('password', models.CharField(blank=True, default='', max_length=255, null=True)),
                ('is_active', models.BooleanField(default=True)),
                ('is_superuser', models.BooleanField(default=False)),
                ('is_staff', models.BooleanField(default=False)),
                ('date_joined', models.DateTimeField(default=django.utils.timezone.now)),
                ('last_login', models.DateTimeField(blank=True, null=True)),
                ('salt', models.CharField(blank=True, default='', max_length=255, null=True)),
                ('phone', models.CharField(blank=True, max_length=20, null=True)),
                ('creationDate', models.DateTimeField(blank=True, null=True)),
                ('lastUpdateDate', models.DateTimeField(blank=True, null=True)),
                ('birthDate', models.DateField(blank=True, null=True)),
                ('profilePhotoID', models.CharField(blank=True, max_length=255, null=True)),
                ('identityPhotoID', models.CharField(blank=True, max_length=255, null=True)),
                ('completedProfile', models.BooleanField(blank=True, null=True)),
                ('emailConfirmed', models.BooleanField(blank=True, null=True)),
                ('annualRegistration', models.BooleanField(blank=True, null=True)),
                ('faceIdentityChecked', models.BooleanField(blank=True, null=True)),
                ('birthDateChecked', models.BooleanField(blank=True, null=True)),
                ('levelNumber', models.IntegerField(blank=True, default=1, null=True)),
            ],
            options={
                'db_table': 'User',
            },
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('id', models.CharField(max_length=100, primary_key=True, serialize=False)),
                ('firstName', models.CharField(blank=True, max_length=150, null=True)),
                ('lastName', models.CharField(blank=True, max_length=150, null=True)),
                ('email', models.EmailField(blank=True, default='', max_length=255, null=True, unique=True)),
                ('is_active', models.BooleanField(default=True)),
                ('is_staff', models.BooleanField(default=False)),
                ('date_joined', models.DateTimeField(default=django.utils.timezone.now)),
                ('salt', models.CharField(blank=True, default='', max_length=255, null=True)),
                ('phone', models.CharField(blank=True, max_length=20, null=True)),
                ('creationDate', models.DateTimeField(blank=True, null=True)),
                ('lastUpdateDate', models.DateTimeField(blank=True, null=True)),
                ('birthDate', models.DateField(blank=True, null=True)),
                ('profilePhotoID', models.CharField(blank=True, max_length=255, null=True)),
                ('identityPhotoID', models.CharField(blank=True, max_length=255, null=True)),
                ('completedProfile', models.BooleanField(blank=True, null=True)),
                ('emailConfirmed', models.BooleanField(blank=True, null=True)),
                ('annualRegistration', models.BooleanField(blank=True, null=True)),
                ('faceIdentityChecked', models.BooleanField(blank=True, null=True)),
                ('birthDateChecked', models.BooleanField(blank=True, null=True)),
                ('levelNumber', models.IntegerField(blank=True, default=1, null=True)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
            ],
            options={
                'abstract': False,
            },
            managers=[
                ('objects', django.contrib.auth.models.UserManager()),
            ],
        ),
    ]
