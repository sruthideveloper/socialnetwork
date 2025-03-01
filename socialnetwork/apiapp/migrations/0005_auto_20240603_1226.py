# Generated by Django 3.2.25 on 2024-06-03 06:56

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('apiapp', '0004_auto_20240603_1220'),
    ]

    operations = [
        migrations.AlterField(
            model_name='profile',
            name='confirm_password',
            field=models.CharField(error_messages={'blank': 'Confirm password cannot be blank.', 'max_length': 'Confirm password cannot be longer than 100 characters.'}, max_length=100),
        ),
        migrations.AlterField(
            model_name='profile',
            name='email',
            field=models.EmailField(error_messages={'blank': 'Email cannot be blank.', 'invalid': 'Enter a valid email address.', 'max_length': 'Email cannot be longer than 100 characters.', 'unique': 'A user with that email already exists.'}, max_length=100, unique=True),
        ),
        migrations.AlterField(
            model_name='profile',
            name='mobile',
            field=models.CharField(blank=True, error_messages={'blank': 'Mobile number cannot be blank.', 'max_length': 'Mobile number cannot be longer than 15 characters.'}, max_length=15, null=True, validators=[django.core.validators.RegexValidator(message='Mobile number must be 10 digits.', regex='^\\d{10}$')]),
        ),
        migrations.AlterField(
            model_name='profile',
            name='password',
            field=models.CharField(error_messages={'blank': 'Password cannot be blank.', 'max_length': 'Password cannot be longer than 100 characters.'}, max_length=100),
        ),
        migrations.AlterField(
            model_name='profile',
            name='username',
            field=models.CharField(error_messages={'blank': 'Username cannot be blank.', 'max_length': 'Username cannot be longer than 100 characters.', 'unique': 'A user with that username already exists.'}, max_length=100, unique=True),
        ),
    ]
