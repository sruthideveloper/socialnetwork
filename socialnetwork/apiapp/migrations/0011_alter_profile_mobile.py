# Generated by Django 3.2.25 on 2024-06-03 10:36

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('apiapp', '0010_alter_profile_mobile'),
    ]

    operations = [
        migrations.AlterField(
            model_name='profile',
            name='mobile',
            field=models.CharField(blank=True, error_messages={'blank': 'Mobile number cannot be blank.', 'max_length': 'Mobile number cannot be longer than 10 characters.', 'required': 'Enter Mobile No'}, max_length=10, null=True, validators=[django.core.validators.RegexValidator(message='Mobile number must be 10 digits.', regex='^\\d{10}$')]),
        ),
    ]
