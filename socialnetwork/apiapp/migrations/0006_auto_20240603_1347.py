# Generated by Django 3.2.25 on 2024-06-03 08:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('apiapp', '0005_auto_20240603_1226'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='profile',
            name='confirm_password',
        ),
        migrations.AlterField(
            model_name='profile',
            name='email',
            field=models.EmailField(error_messages={'blank': 'Email cannot be blank.', 'invalid': 'Enter a valid email address.', 'max_length': 'Email cannot be longer than 100 characters.', 'unique': 'Email address already exists.'}, max_length=100, unique=True),
        ),
        migrations.AlterField(
            model_name='profile',
            name='username',
            field=models.CharField(error_messages={'blank': 'Username cannot be blank.', 'max_length': 'Username cannot be longer than 100 characters.', 'unique': 'Username already exists.'}, max_length=100, unique=True),
        ),
    ]
