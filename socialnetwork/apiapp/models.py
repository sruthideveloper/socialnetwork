from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.core.validators import RegexValidator
from django.db import models


class CustomUserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)  # Hash the password
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(email, username, password, **extra_fields)
    
    

class Profile(AbstractBaseUser):
    username = models.CharField(
        max_length=100,
        unique=True,
        error_messages={
            'unique': "Username already exists.",
            'blank': "Username cannot be blank.",
            'max_length': "Username cannot be longer than 100 characters."
        }
    )
    email = models.EmailField(
        max_length=100,
        unique=True,
        error_messages={
            'unique': "Email address already exists.",
            'invalid': "Enter a valid email address.",
            'blank': "Email cannot be blank.",
            'max_length': "Email cannot be longer than 100 characters."
        }
    )
    password = models.CharField(
        max_length=100,
        error_messages={
            'blank': "Password cannot be blank.",
            'max_length': "Password cannot be longer than 100 characters."
        }
    )
   
    mobile = models.CharField(
        max_length=10,
        blank=True,
        null=True,
        validators=[
            RegexValidator(
                regex=r'^\d{10}$',
                message='Mobile number must be 10 digits.'
            )
        ],
        error_messages={
            'required':'Enter Mobile No',
            'blank': "Mobile number cannot be blank.",
            'max_length': "Mobile number cannot be longer than 10 characters."
        }
    )
    
    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.username



class FriendRequest(models.Model):
    sender = models.ForeignKey(Profile, related_name='sent_requests', on_delete=models.CASCADE)
    receiver = models.ForeignKey(Profile, related_name='received_requests', on_delete=models.CASCADE)
    is_accepted = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('sender', 'receiver')

    def __str__(self):
        return f"{self.sender} to {self.receiver} - {'Accepted' if self.is_accepted else 'Pending'}"