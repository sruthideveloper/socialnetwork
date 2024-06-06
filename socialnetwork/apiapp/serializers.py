from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from .models import Profile,FriendRequest
from rest_framework_simplejwt.tokens import RefreshToken

class ProfileSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True, required=True, error_messages={'required': 'Confirm password is required.'})
    #mobile=serializers.CharField(required=True)

    class Meta:
        model = Profile
        fields = ['username', 'email', 'password', 'confirm_password', 'mobile']
        extra_kwargs = {
            'username': {'required': True, 'error_messages': {'required': 'Username is required.'}},
            'email': {'required': True, 'error_messages': {'required': 'Email is required.'}},
            'password': {'write_only': True, 'required': True, 'error_messages': {'required': 'Password is required.'}},
        #    'confirm_password':{'write_only': True, 'required': True, 'error_messages': {'required': 'confirm password is required.'}},
            'mobile': {'required': True, 'error_messages': {'required': 'Mobile number is required.'}},
        }

    def validate_email(self, value):
        email = value.lower()
        if Profile.objects.filter(email__iexact=email).exists():
            raise ValidationError("A user with this email already exists.")
        return email

    def validate_username(self, value):
        if Profile.objects.filter(username=value).exists():
            raise ValidationError("A user with that username already exists.")
        return value

    def validate_password(self, value):
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(e.messages)
        return value

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise ValidationError("Passwords do not match.")
        return data
    
    def validate_mobile(self, value):
        validator = RegexValidator(
            regex=r'^\d{10}$',
            message='Mobile number must be 10 digits.'
        )
        validator(value)
        return value

    def create(self, validated_data):
        validated_data['email'] = validated_data['email'].lower()
        profile = Profile(
            username=validated_data['username'],
            email=validated_data['email'],
            mobile=validated_data['mobile']
        )
        profile.set_password(validated_data['password'])  # Hash the password
        profile.save()
        return profile
      #  refresh = RefreshToken.for_user(profile)
       # return {
        #    'refresh': str(refresh),
         #   'access': str(refresh.access_token),
        #}


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True)
    
    
    
class UserSearchSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ['username', 'email', 'mobile']    
        
        

#class FriendRequestSerializer(serializers.ModelSerializer):
 #   sender = serializers.StringRelatedField(read_only=True)
 #   receiver = serializers.StringRelatedField(read_only=True)

  #  class Meta:
   #     model = FriendRequest
    #    fields = ['id', 'sender', 'receiver', 'is_accepted', 'timestamp']
     #   read_only_fields = ['id', 'sender', 'receiver', 'is_accepted', 'timestamp']
        
        
        

               
        
class FriendRequestSerializer(serializers.ModelSerializer):
   # sender = ProfileSerializer(read_only=True)
   # receiver = ProfileSerializer(read_only=True)
    sender_name = serializers.SerializerMethodField()
    receiver_name = serializers.SerializerMethodField()
    receiver_email = serializers.EmailField(write_only=True)

    class Meta:
        model = FriendRequest
     #   fields = ['id', 'sender', 'receiver', 'receiver_email', 'is_accepted']
        fields = ['id', 'sender_name', 'receiver_name','receiver_email', 'is_accepted']
        extra_kwargs = {
          #  'sender': {'read_only': True},
           # 'receiver': {'read_only': True},
            'is_accepted': {'read_only': True}
        }
        
    def get_sender_name(self, obj):
        sender = obj.sender
        return sender.username

    def get_receiver_name(self, obj):
       return obj.receiver.username           
  
    def create(self, validated_data):
        receiver_email = validated_data.pop('receiver_email')
        try:
            receiver = Profile.objects.get(email=receiver_email)
        except Profile.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")

        friend_request = FriendRequest.objects.create(
            sender=validated_data['sender'],
            receiver=receiver
        )
        return friend_request
        
        
        
        
class FriendRequestSerializertwo(serializers.ModelSerializer):
    receiver_email = serializers.EmailField(write_only=True)

    class Meta:
        model = FriendRequest
        fields = ['id', 'sender', 'receiver', 'receiver_email', 'is_accepted']
      #  fields = ['id', 'sender', 'receiver','sender_name', 'receiver_email', 'is_accepted']
        extra_kwargs = {
            'sender': {'read_only': True},
            'receiver': {'read_only': True},
            'is_accepted': {'read_only': True}
        }
          
    def validate_receiver_email(self, value):
        request_user = self.context['request'].user
        try:
            receiver = Profile.objects.get(email=value)
        except Profile.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")
        
        if FriendRequest.objects.filter(sender=request_user, receiver=receiver).exists():
            raise serializers.ValidationError("Friend request already sent.")
        
        if request_user.email == value:
            raise serializers.ValidationError("You cannot send a friend request to yourself.")
        
        return value     
  
    def create(self, validated_data):
        receiver_email = validated_data.pop('receiver_email')
        try:
            receiver = Profile.objects.get(email=receiver_email)
        except Profile.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")

        friend_request = FriendRequest.objects.create(
            sender=validated_data['sender'],
            receiver=receiver
        )
        return friend_request
                

class SendFriendRequestSerializer(serializers.ModelSerializer):
    receiver = serializers.EmailField()

    class Meta:
        model = FriendRequest
        fields = ['receiver']

    def validate_receiver(self, value):
        try:
            receiver = Profile.objects.get(email=value)
        except Profile.DoesNotExist:
            raise serializers.ValidationError("No user with this email found.")
        return receiver

    def create(self, validated_data):
        sender = self.context['request'].user
        receiver = validated_data['receiver']
        if FriendRequest.objects.filter(sender=sender, receiver=receiver).exists():
            raise serializers.ValidationError("Friend request already sent.")
        return FriendRequest.objects.create(sender=sender, receiver=receiver)        