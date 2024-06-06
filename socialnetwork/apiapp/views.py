import logging
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.forms import ValidationError
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny
from django.db.models import Q
from .serializers import ProfileSerializer,LoginSerializer,UserSearchSerializer,FriendRequestSerializer, SendFriendRequestSerializer,FriendRequestSerializertwo
from .models import Profile,FriendRequest
from rest_framework.pagination import PageNumberPagination
from django.core.cache import cache
from rest_framework.exceptions import Throttled
from rest_framework import generics, permissions
logger = logging.getLogger(__name__)
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
# Create your views here.


class ProfileSignupView(generics.CreateAPIView):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_data = serializer.save()
        
        refresh = RefreshToken.for_user(user_data)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'msg':'Registered Sucessfully',
        })

       # tokens={
        #    'refresh': user_data['refresh'],
         #   'access': user_data['access'],
        #}
        #return Response(tokens, status=status.HTTP_201_CREATED)
    
 
 
class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email'].lower()
        password = serializer.validated_data['password']
        user = authenticate(email=email, password=password)
        
        if user is not None:
            refresh = RefreshToken.for_user(user)
            #token = get_tokens_for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'msg': 'Login Success',
            }, status=status.HTTP_200_OK)
        else:
            return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
    


class UserSearchPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100

class UserSearchView(generics.ListAPIView):
    serializer_class = UserSearchSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = UserSearchPagination

    def get_queryset(self):
        queryset = Profile.objects.all()
        search_query = self.request.query_params.get('q', None)
        if search_query:
            if '@' in search_query:
                queryset = queryset.filter(email__iexact=search_query)
            else:
                queryset = queryset.filter(username__icontains=search_query)
        return queryset
    
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        page = self.paginate_queryset(queryset)
        if not queryset.exists():
            return Response({"detail": "No results found."}, status=status.HTTP_204_NO_CONTENT)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class SendFriendRequestView(generics.CreateAPIView):
    serializer_class = FriendRequestSerializertwo
    permission_classes = [permissions.IsAuthenticated]

    def create(self, request, *args, **kwargs):
        user_id = request.user.id
        cache_key = f'friend_request_{user_id}'
        request_count = cache.get(cache_key, 0)
        
        if request_count >= 3:
            raise Throttled(detail="You can only send 3 friend requests per minute.")
        
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        receiver_email = serializer.validated_data['receiver_email']
        
        try:
            receiver = Profile.objects.get(email=receiver_email)
        except Profile.DoesNotExist:
            return Response({"detail": "User with this email does not exist."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if a friend request already exists
        if FriendRequest.objects.filter(sender=request.user, receiver=receiver).exists():
            return Response({"detail": "Friend request already sent."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Set the sender and receiver
        friend_request = FriendRequest(sender=request.user, receiver=receiver)
       
        try:
            friend_request.full_clean()
        except ValidationError as e:
            return Response({"detail": e.message_dict}, status=status.HTTP_400_BAD_REQUEST)
        
       
        friend_request.save()

        # Update request count in cache
        if request_count == 0:
            cache.set(cache_key, 1, 60)
        else:
            cache.incr(cache_key)

        headers = self.get_success_headers(serializer.data)
        return Response({"detail": "Friend request sent successfully."}, status=status.HTTP_201_CREATED, headers=headers)
        
        
        
        
        

class RespondToFriendRequestView(generics.UpdateAPIView):
    queryset = FriendRequest.objects.all()
    serializer_class = FriendRequestSerializer
    permission_classes = [IsAuthenticated]

    def update(self, request, *args, **kwargs):
        friend_request = self.get_object()
        if friend_request.receiver != request.user:
            return Response({"detail": "Not authorized to respond to this request."}, status=status.HTTP_403_FORBIDDEN)

        action = request.data.get('action')
        if action == 'accept':
            friend_request.is_accepted = True
            friend_request.save()
            return Response({"detail": "Friend request accepted."}, status=status.HTTP_200_OK)
        elif action == 'reject':
            friend_request.delete()
            return Response({"detail": "Friend request rejected."}, status=status.HTTP_200_OK)
        else:
            return Response({"detail": "Invalid action."}, status=status.HTTP_400_BAD_REQUEST)


class ListReceivedFriendRequestsView(generics.ListAPIView):
    serializer_class = FriendRequestSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return FriendRequest.objects.filter(receiver=self.request.user, is_accepted=False)

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        if not queryset.exists():
            return Response({"detail": "No friend requests received."}, status=status.HTTP_204_NO_CONTENT)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    
    
    
    

class ListFriendsView(generics.ListAPIView):
    serializer_class = FriendRequestSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Get users who have accepted the friend request from the current user
        accepted_requests = FriendRequest.objects.filter(sender=self.request.user, is_accepted=True)
        friend_ids = accepted_requests.values_list('receiver_id', flat=True)
        return Profile.objects.filter(id__in=friend_ids)    
    
class ListPendingFriendRequestsView(generics.ListAPIView):
    serializer_class = FriendRequestSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return FriendRequest.objects.filter(receiver=self.request.user, is_accepted=False)
    
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        if not queryset.exists():
            return Response({"detail": "No pending friend requests."}, status=status.HTTP_204_NO_CONTENT)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    
    
    
class ListAcceptFriendRequestsView(generics.ListAPIView):
    serializer_class = FriendRequestSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return FriendRequest.objects.filter(receiver=self.request.user, is_accepted=True)    
    
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        if not queryset.exists():
            return Response({"detail": "No accepted friend requests."}, status=status.HTTP_204_NO_CONTENT)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)