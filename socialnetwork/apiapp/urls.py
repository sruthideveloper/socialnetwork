from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from .views import ProfileSignupView,LoginView,UserSearchView,SendFriendRequestView,RespondToFriendRequestView,ListReceivedFriendRequestsView,ListFriendsView,ListPendingFriendRequestsView,ListAcceptFriendRequestsView


urlpatterns = [
    path('signup/', ProfileSignupView.as_view(), name='signup'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('login/', LoginView.as_view(), name='login'),
    path('search/', UserSearchView.as_view(), name='user-search'),
    path('send-friend-request/', SendFriendRequestView.as_view(), name='send-friend-request'),
    path('respond-friend-request/<int:pk>/', RespondToFriendRequestView.as_view(), name='respond-friend-request'),
    path('list-received-requests/', ListReceivedFriendRequestsView.as_view(), name='list-received-requests'),
    path('list-friends/', ListFriendsView.as_view(), name='list-friends'),
    path('list-pending-requests/', ListPendingFriendRequestsView.as_view(), name='list-pending-requests'),
    path('list-Accept-requests/', ListAcceptFriendRequestsView.as_view(), name='list-pending-requests'),
    
  #  path('login/', UserLoginView.as_view(), name='login'),
]