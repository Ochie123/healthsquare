from rest_framework.routers import SimpleRouter
from accounts.user.viewsets import UserViewSet
from accounts.auth.viewsets import LoginViewSet, RegistrationViewSet, UserProfileView,UserChangePasswordView,SendPasswordResetEmailView,UserPasswordResetView
from django.urls import path,include

routes = SimpleRouter()

# AUTHENTICATION
routes.register(r'auth/login', LoginViewSet, basename='auth-login')
routes.register(r'auth/register', RegistrationViewSet, basename='auth-register')
#routes.register(r'auth/refresh', RefreshViewSet, basename='auth-refresh')

# USER
routes.register(r'users', UserViewSet, basename='users')


urlpatterns = [
    *routes.urls,
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('changepassword/', UserChangePasswordView.as_view(), name='changepassword'),
    path('send-reset-password-email/', SendPasswordResetEmailView.as_view(), name='send-reset-password-email'),
    path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset-password'),
]