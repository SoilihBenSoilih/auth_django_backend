from django.urls import path
from . import views



urlpatterns = [
    path('register', views.register_view, name="user_register"),
    path('list', views.user_list_view, name="user_list"),
    path('login', views.login_view, name="user_login"),
    path('refresh', views.refresh_view, name="user_refresh"),
    path('verify', views.verify_view, name="user_verify"),
    path('logout', views.logout_view, name="user_logout"),
    path('detail/<uuid:id>', views.user_detail_view, name="user_detail"),
    path('delete/<uuid:id>', views.user_delete_view, name="user_delete"),
    path('verify_email', views.verify_email_view, name="verify_email"),
    path('email_confirm/<str:uidb64>', views.email_confirm_view, name="email_confirm"),
    path('password_reset', views.password_reset_view, name="password_reset"),
    path('password_reset_confirm/<str:uidb64>', views.password_reset_confirm_view, name='password_reset_confirm'),
    path('update', views.user_update_view, name='user_update')
]