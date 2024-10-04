from django.urls import path

from . import views
# from . views import *
	
# from .views import signup, login, signup_page, login_page, home_page, home, add_record


urlpatterns= [
    path('signup/',views.signup,name='register'),
    path('signup-page/', views.signup_page, name='signup_page'),
    path('login/',views.login, name='login'),
    # path('accounts/login/', views.login_view, name='login'),
    path('login-page/', views.login_page, name='login_page'),
    path('records/', views.get_records, name='records'),
    path('', views.home, name='home-page'),
    path('detail/<int:pk>/', views.customer_detail, name='customer_detail'), 
    path('record/<int:pk>/',views.customer_record, name='customer_record'),
    path('add/', views.add_record, name='add_record'),
    path('add_record/',views.addrecord_page, name='addrecord_page'),
    path('update/<int:pk>/', views.update_record, name='update_record'),
    path('update-record/<int:pk>/', views.update_record_page, name='update-record-page'),
    path('delete/<int:pk>/', views.delete_record, name='delete'),
    path('delete_page/<int:pk>/', views.delete, name='delete_page'),
    path('logout', views.logout, name='logout')

    # path('home/', views.home, name='home'),
    # path('add/', views.add_record, name='addRecord'),
    # path('add-record-page/', views.add_record_page, name='add-record-page'),
    # path('update/<int:pk>/', views.update_record, name='update_record'),
    # path('update-record/<int:pk>/', views.update_record_page, name='update-record-page')
] 


