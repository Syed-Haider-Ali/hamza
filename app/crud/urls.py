from django.urls import path
from .views import MakeAPIView
from . import views

urlpatterns = [


    path('make', MakeAPIView.as_view({'get': 'get',
                                      'post': 'post',
                                      'patch': 'update',
                                      'delete': 'delete'}), name='make_view')
]
