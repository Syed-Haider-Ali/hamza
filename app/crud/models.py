from django.db import models
from utils.reusable_classes import TimeStamps
from app.Users.models import User


class Make(TimeStamps):
    name = models.CharField(max_length=100)
    created_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='make_created_by')
    updated_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='make_updated_by')
