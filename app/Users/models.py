from django.db import models
from django.contrib.auth.models import AbstractUser
from utils.reusable_methods import generate_access_token
from utils.reusable_classes import TimeStamps


class Address(TimeStamps):
    address_line_1 = models.CharField(max_length=100)
    address_line_2 = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    country = models.CharField(max_length=100)
    role = models.CharField(max_length=100, null=True, blank=True)
    phone_number = models.CharField(max_length=20)


    def __str__(self):
        return f"{self.address_line_1}, {self.city}, {self.country}"


class Organization(TimeStamps):
    name = models.CharField(max_length=100)


class User(TimeStamps, AbstractUser):
    first_name = models.CharField(max_length=100, blank=True, null=True)
    last_name = models.CharField(max_length=100, blank=True, null=True)
    username = models.CharField(unique=True, max_length=100)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=50, blank=True, null=True)
    password = models.CharField(max_length=100)
    otp = models.IntegerField(null=True, blank=True)
    last_login = models.DateTimeField(null=True, blank=True)
    otp_generated_at = models.DateTimeField(null=True, blank=True)
    failed_login_attempts = models.IntegerField(default=0)
    last_failed_time = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    is_locked = models.BooleanField(default=False)
    addresses = models.ManyToManyField(Address, null=True, blank=True )
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="users")

    REQUIRED_FIELDS = ["email", "password"]

    def get_access_token(self):
        return generate_access_token(self)

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"


class Token(TimeStamps):
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="token"
    )
    token = models.TextField(max_length=500, unique=True, null=False, blank=False)