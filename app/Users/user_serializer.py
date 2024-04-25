from rest_framework import serializers
from django.contrib.auth.hashers import make_password

from app.Users.models import User, Address, Organization
from utils.custom_exceptions import PasswordMustBeEightChar, SameOldPassword, PasswordsDoesNotMatch, WrongOldPassword


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(
        label="old_password",
        style={"input_type": "old_password"},
        trim_whitespace=True,
        write_only=True
    )
    new_password = serializers.CharField(
        label="new_password",
        style={"input_type": "new_password"},
        trim_whitespace=True,
        write_only=True
    )
    confirm_password = serializers.CharField(
        label="confirm_password",
        style={"input_type": "confirm_password"},
        trim_whitespace=True,
        write_only=True
    )
    def validate(self, instance):
        user = self.context.get("user")
        if user.check_password(instance["old_password"]):
            if len(instance["new_password"]) < 8:
                raise PasswordMustBeEightChar()
            if instance["new_password"] == instance["old_password"]:
                raise SameOldPassword()
            if instance['new_password'] != instance['confirm_password']:
                raise PasswordsDoesNotMatch()
            return instance
        else:
            raise WrongOldPassword()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'
    def validate(self,instance):
        if len(instance["password"]) < 7:
            raise PasswordMustBeEightChar()
        instance['password'] = make_password(instance['password'])
        return instance


class VerifyOtpSerializer(serializers.Serializer):
    otp = serializers.CharField(
        label="otp",
        style={"input_type": "otp"},
        trim_whitespace=True,
        write_only=True
    )
    new_password = serializers.CharField(
        label="new_password",
        style={"input_type": "new_password"},
        trim_whitespace=True,
        write_only=True
    )
    confirm_password = serializers.CharField(
        label="confirm_password",
        style={"input_type": "confirm_password"},
        trim_whitespace=True,
        write_only=True
    )
    def validate(self, instance):
        user = self.context.get("user")
        if user.check_password(instance["new_password"]):
            raise SameOldPassword()
        if len(instance["new_password"]) < 7:
            raise PasswordMustBeEightChar()
        if instance['new_password'] != instance['confirm_password']:
            raise PasswordsDoesNotMatch()
        return instance


class ForgetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(
        label="email",
        trim_whitespace=True,
        write_only=True
    )


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(
        label="username",
        trim_whitespace=True,
        write_only=True
    )
    password = serializers.CharField(
        label="password",
        style={"input_type": "password"},
        trim_whitespace = True,
        write_only=True
    )
    def validate(self, instance):
        if len(instance["password"]) < 4:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        if User.objects.filter(username=instance["username"], is_active=False, is_locked=True).exists():
            raise serializers.ValidationError("Your account has been deactivated.")
        return instance


class AddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = Address
        fields = '__all__'

class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = ['id', 'name', 'created_at', 'modified_at']