import threading
from django.core.mail import send_mail
from django.utils import timezone
from rest_framework.response import Response
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from User_Management_Backend.settings import EMAIL_HOST_USER
from app.Users.user_serializer import *
from app.Users.models import Token, Address, User
from utils.reusable_methods import get_first_error_message, generate_six_length_random_number
from utils.response_messages import *
from utils.helper import create_response, paginate_data
from django.core.mail import send_mail


class ChangePasswordController:
    serializer_class = ChangePasswordSerializer

    def change_password(self, request):
        user = request.user
        if not user:
            return create_response({}, USER_NOT_FOUND, status_code=400)

        serialized_data = self.serializer_class(data=request.data, context={'user': user})

        if serialized_data.is_valid():
            user.set_password(request.data['new_password'])
            user.save()
            return create_response({}, PASSWORD_UPDATED, status_code=200)
        else:
            return create_response({}, get_first_error_message(serialized_data.errors, UNSUCCESSFUL), status_code=400)


class VerifyOtpController:
    serializer_class = VerifyOtpSerializer

    def verify_otp(self, request):
        # check OTP time delay
        time_delay = timezone.now() - timezone.timedelta(seconds=300)
        user = User.objects.filter(otp=request.data.get("otp"), otp_generated_at__gt=time_delay).first()

        if not user:
            return create_response({}, INVALID_OTP, status_code=400)

        serialized_data = self.serializer_class(data=request.data, context={'user': user})

        if serialized_data.is_valid():
            user.set_password(request.data['new_password'])
            user.otp = None
            user.save()
            return create_response({}, SUCCESSFUL, status_code=200)
        else:
            return create_response({}, get_first_error_message(serialized_data.errors, UNSUCCESSFUL), status_code=400)


class ForgetPasswordController:
    serializer_class = ForgetPasswordSerializer

    def forget_password(self, request):
        serialized_data = self.serializer_class(data=request.data)
        if not serialized_data.is_valid():
            return create_response({}, get_first_error_message(serialized_data.errors, UNSUCCESSFUL), status_code=400)

        user = User.objects.filter(email=request.data['email']).first()
        if not user:
            return create_response({}, USER_NOT_FOUND, status_code=404)

        otp = generate_six_length_random_number()
        user.otp = otp
        user.otp_generated_at = timezone.now()
        user.save()
        subject = "Password Recovery Request"
        message = f"""
            Hi {user.get_full_name()},
            Your request for password recovery has been received.
            Please use the following otp.
            OTP: {otp}
            """
        recipient_list = [request.data.get("email")]
        t = threading.Thread(target=send_mail, args=(subject, message, EMAIL_HOST_USER, recipient_list))
        t.start()
        return create_response({}, EMAIL_SUCCESSFULLY_SENT, status_code=200)

#fine
class RegisterController:
    user_serializer_class = UserSerializer
    address_serializer_class = AddressSerializer

    def create(self, request):
        user_data = request.data.pop('user', None)
        addresses_data = request.data.pop('addresses', None)

        user_serializer = self.user_serializer_class(data=user_data)
        addresses_serializer = self.address_serializer_class(data=addresses_data, many=True)

        if user_serializer.is_valid() and addresses_serializer.is_valid():
            validated_user_data = user_serializer.validated_data

            # Create the user instance
            user_instance = User.objects.create(**validated_user_data)

            # Create the address instances
            addresses_instances = []
            for address_data in addresses_serializer.validated_data:
                address_instance = Address.objects.create(**address_data)
                addresses_instances.append(address_instance)

            # Add addresses to user
            user_instance.addresses.add(*addresses_instances)

            return create_response(user_serializer.data, "SUCCESSFUL", status_code=200)
        else:
            errors = {}
            if not user_serializer.is_valid():
                errors.update(user_serializer.errors)
            if not addresses_serializer.is_valid():
                errors.update(addresses_serializer.errors)
            return create_response({}, get_first_error_message(errors, "UNSUCCESSFUL"), status_code=400)


class LoginController:
    serializer_class = LoginSerializer

    def login(self, request):
        serialized_data = self.serializer_class(data=request.data)

        if not serialized_data.is_valid():
            return Response({'error': get_first_error_message(serialized_data.errors, UNSUCCESSFUL)}, status=400)

        user = authenticate(username=request.data['username'], password=request.data['password'])
        if not user:
            return create_response({}, message=INCORRECT_EMAIL_OR_PASSWORD, status_code=400)

        response_data = {
            "token": user.get_access_token(),
            "name": user.get_full_name(),
            "username": user.username,
        }
        Token.objects.update_or_create(defaults={"token": response_data.get("token")}, user_id=user.id)
        user.failed_login_attempts = 0
        user.last_failed_time = None
        user.last_login = timezone.now()
        user.save()
        return create_response(response_data, SUCCESSFUL, status_code=200)


class LogoutController:
    def logout(self, request):
        user = request.user.id
        token = Token.objects.filter(user=user)
        if not token:
            return create_response({}, UNSUCCESSFUL, status_code=400)
        token.delete()
        return create_response({}, SUCCESSFUL, status_code=200)

class OrganizationController:

    def create_orgranization(self, request):
        serializer = OrganizationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=200)
        return Response(serializer.errors, status=400)
