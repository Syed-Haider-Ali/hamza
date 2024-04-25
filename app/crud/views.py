from rest_framework.viewsets import ModelViewSet
from .controller import *
from .serializers import MakeSerializer
from utils.base_authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated

make_controller = MakeController()


class MakeAPIView(ModelViewSet):
    serializer_class = MakeSerializer
    authentication_classes = (JWTAuthentication,)
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        return make_controller.get(request)

    def post(self, request):
        return make_controller.post(request)

    def update(self, request):
        return make_controller.update(request)

    def delete(self, request):
        return make_controller.delete(request)