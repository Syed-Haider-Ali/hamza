from .serializers import MakeSerializer
from .filters import *
from rest_framework.viewsets import ModelViewSet

from utils.helper import create_response, paginate_data
from utils.response_messages import *
from utils.reusable_methods import get_first_error_message


class MakeController:
    serializer_class = MakeSerializer
    filterset_class = MakeFilter

    def post(self, request):
        serialized_data = self.serializer_class(data=request.data)
        if serialized_data.is_valid():
            instance = serialized_data.save(created_by=request.user, updated_by=request.user)
            response_data = self.serializer_class(instance).data
            return create_response(response_data, SUCCESSFUL, 200)
        else:
            return create_response({}, get_first_error_message(serialized_data.errors, UNSUCCESSFUL), 400)

    def get(self, request):
        instances = self.serializer_class.Meta.model.objects.all()

        filtered_data = self.filterset_class(request.GET, queryset=instances)
        data = filtered_data.qs

        paginated_data = paginate_data(data, request)
        count = data.count()

        serialized_data = self.serializer_class(paginated_data, many=True).data
        response_data = {
            "count": count,
            "data": serialized_data,
        }
        return create_response(response_data, SUCCESSFUL, 200)

    def update(self, request):
        if not "id" in request.query_params:
            return create_response({}, ID_NOT_PROVIDED, 400)
        else:
            instance = self.serializer_class.Meta.model.objects.filter(id=request.query_params.get('id')).first()
            if not instance:
                return create_response({}, NOT_FOUND, 404)

            serialized_data = self.serializer_class(instance, data=request.data, partial=True)
            if serialized_data.is_valid():
                response_data = serialized_data.save(updated_by=request.user)
                return create_response(self.serializer_class(response_data).data, SUCCESSFUL, 200)
            else:
                return create_response({}, get_first_error_message(serialized_data.errors, UNSUCCESSFUL), 400)

    def delete(self, request):
        if not "id" in request.query_params:
            return create_response({}, ID_NOT_PROVIDED, 400)
        instance = self.serializer_class.Meta.model.objects.filter(id=request.query_params.get("id")).first()
        if not instance:
            return create_response({}, NOT_FOUND, 404)
        instance.delete()
        return create_response({}, SUCCESSFUL, 200)
