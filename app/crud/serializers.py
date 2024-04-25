from rest_framework.serializers import ModelSerializer
from .models import Make


class MakeSerializer(ModelSerializer):
    class Meta:
        model = Make
        fields = '__all__'
