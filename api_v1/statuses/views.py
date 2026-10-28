
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView


class StatusAPIView(APIView):
    serializer_class = None
    permission_classes = [AllowAny]

    def get(self, request):
        return Response({
            'statuses': [
                'pending',
                'approved',
                'rejected',
            ]
        })


