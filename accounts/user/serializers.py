from rest_framework import serializers
from accounts.user.models import User

class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['id', 'username', 'email','mobile','user_bio', 'is_active']
        read_only_field = ['is_active']


    def to_representation(self, instance):
        data = super().to_representation(instance)
        # Obfuscate sensitive information
        data['email'] = "********"
        data['username'] = "********"
        data['is_active'] = "********"
        data['user_bio'] = "********"
        data['mobile'] = "********"
        return data