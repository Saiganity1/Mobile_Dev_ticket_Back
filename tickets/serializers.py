from rest_framework import serializers
from .models import Ticket, Message, Attachment


class MessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Message
        fields = ('id', 'ticket', 'sender', 'content', 'created_at')
        read_only_fields = ('id', 'created_at')


class AttachmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Attachment
        fields = ('id', 'file', 'uploaded_at')


class TicketSerializer(serializers.ModelSerializer):
    messages = MessageSerializer(many=True, read_only=True)
    attachments = AttachmentSerializer(many=True, read_only=True)
    unread_count = serializers.SerializerMethodField()

    class Meta:
        model = Ticket
        fields = ('id', 'uid', 'first_name', 'last_name', 'title', 'description', 'attachments', 'created_at', 'is_open', 'messages', 'unread_count')
        read_only_fields = ('id', 'uid', 'created_at', 'is_open')

    def get_unread_count(self, obj):
        return obj.messages.filter(is_read=False, sender__iexact='user').count()


class TicketAdminSerializer(TicketSerializer):
    unread_count = serializers.SerializerMethodField()
    assigned_to = serializers.SerializerMethodField()

    def get_unread_count(self, obj):
        return obj.messages.filter(is_read=False, sender__iexact='user').count()

    def get_assigned_to(self, obj):
        return obj.assigned_to.username if obj.assigned_to else None
    
    class Meta(TicketSerializer.Meta):
        # include the extra admin-only read fields
        fields = TicketSerializer.Meta.fields + ('unread_count', 'assigned_to')
