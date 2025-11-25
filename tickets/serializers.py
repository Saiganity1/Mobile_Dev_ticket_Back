from rest_framework import serializers
from .models import Ticket, Message, Attachment


class MessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Message
        fields = ('id', 'ticket', 'sender', 'content', 'created_at')
        read_only_fields = ('id', 'created_at')


class AttachmentSerializer(serializers.ModelSerializer):
    filename = serializers.SerializerMethodField()
    size = serializers.SerializerMethodField()

    class Meta:
        model = Attachment
        fields = ('id', 'file', 'filename', 'size', 'uploaded_at')

    def get_filename(self, obj):
        try:
            return obj.file.name.split('/')[-1]
        except Exception:
            return None

    def get_size(self, obj):
        try:
            # file may not have a size until opened; prefer storage.size when available
            f = obj.file
            if hasattr(f, 'size') and f.size is not None:
                return f.size
            # fallback: try storage
            return f.storage.size(f.name)
        except Exception:
            return None


class TicketSerializer(serializers.ModelSerializer):
    messages = MessageSerializer(many=True, read_only=True)
    attachments = AttachmentSerializer(many=True, read_only=True)
    unread_count = serializers.SerializerMethodField()
    closed_by = serializers.SerializerMethodField()
    closed_at = serializers.DateTimeField(read_only=True)
    reopened_by = serializers.SerializerMethodField()
    reopened_at = serializers.DateTimeField(read_only=True)

    class Meta:
        model = Ticket
        fields = (
            'id', 'uid', 'first_name', 'last_name', 'title', 'description', 'attachments', 'created_at', 'is_open', 'messages', 'unread_count',
            'closed_by', 'closed_at', 'reopened_by', 'reopened_at'
        )
        read_only_fields = ('id', 'uid', 'created_at', 'is_open', 'closed_by', 'closed_at', 'reopened_by', 'reopened_at')

    def get_unread_count(self, obj):
        return obj.messages.filter(is_read=False, sender__iexact='user').count()

    def get_closed_by(self, obj):
        return obj.closed_by.username if obj.closed_by else None

    def get_reopened_by(self, obj):
        return obj.reopened_by.username if obj.reopened_by else None


class TicketAdminSerializer(TicketSerializer):
    unread_count = serializers.SerializerMethodField()
    assigned_to = serializers.SerializerMethodField()
    # admin view already inherits closed/reopen fields

    def get_unread_count(self, obj):
        return obj.messages.filter(is_read=False, sender__iexact='user').count()

    def get_assigned_to(self, obj):
        return obj.assigned_to.username if obj.assigned_to else None
    
    class Meta(TicketSerializer.Meta):
        # include the extra admin-only read fields
        fields = TicketSerializer.Meta.fields + ('unread_count', 'assigned_to')
