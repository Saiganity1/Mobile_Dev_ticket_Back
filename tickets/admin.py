from django.contrib import admin
from .models import Ticket, Message, Attachment


@admin.register(Ticket)
class TicketAdmin(admin.ModelAdmin):
    list_display = ('uid', 'title', 'first_name', 'last_name', 'created_at', 'is_open')
    readonly_fields = ('uid',)
    
    class AttachmentInline(admin.TabularInline):
        model = Attachment
        extra = 0

    inlines = [AttachmentInline]


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ('ticket', 'sender', 'created_at')


@admin.register(Attachment)
class AttachmentAdmin(admin.ModelAdmin):
    list_display = ('ticket', 'file', 'uploaded_at')
