from django.db import models
import uuid


class Ticket(models.Model):
    uid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    user = models.ForeignKey('auth.User', related_name='tickets', on_delete=models.SET_NULL, null=True, blank=True)
    assigned_to = models.ForeignKey('auth.User', related_name='assigned_tickets', on_delete=models.SET_NULL, null=True, blank=True)
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150)
    title = models.CharField(max_length=255)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_open = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.title} ({self.uid})"


class Message(models.Model):
    ticket = models.ForeignKey(Ticket, related_name='messages', on_delete=models.CASCADE)
    sender = models.CharField(max_length=150)  # 'user' or 'admin' or a name
    content = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Msg on {self.ticket.uid} by {self.sender}"


class Attachment(models.Model):
    ticket = models.ForeignKey(Ticket, related_name='attachments', on_delete=models.CASCADE)
    file = models.FileField(upload_to='attachments/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Attachment for {self.ticket.uid}: {self.file.name}"
