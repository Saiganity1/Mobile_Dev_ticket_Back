from django.db import models
import uuid


class Ticket(models.Model):
    uid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    # short, unique numeric ticket number for receipts and display
    ticket_number = models.PositiveIntegerField(null=True, blank=True, unique=True, help_text='Short sequential ticket number')
    user = models.ForeignKey('auth.User', related_name='tickets', on_delete=models.SET_NULL, null=True, blank=True)
    assigned_to = models.ForeignKey('auth.User', related_name='assigned_tickets', on_delete=models.SET_NULL, null=True, blank=True)
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150)
    title = models.CharField(max_length=255)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_open = models.BooleanField(default=True)
    # audit fields
    closed_by = models.ForeignKey('auth.User', related_name='closed_tickets', on_delete=models.SET_NULL, null=True, blank=True)
    closed_at = models.DateTimeField(null=True, blank=True)
    reopened_by = models.ForeignKey('auth.User', related_name='reopened_tickets', on_delete=models.SET_NULL, null=True, blank=True)
    reopened_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.title} ({self.uid})"

    def save(self, *args, **kwargs):
        # assign a sequential ticket_number if not set
        creating = self.pk is None
        super().save(*args, **kwargs)
        if self.ticket_number is None:
            # attempt to set ticket_number to max+1
            try:
                last = Ticket.objects.aggregate(models.Max('ticket_number'))['ticket_number__max'] or 0
                self.ticket_number = last + 1
                # save without recursing into this block again
                Ticket.objects.filter(pk=self.pk).update(ticket_number=self.ticket_number)
            except Exception:
                # ignore and leave null; migration / manual fix may be needed
                pass


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
