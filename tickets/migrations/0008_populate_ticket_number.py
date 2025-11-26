from django.db import migrations


def set_ticket_numbers(apps, schema_editor):
    Ticket = apps.get_model('tickets', 'Ticket')
    # Set ticket_number to the existing id for all tickets where it's null.
    for t in Ticket.objects.filter(ticket_number__isnull=True).order_by('id'):
        t.ticket_number = t.id
        t.save(update_fields=['ticket_number'])


class Migration(migrations.Migration):

    dependencies = [
        ('tickets', '0007_ticket_ticket_number'),
    ]

    operations = [
        migrations.RunPython(set_ticket_numbers, migrations.RunPython.noop),
    ]
