from django.urls import path
from . import views

urlpatterns = [
    path('tickets/', views.TicketListView.as_view(), name='ticket-list'),
    path('tickets/my/', views.MyTicketListView.as_view(), name='ticket-my-list'),
    path('tickets/create/', views.TicketCreateView.as_view(), name='ticket-create'),
    path('tickets/<uuid:uid>/', views.TicketDetailView.as_view(), name='ticket-detail'),
    path('tickets/<int:id>/receipt/', views.ticket_receipt, name='ticket-receipt'),
    path('tickets/<int:id>/receipt.pdf', views.ticket_receipt_pdf, name='ticket-receipt-pdf'),
    path('messages/create/', views.MessageCreateView.as_view(), name='message-create'),
    path('auth/register/', views.register, name='register'),
    path('auth/login/', views.login, name='login'),
    path('auth/me/', views.me, name='auth-me'),
    path('admin/tickets/', views.AdminTicketListView.as_view(), name='admin-ticket-list'),
    path('admin/tickets/pending/', views.AdminPendingTicketsView.as_view(), name='admin-ticket-pending'),
    path('admin/tickets/<uuid:uid>/', views.AdminTicketDetailView.as_view(), name='admin-ticket-detail'),
    path('admin/tickets/<uuid:uid>/action/', views.admin_ticket_action, name='admin-ticket-action'),
]
