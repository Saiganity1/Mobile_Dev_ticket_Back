from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from .models import Ticket, Message
from django.db.models import Q
from .serializers import TicketSerializer, MessageSerializer, TicketAdminSerializer
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import serializers


class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'password')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user
    
    def validate_email(self, value):
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError('A user with that email already exists.')
        return value

    def validate_password(self, value):
        # minimal strength: at least 8 chars, include letters and numbers
        if len(value) < 8:
            raise serializers.ValidationError('Password must be at least 8 characters long.')
        if not any(c.isalpha() for c in value) or not any(c.isdigit() for c in value):
            raise serializers.ValidationError('Password must include letters and numbers.')
        return value


@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    serializer = RegisterSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()
    token, _ = Token.objects.get_or_create(user=user)
    return Response({'token': token.key, 'username': user.username, 'is_admin': user.is_staff or user.is_superuser, 'user_id': user.id})


@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    username = request.data.get('username')
    password = request.data.get('password')
    user = None
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return Response({'detail': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)
    if not user.check_password(password):
        return Response({'detail': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)
    token, _ = Token.objects.get_or_create(user=user)
    return Response({'token': token.key, 'username': user.username, 'is_admin': user.is_staff or user.is_superuser, 'user_id': user.id})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def me(request):
    user = request.user
    return Response({'id': user.id, 'username': user.username, 'is_staff': user.is_staff, 'is_superuser': user.is_superuser, 'email': user.email})


class TicketCreateView(generics.CreateAPIView):
    queryset = Ticket.objects.all()
    serializer_class = TicketSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        # Ensure required fields
        required = ['first_name', 'last_name', 'title', 'description']
        for f in required:
            if not request.data.get(f):
                return Response({'detail': f'{f} is required.'}, status=status.HTTP_400_BAD_REQUEST)
        # at least one attachment required
        # accept both plural 'attachments' and single 'attachment' for backward compatibility
        files = request.FILES.getlist('attachments') or request.FILES.getlist('attachment')
        # debug logging to help diagnose upload issues
        try:
            import logging
            logger = logging.getLogger(__name__)
            logger.debug('CONTENT_TYPE: %s', request.META.get('CONTENT_TYPE'))
            logger.debug('FILES keys: %s', list(request.FILES.keys()))
            logger.debug('FILES count: %s', len(request.FILES))
        except Exception:
            pass
        if not files:
            # helpful debug: return counts
            return Response({'detail': 'at least one attachment is required.', 'files_in_request': len(request.FILES)}, status=status.HTTP_400_BAD_REQUEST)

        # create ticket first
        # attach authenticated user reliably by passing to serializer.save()
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if request.user and request.user.is_authenticated:
            ticket = serializer.save(user=request.user)
        else:
            ticket = serializer.save()

        # save attachments
        from .models import Attachment
        for f in files:
            Attachment.objects.create(ticket=ticket, file=f)

        headers = self.get_success_headers(serializer.data)
        return Response(self.get_serializer(ticket).data, status=status.HTTP_201_CREATED, headers=headers)


class TicketListView(generics.ListAPIView):
    queryset = Ticket.objects.all().order_by('-created_at')
    serializer_class = TicketSerializer

    class MyTicketsPagination(PageNumberPagination):
        page_size = 20

    pagination_class = MyTicketsPagination


class MyTicketListView(generics.ListAPIView):
    """Authenticated user's tickets (their own reports)."""
    serializer_class = TicketSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Primary: tickets explicitly linked to user
        user = self.request.user
        qs = Ticket.objects.filter(user=user)
        # Fallback: if some tickets were submitted before authentication and are orphaned,
        # include tickets that match user's first and last name (case-insensitive).
        try:
            fn = (user.first_name or '').strip()
            ln = (user.last_name or '').strip()
            if fn or ln:
                name_q = Q(first_name__iexact=fn) & Q(last_name__iexact=ln)
                qs = Ticket.objects.filter(Q(user=user) | name_q)
        except Exception:
            # if user has no names set or other issue, keep only linked tickets
            qs = Ticket.objects.filter(user=user)
        is_open = self.request.query_params.get('is_open')
        if is_open is not None:
            # treat 'true' (case-insensitive) and '1' as true
            val = str(is_open).lower() in ('1', 'true', 'yes')
            qs = qs.filter(is_open=val)
        return qs.order_by('-updated_at')


class AdminTicketListView(generics.ListAPIView):
    """Admin-only endpoint to list all tickets with messages and attachments."""
    queryset = Ticket.objects.all().order_by('-updated_at')
    serializer_class = TicketAdminSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        if not request.user.is_staff and not request.user.is_superuser:
            return Response({'detail': 'Not authorized'}, status=status.HTTP_403_FORBIDDEN)
        try:
            return super().get(request, *args, **kwargs)
        except Exception as e:
            import traceback as _tb
            tb = _tb.format_exc()
            # In DEBUG it's useful to return the traceback for debugging local dev
            return Response({'detail': 'server error in admin ticket list', 'error': str(e), 'traceback': tb}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AdminPendingTicketsView(generics.ListAPIView):
    """Admin-only endpoint to list pending (open) tickets only."""
    serializer_class = TicketAdminSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Ticket.objects.filter(is_open=True).order_by('-updated_at')

    def get(self, request, *args, **kwargs):
        if not request.user.is_staff and not request.user.is_superuser:
            return Response({'detail': 'Not authorized'}, status=status.HTTP_403_FORBIDDEN)
        try:
            return super().get(request, *args, **kwargs)
        except Exception as e:
            import traceback as _tb
            tb = _tb.format_exc()
            return Response({'detail': 'server error in admin pending tickets', 'error': str(e), 'traceback': tb}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def admin_ticket_action(request, uid):
    if not request.user.is_staff and not request.user.is_superuser:
        return Response({'detail': 'Not authorized'}, status=status.HTTP_403_FORBIDDEN)
    try:
        ticket = Ticket.objects.get(uid=uid)
    except Ticket.DoesNotExist:
        return Response({'detail': 'Ticket not found'}, status=status.HTTP_404_NOT_FOUND)

    action = request.data.get('action')
    if action == 'close':
        ticket.is_open = False
        ticket.closed_by = request.user
        from django.utils import timezone
        ticket.closed_at = timezone.now()
        ticket.save()
        return Response({'status': 'closed', 'closed_by': request.user.username, 'closed_at': ticket.closed_at})
    elif action == 'reopen':
        ticket.is_open = True
        ticket.reopened_by = request.user
        from django.utils import timezone
        ticket.reopened_at = timezone.now()
        ticket.save()
        return Response({'status': 'reopened', 'reopened_by': request.user.username, 'reopened_at': ticket.reopened_at})
    elif action == 'assign':
        uid_user = request.data.get('assign_user_id')
        if not uid_user:
            return Response({'detail': 'assign_user_id required'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(id=uid_user)
            ticket.assigned_to = user
            ticket.save()
            return Response({'status': 'assigned', 'assigned_to': user.username})
        except User.DoesNotExist:
            return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    return Response({'detail': 'unknown action'}, status=status.HTTP_400_BAD_REQUEST)


class AdminTicketDetailView(generics.RetrieveAPIView):
    queryset = Ticket.objects.all()
    serializer_class = TicketAdminSerializer
    lookup_field = 'uid'

    def get(self, request, *args, **kwargs):
        if not request.user.is_staff and not request.user.is_superuser:
            return Response({'detail': 'Not authorized'}, status=status.HTTP_403_FORBIDDEN)
        # mark user messages as read when admin views
        ticket = self.get_object()
        ticket.messages.filter(sender__iexact='user', is_read=False).update(is_read=True)
        return super().get(request, *args, **kwargs)


class TicketDetailView(generics.RetrieveAPIView):
    queryset = Ticket.objects.all()
    serializer_class = TicketSerializer
    lookup_field = 'uid'


class MessageCreateView(generics.CreateAPIView):
    queryset = Message.objects.all()
    serializer_class = MessageSerializer

    def create(self, request, *args, **kwargs):
        # Expect ticket uid or ticket id
        ticket_uid = request.data.get('ticket_uid')
        ticket_id = request.data.get('ticket')
        if ticket_uid:
            try:
                ticket = Ticket.objects.get(uid=ticket_uid)
                request.data['ticket'] = ticket.id
            except Ticket.DoesNotExist:
                return Response({'detail': 'Ticket not found'}, status=status.HTTP_404_NOT_FOUND)
        elif not ticket_id:
            return Response({'detail': 'ticket or ticket_uid is required'}, status=status.HTTP_400_BAD_REQUEST)

        sender = request.data.get('sender')
        content = request.data.get('content')
        if not sender or not content:
            return Response({'detail': 'sender and content are required'}, status=status.HTTP_400_BAD_REQUEST)

        # enforce ticket open/closed rules: users cannot post to closed tickets
        try:
            t = Ticket.objects.get(id=request.data.get('ticket'))
        except Exception:
            t = None

        if sender.lower() == 'user':
            if t is not None and not t.is_open:
                return Response({'detail': 'Ticket is closed; user cannot post new messages.'}, status=status.HTTP_403_FORBIDDEN)

        # only admins may post messages marked as 'admin'
        if sender.lower() == 'admin':
            if not (request.user and (request.user.is_staff or request.user.is_superuser)):
                return Response({'detail': 'Only admin users may send messages as admin.'}, status=status.HTTP_403_FORBIDDEN)
            # also prevent admins from posting to tickets that have been closed
            if t is not None and not t.is_open:
                return Response({'detail': 'Ticket is closed; admin cannot post new messages.'}, status=status.HTTP_403_FORBIDDEN)

        return super().create(request, *args, **kwargs)
