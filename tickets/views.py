from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from .models import Ticket, Message
from django.db.models import Q
from .serializers import TicketSerializer, MessageSerializer, TicketAdminSerializer
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from django.views.decorators.csrf import csrf_exempt
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import serializers
from django.http import HttpResponse


class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("username", "first_name", "last_name", "email", "password")
        extra_kwargs = {"password": {"write_only": True}}

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


@api_view(["POST"])
@permission_classes([AllowAny])
def register(request):
    serializer = RegisterSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()
    token, _ = Token.objects.get_or_create(user=user)
    return Response({
        "token": token.key,
        "username": user.username,
        "user_id": user.id,
        "is_admin": bool(user.is_staff or user.is_superuser)
    })


@api_view(["POST"])
@permission_classes([AllowAny])
def login(request):
    username = request.data.get("username")
    password = request.data.get("password")
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return Response({"detail": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
    if not user.check_password(password):
        return Response({"detail": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
    token, _ = Token.objects.get_or_create(user=user)
    return Response({
        "token": token.key,
        "username": user.username,
        "user_id": user.id,
        "is_admin": bool(user.is_staff or user.is_superuser)
    })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def me(request):
    u = request.user
    return Response({
        "id": u.id,
        "username": u.username,
        "is_staff": u.is_staff,
        "is_superuser": u.is_superuser,
        "is_admin": bool(u.is_staff or u.is_superuser)
    })


class TicketCreateView(generics.CreateAPIView):
    queryset = Ticket.objects.all()
    serializer_class = TicketSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        required = ["first_name", "last_name", "title", "description"]
        for f in required:
            if not request.data.get(f):
                return Response({"detail": f"{f} is required."}, status=status.HTTP_400_BAD_REQUEST)

        files = request.FILES.getlist("attachments") or request.FILES.getlist("attachment")
        if not files:
            return Response({"detail": "at least one attachment is required."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        ticket = serializer.save(user=request.user if request.user and request.user.is_authenticated else None)

        from .models import Attachment
        for f in files:
            Attachment.objects.create(ticket=ticket, file=f)

        return Response(TicketSerializer(ticket).data, status=status.HTTP_201_CREATED)


class TicketListView(generics.ListAPIView):
    queryset = Ticket.objects.all().order_by("-created_at")
    serializer_class = TicketSerializer

    class MyTicketsPagination(PageNumberPagination):
        page_size = 20

    pagination_class = MyTicketsPagination


class MyTicketListView(generics.ListAPIView):
    serializer_class = TicketSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        qs = Ticket.objects.filter(user=user)
        try:
            fn = (user.first_name or "").strip()
            ln = (user.last_name or "").strip()
            if fn or ln:
                name_q = Q(first_name__iexact=fn) & Q(last_name__iexact=ln)
                qs = Ticket.objects.filter(Q(user=user) | name_q)
        except Exception:
            qs = Ticket.objects.filter(user=user)
        is_open = self.request.query_params.get("is_open")
        if is_open is not None:
            val = str(is_open).lower() in ("1", "true", "yes")
            qs = qs.filter(is_open=val)
        return qs.order_by("-updated_at")


class AdminTicketListView(generics.ListAPIView):
    queryset = Ticket.objects.all().order_by("-updated_at")
    serializer_class = TicketAdminSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        if not request.user.is_staff and not request.user.is_superuser:
            return Response({"detail": "Not authorized"}, status=status.HTTP_403_FORBIDDEN)
        try:
            return super().get(request, *args, **kwargs)
        except Exception as e:
            import traceback as _tb

            tb = _tb.format_exc()
            return Response({"detail": "server error in admin ticket list", "error": str(e), "traceback": tb}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AdminPendingTicketsView(generics.ListAPIView):
    serializer_class = TicketAdminSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Ticket.objects.filter(is_open=True).order_by("-updated_at")

    def get(self, request, *args, **kwargs):
        if not request.user.is_staff and not request.user.is_superuser:
            return Response({"detail": "Not authorized"}, status=status.HTTP_403_FORBIDDEN)
        try:
            return super().get(request, *args, **kwargs)
        except Exception as e:
            import traceback as _tb

            tb = _tb.format_exc()
            return Response({"detail": "server error in admin pending tickets", "error": str(e), "traceback": tb}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def admin_ticket_action(request, uid):
    if not request.user.is_staff and not request.user.is_superuser:
        return Response({"detail": "Not authorized"}, status=status.HTTP_403_FORBIDDEN)
    try:
        ticket = Ticket.objects.get(uid=uid)
    except Ticket.DoesNotExist:
        return Response({"detail": "Ticket not found"}, status=status.HTTP_404_NOT_FOUND)

    action = request.data.get("action")
    if action == "close":
        ticket.is_open = False
        ticket.closed_by = request.user
        from django.utils import timezone

        ticket.closed_at = timezone.now()
        ticket.save()
        return Response({"status": "closed", "closed_by": request.user.username, "closed_at": ticket.closed_at})
    elif action == "reopen":
        ticket.is_open = True
        ticket.reopened_by = request.user
        from django.utils import timezone

        ticket.reopened_at = timezone.now()
        ticket.save()
        return Response({"status": "reopened", "reopened_by": request.user.username, "reopened_at": ticket.reopened_at})
    elif action == "assign":
        uid_user = request.data.get("assign_user_id")
        if not uid_user:
            return Response({"detail": "assign_user_id required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(id=uid_user)
            ticket.assigned_to = user
            ticket.save()
            return Response({"status": "assigned", "assigned_to": user.username})
        except User.DoesNotExist:
            return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)
    return Response({"detail": "unknown action"}, status=status.HTTP_400_BAD_REQUEST)


class AdminTicketDetailView(generics.RetrieveAPIView):
    queryset = Ticket.objects.all()
    serializer_class = TicketAdminSerializer
    lookup_field = "uid"

    def get(self, request, *args, **kwargs):
        if not request.user.is_staff and not request.user.is_superuser:
            return Response({"detail": "Not authorized"}, status=status.HTTP_403_FORBIDDEN)
        ticket = self.get_object()
        ticket.messages.filter(sender__iexact="user", is_read=False).update(is_read=True)
        return super().get(request, *args, **kwargs)


class TicketDetailView(generics.RetrieveAPIView):
    queryset = Ticket.objects.all()
    serializer_class = TicketSerializer
    lookup_field = "uid"


@api_view(["GET"])
@permission_classes([AllowAny])
def ticket_receipt(request, id):
    try:
        ticket = Ticket.objects.get(id=id)
    except Ticket.DoesNotExist:
        try:
            ticket = Ticket.objects.get(ticket_number=id)
        except Ticket.DoesNotExist:
            return Response({"detail": "Ticket not found"}, status=status.HTTP_404_NOT_FOUND)

    user = request.user if hasattr(request, "user") else None
    if user and getattr(user, "is_authenticated", False):
        if ticket.user and ticket.user == user:
            allowed = True
        elif user.is_staff or user.is_superuser:
            allowed = True
        else:
            allowed = (ticket.first_name or "").strip().lower() == (user.first_name or "").strip().lower() and (ticket.last_name or "").strip().lower() == (user.last_name or "").strip().lower()
        if not allowed:
            return Response({"detail": "Not authorized to view this receipt"}, status=status.HTTP_403_FORBIDDEN)
    else:
        qfn = (request.query_params.get("first_name") or "").strip().lower()
        qln = (request.query_params.get("last_name") or "").strip().lower()
        if not qfn or not qln or qfn != (ticket.first_name or "").strip().lower() or qln != (ticket.last_name or "").strip().lower():
            return Response({"detail": "Authentication credentials were not provided or name did not match. Provide first_name and last_name query params."}, status=status.HTTP_401_UNAUTHORIZED)

    serializer = TicketSerializer(ticket)
    data = serializer.data
    receipt = {
        "ticket_number": data.get("ticket_number") or data.get("id"),
        "uid": data.get("uid"),
        "first_name": data.get("first_name"),
        "last_name": data.get("last_name"),
        "title": data.get("title"),
        "description": data.get("description"),
    "is_open": ticket.is_open,
        "created_at": data.get("created_at"),
    }
    return Response(receipt)


@csrf_exempt
@api_view(["GET", "POST"])
@permission_classes([AllowAny])
def ticket_receipt_pdf(request, id):
    try:
        ticket = Ticket.objects.get(id=id)
    except Ticket.DoesNotExist:
        try:
            ticket = Ticket.objects.get(ticket_number=id)
        except Ticket.DoesNotExist:
            return Response({"detail": "Ticket not found"}, status=status.HTTP_404_NOT_FOUND)

    # Authorization
    user = getattr(request, "user", None)
    pre_fn = ""
    pre_ln = ""
    if user and getattr(user, "is_authenticated", False):
        if ticket.user and ticket.user != user and not (user.is_staff or user.is_superuser):
            if not ((ticket.first_name or "").strip().lower() == (user.first_name or "").strip().lower() and (ticket.last_name or "").strip().lower() == (user.last_name or "").strip().lower()):
                return Response({"detail": "Not authorized to view this receipt"}, status=status.HTTP_403_FORBIDDEN)
    else:
        posted = request.data if hasattr(request, "data") else {}
        qfn = (posted.get("first_name") or request.query_params.get("first_name") or request.headers.get("X-First-Name") or "")
        qln = (posted.get("last_name") or request.query_params.get("last_name") or request.headers.get("X-Last-Name") or "")
        qfn = (qfn or "").strip().lower()
        qln = (qln or "").strip().lower()

        pre_fn = request.query_params.get("first_name") or ""
        pre_ln = request.query_params.get("last_name") or ""

        if not qfn or not qln:
            accepts = request.META.get("HTTP_ACCEPT", "")
            if "text/html" in accepts:
                html = f"""
                <html><body>
                <h3>Ticket Receipt {ticket.id}</h3>
                <p>Enter first and last name to view the e-receipt for ticket #{ticket.ticket_number or ticket.id}.</p>
                <form method="post">
                  <input name="first_name" placeholder="First name" value="{pre_fn}" />
                  <input name="last_name" placeholder="Last name" value="{pre_ln}" />
                  <button type="submit">View E-Receipt</button>
                </form>
                </body></html>
                """
                return HttpResponse(html)
            return Response({"detail": "Authentication credentials were not provided. Provide first_name and last_name in POST body or query params."}, status=status.HTTP_401_UNAUTHORIZED)

        if qfn != (ticket.first_name or "").strip().lower() or qln != (ticket.last_name or "").strip().lower():
            return Response({"detail": "Name did not match the ticket owner."}, status=status.HTTP_403_FORBIDDEN)

        # If browser requested HTML, render an e-receipt with a hidden form to download PDF
        accepts = request.META.get("HTTP_ACCEPT", "")
        if "text/html" in accepts:
                # friendly status label
                status_text = "Solved" if not ticket.is_open else "Currently Solving"
                status_color = "#22c55e" if not ticket.is_open else "#fb923c"
                created = ticket.created_at.isoformat() if hasattr(ticket, "isoformat") else str(ticket.created_at)
                posted_fn = (request.data.get("first_name") if hasattr(request, "data") else "") or pre_fn
                posted_ln = (request.data.get("last_name") if hasattr(request, "data") else "") or pre_ln

                        # Modern, mobile-friendly compact receipt HTML (single-page friendly)
                html = f"""
                <!doctype html>
                <html>
                <head>
                    <meta name="viewport" content="width=device-width,initial-scale=1" />
                    <style>
                                body {{ font-family: system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial; background:#fff; padding:10px; color:#0f172a }}
                                .receipt {{ width:100%; max-width:520px; margin:0 auto; background:#fff; border-radius:6px; box-shadow:none; overflow:hidden; border:1px solid #e6edf3 }}
                                .header {{ background:#0f172a; color:#fff; padding:12px 14px }}
                                .brand {{ font-size:16px; font-weight:700 }}
                                .meta {{ display:flex; justify-content:space-between; align-items:center; margin-top:6px }}
                                .status {{ padding:4px 8px; border-radius:999px; color:#fff; font-weight:700; font-size:12px }}
                                .body {{ padding:12px 14px; color:#0f172a; font-size:13px }}
                                .row {{ margin-bottom:8px }}
                                .label {{ color:#64748b; font-size:12px }}
                                .value {{ font-weight:700; margin-top:2px }}
                                .desc {{ white-space:pre-wrap; margin-top:6px; color:#334155; font-size:12px }}
                                .actions {{ padding:10px 14px; border-top:1px solid #eef2f7; display:flex; gap:8px }}
                                .btn {{ flex:1; background:#0f172a; color:#fff; padding:8px 10px; border-radius:6px; text-align:center; text-decoration:none; font-weight:700; font-size:13px }}
                                .btn.secondary {{ background:#e2e8f0; color:#0f172a }}
                    </style>
                </head>
                <body>
                    <div class="receipt">
                                <div class="header">
                                    <div class="brand">Chat Support System</div>
                            <div class="meta">
                                <div style="font-size:13px">Ticket #{ticket.ticket_number or ticket.id}</div>
                                <div class="status" style="background:{status_color}">{status_text}</div>
                            </div>
                        </div>
                        <div class="body">
                            <div class="row">
                                <div class="label">Reported by</div>
                                <div class="value">{ticket.first_name} {ticket.last_name} {('(' + ticket.user.username + ')') if getattr(ticket, 'user', None) else ''}</div>
                            </div>
                            <div class="row">
                                <div class="label">Issue</div>
                                <div class="value">{ticket.title}</div>
                            </div>
                            <div class="row">
                                <div class="label">Description</div>
                                <div class="desc">{(ticket.description or '')[:800].replace('\n','\n')}</div>
                            </div>
                            <div class="row">
                                <div class="label">Created</div>
                                <div class="value">{created}</div>
                            </div>
                        </div>
                        <div class="actions">
                            <form method="post" style="flex:1"> 
                                <input type="hidden" name="first_name" value="{posted_fn}" />
                                <input type="hidden" name="last_name" value="{posted_ln}" />
                                <button class="btn" type="submit">Download PDF</button>
                            </form>
                            <a class="btn secondary" href="/">Close</a>
                        </div>
                    </div>
                </body>
                </html>
                """
                return HttpResponse(html)

    # generate PDF
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        from reportlab.lib import colors
        from reportlab.lib.units import mm
        from io import BytesIO

        buffer = BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter

        # Background and header (compact)
        c.setFillColor(colors.HexColor('#0f172a'))
        c.rect(0, height - 72, width, 72, fill=True, stroke=False)
        c.setFillColor(colors.white)
        c.setFont('Helvetica-Bold', 16)
        c.drawString(40, height - 48, 'Chat Support System')

        # status badge
        status_text = 'Solved' if not ticket.is_open else 'Currently Solving'
        status_color = colors.HexColor('#22c55e') if not ticket.is_open else colors.HexColor('#fb923c')
        c.setFillColor(status_color)
        c.roundRect(width - 160, height - 70, 120, 28, 8, fill=True, stroke=False)
        c.setFillColor(colors.white)
        c.setFont('Helvetica-Bold', 11)
        c.drawCentredString(width - 100, height - 52, status_text)

        # Ticket meta
        c.setFillColor(colors.HexColor('#0f172a'))
        c.setFont('Helvetica-Bold', 11)
        c.drawString(40, height - 100, f'Ticket #{ticket.ticket_number or ticket.id}')
        c.setFont('Helvetica', 9)
        c.drawString(40, height - 114, f'Reported by: {ticket.first_name} {ticket.last_name}' + (f' ({ticket.user.username})' if getattr(ticket, 'user', None) else ''))
        c.drawString(40, height - 128, f'Created: {ticket.created_at}')

        # Issue + description (compact)
        y = height - 150
        c.setFont('Helvetica-Bold', 10)
        c.drawString(40, y, 'Issue:')
        c.setFont('Helvetica', 10)
        c.drawString(90, y, (ticket.title or '')[:80])
        y -= 16
        c.setFont('Helvetica-Bold', 10)
        c.drawString(40, y, 'Description:')
        y -= 12
        c.setFont('Helvetica', 9)
        desc_text = (ticket.description or '')[:1000]
        desc_lines = desc_text.splitlines() or ['']
        for line in desc_lines:
            if y < 60:
                break
            c.drawString(40, y, (line[:100]))
            y -= 12

        # Footer
        if y < 80:
            c.showPage()
            y = height - 80
        c.setFont('Helvetica', 9)
        c.drawString(40, 40, 'Thank you for using Chat Support System')

        c.showPage()
        c.save()
        pdf = buffer.getvalue()
        buffer.close()
        resp = HttpResponse(pdf, content_type='application/pdf')
        resp['Content-Disposition'] = f'attachment; filename="ticket_{ticket.ticket_number or ticket.id}_receipt.pdf"'
        return resp
    except Exception as e:
        return Response({'error': 'PDF generation failed', 'detail': str(e)})


class MessageCreateView(generics.CreateAPIView):
    queryset = Message.objects.all()
    serializer_class = MessageSerializer

    def create(self, request, *args, **kwargs):
        ticket_uid = request.data.get("ticket_uid")
        ticket_id = request.data.get("ticket")
        if ticket_uid:
            try:
                ticket = Ticket.objects.get(uid=ticket_uid)
                request.data["ticket"] = ticket.id
            except Ticket.DoesNotExist:
                return Response({"detail": "Ticket not found"}, status=status.HTTP_404_NOT_FOUND)
        elif not ticket_id:
            return Response({"detail": "ticket or ticket_uid is required"}, status=status.HTTP_400_BAD_REQUEST)

        sender = request.data.get("sender")
        content = request.data.get("content")
        if not sender or not content:
            return Response({"detail": "sender and content are required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            t = Ticket.objects.get(id=request.data.get("ticket"))
        except Exception:
            t = None

        if sender.lower() == "user":
            if t is not None and not t.is_open:
                return Response({"detail": "Ticket is closed; user cannot post new messages."}, status=status.HTTP_403_FORBIDDEN)

        if sender.lower() == "admin":
            if not (request.user and (request.user.is_staff or request.user.is_superuser)):
                return Response({"detail": "Only admin users may send messages as admin."}, status=status.HTTP_403_FORBIDDEN)
            if t is not None and not t.is_open:
                return Response({"detail": "Ticket is closed; admin cannot post new messages."}, status=status.HTTP_403_FORBIDDEN)

        return super().create(request, *args, **kwargs)
