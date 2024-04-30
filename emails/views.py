from utils.email import send_email
from rest_framework.views import APIView
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.conf import settings
from django.core.mail import send_mail



class SendMail(APIView):
    """

    """
    permission_classes = [AllowAny]
    def post(self, request):
        try:
            receiver_emails = request.data.get('to')
            subject = request.data.get('subject')
            sender = settings.EMAIL_HOST_USER

            message = request.data.get('msg')
            if not receiver_emails or not subject or not sender or not message:
                return Response({'error': "some parameters missings"}, status=status.HTTP_406_NOT_ACCEPTABLE)
            
            try:
                send_mail(
                    subject=subject,
                    message=message,
                    from_email=sender,
                    recipient_list=[receiver_emails]
                )
                return Response({'error': "Email sent"}, status=status.HTTP_200_OK)

            except:
                return Response({'error': f"Error while sending email"}, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception:  
            return Response({'error': "Internal Error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
send_email_view = SendMail.as_view()