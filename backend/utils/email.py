from typing import List
from django.core.mail import send_mail



def send_email(receiver_emails: List[str], sender_email:str, obj:str, msg:str):
    send_mail(
        subject=obj,
        message=msg,
        from_email=sender_email,
        recipient_list=receiver_emails,
        fail_silently=False
    )