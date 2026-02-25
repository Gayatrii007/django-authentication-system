def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')


# core/utils.py

import random
import requests

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_sms(phone, otp):
    url = "https://www.fast2sms.com/dev/bulkV2"
    payload = {
        "route": "otp",
        "variables_values": otp,
        "numbers": phone,
    }
    headers = {
        "authorization": "kFo0ZnVHTXz3eiNIOvqblwsS7xJdCcaRKBYULEjmQ9fGh2APr5CQ2j5cG9UOhE3Xo1ikNJsITyFzKAwq"
    }

    requests.post(url, data=payload, headers=headers)