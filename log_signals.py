import logging
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver

log = logging.getLogger("viper_web")

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')

@receiver(user_logged_in)
def log_login(sender, request, user, **kwargs):
    log.info(f"LOGIN: user={user.username} ip={get_client_ip(request)}")

@receiver(user_logged_out)
def log_logout(sender, request, user, **kwargs):
    log.info(f"LOGOUT: user={user.username} ip={get_client_ip(request)}")

@receiver(user_login_failed)
def log_login_failed(sender, credentials, request, **kwargs):
    log.warning(f"FAILED LOGIN: user={credentials.get('username', '<unknown>')} ip={get_client_ip(request)}")
