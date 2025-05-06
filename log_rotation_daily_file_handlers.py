'auth_file': {
    'level': 'INFO',
    'class': 'logging.handlers.TimedRotatingFileHandler',
    'filename': os.path.join(__project__.base_path, 'logs/auth.log'),
    'when': 'midnight',
    'interval': 1,
    'backupCount': 180,  # keep 180 days
    'formatter': 'verbose',
},

'actions_file': {
    'level': 'INFO',
    'class': 'logging.handlers.TimedRotatingFileHandler',
    'filename': os.path.join(__project__.base_path, 'logs/actions.log'),
    'when': 'midnight',
    'interval': 1,
    'backupCount': 180,
    'formatter': 'verbose',
},

'django_file': {
    'level': 'INFO',
    'class': 'logging.handlers.TimedRotatingFileHandler',
    'filename': os.path.join(__project__.base_path, 'logs/django.log'),
    'when': 'midnight',
    'interval': 1,
    'backupCount': 180,
    'formatter': 'verbose',
},
