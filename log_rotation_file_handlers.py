'auth_file': {
    'level': 'INFO',
    'class': 'logging.handlers.RotatingFileHandler',
    'filename': os.path.join(__project__.base_path, 'logs/auth.log'),
    'formatter': 'verbose',
    'maxBytes': 5 * 1024 * 1024,  # 5 MB
    'backupCount': 3,
},

'actions_file': {
    'level': 'INFO',
    'class': 'logging.handlers.RotatingFileHandler',
    'filename': os.path.join(__project__.base_path, 'logs/actions.log'),
    'formatter': 'verbose',
    'maxBytes': 5 * 1024 * 1024,
    'backupCount': 3,
},

'django_file': {
    'level': 'INFO',
    'class': 'logging.handlers.RotatingFileHandler',
    'filename': os.path.join(__project__.base_path, 'logs/django.log'),
    'formatter': 'verbose',
    'maxBytes': 10 * 1024 * 1024,
    'backupCount': 5,
},
