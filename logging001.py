LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
            'datefmt': "%Y-%m-%d %H:%M:%S",
        },
        'simple': {
            'format': '%(levelname)s %(message)s'
        },
    },
    'handlers': {
        'null': {
            'level': 'DEBUG',
            'class': 'logging.NullHandler',
            'formatter': 'verbose',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'auth_file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': os.path.join(__project__.base_path, 'logs/auth.log'),
            'formatter': 'verbose',
        },
        'actions_file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': os.path.join(__project__.base_path, 'logs/actions.log'),
            'formatter': 'verbose',
        },
        'django_file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': os.path.join(__project__.base_path, 'logs/django.log'),
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['django_file', 'console'],
            'propagate': True,
            'level': 'INFO',
        },
        'viper': {
            'handlers': ['console'],
            'propagate': True,
            'level': 'INFO',
        },
        'viper_web': {
            'handlers': ['console'],
            'propagate': True,
            'level': 'DEBUG',
        },
        'viper_web.auth': {
            'handlers': ['auth_file'],
            'propagate': False,
            'level': 'INFO',
        },
        'viper_web.actions': {
            'handlers': ['actions_file'],
            'propagate': False,
            'level': 'INFO',
        },
        'sqlalchemy.pool.NullPool': {
            'handlers': ['null'],
            'propagate': True,
            'level': 'INFO',
        },
        'werkzeug': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}
