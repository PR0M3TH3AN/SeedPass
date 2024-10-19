# nostr/logging_config.py

import os
import sys
import logging

def configure_logging(log_file='nostr.log'):
    """
    Configures logging with both file and console handlers.
    Only ERROR and higher-level messages are shown in the terminal, while all messages
    are logged in the log file.
    """
    # Create the 'logs' folder if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')

    # Create the custom logger
    logger = logging.getLogger('nostr')
    logger.setLevel(logging.DEBUG)  # Set to DEBUG for detailed output

    if not logger.handlers:
        # Create handlers
        c_handler = logging.StreamHandler(sys.stdout)
        f_handler = logging.FileHandler(os.path.join('logs', log_file))

        # Set levels
        c_handler.setLevel(logging.ERROR)
        f_handler.setLevel(logging.DEBUG)

        # Create formatters
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s [%(filename)s:%(lineno)d]')
        c_handler.setFormatter(formatter)
        f_handler.setFormatter(formatter)

        # Add handlers to the logger
        logger.addHandler(c_handler)
        logger.addHandler(f_handler)

    return logger
