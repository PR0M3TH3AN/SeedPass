# nostr/logging_config.py

import logging
import os

# Comment out or remove the configure_logging function to avoid conflicts
# def configure_logging():
#     """
#     Configures logging with both file and console handlers.
#     Logs include the timestamp, log level, message, filename, and line number.
#     Only ERROR and higher-level messages are shown in the terminal, while all messages
#     are logged in the log file.
#     """
#     logger = logging.getLogger()
#     logger.setLevel(logging.DEBUG)  # Set root logger to DEBUG
#
#     # Prevent adding multiple handlers if configure_logging is called multiple times
#     if not logger.handlers:
#         # Create the 'logs' folder if it doesn't exist
#         log_directory = 'logs'
#         if not os.path.exists(log_directory):
#             os.makedirs(log_directory)
#
#         # Create handlers
#         c_handler = logging.StreamHandler()
#         f_handler = logging.FileHandler(os.path.join(log_directory, 'app.log'))
#
#         # Set levels: only errors and critical messages will be shown in the console
#         c_handler.setLevel(logging.ERROR)
#         f_handler.setLevel(logging.DEBUG)
#
#         # Create formatters and add them to handlers, include file and line number in log messages
#         formatter = logging.Formatter(
#             '%(asctime)s [%(levelname)s] %(message)s [%(filename)s:%(lineno)d]'
#         )
#         c_handler.setFormatter(formatter)
#         f_handler.setFormatter(formatter)
#
#         # Add handlers to the logger
#         logger.addHandler(c_handler)
#         logger.addHandler(f_handler)
