import logging
import logging.handlers
import os
import sys
from datetime import datetime
from pathlib import Path

# Create logs directory if it doesn't exist
logs_dir = Path("logs")
logs_dir.mkdir(exist_ok=True)

# Configure logging format
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
DETAILED_LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s"

def setup_logging(
    log_level=logging.INFO,
    log_to_file=True,
    log_to_console=True,
    max_file_size=10*1024*1024,  # 10MB
    backup_count=5
):
    """
    Setup comprehensive logging configuration
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_to_file: Whether to log to files
        log_to_console: Whether to log to console
        max_file_size: Maximum size of log files before rotation
        backup_count: Number of backup log files to keep
    """
    
    # Create root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Create formatters
    console_formatter = logging.Formatter(LOG_FORMAT)
    file_formatter = logging.Formatter(DETAILED_LOG_FORMAT)
    
    # Console handler
    if log_to_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(console_formatter)
        # Set encoding to utf-8 to handle emojis on Windows
        if hasattr(console_handler.stream, 'reconfigure'):
            console_handler.stream.reconfigure(encoding='utf-8')
        root_logger.addHandler(console_handler)
    
    # File handlers
    if log_to_file:
        # General application log
        app_log_file = logs_dir / "app.log"
        app_handler = logging.handlers.RotatingFileHandler(
            app_log_file,
            maxBytes=max_file_size,
            backupCount=backup_count
        )
        app_handler.setLevel(log_level)
        app_handler.setFormatter(file_formatter)
        root_logger.addHandler(app_handler)
        
        # Error log
        error_log_file = logs_dir / "error.log"
        error_handler = logging.handlers.RotatingFileHandler(
            error_log_file,
            maxBytes=max_file_size,
            backupCount=backup_count
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(file_formatter)
        root_logger.addHandler(error_handler)
        
        # Database operations log
        db_log_file = logs_dir / "database.log"
        db_handler = logging.handlers.RotatingFileHandler(
            db_log_file,
            maxBytes=max_file_size,
            backupCount=backup_count
        )
        db_handler.setLevel(logging.INFO)
        db_handler.setFormatter(file_formatter)
        
        # Create database logger
        db_logger = logging.getLogger("database")
        db_logger.addHandler(db_handler)
        db_logger.setLevel(logging.INFO)
        
        # API requests log
        api_log_file = logs_dir / "api.log"
        api_handler = logging.handlers.RotatingFileHandler(
            api_log_file,
            maxBytes=max_file_size,
            backupCount=backup_count
        )
        api_handler.setLevel(logging.INFO)
        api_handler.setFormatter(file_formatter)
        
        # Create API logger
        api_logger = logging.getLogger("api")
        api_logger.addHandler(api_handler)
        api_logger.setLevel(logging.INFO)
    
    # Set specific loggers
    logging.getLogger("uvicorn").setLevel(logging.INFO)
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)
    logging.getLogger("gunicorn").setLevel(logging.INFO)
    logging.getLogger("motor").setLevel(logging.WARNING)  # Reduce MongoDB driver noise
    logging.getLogger("pymongo").setLevel(logging.WARNING)
    
    print(f"✅ Logging configured successfully")
    print(f"📁 Log files directory: {logs_dir.absolute()}")
    if log_to_file:
        print(f"📄 Application log: {logs_dir / 'app.log'}")
        print(f"📄 Error log: {logs_dir / 'error.log'}")
        print(f"📄 Database log: {logs_dir / 'database.log'}")
        print(f"📄 API log: {logs_dir / 'api.log'}")

def get_logger(name):
    """Get a logger instance with the specified name"""
    return logging.getLogger(name)

# Performance monitoring decorator
def log_performance(logger_name="performance"):
    """Decorator to log function performance"""
    def decorator(func):
        import time
        import functools
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            logger = get_logger(logger_name)
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                execution_time = time.time() - start_time
                logger.info(f"{func.__name__} completed in {execution_time:.3f}s")
                return result
            except Exception as e:
                execution_time = time.time() - start_time
                logger.error(f"{func.__name__} failed after {execution_time:.3f}s: {str(e)}")
                raise
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            logger = get_logger(logger_name)
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                execution_time = time.time() - start_time
                logger.info(f"{func.__name__} completed in {execution_time:.3f}s")
                return result
            except Exception as e:
                execution_time = time.time() - start_time
                logger.error(f"{func.__name__} failed after {execution_time:.3f}s: {str(e)}")
                raise
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator

# Database connection monitoring
class DatabaseMonitor:
    def __init__(self):
        self.logger = get_logger("database")
        self.connection_count = 0
        self.query_count = 0
        self.slow_query_threshold = 1.0  # seconds
    
    def log_connection(self, operation="connect"):
        self.connection_count += 1
        self.logger.info(f"Database {operation} - Total connections: {self.connection_count}")
    
    def log_query(self, query_type, duration, collection=None):
        self.query_count += 1
        if duration > self.slow_query_threshold:
            self.logger.warning(f"Slow query detected: {query_type} on {collection} took {duration:.3f}s")
        else:
            self.logger.debug(f"Query: {query_type} on {collection} took {duration:.3f}s")
    
    def get_stats(self):
        return {
            "connection_count": self.connection_count,
            "query_count": self.query_count
        }

# Initialize global database monitor
db_monitor = DatabaseMonitor()

# API request monitoring
class APIMonitor:
    def __init__(self):
        self.logger = get_logger("api")
        self.request_count = 0
        self.slow_request_threshold = 2.0  # seconds
    
    def log_request(self, method, path, status_code, duration, user_id=None):
        self.request_count += 1
        
        log_data = {
            "method": method,
            "path": path,
            "status_code": status_code,
            "duration": f"{duration:.3f}s",
            "user_id": user_id
        }
        
        if duration > self.slow_request_threshold:
            self.logger.warning(f"Slow API request: {log_data}")
        else:
            self.logger.info(f"API request: {log_data}")
    
    def get_stats(self):
        return {
            "request_count": self.request_count
        }

# Initialize global API monitor
api_monitor = APIMonitor() 