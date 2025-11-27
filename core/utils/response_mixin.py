from fastapi.responses import JSONResponse
from .exceptions import CustomValidationError
from typing import Optional

#class for CustomResponseMixin
class CustomResponseMixin:
    def success_message(self, message: str, data: Optional[dict] = None, status_code: int = 200):
        return JSONResponse(
            content={
                "message": message,
                "data": data or {},
                "success": True,
                "status_code": status_code,
            },
            status_code=status_code,
        )
    
    def error_message(self, message: str, data: Optional[dict] = None, status_code: int = 400):
        return JSONResponse(
            content={
                "message": message,
                "data": data or {},
                "success": False,
                "status_code": status_code,
            },
            status_code=status_code,
        )
    
    def raise_exception(self, message: str, data: Optional[dict] = None, status_code: int = 400):
        raise CustomValidationError(message=message, data=data, status_code=status_code)
