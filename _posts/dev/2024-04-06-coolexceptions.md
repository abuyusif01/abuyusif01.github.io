---
title: Decorating Exception Handler
date: 2024-04-06
categories: [development]
tags: [python, decorators]     # TAG names should always be lowercase
---

# Elevating Python Exception Handling: A Deep Dive into Custom Exception Handlers

Exception handling is a fundamental aspect of software development. It ensures that your application gracefully handles unforeseen circumstances, providing users with a seamless experience. Python, with its robust error handling mechanisms, offers developers a plethora of tools to manage exceptions effectively. One such tool that stands out is the custom exception handler, a powerful construct that empowers developers to take control of error management like never before.

In this article, we'll explore a sophisticated custom exception handler developed for the H2OGPT Module. We'll dissect its features, showcase its utility in real-world scenarios, and demonstrate how it revolutionizes exception handling in Python projects.

## Understanding the Exception Handler

Let's start by examining the core components of our custom exception handler:

```python
from functools import wraps
import inspect, os
from typing import Any, Optional

from app.h2ogpt.src.h2ogpt.schemas.response import APIExceptionResponse


class ExceptionHandler(Exception):
    """
    Custom exception handler for H2OGPT application.
    Args:
        exception (Exception): The original exception that occurred.
        msg (Optional[Any]): Additional message describing the exception.
        cls_name (Optional[str]): Name of the class where the exception occurred.
        func_name (Optional[str]): Name of the function where the exception occurred.
        solution (Optional[Any]): Suggested solution for the exception.
    """

    def __init__(
        self,
        exception: Exception,
        msg: Optional[Any] = None,
        solution: Optional[Any] = None,
    ) -> None:
        super().__init__()
        self.exception = exception
        self.msg = msg if isinstance(msg, str) else self.exception.__str__()
        self.func_name = inspect.stack()[2].function
        self.solution = solution

    def __repr__(self) -> dict:
        verbose: int = int(os.getenv("H2OGPT_VERBOSE", 3))
        exception_name = self.exception.__class__.__name__
        cause = self.msg if verbose != 3 else self.get_cause_details()
        if verbose == 1:
            return {
                "msg": self.msg,
                "error": exception_name,
                "solution": self.solution,
            }
        elif verbose >= 2:
            return {
                "error": exception_name,
                "cause": cause,
                "solution": self.solution,
                "msg": self.msg,
            }
        else:
            return {"msg": self.msg}

    def get_cause_details(self) -> str:
        frames = inspect.stack()
        for frame_info in frames:
            frame = frame_info.frame

            if frame.f_code.co_name == self.func_name:
                filename = frame_info.filename
                lineno = frame_info.lineno
                func_name = frame_info.function
                cls_name = frame.f_globals.get("__name__", "Unknown")
                return f"{cls_name}.{func_name} raised the exception at line {lineno} in {filename}"
```

### Understanding the `exhandler` Decorator

The `exhandler` decorator is a versatile construct designed to augment functions with advanced exception handling capabilities. Let's dissect its inner workings:

```python
def exhandler(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        cls_name = args[0].__class__.__name__
        func_name = func.__name__
        try:
            result = func(*args, **kwargs)
        except Exception as e:
            return APIExceptionResponse(**ExceptionHandler(e).__repr__())
        if isinstance(result, ExceptionHandler):
            if int(os.getenv("H2OGPT_VERBOSE", 0)) == 3:
                return APIExceptionResponse(
                    **result.__repr__(),
                    class_name=cls_name,
                    function_name=func_name,
                )
            else:
                return APIExceptionResponse(**result.__repr__())
        return result

    return wrapper
```

#### Key Features:

1. **Wrapping Functionality**: The `@wraps` decorator from the `functools` module ensures that the metadata of the original function is preserved when it's decorated. This ensures that attributes such as `__name__` and `__doc__` remain unchanged, facilitating better introspection and debugging.

2. **Exception Handling**: Within the `wrapper` function, the decorated function `func` is invoked within a `try-except` block. This allows the decorator to intercept any exceptions raised during the execution of `func`.

3. **Custom Error Handling**: If an exception is caught, the `ExceptionHandler` class is utilized to create a custom error response. This response encapsulates details about the exception, including its type, message, and potential solutions.

4. **Integration with Environment Variables**: The verbosity level for error messages is determined dynamically based on the value of the `H2OGPT_VERBOSE` environment variable. This ensures that developers have fine-grained control over the level of detail provided in error responses.

5. **Enhanced Response**: If the result returned by the decorated function is an instance of `ExceptionHandler`, the error response is further augmented with contextual information such as the class name and function name where the exception occurred.

This custom exception handler, tailored for the H2OGPT application, offers a suite of features to streamline error management. The handler's design prioritizes flexibility and customization. Developers can tailor the verbosity level of error messages to suit specific requirements. Whether it's providing a succinct summary or an in-depth analysis including causes and solutions, the handler adapts effortlessly.


## Example of how to use it with FastAPI

```python
from fastapi import APIException, Depends, HTTPException, status
from fastapi.routing import APIRouter

router = APIRouter()

@router.get("/", response_model=list | APIExceptionResponse)
async def get_all_docs(user: CurrentUser, client: Client = Depends(h2ogpt_client)):
    """
    Get all documents
    """
    try:
        result = H2ogptDocs(client).get_docs(user.id)
    finally:
        if isinstance(result, APIExceptionResponse):
            raise HTTPException(status_code=500, detail=result.dict())
    return result
```

Here, our custom exception handler ensures that any exceptions raised during the retrieval of documents are captured and handled appropriately. Whether it's returning a custom error response or propagating the exception with additional context, the handler ensures a smooth user experience.

In complex applications like the project i was working on, pinpointing the exact cause of an error is paramount. Our custom exception handler excels in this aspect. By setting the verbosity level to its maximum, developers gain unprecedented insight into error occurrences. Detailed information, including class names, function names, and line numbers, empowers developers to diagnose and resolve issues swiftly.


## The Power of Decorators

A standout feature of our custom exception handler is its seamless integration with Python decorators. Let's explore this further by creating a custom function and applying the `@exhandler` decorator to showcase its utility:

```python
@exhandler
def custom_function():
    raise Exception("what ever")
    pass
```

By simply decorating our function with `@exhandler`, we imbue it with the exceptional error handling capabilities offered by our custom handler. Whether it's handling exceptions gracefully or providing detailed error reports, the decorator enhances the robustness of our function effortlessly.

## Conclusion

In conclusion, the custom exception handler we've explored in this article represents a paradigm shift in Python exception handling. Its flexibility, integration capabilities, and granular error reporting elevate error management to new heights. Whether you're developing complex applications like H2OGPT or building APIs with FastAPI, this handler empowers you to tackle exceptions with confidence.

As you embark on your software development journey, remember the power of effective exception handling. Embrace the tools and techniques that streamline error management, and watch as your applications soar to new levels of reliability and user satisfaction.