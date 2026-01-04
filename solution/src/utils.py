#!/usr/bin/env python3
"""Utility functions for the vulnerability RAG system.

Reviewer: This is just a simple retry with backoff utility for API calls. No need to focus on this.

NOTE: If we were using PydanticAI or similar frameworks, this would be replaced by built-in retry mechanisms. 
As you can see, we are adding considerable amount of boilerplate code just to handle retries, ReACT, memory, etc.
"""

import time
from typing import Callable, TypeVar

from google.genai import errors

from logger import get_logger

T = TypeVar("T")
logger = get_logger(__name__)


def retry_with_backoff(
    func: Callable[..., T],
    max_retries: int = 3,
    initial_delay: float = 1.0,
    extra_prompt: str = "",
) -> T:
    """Retry a function with exponential backoff on error.

    Args:
        func: Function to retry
        max_retries: Maximum number of retries
        initial_delay: Initial delay in seconds
        extra_prompt: Additional context to add on retry

    Returns:
        Function result

    Raises:
        Last exception if all retries fail
    """
    last_error = None
    delay = initial_delay

    for attempt in range(max_retries):
        try:
            return func()
        except errors.APIError as e:
            last_error = e
            if attempt < max_retries - 1:
                logger.warning(
                    f"API error (attempt {attempt + 1}/{max_retries}): {e.code} - {e.message}. "
                    f"Retrying in {delay}s{' with hint: ' + extra_prompt if extra_prompt else ''}..."
                )
                time.sleep(delay)
                delay *= 2  # Exponential backoff
            else:
                logger.error(
                    f"All {max_retries} retries failed. Last error: {e.code} - {e.message}"
                )
        except Exception as e:
            last_error = e
            if attempt < max_retries - 1:
                logger.warning(
                    f"Error (attempt {attempt + 1}/{max_retries}): {str(e)}. "
                    f"Retrying in {delay}s{' with hint: ' + extra_prompt if extra_prompt else ''}..."
                )
                time.sleep(delay)
                delay *= 2
            else:
                logger.error(f"All {max_retries} retries failed. Last error: {str(e)}")

    raise last_error
