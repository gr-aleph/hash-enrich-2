# Shared test setup (pytest loads this file by itself).

import pytest

from backend import cache


# Start every test with an empty cache, so one test's answers can never leak into the next.
# autouse means no test has to ask for it.
@pytest.fixture(autouse=True)
def empty_cache():
    cache.clear()
