import asyncio

import pytest
from pydantic import ValidationError

from app.main import MAX_CONCURRENT_SCANS, ScanRequest
from app.scans import ScanAdmissionCancelled, ScanConcurrencyLimiter


@pytest.mark.asyncio
async def test_concurrency_is_bounded_and_exclusive_scan_is_not_starved():
    limiter = ScanConcurrencyLimiter(2)
    first_entered = asyncio.Event()
    release_first = asyncio.Event()
    order = []

    async def first():
        async with limiter.slot(2):
            first_entered.set()
            await release_first.wait()

    async def exclusive():
        async with limiter.slot(1):
            assert len(limiter._active) == 1
            order.append("exclusive")

    async def later():
        async with limiter.slot(2):
            order.append("later")

    task = asyncio.create_task(first())
    await first_entered.wait()
    one = asyncio.create_task(exclusive())
    await asyncio.sleep(0)
    two = asyncio.create_task(later())
    await asyncio.sleep(0)
    assert order == []
    release_first.set()
    await asyncio.wait_for(asyncio.gather(task, one, two), timeout=2)
    assert order == ["exclusive", "later"]
    assert not limiter._active and not limiter._waiting


@pytest.mark.asyncio
async def test_canceling_queued_scan_removes_it_without_waiting_for_running_scan():
    limiter = ScanConcurrencyLimiter(1)
    canceled = asyncio.Event()
    async with limiter.slot(1):
        async def queued():
            async with limiter.slot(1, canceled):
                pytest.fail("Canceled scan must never start a browser")
        waiting = asyncio.create_task(queued())
        await asyncio.sleep(0)
        canceled.set()
        with pytest.raises(ScanAdmissionCancelled):
            await asyncio.wait_for(waiting, timeout=1)
        assert len(limiter._active) == 1 and not limiter._waiting
    assert not limiter._active


@pytest.mark.asyncio
async def test_deadline_cancellation_releases_admission_capacity():
    limiter = ScanConcurrencyLimiter(1)
    with pytest.raises(TimeoutError):
        async with asyncio.timeout(0.01), limiter.slot(1):
            await asyncio.Event().wait()
    async with limiter.slot(1):
        assert len(limiter._active) == 1
    assert not limiter._active and not limiter._waiting


def test_scan_cannot_raise_deployment_concurrency_cap():
    assert ScanRequest(target="portal.example").concurrency_limit == MAX_CONCURRENT_SCANS
    for invalid in (0, MAX_CONCURRENT_SCANS + 1):
        with pytest.raises(ValidationError):
            ScanRequest(target="portal.example", concurrency_limit=invalid)
