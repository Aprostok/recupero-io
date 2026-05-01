"""Worker that drains the public.investigations queue.

Single-process, sync, polling. One worker process processes one investigation
end-to-end before claiming the next. Multiple workers run safely against the
same queue thanks to FOR UPDATE SKIP LOCKED.

Entry point: ``recupero.worker.main:cli`` (registered as ``recupero-worker``).
"""
