"""
Prometheus metrics exposition helpers.
"""

from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST

challenges_issued = Counter("aog_challenges_issued_total", "Total number of challenges issued")
tasks_accepted = Counter("aog_tasks_accepted_total", "Total number of accepted tasks")
tasks_rejected = Counter("aog_tasks_rejected_total", "Total number of rejected tasks")
rate_limited = Counter("aog_rate_limited_total", "Total number of rate-limited requests")

def metrics_response():
    data = generate_latest()
    return data, CONTENT_TYPE_LATEST