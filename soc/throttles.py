from rest_framework.throttling import UserRateThrottle


class IngestRateThrottle(UserRateThrottle):
    scope = 'ingest'
