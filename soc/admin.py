from django.contrib import admin
from .models import *

for m in [Organization, UserProfile, Agent, EnrollmentToken, LogEvent, Rule, CorrelationRecord, Alert, Case, CaseEventLink, CaseNote, IRAction, IOC, ParsingError]:
    admin.site.register(m)
