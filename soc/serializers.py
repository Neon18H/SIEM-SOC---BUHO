from django.contrib.auth.models import User
from rest_framework import serializers
from .models import Agent, Alert, Case, EnrollmentToken, LogEvent, Organization, Rule, UserProfile


class EnrollmentSerializer(serializers.Serializer):
    token = serializers.CharField()
    hostname = serializers.CharField()
    os = serializers.CharField()
    ip = serializers.IPAddressField()


class IngestSerializer(serializers.Serializer):
    ts = serializers.DateTimeField()
    source = serializers.CharField(required=False, default='agent')
    severity = serializers.IntegerField(min_value=0, max_value=10, required=False, default=3)
    category = serializers.CharField()
    message = serializers.CharField(required=False, allow_blank=True, default='')
    user = serializers.CharField(required=False, allow_blank=True)
    ip = serializers.IPAddressField(required=False)
    host = serializers.CharField(required=False, allow_blank=True)
    raw = serializers.JSONField(required=False)


class LogEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = LogEvent
        fields = '__all__'


class RuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Rule
        fields = '__all__'


class AlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = '__all__'


class CaseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Case
        fields = '__all__'
