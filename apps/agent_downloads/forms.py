from django import forms

from .models import AgentRelease


class AgentReleaseForm(forms.ModelForm):
    class Meta:
        model = AgentRelease
        fields = ['platform', 'version', 'file', 'file_url', 'is_active', 'release_notes']
        widgets = {
            'release_notes': forms.Textarea(attrs={'rows': 3}),
        }
