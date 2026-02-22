from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render

from .auth import user_org
from .models import Agent


@login_required
def uba_endpoint_default_view(request):
    org = user_org(request.user)
    first_agent = Agent.objects.filter(organization=org).order_by('hostname', 'id').first()
    if not first_agent:
        return render(request, 'uba/endpoint.html', {'agents': [], 'selected_agent': None, 'range': '24h'})
    return redirect('uba_endpoint', agent_id=first_agent.id)


@login_required
def uba_endpoint_view(request, agent_id):
    org = user_org(request.user)
    selected_agent = get_object_or_404(Agent, id=agent_id, organization=org)
    agents = Agent.objects.filter(organization=org).order_by('hostname', 'id')
    selected_range = request.GET.get('range', '24h')
    if selected_range not in ['1h', '24h', '7d']:
        selected_range = '24h'
    return render(
        request,
        'uba/endpoint.html',
        {
            'agents': agents,
            'selected_agent': selected_agent,
            'range': selected_range,
        },
    )
