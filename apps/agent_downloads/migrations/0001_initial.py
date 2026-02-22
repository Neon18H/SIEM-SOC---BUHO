from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
        ('soc', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='AgentRelease',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('platform', models.CharField(choices=[('linux', 'Linux (x86_64)'), ('windows', 'Windows (x64)')], max_length=20)),
                ('version', models.CharField(max_length=32)),
                ('file', models.FileField(blank=True, null=True, upload_to='agents/')),
                ('file_url', models.URLField(blank=True)),
                ('sha256', models.CharField(max_length=64)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('is_active', models.BooleanField(default=False)),
                ('release_notes', models.TextField(blank=True)),
            ],
            options={'ordering': ['-created_at']},
        ),
        migrations.CreateModel(
            name='DownloadAudit',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('platform', models.CharField(choices=[('linux', 'Linux (x86_64)'), ('windows', 'Windows (x64)')], max_length=20)),
                ('version', models.CharField(max_length=32)),
                ('ip', models.GenericIPAddressField(blank=True, null=True)),
                ('user_agent', models.TextField(blank=True)),
                ('type', models.CharField(choices=[('installer', 'Installer'), ('bundle', 'Bundle')], max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='soc.organization')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='auth.user')),
            ],
            options={'ordering': ['-created_at']},
        ),
    ]
