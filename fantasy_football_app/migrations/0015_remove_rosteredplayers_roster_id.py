# Generated by Django 4.2.9 on 2024-01-10 19:05

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('fantasy_football_app', '0014_alter_player_position'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='rosteredplayers',
            name='roster_id',
        ),
    ]
