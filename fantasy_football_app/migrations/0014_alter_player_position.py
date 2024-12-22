# Generated by Django 4.2.9 on 2024-01-08 18:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fantasy_football_app', '0013_rosteredplayers_alter_entry_players'),
    ]

    operations = [
        migrations.AlterField(
            model_name='player',
            name='position',
            field=models.CharField(choices=[('QB', 'Quarterback'), ('RB', 'Running Back'), ('WR', 'Wide Receiver'), ('TE', 'Tight End'), ('DEF', 'Defense/Special Teams')], max_length=12),
        ),
    ]