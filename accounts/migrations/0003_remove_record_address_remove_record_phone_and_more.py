# Generated by Django 5.1.1 on 2024-10-01 10:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_record'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='record',
            name='address',
        ),
        migrations.RemoveField(
            model_name='record',
            name='phone',
        ),
        migrations.RemoveField(
            model_name='record',
            name='state',
        ),
        migrations.RemoveField(
            model_name='record',
            name='zipcode',
        ),
        migrations.AlterField(
            model_name='record',
            name='rec_email',
            field=models.CharField(max_length=100, null=True),
        ),
    ]