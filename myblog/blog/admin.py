from django.contrib import admin
from .models import Posts  # Replace with your actual model
from unfold.admin import ModelAdmin


class YourModelAdmin(ModelAdmin):  # Extend ModelAdmin for customization
    pass

admin.site.register(Posts, YourModelAdmin)  # Register your model





'''FOR THE ANALYTICS MODEL FOR SIGNUP'''
