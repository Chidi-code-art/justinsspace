from django.db import models #models is like creating databse for each class and specifying the columns (the different variables)
from django.contrib.auth.models import User
from django_ckeditor_5.fields import CKEditor5Field
# Create your models here. but this will not store ur users data bc we are using the builtin Users model which stores that data in auth_uers



class Posts(models.Model):
    image_head = models.ImageField(upload_to='postings/', null=True, blank=True)
    slug = models.SlugField(max_length=250, unique_for_date='post_date', default='default-slug') #to make the url to be easily defined by the browser
    post_title = models.CharField(max_length=255)
     #body = models.TextField() 
    post_content = CKEditor5Field(default="Default body") # CKEditor Rich Text Field
    post_date = models.DateTimeField(auto_now_add=True) #set date on creating
    update_date = models.DateTimeField(auto_now=True) #udate date on deleting
    deleted_at = models.DateTimeField(auto_now=True)
    likes = models.PositiveIntegerField(default=0)
    liked_by = models.ManyToManyField(User, blank=True)
    image_credit = models.CharField(max_length=255, default="Image by Author")





    def __str__(self):
        return self.post_title #defines how the object should be represented as a string in the admin
    







    

