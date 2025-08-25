from django.urls import path
from . import views
from .views import like_post, get_likes


urlpatterns = [
    path('home/', views.home, name='home'),
    path('posts/', views.posts, name='posts' ),
    path('<slug:post>/',views.post_single,name='post_single'),
    # ... your existing URLs ...
    path('like-post/<int:post_id>/', like_post, name='like_post'),
    path('get-likes/<int:post_id>/', get_likes, name='get_likes')
]