from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.contrib.auth.models import User #for handling user authentication
from django.contrib import messages
from django.contrib.auth import authenticate, login as auth_login
from django.contrib import admin
from .models import Posts #to have access to the databse for the posts.html
import os #to store the codes in the enviroment variable for security purposes especially for the hardcoded password
from django.db.models import Count
from datetime import datetime, timedelta
from django.db.models.functions import TruncDate




admin_name = "olusolasu"
admin_email = "umehkemol@gmail.com"
admin_password = "Jesusisking"

#ikemdinachi umehkemdi@gmai.com jesus


from django.http import JsonResponse

def toggle_sidebar(request):
    # Handle sidebar toggling logic here
    return JsonResponse({'status': 'success'})



def signup(request):
    if request.method == 'POST':
        name = request.POST.get("username")
        password = request.POST.get("password")
        email = request.POST.get("email")

        #check if user exists
        if name and password and email:

            #login admin:
            if name == admin_name and password == admin_password and email == admin_email:
                return redirect('/admin/')
            

            elif User.objects.filter(username=name):
                 messages.error(request, "Sorry, user already exists. Try again please.")
                 return redirect('signup')
            
            
            elif User.objects.filter(email=email):
                 messages.error(request, "Sorry, this email already exists. Try again please.")
                

            #create the user:
            else:
                user = User.objects.create_user(username=name,email=email,password=password)
                user.save()
                return redirect('login')
        
            
            

    return render(request, 'signup.html')



from django.shortcuts import redirect

def login(request):
    if request.method == "POST":
        name = request.POST.get("username")
        password = request.POST.get("password")

        if name == admin_name and password == admin_password:
            return redirect('/admin/')

        user = authenticate(request, username=name, password=password)
        if user is not None:
            auth_login(request, user)
            return redirect('posts')  # Redirect to the custom admin dashboard
        else:
            messages.error(request, "Invalid user or password")
            return redirect('login')

    return render(request, 'login.html')


def home(request):
    post1 = Posts.objects.all().order_by('-post_date').first()
    post2 = Posts.objects.all().order_by('-post_date')[1]
    post3 = Posts.objects.all().order_by('-post_date')[2]
    post4 = Posts.objects.all().order_by('-post_date')[3]


    return render(request, 'index.html', {
        'post1': post1,
        'post2': post2,
        'post3': post3,
        'post4': post4,
    })


def posts(request):
        #collecting all data from the database using a query
        all_posts = Posts.objects.all().order_by('-post_date') #then put this in the posts.html template
        recent_post = Posts.objects.all().order_by('-post_date').first()
        return render(request, 'posts.html', {'posts': all_posts, 'recent_post':recent_post }) #refrencing it as posts

def post_single(request, post): #takes a request and post which is the slug bc <slug:post>
    post = get_object_or_404(Posts, slug=post) #simply uses thee get_object_model to get the model which bears the data we need, and select the one that have slug (which is all) and we saved it as post (simply the place where we are getting the object, and then filter it to get the one i ndee; slug and or any other)
    return render(request, 'post.html', {'post': post}) #the 'post' and :post is the variable is the tag that will be used in the html


'''FOR THE ANALYTICS VIEW'''
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.db.models import Count
from datetime import datetime, timedelta

@login_required
def dashboard(request):
    """Handles the admin dashboard analytics view"""
    thirty_days_ago = datetime.today() - timedelta(days=30)
    
    user_data = (
        User.objects.filter(date_joined__gte=thirty_days_ago)
        .extra({'date_joined': "date(date_joined)"})
        .values('date_joined')
        .annotate(count=Count('id'))
        .order_by('date_joined')
    )
    
    labels = [entry['date_joined'].strftime('%Y-%m-%d') for entry in user_data]
    data = [entry['count'] for entry in user_data]

    print("Labels:", labels)  # ✅ Debugging
    print("Data:", data)  # ✅ Debugging

    return render(request, "admin/dashboard.html", {"labels": labels, "data": data})



'''VIEWS FOR THE ANALYSIS OF POSTS'''
from datetime import datetime, timedelta
from datetime import datetime as dt
from django.db.models import Count, Q
from django.db.models.functions import TruncDate
from django.http import JsonResponse
from .models import Posts  # Ensure this is your correct model

def posts_chart(request):
    thirty_days_ago = dt.now() - timedelta(days=30)  # ✅ This will now work

    posts_data = (
        Posts.objects
        .filter(post_date__gte=thirty_days_ago)
        .annotate(date=TruncDate('post_date'))  # ✅ Fix: Replace .extra() with TruncDate
        .values('date')
        .annotate(
            created=Count('id'), 
            deleted=Count('id', filter=~Q(deleted_at=None))  # ✅ Count deleted posts
        )
        .order_by('date')
    )

    labels = [entry['date'].strftime('%Y-%m-%d') for entry in posts_data]
    created_posts = [entry['created'] for entry in posts_data]
    deleted_posts = [entry['deleted'] for entry in posts_data]

    return JsonResponse({"labels": labels, "created": created_posts, "deleted": deleted_posts})




'''VIEWS FOR ANALYSIS OF REGISTERED USERS'''

from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from django.http import JsonResponse
from django.utils.timezone import now, timedelta
from django.shortcuts import render
from django.db.models import Count
from django.contrib.sessions.models import Session

def signup_chart_data(request):
    """Fetch user signup and login data over the last 30 days"""
    today = now().date()
    last_30_days = [today - timedelta(days=i) for i in range(30)]
    
    labels = [date.strftime('%Y-%m-%d') for date in reversed(last_30_days)]

    # Count user signups per day
    signups = [
        User.objects.filter(date_joined__date=date).count() for date in reversed(last_30_days)
    ]

    # Count user logins per day (based on session activity)
    logins = [
        Session.objects.filter(expire_date__date=date).count() for date in reversed(last_30_days)
    ]

    return JsonResponse({"labels": labels, "signups": signups, "logins": logins})

def signup_analysis_view(request):
    """Render the signup & login analysis page"""
    return render(request, "admin/auth/user/change_list.html")

from django.http import JsonResponse
from django.views.decorators.http import require_POST
from .models import Posts
import json

@require_POST
def like_post(request, post_id):
    try:
        post = Posts.objects.get(id=post_id)

        # Track likes via session for anonymous users
        liked_posts = request.session.get('liked_posts', [])
        if post_id in liked_posts:
            return JsonResponse({'status': 'error', 'message': 'Already liked'}, status=400)

        post.likes += 1
        post.save()

        liked_posts.append(post_id)
        request.session['liked_posts'] = liked_posts
        request.session.modified = True

        return JsonResponse({'status': 'success', 'likes': post.likes})

    except Posts.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Post not found'}, status=404)


def get_likes(request, post_id):
    try:
        post = Posts.objects.get(id=post_id)
        return JsonResponse({'status': 'success', 'likes': post.likes})
    except Posts.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Post not found'}, status=404)
