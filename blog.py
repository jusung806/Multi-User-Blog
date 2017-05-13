import os
import webapp2
import jinja2
import codecs
import re
import hashlib
import hmac
import random
from string import letters
import time

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir),
    autoescape=True)

secret = 'whoohoo'

# User

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)



def blog_key(name='default'):
    return db.Key.from_path('Blog', name)



def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())



def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val




def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))




def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(''.join([name, pw, salt])).hexdigest()
    return '%s,%s' % (salt, h)




def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)




def users_key(group='default'):
    return db.Key.from_path('users', group)


USER_RE = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r'^.{3,20}$')


def valid_password(password):
    return password and USER_RE.match(password)



class BlogHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)


    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))




class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

# Blog



class Blog(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    user = db.ReferenceProperty(User,
                                required=True,
                                collection_name="blogs")


    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", post=self)


class Like(db.Model):
    post = db.ReferenceProperty(Blog, required=True)
    user = db.ReferenceProperty(User, required=True)

    
    @classmethod
    def by_blog_id(cls, blog_id):
        l = Like.all().filter('post =', blog_id)
        return l.count()


    @classmethod
    def check_like(cls, blog_id, user_id):
        cl = Like.all().filter(
            'post =', blog_id).filter(
            'user =', user_id)
        return cl.count()


class Unlike(db.Model):
    post = db.ReferenceProperty(Blog, required=True)
    user = db.ReferenceProperty(User, required=True)

    @classmethod
    def by_blog_id(cls, blog_id):
        ul = Unlike.all().filter('post =', blog_id)
        return ul.count()

    @classmethod
    def check_unlike(cls, blog_id, user_id):
        cul = Unlike.all().filter(
            'post =', blog_id).filter(
            'user =', user_id)
        return cul.count()



class Comment(db.Model):
    post = db.ReferenceProperty(Blog, required=True)
    user = db.ReferenceProperty(User, required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    text = db.TextProperty(required=True)

    @classmethod
    def count_by_blog_id(cls, blog_id):
        c = Comment.all().filter('post =', blog_id)
        return c.count()

    @classmethod
    def all_by_blog_id(cls, blog_id):
        c = Comment.all().filter('post =', blog_id).order('created')
        return c





class MainPage(BlogHandler):

    def get(self):
        blogs = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC")
        if blogs:
            self.render("blogs.html", blogs=blogs)



class NewPost(BlogHandler):

    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content").replace('\n', '<br>')
        user_id = User.by_name(self.user.name)

        if subject and content:
            a = Blog(
                parent=blog_key(),
                subject=subject,
                content=content,
                user=user_id)
            a.put()
            self.redirect('/post/%s' % str(a.key().id()))        # content are required
        else:
            post_error = "You need to enter a title and a rant!"
            self.render(
                "newpost.html",
                subject=subject,
                content=content,
                post_error=post_error)



class PostPage(BlogHandler):

    def get(self, blog_id):
        key = db.Key.from_path("Blog", int(blog_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return
        likes = Like.by_blog_id(post)
        unlikes = Unlike.by_blog_id(post)
        post_comments = Comment.all_by_blog_id(post)
        comments_count = Comment.count_by_blog_id(post)

        self.render(
            "post.html",
            post=post,
            likes=likes,
            unlikes=unlikes,
            post_comments=post_comments,
            comments_count=comments_count)

    def post(self, blog_id):
        key = db.Key.from_path("Blog", int(blog_id), parent=blog_key())
        post = db.get(key)
        user_id = User.by_name(self.user.name)
        comments_count = Comment.count_by_blog_id(post)
        post_comments = Comment.all_by_blog_id(post)
        likes = Like.by_blog_id(post)
        unlikes = Unlike.by_blog_id(post)
        previously_liked = Like.check_like(post, user_id)
        previously_unliked = Unlike.check_unlike(post, user_id)

        if self.user:
            if self.request.get("like"):                
                if post.user.key().id() != User.by_name(self.user.name).key().id():
                    if previously_liked == 0:
                        l = Like(
                            post=post, user=User.by_name(
                                self.user.name))
                        l.put()
                        time.sleep(0.1)
                        self.redirect('/post/%s' % str(post.key().id()))

                    else:
                        error = "You cannot like this twice even though you LOVE it!"
                        self.render(
                            "post.html",
                            post=post,
                            likes=likes,
                            unlikes=unlikes,
                            error=error,
                            comments_count=comments_count,
                            post_comments=post_comments)
                else:
                    error = "Stop being biased you can't like your own post!"
                    self.render(
                        "post.html",
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        error=error,
                        comments_count=comments_count,
                        post_comments=post_comments)

            if self.request.get("unlike"):
                if post.user.key().id() != User.by_name(self.user.name).key().id():
                    if previously_unliked == 0:
                        ul = Unlike(
                            post=post, user=User.by_name(
                                self.user.name))
                        ul.put()
                        time.sleep(0.1)
                        self.redirect('/post/%s' % str(post.key().id()))
                    else:
                        error = "You can only dislike this once!"
                        self.render(
                            "post.html",
                            post=post,
                            likes=likes,
                            unlikes=unlikes,
                            error=error,
                            comments_count=comments_count,
                            post_comments=post_comments)
                else:
                    error = "Why did you write it if you want to unlike it? Chin Up!"
                    self.render(
                        "post.html",
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        error=error,
                        comments_count=comments_count,
                        post_comments=post_comments)
            if self.request.get("add_comment"):
                comment_text = self.request.get("comment_text")
                if comment_text:
                    c = Comment(
                        post=post, user=User.by_name(
                            self.user.name), text=comment_text)
                    c.put()
                    time.sleep(0.1)
                    self.redirect('/post/%s' % str(post.key().id()))
                else:
                    comment_error = "You need to write a comment!"
                    self.render(
                        "post.html",
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        comments_count=comments_count,
                        post_comments=post_comments,
                        comment_error=comment_error)
            if self.request.get("edit"):
                if post.user.key().id() == User.by_name(self.user.name).key().id():
                    self.redirect('/edit/%s' % str(post.key().id()))
                else:
                    error = "Stop trying to edit other's posts!"
                    self.render(
                        "post.html",
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        comments_count=comments_count,
                        post_comments=post_comments,
                        error=error)
            if self.request.get("delete"):
                if post.user.key().id() == User.by_name(self.user.name).key().id():
                    db.delete(key)
                    time.sleep(0.1)
                    self.redirect('/')
                else:
                    error = "This does not belong to you therefore you cannot edit!"
                    self.render(
                        "post.html",
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        comments_count=comments_count,
                        post_comments=post_comments,
                        error=error)
        else:
            self.redirect("/login")



class DeleteComment(BlogHandler):

    def get(self, post_id, comment_id):
        # get the comment from the comment id
        comment = Comment.get_by_id(int(comment_id))
        # check if there is a comment associated with that id
        if comment:
            # check if this user is the author of this comment
            if comment.user.name == self.user.name:
                # delete the comment and redirect to the post page
                db.delete(comment)
                time.sleep(0.1)
                self.redirect('/post/%s' % str(post_id))
            # otherwise if this user is not the author of this comment throw an
            # error
            else:
                self.write("You cannot delete other user's comments")
        # otherwise if there is no comment associated with that id throw an
        # error
        else:
            self.write("This comment no longer exists")



class EditComment(BlogHandler):

    def get(self, post_id, comment_id):

        post = Blog.get_by_id(int(post_id), parent=blog_key())
        comment = Comment.get_by_id(int(comment_id))

        if comment:

            if comment.user.name == self.user.name:

                self.render("editcomment.html", comment_text=comment.text)

            else:
                error = "This isn't your comment write your own!"
                self.render("editcomment.html", edit_error=error)
        else:
            error = "You've successfully delted your comment!"
            self.render("editcomment.html", edit_error=error)

    def post(self, post_id, comment_id):

        if self.request.get("update_comment"):

            comment = Comment.get_by_id(int(comment_id))

            if comment.user.name == self.user.name:
                comment.text = self.request.get('comment_text')
                comment.put()
                time.sleep(0.1)
                self.redirect('/post/%s' % str(post_id))

            else:
                error = "This isn't yours stop it!"
                self.render(
                    "editcomment.html",
                    comment_text=comment.text,
                    edit_error=error)

        elif self.request.get("cancel"):
            self.redirect('/post/%s' % str(post_id))



class EditPost(BlogHandler):

    def get(self, blog_id):
        key = db.Key.from_path("Blog", int(blog_id), parent=blog_key())
        post = db.get(key)

        if self.user:
            if post.user.key().id() == User.by_name(self.user.name).key().id():
                self.render("editpost.html", post=post)

            else:
                self.response.out.write("This isn't yours! Write your own!")
        else:
            self.redirect("/login")

    def post(self, blog_id):
        key = db.Key.from_path("Blog", int(blog_id), parent=blog_key())
        post = db.get(key)

        if self.request.get("update"):

            subject = self.request.get("subject")
            content = self.request.get("content").replace('\n', '<br>')

            if post.user.key().id() == User.by_name(self.user.name).key().id():
                if subject and content:
                    post.subject = subject
                    post.content = content
                    post.put()
                    time.sleep(0.1)
                    self.redirect('/post/%s' % str(post.key().id()))
                else:
                    post_error = "Please enter a title and a rant!"
                    self.render(
                        "editpost.html",
                        subject=subject,
                        content=content,
                        post_error=post_error)

            else:
                self.response.out.write("Stop! This isn't yours go write your own!")
        elif self.request.get("cancel"):
            self.redirect('/post/%s' % str(post.key().id()))

#User Login

class Signup(BlogHandler):

    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
  
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True

        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if have_error:
            self.render("signup.html", **params)

        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError



class Register(Signup):

    def done(self):
        u = User.by_name(self.username)
        if u:
            error = 'Did you sign up before?'
            self.render('signup.html', error_username=error)

        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')




class Welcome(BlogHandler):

    def get(self):
        if self.user:
            self.render("welcome.html", username=self.user.name)

        else:
            self.redirect("/login")



class Login(BlogHandler):

    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)

        if u:
            self.login(u)
            self.redirect('/welcome')

        else:
            error = 'Invalid login'
            self.render('login.html', error=error)



class Logout(BlogHandler):

    def get(self):
        if self.user:
            self.logout()
            self.redirect("/signup")
        else:
            error = 'You need to log in!'
            self.render('login.html', error=error)

#====================================================

app = webapp2.WSGIApplication([('/', MainPage), 
                               ('/newpost', NewPost),
                               ('/post/([0-9]+)', PostPage), 
                               ('/login', Login),
                               ('/logout', Logout), 
                               ('/signup', Register), 
                               ('/welcome', Welcome),
                               ('/edit/([0-9]+)', EditPost), 
                               ('/blog/([0-9]+)/editcomment/([0-9]+)', EditComment),
                               ('/blog/([0-9]+)/de], debug=True)letecomment/([0-9]+)', DeleteComment),
                               ], debug=True)