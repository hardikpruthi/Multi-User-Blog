import os
import webapp2
import jinja2
import re
import hmac
import hashlib
import random
from google.appengine.ext import db
from string import letters

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir), autoescape=True)


SECRET = 'nosecret'


def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return "%s,%s" % (salt, h)


def valid_pw_hash(name, pw, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, pw, salt)


class Handler(webapp2.RequestHandler):

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.response.out.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie',
                                         '%s=%s; Path=/'
                                         % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)

    @classmethod
    def by_name(cls, name):
        return User.all().filter('name = ', name).get()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def login(cls, name, pw):
        u = User.by_name(name)
        if u and valid_pw_hash(name, pw, u.pw_hash):
            return u


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(Handler):

    def get(self):
        self.render('signup-form.html')

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        email = self.request.get('email')
        verify = self.request.get('verify')
        error_username = ''
        error_password = ''
        error_email = ''
        error_verify = ''

        if not valid_username(username):
            error_username = "This isn't right username"
            have_error = True

        if not valid_password(password):
            error_password = "This isn't right password"
            have_error = True
        elif password != verify:
            error_verify = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            error_email = "This isn't right email"
            have_error = True

        u = User.by_name(username)
        if u:
            error_username = "User already exists"
            have_error = True

        if have_error:
            self.render('signup-form.html', error_username=error_username,
                        error_password=error_password,
                        error_email=error_email,
                        error_verify=error_verify,
                        username=username)
        else:
            pw_hash = make_pw_hash(username, password)
            a = User(name=username, pw_hash=pw_hash)
            a.put()
            self.set_secure_cookie("name", str(username))
            self.redirect('/welcome')


class WelcomeDb(Handler):

    def get(self):
        username = self.read_secure_cookie("name")
        if username:
            self.render('welcome.html', username=username)
        else:
            self.redirect('/signup')


class Login(Handler):

    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.set_secure_cookie("name", str(username))
            self.redirect("/welcome")
        else:
            self.render("login.html",
                        error_username="Invalid Username or password")


class Logout(Handler):

    def get(self):
        self.response.headers.add_header('Set-Cookie',
                                         'user-id=; Path=/')
        self.redirect("/signup")


class Blogs(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    user_id = db.StringProperty()
    likes = db.IntegerProperty(default=0)


class Like(db.Model):
    blog_id = db.IntegerProperty(required=True)
    viewer = db.StringProperty(required=True)


class Comment(db.Model):
    blog_id = db.IntegerProperty(required=True)
    comment = db.TextProperty(required=True)
    commentator = db.StringProperty(required=True)


class Blogpost(Handler):

    def get(self):
        blogs = db.GqlQuery("Select * From Blogs Order By created DESC")
        comments = db.GqlQuery("Select * From Comment")
        self.render("blogpost.html", blogs=blogs, comments=comments)


class Post(Handler):

    def get(self, key):
        key = int(key)
        subject = ""
        content = ""
        c = Blogs.get_by_id(key)
        if c:
            subject = c.subject
            content = c.content
            self.render("postlink.html", subject=subject, content=content)
        else:
            self.error(404)


class Form(Handler):

    def get(self):
        name = self.read_secure_cookie("name")
        if name:
            self.render("front.html")
        else:
            self.redirect("/login")

    def post(self):
        name = self.read_secure_cookie("name")
        if not name:
            self.error(404)
            return
        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            a = Blogs(subject=subject, content=content, user_id=name, likes=0)
            a.put()
            key = a.key().id()
            self.redirect("/post/"+str(key))
        else:
            error = "add both subject and content"
            self.render(
                "front.html", subject=subject, content=content, error=error)


class LikePost(Handler):

    def get(self, blog_id):
        name = self.read_secure_cookie("name")
        if name:
            blog = Blogs.get_by_id(int(blog_id))
            if not blog:
                self.error(404)
                return
            if not blog.user_id == name:
                likes = db.GqlQuery("select * from Like")
                for l in likes:
                    if l.blog_id == int(blog_id):
                        if name == l.viewer:
                            self.response.out.write("Can't like twice")
                            return
                a = Like(blog_id=int(blog_id), viewer=name)
                a.put()
                blog.likes += 1
                blog.put()
                self.redirect("/post")
            else:
                self.response.out.write("You can't like your own posts")
        else:
            self.redirect("/login")


class NewComment(Handler):

    def post(self, blog_id):
        name = self.read_secure_cookie("name")
        comment = self.request.get("comment")
        if not name:
            self.redirect("/login")
        else:
            if comment:
                blog = Blogs.get_by_id(int(blog_id))
                if not blog:
                    self.error(404)
                    return
                a = Comment(
                    comment=comment, commentator=name, blog_id=int(blog_id))
                a.put()
                self.redirect("/post")


class EditComment(Handler):

    def get(self, blog_id):
        name = self.read_secure_cookie("name")
        if name:
            comment = Comment.get_by_id(int(blog_id))
            if comment.commentator == name:
                self.render("editcomment.html", pretext=comment.comment, comment=comment)
            else:
                self.response.write("You can only edit your own comment")
        else:
            self.redirect("/login")

    def post(self, blog_id):
        name = self.read_secure_cookie("name")
        if not name:
            self.error(404)
            return
        comment = self.request.get("comment")
        c = Comment.get_by_id(int(blog_id))
        if not c:
            self.error(404)
            return
        if c.commentator == name:
            c.comment = comment
            c.put()
            self.redirect("/post")


class DelComment(Handler):

    def get(self, blog_id):
        name = self.read_secure_cookie("name")
        comment = Comment.get_by_id(int(blog_id))
        if not name:
            self.redirect("/login")
        else:
            if comment and comment.commentator == name:
                comment.delete()
                self.redirect("/post")
            else:
                self.response.write("You can delete only your comments")


class EditPost(Handler):

    def get(self, blog_id):
        name = self.read_secure_cookie("name")
        if name:
            blog = Blogs.get_by_id(int(blog_id))
            if blog.user_id == name:
                self.render("editfront.html", subject=blog.subject, content=blog.content, blog=blog)
            else:
                self.response.write("You can only edit your own posts")
        else:
            self.redirect("/login")

    def post(self, blog_id):
        name = self.read_secure_cookie("name")
        subject = self.request.get("subject")
        content = self.request.get("content")
        if blog_id:
            if subject and content:
                blog = Blogs.get_by_id(int(blog_id))
                if not blog:
                    self.error(404)
                    return
                if blog.user_id == name:
                    blog.subject = subject
                    blog.content = content
                    blog.put()
                    self.redirect("/post")
                else:
                    self.write("Cannot edit other's post")


class DelPost(Handler):

    def get(self, blog_id):
        name = self.read_secure_cookie("name")
        blog = Blogs.get_by_id(int(blog_id))
        if not name:
            self.redirect("/login")
        else:
            if blog and blog.user_id == name:
                blog.delete()
                self.redirect("/post")
            else:
                self.response.write("You can delete only your posts")

app = webapp2.WSGIApplication([('/signup', Signup),
                               ('/welcome', WelcomeDb),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/post/newpost', Form),
                               ('/post', Blogpost),
                               ('/post/(\d+)', Post),
                               ('/like/(\d+)', LikePost),
                               ('/newcomment/(\d+)', NewComment),
                               ('/editcomment/(\d+)', EditComment),
                               ('/delcomment/(\d+)', DelComment),
                               ('/editpost/(\d+)', EditPost),
                               ('/delpost/(\d+)', DelPost)
                               ], debug=True)
