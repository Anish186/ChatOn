from flask import Flask, render_template, request, session, url_for, redirect, flash
from flask_socketio import SocketIO, send
import string
import secrets
from flask_mail import Mail, Message
import rsa
import re
# importing all the necessary libraries.

# ----------------App----------------
app = Flask(__name__, template_folder="templates", static_folder="static") 
# Flask(__name__): This creates an instance of the Flask class, which is the core of your web application. The __name__ argument is a special Python variable that gets the name of the current module. It's used by Flask to determine the root path of the application. 
# template_folder="templates": This specifies the folder where Flask will look for HTML templates. In this case, it's set to "templates," which is a common convention. 
# static_folder="static": This specifies the folder where Flask will look for static files like CSS, JavaScript, images, etc. Here, it's set to "static," another common convention. 

# ----------------Flask-Mail-Configuration----------------
app.config["MAIL_SERVER"] = "smtp.gmail.com" # This sets the SMTP server for sending emails. In this case, it's set to Gmail's SMTP server.
app.config["MAIL_PORT"] = 587 # This specifies the port to use for the SMTP server. The default port for TLS encryption is 587.
app.config["MAIL_USERNAME"] = "chaton.webchat@gmail.com"
app.config["MAIL_PASSWORD"] = "gasi yaqx oznp tzvd" 
app.config["MAIL_USE_TLS"] = True # This enables TLS (Transport Layer Security) for secure communication with the SMTP server. The use of TLS is common for secure email communication.
app.config["MAIL_USE_SSL"] = False # This disables the use of SSL (Secure Sockets Layer). SSL and TLS are alternative methods for securing communication, and here, you've chosen to use TLS.
app.config["MAIL_DEBUG"] = True # This enables debugging for the Flask-Mail extension. When set to True, it will print debugging information to the console.
mail = Mail(app) # This creates an instance of the Mail class, passing the Flask application as a parameter. This instance can be used to send emails in your Flask application.

# ----------------Secure-App---------------- 
num = string.digits # Assigned a variable called string which contains all the numbers
char_num = string.ascii_letters + string.digits # Assigned a variable called char_num containing letters and numbers
secret_key = "".join(secrets.choice(char_num)for i in range(50)) # Assigned a variable called secret_key, which generates a 50 characters long random letters and numbers

app.config["SECRET_KEY"] = secret_key # Configuring the secret key to app

socket = SocketIO(app) 

# ----------------Getting-RSA-Keys----------------
with open("public.pem", "rb") as f: # opening a file called public.pem as f, which contains the public key for RSA
    public_key = rsa.PublicKey.load_pkcs1(f.read()) # loading PKCS1 and reading the RSA Public key from the public.pem file

with open("private.pem", "rb") as f: 
    private_key = rsa.PrivateKey.load_pkcs1(f.read())

# ----------------DataBase----------------
file = "DataBase_for_ChatOn.txt" # Assigned a variable a string, which has a filename; DataBase_for_ChatOn.txt

# ----------------Deleting-Duplicates----------------
with open(file, "r") as f: # Opened a file called DataBase_for_ChatOn.txt, which contains all the username and the password
    fl = f.readlines() # Assigned a variable which holds all the contains of the file

dup_dict = [] # created two dictionaries one for the duplicates and the other one is for the non duplicates
dict = [] # the non duplicates dictionary

for l in fl: # for every line in the variable fl do the following:
    if l in dict: # if the line is in the non duplicate dictionary then:
        dup_dict.append(l) # add it to the duplicate dictionary because it already exists in "dict"
    else: # if not:
        dict.append(l) # add it to "dict"

with open(file, "w") as f: # Now open the DataBase_for_ChatOn.txt file and overwriting the existing information:
    for l in dict: # for every line in the non duplicate dictionary:
        f.write(l) # add the lines to the file erasing the previous information

# ----------------Routes----------------
@app.route("/") # The starting route of the website which does the following:
def index(): # This function will be called everytime the route is called,
    session.pop("username", None) # Erasing the user's username
    # ----------------Home-Page----------------
    return render_template("index.html") # calling "index.html" file

@app.route("/login", methods=['GET', 'POST']) 
def login(): # This function will be called everytime the route is called,
    session.pop("username", None) # Erasing the user's username
    # ----------------Deleting-Duplicates----------------
    with open(file, "r") as f: # it is the same code from before
        fl = f.readlines()

    dup_dict = []
    dict = []

    for l in fl:
        if l in dict:
            dup_dict.append(l)
        else:
            dict.append(l)

    with open(file, "w") as f:
        for l in dict:
            f.write(l)

    # This part of the code --> 
    # Will only work if the request method is POST, meaning this route holds a form which requires the users input
    # Once the input has been submitted:
    if request.method == "POST":
        user = request.form.get("username") # These variables will store the user's inputs:
        pw = request.form.get("password") # By asking the form in an HTML file for the input by their ID
        session['username'] = user # Making the user global

        # ----------------Encryption----------------
        encrypted_message = rsa.encrypt(pw.encode(), public_key) # Encoding pw adn then encrypting it with the public_key
        decrypted_message = rsa.decrypt(encrypted_message, private_key) # Decrypting the encrypted message with the private_key
        clear_message = decrypted_message.decode() # Decoding the decrypted message

        # ----------------Logic-for-logging-in----------------
        save_dict = {} # Dictionary called save_dict

        with open(file, "r") as f: # Opening the database file and reading it's content
            for i in f: # for information in file, do the following:
                username, password = i.strip().split(":") # The content in the file is: username:password, I want to separate them into two separate variable.
                # I took the following content (" username:password ") .strip() deletes any whitespace, ("username:password") .split(":") will split the two into their own strings, ("username", "password")
                # These two separate strings will assign themselves to the variables. (username="username", password="password")
                save_dict[username] = password # Now I added them into save_dict as username:password

        if user in save_dict and save_dict[user] == clear_message: # I am checking if username is in the in the dictionary and, if the password for the username that was given is the same one as the password that is in the dictionary
            return redirect(url_for("main")) # if it is the same then redirect the url to a function called main, which is the chatting area
        else: # if not:
            flash("Incorrect Username or Password!") # Flash this message for the user

    return render_template("login.html") # This whole programe will run in "login.html"

@app.route("/register", methods=['GET', 'POST']) # Route for the registration page
def register():  
    session.pop("username", None) # making the global variable "username" none
    if request.method == "POST": # run the following code if the registration form has been submitted:
        # ----------------Receiving-User-Data---------------- 
        email = request.form.get("email") # gather the user's inputs
        user = request.form.get("username")
        pw = request.form.get("password")

        # ----------------Encrypting----------------
        encrypted_message = rsa.encrypt(pw.encode(), public_key) # Encrypting pw
        decrypted_message = rsa.decrypt(encrypted_message, private_key)
        clear_message = decrypted_message.decode()
        
        # ----------------Checking-User-Data----------------
        save_dict = {}

        with open(file, "r") as f:
            for i in f:
                username, password = i.strip().split(":")
                save_dict[username] = password # getting the variables in the database file

        # ----------------Generating-Email-Verification-Code----------------
        ver_code = "".join(secrets.choice(num) for i in range(5)) # Generating a 5 characters long randomly generated verification code
        session["ver_code"] = ver_code
        # ----------------Generating-Email----------------
        msg_title = "Verification Code" # Email subject is assigned to a variable
        sender = "noreply@app.com" 
        msg = Message(msg_title, recipients=[email], sender=sender) # the message contains all the variables above

        # ----------------Email-Content-(Body)----------------
        msg.html = f"""
        <!DOCTYPE html>
        <html>
            <head>
                <style>
                    body {{
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        font-family: Arial, sans-serif;
                        background-color: #ffffff;
                        text-align: center;
                    }}
                    .container {{
                        gap: 2px;
                        display: grid;
                        background-color: #ffffff;
                        border: 4px solid rgb(54, 144, 246);
                        border-radius: 10px;
                        width: 400px;
                        text-align: center;
                    }}
                    .h {{
                        grid-column: 1;
                        grid-row: 3;
                        color: #333;
                        grid-column: 1;
                    }}
                    .code {{
                        grid-column: 1;
                        grid-row: 4;
                        color: #333;
                        font-size: 20px;
                    }}
                    h1 {{
                        grid-column: 1;
                        grid-row: 1;
                        color: rgba(250, 198, 27, 0.948);
                        font-size: 40px;
                    }}
                    span {{
                        color: #333;
                        padding-bottom: 13px;
                        text-decoration: none;
                        color: rgb(54, 144, 246);
                    }}
                    p {{
                        grid-column: 1;
                        grid-row: 2;
                        font-size: 13px;
                    }}
                    .start {{
                        border-bottom: 3px solid rgb(54, 144, 246);
                    }}
                    .orange {{
                        font-size: 20px;
                        color: rgba(250, 198, 27, 0.948);
                    }}
                </style>
            </head>
            <body>
                <center>
                    <div class="container">
                        <div class="start">
                            <h1>Chat<span>On</span></h1>
                            <p>Email sent to <span>{email}</span></p>
                        </div>
                        <div class="h">
                            <h3>Your <span class="orange">Verification Code:</span></h3>
                        </div>
                        <div class="code">
                            <h3>{ver_code}</h3>
                        </div>
                    </div>
                </center>
            </body>
        </html>
        """
        # ----------------Checking-For-Duplicates----------------
        if user in save_dict:
            flash("The username is already taken by another user!")
        else:
            # ----------------Email-Validation----------------
            pat = r"^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$"
            if re.match(pat, email):
                print("Valid Email")
                # ----------------Sending-Email-And-Handeling-Error----------------
                try:
                    mail.send(msg)
                    session['user'] = user
                    session['encrypted_password'] = clear_message
                    return redirect(url_for("ver"))
                except Exception as e:
                    # ----------------Error-Handling----------------
                    flash("Incorrect email address. Please double-check and try again.")
                    print("Error sending email", str(e))
            else: 
                # ----------------Error-Handling----------------
                flash("Incorrect email address. Please double-check and try again.")
    return render_template("register.html")

@app.route("/verification", methods=['GET', 'POST'])
def ver():
    session.pop("username", None)
    # ----------------Verification----------------
    if request.method == "POST":
        code = request.form.get("code")
        user = session.get('user')
        ver = session.get("ver_code")
        clear_message = session.get("encrypted_password")

        if code == ver:
            with open(file, "a") as f:
                f.write(f"{user}:{clear_message}\n")
            return redirect(url_for("login"))
        else:
            flash("Verification failed; please re-enter the code or register again!")
    return render_template("email_verification.html", email=mail)

@app.route("/about", methods=['GET', 'POST'])
def about():
    session.pop("username", None)
    # ----------------About-Page----------------
    return render_template("about.html")

@app.route("/feedback", methods=['GET', 'POST'])
def feedback():
    session.pop("username", None)
    # ----------------Feedback-Page----------------
    if request.method == "POST":
        email = request.form.get("email")
        name = request.form.get("name")
        feedback = request.form.get("feedback")

        file = "feedback_from_ChatOn.txt"

        if email == 0 and feedback == 0:
            print("No feedback recieved")
        else:
            with open(file, "a") as f:
                f.write(f"{email}: {feedback}\n")
            print("Feedback received!")

            msg_to_send_title = "Thank You!"
            sender = "noreply@app.com"
            msg_to_send = Message(msg_to_send_title, recipients=[email], sender=sender)

            msg_to_send.html = f"""
                <!DOCTYPE html>
                <html>
                    <head>
                        <style>
                            body {{
                                font-family: Arial, sans-serif;
                                background-color: #ffffff;
                                color: #000000;
                            }}
                            .container {{
                                padding: 15px;
                                border-radius: 25px;
                                border: 3px solid rgb(54, 144, 246);
                            }}
                            h1 {{
                                font-size: 32px;
                            }}
                            h2 {{
                                font-size: 25px;
                            }}
                            h3 {{
                                font-size: 28px;
                            }}
                            p {{
                                font-size: 20px;
                            }}
                            .Chat, .dear, span {{
                                font-weight: bold;
                                color: rgb(54, 144, 246);
                            }}
                            .On, .name, .other {{
                                font-weight: bold;
                                color: rgba(251, 196, 16, 0.948);
                            }}
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <h1><span class="dear">Dear</span> <span class="name">{name},</span></h1>
                            <h2><span>Thank you</span> for your feedback!</h2>
                            <p>We truly <span>appreciate</span> you sharing your feedback with us.
                                Your feedback provides us with <span class="other">valuable information</span> that helps us understand your needs better and allows us to make the necessary adjustments to create a more enjoyable and seamless chatting experience for you. 
                                We are <span>truly grateful</span> for your input, as it enables us to <span class="other">grow and evolve.</span> <br><br>
                                We <span>appreciate</span> your support and the trust you've placed in us. 
                                If you ever have more feedback or suggestions, please don't hesitate to reach out. We're always here to listen and improve based on your needs.
                                <span class="other">Thank you</span> once again for <span>helping</span> us make our chatting platform even <span class="other">better.</span></p>
                            <h3 class="bold">Best regards,<br>
                            <span class="Chat">Chat<span class="On">On</span></span>
                            </h3>
                        </div>
                    </body>
                </html>
            """
            pat = r"^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$"
            if re.match(pat, email):
                print("Valid Email")
                try:
                    mail.send(msg_to_send)
                    email = 0
                    feedback = 0
                    flash("Thank you for the feedback!")
                except Exception as error:
                    flash("Incorrect email address. Please double-check and try again.")
                    print(f"Unable to send an email, reason: {error}")
            else: 
                flash("Incorrect email address. Please double-check and try again.")
                print("Invalid Email")
    return render_template("feedback.html")

@app.route("/main")
def main():
    user = session.get("username")
    if user == None:
        return redirect(url_for('login'))
    else:
        # ----------------Chatting-Area----------------
        return render_template("main.html", user=user)
    

# ----------------Sockets----------------
@socket.on("message")
def handle_message(message):
    encrypted_message = rsa.encrypt(message.encode(), public_key)
    decrypted_message = rsa.decrypt(encrypted_message, private_key)
    message_clear = decrypted_message.decode()
    print(f"Received message: {message_clear}")
    send(message_clear, broadcast=True)

# ----------------Runing----------------
if __name__ == "__main__":
    socket.run(app,  host='0.0.0.0', port=5000)
    