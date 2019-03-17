import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    return apology("TODO")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        # display form

        #Ensure the symbol exists
        if lookup(request.form.get("symbol")) is None:
            return apology("Invalid Symbol")
        # Check if shares was a positive integer
        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("shares must be a positive integer", 400)
        # Query database for username
        rows = db.execute("SELECT cash from users where id= :user_id", user_id = session["user_id"])
        cash = rows[0]['cash'] ################### COULD BE A PROBLEM

        # price shares
        price_shares = shares * lookup(request.form.get("symbol"))['price']

        # determine if enough money
        if price_shares > cash:
            return apology("You cannot afford it.")

        # calculate money after buy
        cash = cash - price_shares

        # calculate present time, username, stock_symbol, price_share


        # introduce values into database


        # update users database


    #add stock to user's portfolio

    #

    else:
        return render_template("buy.html")



    return apology("TODO")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        # Ensure quote was submitted
        if not request.form.get("symbol"):
            return apology("Missing Symbol!")

        #Ensure the symbol exists
        if lookup(request.form.get("symbol")) is None:
            return apology("Invalid Symbol")

        # Find the information on the website
        quote = lookup(request.form.get("symbol"))
        return render_template("quoteInformation.html", name = quote['name'], symbol = quote['symbol'], price = quote['price'])

    else:
        return render_template("quote.html")
        # I think it works but i must confirm with render template (HOW MANY ARGUments???buy)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("Missing username!")

        # Ensure passwords were submitted
        if not request.form.get("password"):
            return apology("must provide password")

        if not request.form.get("password_check"):
            return apology("must provide password confirm")

        #Ensure passwords match
        if request.form.get("password") != request.form.get("password_check"):
            return apology("Passwords don't match")

        # Retrieve submitted values:
        hash = generate_password_hash(request.form.get("password"))

        # Query database for username
        new_user_id = db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",
                                    username=request.form.get("username"),
                                    hash=hash)
        #unique username?
        if not new_user_id:
            return apology("Username already exists. Pick another one.", 400)


        #Remember which user has logged in
        session["user_id"] = new_user_id

        flash("Registered!")

        #Redirect user to home page
        return redirect(url_for("index"))

    #THERE IS A PROBLEM WITH THE PAGE AT THE END. THE ERROR GIVE ME IS 500 INTERNAL SERVER ERROR
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    return apology("TODO")


def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


# listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
