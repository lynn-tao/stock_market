import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # Single query for the transactions table
    portfolio = db.execute("SELECT stock, SUM(shares) as total_shares, price FROM transactions WHERE user_id = ? GROUP BY stock", session["user_id"])
    # print(portfolio)

    # print(portfolio)
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
    # print(cash)

    # don't pass in stocks with zero
    portfolio_nonzero = []
    for item in portfolio:
        if item["total_shares"] != 0:
            portfolio_nonzero.append(item)
    # print(portfolio_nonzero)

    # calculate total value of assets incl. cash and remove any stocks the user no longer holds
    total = 0
    for item in portfolio_nonzero:
        # print(item)
        total += item["total_shares"] * item["price"]
    total_money = total+cash
    # print(total_money)

    # Render portfolio page
    return render_template("index.html", portfolio=portfolio_nonzero, cash=cash, total_money=total_money)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    if request.method == "POST":
        # get symbol and share info
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        stock_info = lookup(symbol)
        # error checking - are symbol and stock info both valid
        if not symbol or stock_info is None:
            return apology("Invalid Symbol!")
        if not shares:
            return apology("Missing Shares")
        try:
            shares = int(shares)
        except ValueError:
            return apology("Invalid Shares Input")
        if shares <= 0:
            return apology("Invalid Shares Input")

        # Obtain the user's current cash balance
        rows = db.execute(
            "SELECT cash FROM users WHERE id = ?", session["user_id"]
        )
        # Error check if user can afford this purchase
        if float(rows[0]["cash"]) < float(stock_info["price"]) * float(shares):
            return apology("Can't Afford!")
        balance = float(rows[0]["cash"]) - (float(stock_info["price"]) * shares)

        # Create a new SQL table to record user transactions - add to table if it doesn't exit
        db.execute("CREATE TABLE IF NOT EXISTS transactions(transact_id INTEGER PRIMARY KEY NOT NULL, user_id INTEGER NOT NULL, stock TEXT NOT NULL, price FLOAT(2) NOT NULL, shares INTEGER NOT NULL, time TEXT NOT NULL)")

        #  Insert this new transaction into table
        rows = int(db.execute("SELECT COUNT(*) FROM transactions;")[0]["COUNT(*)"])
        db.execute("INSERT INTO transactions(transact_id, user_id, stock, price, shares, time) VALUES(?, ?, ?, ?, ?, ?)", rows, session["user_id"], stock_info["symbol"], stock_info["price"], shares, datetime.now())

        # Update the user's cash
        db.execute("UPDATE users SET cash = ? WHERE id = ?", balance, session["user_id"])

        # print a success message
        flash("Bought!")

        # Redirect user to home page
        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

     # Query for all birthdays
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = ?", session["user_id"])
    # print(transactions)

    # Render history of transactions page
    return render_template("history.html", transactions=transactions)



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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

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
    if request.method == "GET":
        return render_template("quote.html")
    if request.method == "POST":
        symbol = request.form.get("symbol")
        # error check if valid input was entered
        if not symbol:
            return apology("Missing symbol")
        # get stock price info
        stock_info = lookup(symbol)
        # extra error check invalid stock symbol
        if stock_info == None:
            return apology("Invalid stock symbol")
        # print(stock_info)
        return render_template("quoted.html", info=stock_info)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # error checking
    if request.method == "POST":
        # Access form data
        username = request.form.get("username")
        # PERSONAL TOUCH - Require users’ passwords to have some number of letters, numbers, and/or symbols.
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        # error checking if valid input was entered
        if not username or not password or not confirmation:
            return apology("must enter username, password, and confirmation! nothing can be blank >:()")
        if password != confirmation:
            return apology("passwords must match!")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        if len(rows) > 0:
            return apology("that username already exists!")

        # Insert new user data into database
        db.execute("INSERT INTO users (username, hash, cash) VALUES(?, ?, ?)", username, generate_password_hash(password), 10000.00)

        # success message, let the user log in
        flash("Your registration was successful! Please log in.")

    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        # Single query from the transactions table
        portfolio = db.execute("SELECT stock, SUM(shares) as total_shares, price FROM transactions WHERE user_id = ? GROUP BY stock", session["user_id"])
        # print(portfolio)
        # find which stocks have shares to sell
        select_stocks = []
        for item in portfolio:
            if item["total_shares"] > 0:
                select_stocks.append(item["stock"])
        return render_template("sell.html", stocks=select_stocks)

    if request.method == "POST":
        symbol = request.form.get("symbol")
        share = request.form.get("shares")
        # error checking
        if not symbol:
            return apology("Select a stock!")
        # get how many shares of the stock the user has
        shares = db.execute("SELECT shares FROM transactions WHERE stock = ? AND user_id = ?", symbol, session["user_id"])
        total_shares = 0
        for item in shares:
            total_shares += item["shares"]

        # error check that user entered valid shares input
        if total_shares <= 0:
            return apology("You don't own this stock!")
        if not share:
            return apology("Missing Shares")
        try:
            share = int(share)
        except ValueError:
            return apology("Invalid Shares Input")
        if share <= 0:
            return apology("Invalid Shares Input")
        if total_shares < share:
            return apology("Too many shares!")

        # update transaction table by adding another transaction
        rows = int(db.execute("SELECT COUNT(*) FROM transactions;")[0]["COUNT(*)"])
        db.execute("INSERT INTO transactions(transact_id, user_id, stock, price, shares, time) VALUES(?, ?, ?, ?, ?, ?)", rows, session["user_id"], symbol, lookup(symbol)["price"], -1*share, datetime.now())

        # Query database for user's cash
        rows = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        # update cash and query it back to the table
        balance = float(rows[0]["cash"]) + (float(lookup(symbol)["price"]) * share)
        db.execute("UPDATE users SET cash = ? WHERE id = ?", balance, session["user_id"])

        # Redirect user to home page
        return redirect("/")

    return apology("TODO")
