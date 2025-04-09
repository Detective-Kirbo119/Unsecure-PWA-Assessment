import sqlite3 as sql
import bcrypt
import time
import random
import os


def insertUser(username, password, DoB):
    """Inserts a new user into the database with a hashed password."""
    try:
        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode('utf-8')  # Decode to store as string
        with sql.connect("database_files/database.db") as con:
            cur = con.cursor()
            cur.execute(
                "INSERT INTO users (username, password, dateOfBirth) VALUES (?, ?, ?)",
                (username, hashed_pw, DoB)
            )
            con.commit()
    except sql.Error as e:
        print(f"[Database Error]: {e}")


def retrieveUsers(username, password):
    """Verifies user credentials securely."""
    try:
        with sql.connect("database_files/database.db") as con:
            cur = con.cursor()
            cur.execute("SELECT password FROM users WHERE username = ?", (username,))
            row = cur.fetchone()

        if row is None:
            return False  # Username does not exist

        stored_hashed_pw = row[0]

        if bcrypt.checkpw(password.encode(), stored_hashed_pw.encode('utf-8')):  # Encode for comparison
            update_visitor_count()
            return True
        return False
    except sql.Error as e:
        print(f"[Database Error]: {e}")
        return False


def update_visitor_count():
    """Securely updates the visitor log counter."""
    path = "visitor_log.txt"
    try:
        if os.path.exists(path):
            with open(path, "r+", encoding="utf-8") as file:
                try:
                    number = int(file.read().strip())
                except ValueError:
                    number = 0
                number += 1
                file.seek(0)
                file.write(str(number))
                file.truncate()
        else:
            with open(path, "w", encoding="utf-8") as file:
                file.write("1")
    except Exception as e:
        print(f"[Visitor Log Error]: {e}")


def insertFeedback(feedback):
    """Inserts feedback into the database."""
    try:
        with sql.connect("database_files/database.db") as con:
            cur = con.cursor()
            cur.execute("INSERT INTO feedback (feedback) VALUES (?)", (feedback,))
            con.commit()
    except sql.Error as e:
        print(f"[Database Error]: {e}")


def listFeedback():
    """Fetches feedback and renders HTML snippet for success page."""
    try:
        with sql.connect("database_files/database.db") as con:
            cur = con.cursor()
            data = cur.execute("SELECT * FROM feedback").fetchall()

        output_dir = "templates/partials"
        os.makedirs(output_dir, exist_ok=True)
        feedback_file = os.path.join(output_dir, "success_feedback.html")

        with open(feedback_file, "w", encoding="utf-8") as f:
            for row in data:
                if len(row) > 1:  # Ensure feedback text exists in the second column
                    f.write("<p>\n")
                    f.write(f"{row[1]}\n")  # Assumes feedback text is in the second column
                    f.write("</p>\n")
    except sql.Error as e:
        print(f"[Database Error]: {e}")
    except Exception as e:
        print(f"[Feedback Write Error]: {e}")
