"""
Advanced Interview Quiz - Python + Tkinter
Single-file desktop application with:
 - SQLite-backed users (register/login) with SHA-256 hashing
 - Quiz loaded from embedded list (easily loadable from JSON)
 - Timer per question (configurable)
 - Animated home mascot, slide transitions, and radial result animation
 - Leaderboard (top scores) saved in DB
 - Polished ttk buttons and layout

Run: python3 advanced_interview_quiz.py
Requires: Python 3.8+, Tkinter (standard library), no external packages.

Notes:
 - If tkinter is missing, the script prints helpful install instructions and exits.
 - Questions are included in QUESTIONS; replace with JSON loader if desired.
"""

import sys
import os
import sqlite3
import hashlib
import time
import json
import math
from datetime import datetime

try:
    import tkinter as tk
    from tkinter import ttk, messagebox
except Exception as e:
    print("Tkinter is not available in this Python environment.")
    print("Install tkinter (e.g., on Debian/Ubuntu: sudo apt-get install python3-tk")
    sys.exit(1)

DB_FILE = 'advanced_quiz.db'
QUESTION_TIMER_SECONDS = 20  # seconds per question

# -------------------- Data (replaceable with dynamic loader) --------------------
QUESTIONS = [
    {
        'q': 'What is the time complexity of binary search?',
        'choices': ['O(n)', 'O(log n)', 'O(n log n)', 'O(1)'],
        'answer': 1,
        'difficulty': 'Easy'
    },
    {
        'q': 'Which HTML element is used for the largest heading?',
        'choices': ['<heading>', '<h1>', '<head>', '<h6>'],
        'answer': 1,
        'difficulty': 'Easy'
    },
    {
        'q': 'Which data type is immutable in Python?',
        'choices': ['list', 'dict', 'set', 'tuple'],
        'answer': 3,
        'difficulty': 'Easy'
    },
    {
        'q': 'Which of these is NOT a database?',
        'choices': ['MySQL', 'Postgres', 'Redis', 'React'],
        'answer': 3,
        'difficulty': 'Medium'
    },
    {
        'q': 'Which HTTP status code means Not Found?',
        'choices': ['200', '301', '404', '500'],
        'answer': 2,
        'difficulty': 'Easy'
    },
    {
        'q': 'Which sorting algorithm is typically fastest on average for general data?',
        'choices': ['Bubble Sort', 'Quick Sort', 'Selection Sort', 'Insertion Sort'],
        'answer': 1,
        'difficulty': 'Medium'
    }
]

# -------------------- Helpers --------------------#

def init_db(path=DB_FILE):
    conn = sqlite3.connect(path)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS scores (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            username TEXT,
            score INTEGER,
            total INTEGER,
            duration REAL,
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()


def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode('utf-8')).hexdigest()


def register_user(username: str, password: str) -> bool:
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, hash_password(password)))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False


def verify_user(username: str, password: str):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    uid, ph = row
    if ph == hash_password(password):
        return uid
    return None

     #---------Leaderboard and Score Saving---------#
     
def save_score(user_id: int, username: str, score: int, total: int, duration: float):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('INSERT INTO scores (user_id, username, score, total, duration) VALUES (?, ?, ?, ?, ?)',
              (user_id, username, score, total, duration))
    conn.commit()
    conn.close()


def top_scores(limit=10):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT username, score, total, duration, ts FROM scores ORDER BY score DESC, duration ASC LIMIT ?', (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

# -------------------- GUI --------------------#

class AdvancedQuizApp(tk.Tk):
    def __init__(self):
        super().__init__()
        #------Window Size-------#
        self.title('Python Interview Quiz')
        self.geometry('1480x1200')
        self.resizable(True, True)

        # state
        self.user_id = None
        self.username = None
        self.current_q = 0
        self.score = 0
        self.start_time = None
        self.question_start_time = None
        self.remaining_time = QUESTION_TIMER_SECONDS
        self.timer_job = None

        # Styles
        self.style = ttk.Style(self)
        self.style.theme_use('default')
        self.style.configure('TButton', padding=6, font=('Helvetica', 11))
        self.style.configure('Header.TLabel', font=('Helvetica', 18, 'bold'))

        # frames container
        container = ttk.Frame(self)
        container.pack(fill='both', expand=True)

        self.frames = {}
        for F in (LoginFrame, RegisterFrame, HomeFrame, QuizFrame, ResultFrame, LeaderboardFrame):
            page = F(parent=container, controller=self)
            self.frames[F.__name__] = page
            page.grid(row=0, column=0, sticky='nsew')

        self.show_frame('LoginFrame')

    def show_frame(self, name):
        frame = self.frames[name]
        frame.tkraise()
        if hasattr(frame, 'on_show'):
            frame.on_show()

    def start_quiz(self):
        self.current_q = 0
        self.score = 0
        self.start_time = time.time()
        self.show_frame('QuizFrame')

    def end_quiz(self):
        duration = time.time() - (self.start_time or time.time())
        save_score(self.user_id or -1, self.username or 'Guest', self.score, len(QUESTIONS), duration)
        self.show_frame('ResultFrame')

    def logout(self):
        self.user_id = None
        self.username = None
        self.show_frame('LoginFrame')


class LoginFrame(ttk.Frame):
    def __init__(self, parent, controller: AdvancedQuizApp):
        super().__init__(parent)
        self.controller = controller
        self.build()

    def build(self):
        header = ttk.Label(self, text='Welcome to Python Interview Quiz', style='Header.TLabel')
        header.pack(pady=12)

        frm = ttk.Frame(self)
        frm.pack(pady=8)

        ttk.Label(frm, text='Username').grid(row=0, column=0, sticky='e', padx=10, pady=10)
        self.username_entry = ttk.Entry(frm)
        self.username_entry.grid(row=0, column=1, padx=10, pady=10)

        ttk.Label(frm, text='Password').grid(row=1, column=0, sticky='e', padx=10, pady=10)
        self.password_entry = ttk.Entry(frm, show='*')
        self.password_entry.grid(row=1, column=1, padx=10, pady=10)

        btn_fr = ttk.Frame(self)
        btn_fr.pack(pady=10)
        ttk.Button(btn_fr, text='Login', command=self.do_login).grid(row=0, column=0, padx=6)
        ttk.Button(btn_fr, text='Register', command=lambda: self.controller.show_frame('RegisterFrame')).grid(row=0, column=1, padx=6)
        ttk.Button(btn_fr, text='Leaderboard', command=lambda: self.controller.show_frame('LeaderboardFrame')).grid(row=0, column=2, padx=6)
    #--------------------Login Functionality--------------------#
    def do_login(self):
        u = self.username_entry.get().strip()
        p = self.password_entry.get().strip()
        if not u or not p:
            messagebox.showwarning('Input', 'Enter username and password')
            return
        uid = verify_user(u, p)
        if uid:
            self.controller.user_id = uid
            self.controller.username = u
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            self.controller.show_frame('HomeFrame')
        else:
            messagebox.showerror('Login failed', 'Invalid username or password')


class RegisterFrame(ttk.Frame):
    def __init__(self, parent, controller: AdvancedQuizApp):
        super().__init__(parent)
        self.controller = controller
        self.build()

    def build(self):
        ttk.Label(self, text='Create Account', style='Header.TLabel').pack(pady=8)
        frm = ttk.Frame(self)
        frm.pack(pady=6)

        ttk.Label(frm, text='Username:').grid(row=0, column=0, sticky='e', padx=6, pady=6)
        self.username_entry = ttk.Entry(frm)
        self.username_entry.grid(row=0, column=1, padx=6, pady=6)

        ttk.Label(frm, text='Password:').grid(row=1, column=0, sticky='e', padx=6, pady=6)
        self.password_entry = ttk.Entry(frm, show='*')
        self.password_entry.grid(row=1, column=1, padx=6, pady=6)

        ttk.Label(frm, text='Confirm:').grid(row=2, column=0, sticky='e', padx=6, pady=6)
        self.confirm_entry = ttk.Entry(frm, show='*')
        self.confirm_entry.grid(row=2, column=1, padx=6, pady=6)

        btn_fr = ttk.Frame(self)
        btn_fr.pack(pady=8)
        ttk.Button(btn_fr, text='Create', command=self.create_account).grid(row=0, column=0, padx=6)
        ttk.Button(btn_fr, text='Back', command=lambda: self.controller.show_frame('LoginFrame')).grid(row=0, column=1, padx=6)

    def create_account(self):
        u = self.username_entry.get().strip()
        p = self.password_entry.get().strip()
        c = self.confirm_entry.get().strip()
        if not u or not p:
            messagebox.showwarning('Input', 'All fields required')
            return
        if p != c:
            messagebox.showerror('Mismatch', 'Passwords do not match')
            return
        ok = register_user(u, p)
        if ok:
            messagebox.showinfo('Success', 'Account created — you may login now')
            self.controller.show_frame('LoginFrame')
        else:
            messagebox.showerror('Error', 'Username already exists')


class HomeFrame(ttk.Frame):
    def __init__(self, parent, controller: AdvancedQuizApp):
        super().__init__(parent)
        self.controller = controller
        self.build()

    def build(self):
        header = ttk.Label(self, text='Home', style='Header.TLabel')
        header.pack(pady=8)

        self.welcome_lbl = ttk.Label(self, text='')
        self.welcome_lbl.pack(pady=4)
        
    #--------------------Home Frame Buttons--------------------#
    
        btn_fr = ttk.Frame(self)
        btn_fr.pack(pady=8)
        ttk.Button(btn_fr, text='Start Quiz', command=self.start).grid(row=0, column=0, padx=6)
        ttk.Button(btn_fr, text='Scoreboard', command=lambda: self.controller.show_frame('LeaderboardFrame')).grid(row=0, column=1, padx=6)
        ttk.Button(btn_fr, text='Logout', command=self.controller.logout).grid(row=0, column=2, padx=6)

        # animated mascot canvas
        self.canvas = tk.Canvas(self, width=780, height=300, bg='#f0f0f0', highlightthickness=0)
        self.canvas.pack(pady=8)
        # draw sun-like mascot
        self.mascot = self.canvas.create_oval(100, 100, 210, 10, fill='#ffcc33', outline='')
        self.eye1 = self.canvas.create_oval(55, 55, 65, 65, fill='black')
        self.eye2 = self.canvas.create_oval(75, 55, 85, 65, fill='black')
        self.smile = self.canvas.create_arc(50, 70, 90, 110, start=190, extent=160, style='arc', width=3)
        self._dx = 3
        self.animate()

    def on_show(self):
        self.welcome_lbl.config(text=f'Hello, {self.controller.username or "Guest"}!')

    def start(self):
        self.controller.start_quiz()

    def animate(self):
        # simple bobbing animation
        coords = self.canvas.coords(self.mascot)
        if coords:
            x0, y0, x1, y1 = coords
            if x1 >= 780 or x0 <= 0:
                self._dx = -self._dx
            self.canvas.move(self.mascot, self._dx, 0)
            self.canvas.move(self.eye1, self._dx, 0)
            self.canvas.move(self.eye2, self._dx, 0)
            self.canvas.move(self.smile, self._dx, 0)
        self.after(40, self.animate)


class QuizFrame(ttk.Frame):
    def __init__(self, parent, controller: AdvancedQuizApp):
        super().__init__(parent)
        self.controller = controller
        self.build()

    def build(self):
        header_fr = ttk.Frame(self)
        header_fr.pack(fill='x', pady=6)
        self.q_index_lbl = ttk.Label(header_fr, text='Q1', font=('Helvetica', 12, 'bold'))
        self.q_index_lbl.pack(side='left', padx=8)
        self.timer_lbl = ttk.Label(header_fr, text='Time: --')
        self.timer_lbl.pack(side='right', padx=8)

        self.canvas_main = tk.Canvas(self, width=860, height=460)
        self.canvas_main.pack(pady=6)

        self.q_frame = ttk.Frame(self.canvas_main, width=820, height=420)
        self.q_frame.pack_propagate(False)
        self.canvas_main.create_window(430, 230, window=self.q_frame)

        self.question_lbl = ttk.Label(self.q_frame, text='', wraplength=760, font=('Helvetica', 14))
        self.question_lbl.pack(pady=8)

        self.choice_var = tk.IntVar(value=-1)
        self.choice_buttons = []
        for i in range(4):
            b = ttk.Radiobutton(self.q_frame, text='', variable=self.choice_var, value=i)
            b.pack(anchor='w', padx=20, pady=6)
            self.choice_buttons.append(b)

        btn_fr = ttk.Frame(self.q_frame)
        btn_fr.pack(pady=8)
        self.next_btn = ttk.Button(btn_fr, text='Next', command=self.next_question)
        self.next_btn.grid(row=0, column=0, padx=6)
        self.quit_btn = ttk.Button(btn_fr, text='Quit', command=self.confirm_quit)
        self.quit_btn.grid(row=0, column=1, padx=6)

        self.progress = ttk.Progressbar(self.q_frame, orient='horizontal', length=700, mode='determinate')
        self.progress.pack(pady=6)

    def on_show(self):
        # prepare first question
        self.controller.current_q = 0
        self.controller.score = 0
        self.show_question(animate=False)

    def show_question(self, animate=True):
        idx = self.controller.current_q
        if idx >= len(QUESTIONS):
            self.controller.end_quiz()
            return
        q = QUESTIONS[idx]
        self.choice_var.set(-1)
        self.question_lbl.config(text=f'Q{idx+1}. {q["q"]}')
        for i, ch in enumerate(q['choices']):
            self.choice_buttons[i].config(text=f'{i+1}. {ch}')
        self.q_index_lbl.config(text=f'Q{idx+1} / {len(QUESTIONS)}')
        self.update_progress()
        # timer start
        self.controller.question_start_time = time.time()
        self.controller.remaining_time = QUESTION_TIMER_SECONDS
        self.update_timer()
        if animate:
            self.slide_in()

    def update_progress(self):
        total = len(QUESTIONS)
        val = int((self.controller.current_q / total) * 100)
        self.progress['value'] = val

    def update_timer(self):
        # update timer label every second
        rem = int(self.controller.remaining_time)
        self.timer_lbl.config(text=f'Time: {rem}s')
        if rem <= 0:
            # time's up for this question
            self.time_up()
            return
        self.controller.remaining_time -= 1
        self.controller.timer_job = self.after(1000, self.update_timer)

    def time_up(self):
        messagebox.showinfo('Time up', "Time's up for this question — moving on.")
        self.record_answer(None)
        self.advance()

    def record_answer(self, choice_index: int):
        idx = self.controller.current_q
        if idx < len(QUESTIONS):
            correct = QUESTIONS[idx]['answer']
            if choice_index is not None and choice_index == correct:
                self.controller.score += 1

    def next_question(self):
        # cancel timer tick
        if self.controller.timer_job:
            self.after_cancel(self.controller.timer_job)
            self.controller.timer_job = None
        sel = self.choice_var.get()
        if sel == -1:
            if not messagebox.askyesno('No answer', 'No option selected. Do you want to skip?'):
                # restart timer
                self.controller.remaining_time = max(1, self.controller.remaining_time)
                self.update_timer()
                return
            else:
                sel = None
        self.record_answer(sel)
        self.advance()

    def advance(self):
        self.controller.current_q += 1
        self.show_question()

    def confirm_quit(self):
        if messagebox.askyesno('Quit', 'Quit quiz and submit your score?'):
            # cancel timer
            if self.controller.timer_job:
                self.after_cancel(self.controller.timer_job)
                self.controller.timer_job = None
            self.controller.end_quiz()

    def slide_in(self):
        # small slide animation for q_frame inside canvas_main
        # move the canvas window left to right
        for i in range(15):
            self.canvas_main.move(self.q_frame, -8, 0)
            self.update()
        for i in range(15):
            self.canvas_main.move(self.q_frame, 8, 0)
            self.update()


class ResultFrame(ttk.Frame):
    def __init__(self, parent, controller: AdvancedQuizApp):
        super().__init__(parent)
        self.controller = controller
        self.build()

    def build(self):
        ttk.Label(self, text='Results', style='Header.TLabel').pack(pady=8)
        self.lbl = ttk.Label(self, text='', font=('Helvetica', 14))
        self.lbl.pack(pady=6)

        self.canvas = tk.Canvas(self, width=320, height=320)
        self.canvas.pack(pady=8)

        btn_fr = ttk.Frame(self)
        btn_fr.pack(pady=6)
        ttk.Button(btn_fr, text='Back to Home', command=lambda: self.controller.show_frame('HomeFrame')).grid(row=0, column=0, padx=6)
        ttk.Button(btn_fr, text='Leaderboard', command=lambda: self.controller.show_frame('LeaderboardFrame')).grid(row=0, column=1, padx=6)

    def on_show(self):
        s = self.controller.score
        total = len(QUESTIONS)
        self.lbl.config(text=f'{self.controller.username or "Guest"}, you scored {s} out of {total}')
        self.animate_circle(int((s/total) * 100))

    def animate_circle(self, pct):
        self.canvas.delete('all')
        x0, y0, x1, y1 = 10, 10, 310, 310
        arc = self.canvas.create_arc(x0, y0, x1, y1, start=90, extent=0, width=20, style='arc')
        text = self.canvas.create_text(160, 160, text='0%', font=('Helvetica', 20, 'bold'))

        def step(i=0):
            if i <= pct:
                extent = -3.6 * i
                self.canvas.itemconfigure(arc, extent=extent)
                self.canvas.itemconfigure(text, text=f'{i}%')
                self.after(15, lambda: step(i+1))
        step()


class LeaderboardFrame(ttk.Frame):
    def __init__(self, parent, controller: AdvancedQuizApp):
        super().__init__(parent)
        self.controller = controller
        self.build()

    def build(self):
        ttk.Label(self, text='Leaderboard', style='Header.TLabel').pack(pady=8)
        self.tree = ttk.Treeview(self, columns=('user','score','total','duration','ts'), show='headings', height=10)
        self.tree.heading('user', text='User')
        self.tree.heading('score', text='Score')
        self.tree.heading('total', text='Total')
        self.tree.heading('duration', text='Duration(s)')
        self.tree.heading('ts', text='When')
        self.tree.pack(pady=6)
        btn_fr = ttk.Frame(self)
        btn_fr.pack(pady=6)
        ttk.Button(btn_fr, text='Refresh', command=self.load).grid(row=0, column=0, padx=6)
        ttk.Button(btn_fr, text='Back', command=lambda: self.controller.show_frame('HomeFrame')).grid(row=0, column=1, padx=6)

    def on_show(self):
        self.load()

    def load(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        rows = top_scores(20)
        for r in rows:
            user, score, total, duration, ts = r
            ts_fmt = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S').strftime('%b %d %H:%M') if isinstance(ts, str) else str(ts)
            self.tree.insert('', 'end', values=(user, score, total, f'{duration:.1f}', ts_fmt))


# -------------------- Main --------------------

def main():
    init_db()
    app = AdvancedQuizApp()
    app.mainloop()


if __name__ == '__main__':
    main()
    # !/usr/bin/env python3
    """
    Advanced Interview Quiz - Python + Tkinter
    Single-file desktop application with:
     - SQLite-backed users (register/login) 
     - Quiz loaded from embedded list (easily loadable from JSON)
     - Timer per question (configurable)
     - Animated home mascot, slide transitions, and radial result animation
     - Leaderboard (top scores) saved in DB
     - Polished ttk buttons and layout

    Run: python3 advanced_interview_quiz.py
    Requires: Python 3.8+, Tkinter (standard library), no external packages.

    Notes:
     - If tkinter is missing, the script prints helpful install instructions and exits.
     - Questions are included in QUESTIONS; replace with JSON loader if desired.
    """

    import sys
    import os
    import sqlite3
    import hashlib
    import time
    import json
    import math
    from datetime import datetime

    try:
        import tkinter as tk
        from tkinter import ttk, messagebox
    except Exception as e:
        print("Tkinter is not available in this Python environment.")
        print("Install tkinter (e.g., on Debian/Ubuntu: sudo apt-get install python3-tk")
        sys.exit(1)

    DB_FILE = 'advanced_quiz.db'
    QUESTION_TIMER_SECONDS = 20  # seconds per question

    # -------------------- Data (replaceable with dynamic loader) --------------------
    QUESTIONS = [
        {
            'q': 'What is the time complexity of binary search?',
            'choices': ['O(n)', 'O(log n)', 'O(n log n)', 'O(1)'],
            'answer': 1,
            'difficulty': 'Easy'
        },
        {
            'q': 'Which HTML element is used for the largest heading?',
            'choices': ['<heading>', '<h1>', '<head>', '<h6>'],
            'answer': 1,
            'difficulty': 'Easy'
        },
        {
            'q': 'Which data type is immutable in Python?',
            'choices': ['list', 'dict', 'set', 'tuple'],
            'answer': 3,
            'difficulty': 'Easy'
        },
        {
            'q': 'Which of these is NOT a database?',
            'choices': ['MySQL', 'Postgres', 'Redis', 'React'],
            'answer': 3,
            'difficulty': 'Medium'
        },
        {
            'q': 'Which HTTP status code means Not Found?',
            'choices': ['200', '301', '404', '500'],
            'answer': 2,
            'difficulty': 'Easy'
        },
        {
            'q': 'Which sorting algorithm is typically fastest on average for general data?',
            'choices': ['Bubble Sort', 'Quick Sort', 'Selection Sort', 'Insertion Sort'],
            'answer': 1,
            'difficulty': 'Medium'
        }
    ]


    # -------------------- Helpers --------------------

    def init_db(path=DB_FILE):
        conn = sqlite3.connect(path)
        c = conn.cursor()
        c.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL
                    )
                ''')
        c.execute('''
                    CREATE TABLE IF NOT EXISTS scores (
                        id INTEGER PRIMARY KEY,
                        user_id INTEGER,
                        username TEXT,
                        score INTEGER,
                        total INTEGER,
                        duration REAL,
                        ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
        conn.commit()
        conn.close()


    def hash_password(pw: str) -> str:
        return hashlib.sha256(pw.encode('utf-8')).hexdigest()


    def register_user(username: str, password: str) -> bool:
        try:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, hash_password(password)))
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            return False


    def verify_user(username: str, password: str):
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
        row = c.fetchone()
        conn.close()
        if not row:
            return None
        uid, ph = row
        if ph == hash_password(password):
            return uid
        return None


    def save_score(user_id: int, username: str, score: int, total: int, duration: float):
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('INSERT INTO scores (user_id, username, score, total, duration) VALUES (?, ?, ?, ?, ?)',
                  (user_id, username, score, total, duration))
        conn.commit()
        conn.close()


    def top_scores(limit=10):
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT username, score, total, duration, ts FROM scores ORDER BY score DESC, duration ASC LIMIT ?',
                  (limit,))
        rows = c.fetchall()
        conn.close()
        return rows


    # -------------------- GUI --------------------
    class AdvancedQuizApp(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title('Advanced Interview Quiz')
            self.geometry('900x620')
            self.resizable(False, False)

            # state
            self.user_id = None
            self.username = None
            self.current_q = 0
            self.score = 0
            self.start_time = None
            self.question_start_time = None
            self.remaining_time = QUESTION_TIMER_SECONDS
            self.timer_job = None

            # Styles
            self.style = ttk.Style(self)
            self.style.theme_use('default')
            self.style.configure('TButton', padding=6, font=('Helvetica', 11))
            self.style.configure('Header.TLabel', font=('Helvetica', 18, 'bold'))

            # frames container
            container = ttk.Frame(self)
            container.pack(fill='both', expand=True)

            self.frames = {}
            for F in (LoginFrame, RegisterFrame, HomeFrame, QuizFrame, ResultFrame, LeaderboardFrame):
                page = F(parent=container, controller=self)
                self.frames[F.__name__] = page
                page.grid(row=0, column=0, sticky='nsew')

            self.show_frame('LoginFrame')

        def show_frame(self, name):
            frame = self.frames[name]
            frame.tkraise()
            if hasattr(frame, 'on_show'):
                frame.on_show()

        def start_quiz(self):
            self.current_q = 0
            self.score = 0
            self.start_time = time.time()
            self.show_frame('QuizFrame')

        def end_quiz(self):
            duration = time.time() - (self.start_time or time.time())
            save_score(self.user_id or -1, self.username or 'Guest', self.score, len(QUESTIONS), duration)
            self.show_frame('ResultFrame')

        def logout(self):
            self.user_id = None
            self.username = None
            self.show_frame('LoginFrame')


    class LoginFrame(ttk.Frame):
        def __init__(self, parent, controller: AdvancedQuizApp):
            super().__init__(parent)
            self.controller = controller
            self.build()

        def build(self):
            header = ttk.Label(self, text='Welcome to Python Quiz', style='Header.TLabel')
            header.pack(pady=12)

            frm = ttk.Frame(self)
            frm.pack(pady=8)

            ttk.Label(frm, text='Username:').grid(row=0, column=0, sticky='e', padx=6, pady=6)
            self.username_entry = ttk.Entry(frm)
            self.username_entry.grid(row=0, column=1, padx=6, pady=6)

            ttk.Label(frm, text='Password:').grid(row=1, column=0, sticky='e', padx=6, pady=6)
            self.password_entry = ttk.Entry(frm, show='*')
            self.password_entry.grid(row=1, column=1, padx=6, pady=6)

            btn_fr = ttk.Frame(self)
            btn_fr.pack(pady=10)
            ttk.Button(btn_fr, text='Login', command=self.do_login).grid(row=0, column=0, padx=6)
            ttk.Button(btn_fr, text='Register', command=lambda: self.controller.show_frame('RegisterFrame')).grid(row=0,  column=1,padx=6)
            ttk.Button(btn_fr, text='Leaderboard', command=lambda: self.controller.show_frame('LeaderboardFrame')).grid(row=0, column=2, padx=6)

        def do_login(self):
            u = self.username_entry.get().strip()
            p = self.password_entry.get().strip()
            if not u or not p:
                messagebox.showwarning('Input', 'Enter username and password')
                return
            uid = verify_user(u, p)
            if uid:
                self.controller.user_id = uid
                self.controller.username = u
                self.username_entry.delete(0, tk.END)
                self.password_entry.delete(0, tk.END)
                self.controller.show_frame('HomeFrame')
            else:
                messagebox.showerror('Login failed', 'Invalid credentials')


    class RegisterFrame(ttk.Frame):
        def __init__(self, parent, controller: AdvancedQuizApp):
            super().__init__(parent)
            self.controller = controller
            self.build()

        def build(self):
            ttk.Label(self, text='Create Account', style='Header.TLabel').pack(pady=8)
            frm = ttk.Frame(self)
            frm.pack(pady=6)

            ttk.Label(frm, text='Username:').grid(row=0, column=0, sticky='e', padx=6, pady=6)
            self.username_entry = ttk.Entry(frm)
            self.username_entry.grid(row=0, column=1, padx=6, pady=6)

            ttk.Label(frm, text='Password:').grid(row=1, column=0, sticky='e', padx=6, pady=6)
            self.password_entry = ttk.Entry(frm, show='*')
            self.password_entry.grid(row=1, column=1, padx=6, pady=6)

            ttk.Label(frm, text='Confirm:').grid(row=2, column=0, sticky='e', padx=6, pady=6)
            self.confirm_entry = ttk.Entry(frm, show='*')
            self.confirm_entry.grid(row=2, column=1, padx=6, pady=6)

            btn_fr = ttk.Frame(self)
            btn_fr.pack(pady=8)
            ttk.Button(btn_fr, text='Create', command=self.create_account).grid(row=0, column=0, padx=6)
            ttk.Button(btn_fr, text='Back', command=lambda: self.controller.show_frame('LoginFrame')).grid(row=0,
                                                                                                           column=1,
                                                                                                           padx=6)

        def create_account(self):
            u = self.username_entry.get().strip()
            p = self.password_entry.get().strip()
            c = self.confirm_entry.get().strip()
            if not u or not p:
                messagebox.showwarning('Input', 'All fields required')
                return
            if p != c:
                messagebox.showerror('Mismatch', 'Passwords do not match')
                return
            ok = register_user(u, p)
            if ok:
                messagebox.showinfo('Success', 'Account created — you may login now')
                self.controller.show_frame('LginFrameo')
            else:
                messagebox.showerror('Error', 'Username already exists')


    class HomeFrame(ttk.Frame):
        def __init__(self, parent, controller: AdvancedQuizApp):
            super().__init__(parent)
            self.controller = controller
            self.build()

        def build(self):
            header = ttk.Label(self, text='Home', style='Header.TLabel')
            header.pack(pady=8)

            self.welcome_lbl = ttk.Label(self, text='')
            self.welcome_lbl.pack(pady=4)

            btn_fr = ttk.Frame(self)
            btn_fr.pack(pady=8)
            ttk.Button(btn_fr, text='Start Quiz ', command=self.start).grid(row=0, column=0, padx=6)
            ttk.Button(btn_fr, text='Leaderboard', command=lambda: self.controller.show_frame('LeaderboardFrame')).grid(
                row=0, column=1, padx=6)
            ttk.Button(btn_fr, text='Logout', command=self.controller.logout).grid(row=0, column=2, padx=6)

            # animated mascot canvas
            self.canvas = tk.Canvas(self, width=780, height=300, bg='#f0f0f0', highlightthickness=0)
            self.canvas.pack(pady=8)
            # draw sun-like mascot
            self.mascot = self.canvas.create_oval(30, 30, 110, 110, fill='#ffcc33', outline='')
            self.eye1 = self.canvas.create_oval(55, 55, 65, 65, fill='black')
            self.eye2 = self.canvas.create_oval(75, 55, 85, 65, fill='black')
            self.smile = self.canvas.create_arc(50, 70, 90, 110, start=190, extent=160, style='arc', width=3)
            self._dx = 3
            self.animate()

        def on_show(self):
            self.welcome_lbl.config(text=f'Hello, {self.controller.username or "Guest"}!')

        def start(self):
            self.controller.start_quiz()

        def animate(self):
            # simple bobbing animation
            coords = self.canvas.coords(self.mascot)
            if coords:
                x0, y0, x1, y1 = coords
                if x1 >= 780 or x0 <= 0:
                    self._dx = -self._dx
                self.canvas.move(self.mascot, self._dx, 0)
                self.canvas.move(self.eye1, self._dx, 0)
                self.canvas.move(self.eye2, self._dx, 0)
                self.canvas.move(self.smile, self._dx, 0)
            self.after(40, self.animate)


    class QuizFrame(ttk.Frame):
        def __init__(self, parent, controller: AdvancedQuizApp):
            super().__init__(parent)
            self.controller = controller
            self.build()

        def build(self):
            header_fr = ttk.Frame(self)
            header_fr.pack(fill='x', pady=6)
            self.q_index_lbl = ttk.Label(header_fr, text='Q1', font=('Helvetica', 12, 'bold'))
            self.q_index_lbl.pack(side='left', padx=8)
            self.timer_lbl = ttk.Label(header_fr, text='Time: --')
            self.timer_lbl.pack(side='right', padx=8)

            self.canvas_main = tk.Canvas(self, width=860, height=460)
            self.canvas_main.pack(pady=6)

            self.q_frame = ttk.Frame(self.canvas_main, width=820, height=420)
            self.q_frame.pack_propagate(False)
            self.canvas_main.create_window(430, 230, window=self.q_frame)

            self.question_lbl = ttk.Label(self.q_frame, text='', wraplength=760, font=('Helvetica', 14))
            self.question_lbl.pack(pady=8)

            self.choice_var = tk.IntVar(value=-1)
            self.choice_buttons = []
            for i in range(4):
                b = ttk.Radiobutton(self.q_frame, text='', variable=self.choice_var, value=i)
                b.pack(anchor='w', padx=20, pady=6)
                self.choice_buttons.append(b)

            btn_fr = ttk.Frame(self.q_frame)
            btn_fr.pack(pady=8)
            self.next_btn = ttk.Button(btn_fr, text='Next', command=self.next_question)
            self.next_btn.grid(row=0, column=0, padx=6)
            self.quit_btn = ttk.Button(btn_fr, text='Quit', command=self.confirm_quit)
            self.quit_btn.grid(row=0, column=1, padx=6)

            self.progress = ttk.Progressbar(self.q_frame, orient='horizontal', length=700, mode='determinate')
            self.progress.pack(pady=6)

        def on_show(self):
            # prepare first question
            self.controller.current_q = 0
            self.controller.score = 0
            self.show_question(animate=False)

        def show_question(self, animate=True):
            idx = self.controller.current_q
            if idx >= len(QUESTIONS):
                self.controller.end_quiz()
                return
            q = QUESTIONS[idx]
            self.choice_var.set(-1)
            self.question_lbl.config(text=f'Q{idx + 1}. {q["q"]}')
            for i, ch in enumerate(q['choices']):
                self.choice_buttons[i].config(text=f'{i + 1}. {ch}')
            self.q_index_lbl.config(text=f'Q{idx + 1} / {len(QUESTIONS)}')
            self.update_progress()
            # timer start
            self.controller.question_start_time = time.time()
            self.controller.remaining_time = QUESTION_TIMER_SECONDS
            self.update_timer()
            if animate:
                self.slide_in()

        def update_progress(self):
            total = len(QUESTIONS)
            val = int((self.controller.current_q / total) * 100)
            self.progress['value'] = val

        def update_timer(self):
            # update timer label every second
            rem = int(self.controller.remaining_time)
            self.timer_lbl.config(text=f'Time: {rem}s')
            if rem <= 0:
                # time's up for this question
                self.time_up()
                return
            self.controller.remaining_time -= 1
            self.controller.timer_job = self.after(1000, self.update_timer)

        def time_up(self):
            messagebox.showinfo('Time up', "Time's up for this question — moving on.")
            self.record_answer(None)
            self.advance()

        def record_answer(self, choice_index: int):
            idx = self.controller.current_q
            if idx < len(QUESTIONS):
                correct = QUESTIONS[idx]['answer']
                if choice_index is not None and choice_index == correct:
                    self.controller.score += 1

        def next_question(self):
            # cancel timer tick
            if self.controller.timer_job:
                self.after_cancel(self.controller.timer_job)
                self.controller.timer_job = None
            sel = self.choice_var.get()
            if sel == -1:
                if not messagebox.askyesno('No answer', 'No option selected. Do you want to skip?'):
                    # restart timer
                    self.controller.remaining_time = max(1, self.controller.remaining_time)
                    self.update_timer()
                    return
                else:
                    sel = None
            self.record_answer(sel)
            self.advance()

        def advance(self):
            self.controller.current_q += 1
            self.show_question()

        def confirm_quit(self):
            if messagebox.askyesno('Quit', 'Quit quiz and submit your score?'):
                # cancel timer
                if self.controller.timer_job:
                    self.after_cancel(self.controller.timer_job)
                    self.controller.timer_job = None
                self.controller.end_quiz()

        def slide_in(self):
            # small slide animation for q_frame inside canvas_main
            # move the canvas window left to right
            for i in range(15):
                self.canvas_main.move(self.q_frame, -8, 0)
                self.update()
            for i in range(15):
                self.canvas_main.move(self.q_frame, 8, 0)
                self.update()


    class ResultFrame(ttk.Frame):
        def __init__(self, parent, controller: AdvancedQuizApp):
            super().__init__(parent)
            self.controller = controller
            self.build()

        def build(self):
            ttk.Label(self, text='Results', style='Header.TLabel').pack(pady=8)
            self.lbl = ttk.Label(self, text='', font=('Helvetica', 14))
            self.lbl.pack(pady=6)

            self.canvas = tk.Canvas(self, width=320, height=320)
            self.canvas.pack(pady=8)

            btn_fr = ttk.Frame(self)
            btn_fr.pack(pady=6)
            ttk.Button(btn_fr, text='Back to Home', command=lambda: self.controller.show_frame('HomeFrame')).grid(row=0,
                                                                                                                  column=0,
                                                                                                                  padx=6)
            ttk.Button(btn_fr, text='Leaderboard', command=lambda: self.controller.show_frame('LeaderboardFrame')).grid(
                row=0, column=1, padx=6)

        def on_show(self):
            s = self.controller.score
            total = len(QUESTIONS)
            self.lbl.config(text=f'{self.controller.username or "Guest"}, you scored {s} out of {total}')
            self.animate_circle(int((s / total) * 100))

        def animate_circle(self, pct):
            self.canvas.delete('all')
            x0, y0, x1, y1 = 10, 10, 310, 310
            arc = self.canvas.create_arc(x0, y0, x1, y1, start=90, extent=0, width=20, style='arc')
            text = self.canvas.create_text(160, 160, text='0%', font=('Helvetica', 20, 'bold'))

            def step(i=0):
                if i <= pct:
                    extent = -3.6 * i
                    self.canvas.itemconfigure(arc, extent=extent)
                    self.canvas.itemconfigure(text, text=f'{i}%')
                    self.after(15, lambda: step(i + 1))

            step()


    class LeaderboardFrame(ttk.Frame):
        def __init__(self, parent, controller: AdvancedQuizApp):
            super().__init__(parent)
            self.controller = controller
            self.build()

        def build(self):
            ttk.Label(self, text='Leaderboard', style='Header.TLabel').pack(pady=8)
            self.tree = ttk.Treeview(self, columns=('user', 'score', 'total', 'duration', 'ts'), show='headings',
                                     height=10)
            self.tree.heading('user', text='User')
            self.tree.heading('score', text='Score')
            self.tree.heading('total', text='Total')
            self.tree.heading('duration', text='Duration(s)')
            self.tree.heading('ts', text='When')
            self.tree.pack(pady=6)
            btn_fr = ttk.Frame(self)
            btn_fr.pack(pady=6)
            ttk.Button(btn_fr, text='Refresh', command=self.load).grid(row=0, column=0, padx=6)
            ttk.Button(btn_fr, text='Back', command=lambda: self.controller.show_frame('HomeFrame')).grid(row=0,
                                                                                                          column=1,
                                                                                                          padx=6)

        def on_show(self):
            self.load()

        def load(self):
            for i in self.tree.get_children():
                self.tree.delete(i)
            rows = top_scores(20)
            for r in rows:
                user, score, total, duration, ts = r
                ts_fmt = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S').strftime('%b %d %H:%M') if isinstance(ts,
                                                                                                          str) else str(
                    ts)
                self.tree.insert('', 'end', values=(user, score, total, f'{duration:.1f}', ts_fmt))


    # -------------------- Main --------------------

    def main():
        init_db()
        app = AdvancedQuizApp()
        app.mainloop()


    if __name__ == '__main__':
        main()
