import tkinter as tk
from tkinter import messagebox

# Suspicious phishing words
suspicious_words = [
    "urgent",
    "click here",
    "verify account",
    "password",
    "bank",
    "winner",
    "free money",
    "login now",
    "limited time",
    "earn reward",
    "reward"
]

# Function to check email
def check_email():
    email = text_box.get("1.0", tk.END).lower()

    score = 0
    detected_words = []

    for word in suspicious_words:
        if word in email:
            score += 1
            detected_words.append(word)

    if "http" in email:
        score += 1

    if "@gmail.com" not in email:
        score += 1

    result = f"Risk Score: {score}\n"
    result += f"Detected Words: {detected_words}\n\n"

    if score >= 3:
        result += "🚨 Phishing Email Detected!"
    elif score == 2:
        result += "⚠️ Suspicious Email!"
    else:
        result += "✅ Email Looks Safe"

    messagebox.showinfo("Detection Result", result)

# Create window
window = tk.Tk()
window.title("Phishing Email Detector")
window.geometry("500x400")

# Heading
label = tk.Label(window, text="Phishing Email Detector", font=("Arial", 16))
label.pack(pady=10)

# Text box
text_box = tk.Text(window, height=10, width=50)
text_box.pack(pady=10)

# Button
check_button = tk.Button(window, text="Check Email", command=check_email)
check_button.pack(pady=10)

# Run app
window.mainloop()