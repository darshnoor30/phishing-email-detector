# Simple Phishing Email Detector

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
    "earn reward"
]

email = input("Enter the email message:\n").lower()

score = 0
detected_words=[]

for word in suspicious_words:
    if word in email:
        score += 1
        detected_words.append(word)
if "http" in email:
    score += 1
if "@gmail.com" not in email:
    score += 1

print("\n--- Result ---")
print(f"Risk Score: {score}")
print("Detected words:", detected_words)

if score >= 3:
    print("🚨 Phishing Email Detected!")
elif score == 2:
    print("⚠️ Suspicious Email!")
else:
    print("✅ Email Looks Safe")