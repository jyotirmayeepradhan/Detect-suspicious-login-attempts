from datetime import datetime

SUSPICIOUS_START = 0    
SUSPICIOUS_END = 5      
VELOCITY_COUNT = 5    
VELOCITY_TIME = 300     

total_attempts = {}
failed_attempts = {}
user_ips = {}
suspicious_hour_users = set()
user_times = {}  
velocity_users = set()  
blocked_users = set()

with open(r"C:\Users\RANI-KUNU\logins.txt") as f:
    for line in f:
        time_str, user, ip, status = line.strip().split(",")
        time_obj = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
        time_sec = int(time_obj.timestamp())

        if user not in total_attempts:
            total_attempts[user] = 0
        total_attempts[user] += 1

        if total_attempts[user] > 10:
            blocked_users.add(user)
        if status.upper() == "FAILURE":
            if user not in failed_attempts:
                failed_attempts[user] = 0
            failed_attempts[user] += 1
    
        if user not in user_ips:
            user_ips[user] = []
        if ip not in user_ips[user]:
            user_ips[user].append(ip)
        if SUSPICIOUS_START <= time_obj.hour < SUSPICIOUS_END:
            suspicious_hour_users.add(user)
        if user not in user_times:
            user_times[user] = []
        user_times[user].append(time_sec)

for user in user_times:
    times = sorted(user_times[user])  
    for i in range(len(times) - VELOCITY_COUNT):
        if times[i + VELOCITY_COUNT] - times[i] <= VELOCITY_TIME:
            velocity_users.add(user)
            break

print("==== LOGIN REPORT ====")
print("\nTotal login attempts per user:")
for u in total_attempts:
    print(f"{u}: {total_attempts[u]} attempts")

print("\nFailed attempts per USER:")
for name in failed_attempts:
    print(f"{name}: {failed_attempts[name]} failed attempts")

print("\nExcessive Failed Login Attempts (More Than or equal to 3 Failures):")
for name in failed_attempts:
    if failed_attempts[name] >= 3:
        print(f"⚠️ {name} has {failed_attempts[name]} failed attempts")

print("\nMultiple IP Addresses Accessed from a Single User Account:")
for user in user_ips:
    if len(user_ips[user]) > 1:
        print(f"⚠️ {user} logged in from multiple IPs: {user_ips[user]}")

print("\nLogin attempts During Unusual or Off-Hours\nUsers logged in during suspicious hours (12 AM – 5 AM):")
for user in suspicious_hour_users:
    print(f"⚠️ {user} logged in at suspicious hours")

print("\nHigh-Frequency Failed Login Attempts (More Than 5 Failures Within 5 Minutes):")
for user in velocity_users:
    print(f"🚨 {user} logged in more than {VELOCITY_COUNT} times within 5 minutes")

final_suspicious_users = set()
final_suspicious_users.update(suspicious_hour_users)
final_suspicious_users.update(velocity_users)
for user in user_ips:
    if len(user_ips[user]) > 1:
        final_suspicious_users.add(user)
final_suspicious_users.update(failed_attempts.keys())

print("\n==== FINAL SUSPICIOUS USERS FOR INVESTIGATION ====")

if blocked_users:
    print("\nBlocked Users (Attempted to login more than 10 times):")
    for u in blocked_users:
        print(f"🚫 {u} has been blocked due to excessive login attempts.")

final_suspicious_users -= blocked_users

if final_suspicious_users:
    print("\nUnblocked Users for further investigation:")
    for user in final_suspicious_users:
        print(f"🚨 {user}")
else:
    print("\nNo suspicious users detected.")

print("\n==== END OF REPORT ====")
