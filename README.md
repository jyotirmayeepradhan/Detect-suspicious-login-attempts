# Python Login Activity Analyzer

## Description
This program reads a login log file and analyzes user activity to detect suspicious behavior.  
It tracks:
- Total login attempts  
- Failed attempts  
- IP addresses used by each user  

It flags users who:
- Log in during off-hours (12 AM – 5 AM)  
- Log in from multiple IPs  
- Perform more than 5 logins within 5 minutes  

All login times are stored and compared to identify rapid logins.  
Finally, the code generates a consolidated report listing total attempts, failed attempts, suspicious activities, and a final list of users flagged for investigation.

## How to Run
Make sure you have Python installed. Then, run the program using:

```bash
python main.py

