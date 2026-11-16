# Setup for Isaac

You don't write or change any code. You set up your Mac once, then clone and run.

## Part 1: do now (about 45 minutes)

This doesn't depend on the code being finished.

1. **Install UTM** from mac.getutm.app (free).
2. **Download Ubuntu Server 24.04 LTS for ARM64** from ubuntu.com. It must be the **ARM64** version.
3. **Create the VM in UTM:** Virtualize → Linux → choose the ISO.
   - Memory **4 GB**, CPUs **2–4**, disk **20 GB**
   - Network: **Shared Network** (the default)
   - During the Ubuntu install, tick **Install OpenSSH server**
4. **Install Ollama** from ollama.com, then in the Mac's Terminal:
   ```
   ollama pull qwen3:4b
   launchctl setenv OLLAMA_HOST "0.0.0.0"
   ```
   Quit and reopen Ollama so the VM can reach it.
5. **Inside the VM** (UTM window, or `ssh <user>@<VM address>` from the Mac's Terminal):
   ```
   sudo apt update && sudo apt install -y git gh
   gh auth login          # only needed if the repo is private; choose HTTPS
   ```
6. **Accept the GitHub collaborator invite** from Sergio.

Free disk space needed on the Mac: about 30 GB.

## Part 2: when Sergio says it's ready (about 15 minutes)

Inside the VM:

```
git clone [REPO URL] cybersec
cd cybersec
sudo ./scripts/install.sh
nano .env                 # set AI_MODE=ollama; check OLLAMA_URL
sudo ./scripts/start.sh
```

Find the VM's address with `ip -4 addr` and open `http://<VM address>:8000` in your Mac's browser.

## Getting updates

```
cd cybersec
git pull
sudo ./scripts/install.sh   # safe to rerun; only needed if Sergio says dependencies changed
sudo ./scripts/start.sh
```

## If something goes wrong

Send Sergio the exact error text, or the output of:
```
sudo ./scripts/start.sh 2>&1 | tail -50
```

## Afterward

To stop other devices on your network from reaching Ollama:
```
launchctl unsetenv OLLAMA_HOST
```
then quit and reopen Ollama.
