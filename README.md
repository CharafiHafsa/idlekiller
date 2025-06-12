# 🧠 idlekiller.sh - Intelligent Idle Process Manager

A smart Bash script designed to **scan**, **analyze**, and **safely kill** idle or resource-heavy processes on a Linux system. Created as part of an Operating Systems mini project to apply real-world process management.

---

## 🔧 Features

- ✅ Idle detection by CPU usage and elapsed time
- 🧠 Whitelisting of critical processes and users
- 🔐 Safety checks to avoid terminating system processes
- 🧪 Dry run and verbose logging support
- 📊 Logging with timestamps and user info
- 🎯 Pattern matching for targeted process control
- 🎮 Interactive selection using `fzf`
- ⚙️ Parallel (threaded) and forked execution modes

---

## 📁 Structure

| File/Folder       | Purpose                                  |
|-------------------|-------------------------------------------|
| `idlekiller.sh`   | Main script                               |
| `config/`         | Default configurations and whitelist      |
| `logs/`           | Generated logs (auto-created)             |
| `test/demo.mp4`   | Video demonstration of script in action   |

---

## 🚀 Usage

```bash
chmod +x idlekiller.sh
./idlekiller.sh -i 10 -c 5 -x  # Scan for idle processes >10mi

Use ./idlekiller.sh -h to see all options.
```
---

## 📽️ Demo
A quick video showing how the script detects and terminates idle processes is available in the test/demo.mp4 file.

---

## 📚 Project Context
This script was created as part of a mini project in Operating Systems during my engineering studies in Cybersecurity and Digital Trust. The goal was to:

Learn how to interact with system processes, build safe automation tools, and understand concurrency, signals, and resource management in Unix-based systems.
