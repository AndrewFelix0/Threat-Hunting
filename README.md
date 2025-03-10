<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/AndrewFelix0/Threat-Hunting/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "labuser" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-03-10T01:08:04.5187793Z`. These events began at `2025-03-10T00:45:36.4618546Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "andrew-sentinel"
| where InitiatingProcessAccountName == "labuser"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-03-10T00:45:36.4618546Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![image](https://github.com/user-attachments/assets/999649d5-6f2e-4de2-865c-ffc680c12a23)


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.7.exe". Based on the logs returned, at `2025-03-10T00:47:56.8183305Z`, an employee on the "andrew-sentinel" device ran the file `tor-browser-windows-x86_64-portable-14.0.7.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "andrew-sentinel"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.7.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/70bbed01-0a7d-4fd4-a2a4-a80989c555b0)


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "labuser" actually opened the TOR browser. There was evidence that they did open it at `2025-03-10T00:55:44.9221867Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "andrew-sentinel"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc 
```
![image](https://github.com/user-attachments/assets/3237e3c9-8857-401b-a7df-c7570e1bead8)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the `DeviceNetworkEvents` table for any indication the tor browser was used to establish a connection using well known ports. `2025-03-10T00:48:32.7767024Z`, the user "labuser" on the device "andrew-sentinel" successfully established an outbound connection using `tor.exe`. The connection was made from the Tor Browser directory on the desktop to the remote IP address `103.196.37.111` over port `443` (HTTPS)

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "andrew-sentinel"
| where InitiatingProcessAccountName == "labuser"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc 
```
![image](https://github.com/user-attachments/assets/2aef8186-ec7c-49a7-84b1-3d37798e365b)


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-03-10T00:45:36.4618546Z`
- **Event:** The user "labuser" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.7.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\Labuser\Downloads\tor-browser-windows-x86_64-portable-14.0.7.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-03-10T00:47:56.8183305Z`
- **Event:** The user "labuser" executed the file `tor-browser-windows-x86_64-portable-14.0.7.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.7.exe /S`
- **File Path:** `C:\Users\Labuser\Downloads\tor-browser-windows-x86_64-portable-14.0.7.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-03-10T00:55:44.9221867Z`
- **Event:** User "labuser" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\Labuer\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-03-10T00:48:32.7767024Z`
- **Event:** A network connection to IP `103.196.37.111` on port `443` by user "labuser" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\Labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`


### 5. File Creation - TOR Shopping List

- **Timestamp:** `2025-03-10T01:08:04.5187793Z`
- **Event:** The user "labuser" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\Labuser\Desktop\tor-shopping-list.txt`

---

## Summary

The user "labuser" on the "andrew-sentinel" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `andrew-sentinel` by the user `labuser`. The device was isolated, and the user's direct manager was notified.

---
