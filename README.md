# Kai

A shellcode loader based on [charlotte](https://github.com/9emin1/charlotte), thank you 9emin1!

![](https://ew.com/thmb/3i8WhApnsVOei_-e60ooTLK28Bg=/1500x0/filters:no_upscale():max_bytes(150000):strip_icc():format(webp)/screen20shot202015-07-2820at202-27-5520pm-3c0681e857aa4b77a7e638f43d65e043.png)

Mainly has the same features as Charlotte, but main difference is that the output DLL does not expose any export functions. Rather, the execution of shellcode occurs in `DllMain` allowing it to be used for DLL sideloading/hijacking.

## Usage
TBD
