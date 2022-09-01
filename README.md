# Telegram passcode bypass

Bypass Telegram Desktop "Local passcode" lock widget.
Works for Telegram for Windows version 4.1.1 both x64 and x86.
Telegram should be unlocked at least once while the process is running, otherwise Telegram's process will crash after injection.

![](https://raw.githubusercontent.com/ardabada/telegram-passcode-bypass/main/images/demo.gif)

## Build

```
dotnet build
```

## Usage
```
cd injector
dotnet run [pid] [mode]
```
Once build you can launch `injector.exe` passing `pid` and `mode` as arguments. Specify telegram's process id as `pid` and `mode` one of the values 0, 1 or 2, that represents:
- `0` - window will be unlocked when valid passcode is introduced
- `1` - window will be unlocked when only invalid passcode is introduced
- `2` - window will be unlocked when any non-empty value is introduced

If no `pid` and/or `mode` are specified, the default values are:
- `pid` - active process with name `telegram`
- `mode` - `2`

## Hook
|Original|Allow invalid only|Allow all|
|---|---|---|
|![](https://raw.githubusercontent.com/ardabada/telegram-passcode-bypass/main/images/original.jpg)|![](https://raw.githubusercontent.com/ardabada/telegram-passcode-bypass/main/images/invalid_only.jpg)|![](https://raw.githubusercontent.com/ardabada/telegram-passcode-bypass/main/images/all.jpg)|
