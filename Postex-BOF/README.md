# Process-BOF

This extension allows you to customize the Beacon Object File (BOF) for future use.

![](_img/01.png)

## addfirewallrule

A BOF tool that can be used to add a new inbound or outbound firewall rule using COM.

```
addfirewallrule <direction> <port> "<rulename>" "<rulegroup>" "<description>"
```


## ScreenshotBOF

An alternative screenshot capability that uses WinAPI and does not perform a fork & run:
- JPEG is used in place of BMP
- Added beacon screenshot callback option
- Removed BMP renderer (it will be missed)
- Supports capturing of minimized windows

```
screenshot_bof [-n note] [-p pid]
```

The screenshot will be saved in the AdaptixC2 screenshot storage.

## Credits
* ScreenshotBOF - https://github.com/CodeXTF2/ScreenshotBOF