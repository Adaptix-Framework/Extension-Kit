# PostEx-BOF

This extension allows you to customize the Beacon Object File (BOF) for future use.

![](_img/01.png)



## firewallrule

A BOF tool that can be used to add a new inbound or outbound firewall rule using COM.

```
firewallrule add <port> <rulename> [direction] [-g rulegroup] [-d description]
```



## ScreenshotBOF

An alternative screenshot capability that uses WinAPI and does not perform a fork & run:
- JPEG is used in place of BMP
- Added beacon screenshot callback option
- Removed BMP renderer (it will be missed)
- Supports capturing of minimized windows

The screenshot will be saved in the AdaptixC2 screenshot storage.

```
screenshot_bof [-n note] [-p pid]
```

The **Screenshot** item will be added to the **Access** menu in the Sessions Table and Graph.

![](_img/02.png)



## Credits
* ScreenshotBOF - https://github.com/CodeXTF2/ScreenshotBOF
* OperatorsKit - https://github.com/REDMED-X/OperatorsKit