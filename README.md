# Fox dissector

A Wireshark dissector for the Niagara FOX protocol written in LUA.  
Fox is a text-based protocol developed by [Tridium](https://www.tridium.com/us/en) and used by Niagara devices to communicate.

## Usage

To launch Wireshark with the Fox dissector

```
cd foxdissector
wireshark -X lua_script:fox.lua [your.pcap]
```

Alternatively it can be directly installed in Wireshark by copying the `fox.lua` file under the Wireshark plugins folder. More information can be found  [here](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html#wsluarm_intro) and [here](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html).
