# netfilter_inspect

Utility that tracks netfilter verdicts through the different namespaces

## Output

The output can be grabbed via dmesg and will look something like this

```  
[Sun Jan  7 17:27:34 2024] ipt_do_table(filter) - devin=(null)/0, devout=eth0/2, saddr=a010002, daddr=a010001, proto=6, spt=b986, dpt=1f90, verdict=0
```

- devin: ingress device
- devout: egress device
- saddr: source IP address in little-endian (hex)
- daddr: destination IP address in little-endian (hex)
- proto: 6 = TCP and 17 = UDP (only supported protocols for now)
- spt: source TCP/UDP port in little-endian (hex)
- dpt: destination TCP/UDP port in little-endian (hex)
- retval: netfilter verdict (NF_*)
