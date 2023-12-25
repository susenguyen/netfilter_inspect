# netfilter_inspect

Utility that tracks netfilter verdicts through the different namespaces

## Output

The output can be grabbed via dmesg and will look something like this

```
Dec 25 11:57:39 leap kernel: ipt_do_table - saddr=a00fe01, daddr=ac100002, proto=6, spt=a1c4, dpt=1f90, retval=1
Dec 25 11:57:39 leap kernel: ipt_do_table - saddr=a00fe01, daddr=ac100002, proto=6, spt=a1c4, dpt=1f90, retval=0
```

- saddr: source IP address in little-endian
- daddr: destination IP address in little-endian
- proto: 6 = TCP and 17 = UDP (only supported protocols for now)
- spt: source TCP/UDP port in little-endian
- dpt: destination TCP/UDP port in little-endian
- retval: netfilter verdict (NF_*)
