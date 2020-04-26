# slack-osquery
osquery extensions for slackware

# slackware_packages

The installed slackware packages.

```
osquery> select * from slackware_packages where name = 'kernel-generic';
+----------------+---------+--------+-------+-----+
| name           | version | arch   | build | tag |
+----------------+---------+--------+-------+-----+
| kernel-generic | 5.4.35  | x86_64 | 1     |     |
+----------------+---------+--------+-------+-----+
```
