# Yara-rules
Yara rules for various malware and security related stuff.

*Disclaimer: These are not all inclusive that will catch everything, it will only catch those samples that they are built for.*

Example The Emotet rule released in Jan 2020 (Emotet_2019-12.yara) was based on 5341 samples out of which 771 had a richheader, naturally those samples that didn't have a richheader will not be caught by that rule which is based on richheader signatures.

Files may be updated continously until there is a new file (or new month).

Always validate the results, the rules are only as good as the technology is capable of. Richhashes for example are not perfect, there will be false positives at some point since the entropy they hash is quite small, very much like JA3/JA3S signatures.
