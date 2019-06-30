[![Build Status](https://travis-ci.com/clslgrnc/tbrop.svg?branch=master)](https://travis-ci.com/clslgrnc/tbrop)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=clslgrnc_tbrop&metric=alert_status)](https://sonarcloud.io/dashboard?id=clslgrnc_tbrop)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=clslgrnc_tbrop&metric=coverage)](https://sonarcloud.io/dashboard?id=clslgrnc_tbrop)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=clslgrnc_tbrop&metric=code_smells)](https://sonarcloud.io/dashboard?id=clslgrnc_tbrop)

PoC

The Dockerfile can be used as a crude installation instruction.

To build with docker:
```
sudo docker build -t tbrop .
```

To analyse ```/FULL/LOCAL/PATH/FILE```:
```
sudo docker run --rm -it -v /FULL/LOCAL/PATH/FILE:/app/FILE:ro tbrop /app/FILE
```

It should (eventually) bring you to an ipython shell where you can do stuff like:
```python
for g in gdgtCollection.gdgtCollection:
  if g.gadgetMatrix.matrix[X86_REG_RSP,X86_REG_RAX] \
  and g.gadgetMatrix.chainCond[0,X86_REG_RCX]:
    print(hex(g.getAddress()),g)
```

More info [here (in french)](https://www.sstic.org/2018/presentation/T-Brop/) or [there](https://recon.cx/2018/montreal/schedule/events/129.html).

This is still a PoC

It'll get worse before it gets better... hopefully.

