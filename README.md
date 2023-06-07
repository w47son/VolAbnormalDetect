# VolAbnormalDetect

![volatility-logo](https://github.com/w47son/VolAbnormalDetect/assets/54062322/21c72bbc-4b13-483d-a07d-0a0c01f66629)


Searches for abnormal processes and prints out the source problem

## Setup

Clone the repo:
```
$ git clone https://github.com/w47son/VolAbnormalDetect.git && cd VolAbnormalDetect
```

Extract json from volatility pslist:
```
$ vol.py -f ./<memory.mem> --profile=<profile> pslist --output=json --output-file=pslist.json
```
![volatility-outputJson](https://github.com/w47son/VolAbnormalDetect/assets/54062322/17558a88-10d1-4d0b-9ca4-c95e12a1c9b8)

## Usage

```
$ python VolAbnormalDetect.py pslist.json
```

![lsass-detection](https://github.com/w47son/VolAbnormalDetect/assets/54062322/16e483fb-666b-4e78-aa92-1b085cd399df)
