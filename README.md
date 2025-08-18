# Enochecker CLI [![PyPI version](https://badge.fury.io/py/enochecker-cli.svg)](https://pypi.org/project/enochecker-cli) [![Build Status](https://github.com/enowars/enochecker_cli/actions/workflows/pythonapp.yml/badge.svg?branch=main)](https://github.com/enowars/enochecker_cli/actions/workflows/pythonapp.yml) ![Lines of code](https://tokei.rs/b1/github/enowars/enochecker_cli)


## Usage

```
usage: enochecker_cli [-h] [-a CHECKER_ADDRESS] [-p {1..65535}]
                      [-A SERVICE_ADDRESS] [--flag-regex FLAG_REGEX]
                      [--timeout TIMEOUT]
                      {raw,run,sim} ...

Your friendly checker script

options:
  -h, --help            show this help message and exit
  -a CHECKER_ADDRESS, --checker-address CHECKER_ADDRESS
                        The address on which checker is listening
  -p {1..65535}, --checker-port {1..65535}
                        The port on which the checker is listening
  -A SERVICE_ADDRESS, --service-address SERVICE_ADDRESS
                        The ip or address of the remote team to check
  --flag-regex FLAG_REGEX
  --timeout TIMEOUT     Number of seconds to wait until a checker tasks
                        complete

Commands:
  {raw,run,sim}
    raw                 Build and dispatch a single raw checker task
    run                 Run (multiple) checker task chains
    sim                 Simulate checker load
```

```
usage: enochecker_cli raw [-h] [--task-id TASK_ID] [--team-id TEAM_ID]
                          [--team-name TEAM_NAME]
                          [--current-round-id CURRENT_ROUND_ID]
                          [--related-round-id RELATED_ROUND_ID] [--flag FLAG]
                          [--variant-id VARIANT_ID]
                          [--round-length ROUND_LENGTH]
                          [--task-chain-id TASK_CHAIN_ID]
                          [--attack-info ATTACK_INFO]
                          {putflag,getflag,putnoise,getnoise,havoc,exploit}

positional arguments:
  {putflag,getflag,putnoise,getnoise,havoc,exploit}
                        One of: putflag, getflag, putnoise, getnoise, havoc,
                        exploit

options:
  -h, --help            show this help message and exit
  --task-id TASK_ID     An unique id for this task.
  --team-id TEAM_ID     The Team_id belonging to the specified Team
  --team-name TEAM_NAME
                        The name of the target team to check
  --current-round-id CURRENT_ROUND_ID
                        The round we are in right now
  --related-round-id RELATED_ROUND_ID
                        The round in which the flag or noise was stored when
                        method is getflag/getnoise. Equal to current_round_id
                        otherwise.
  --flag FLAG           The flag for putflag/getflag or the flag to find in
                        exploit mode
  --variant-id VARIANT_ID
                        The variantId for the method being called
  --round-length ROUND_LENGTH
                        The round length in milliseconds (default 300 000)
  --task-chain-id TASK_CHAIN_ID
                        A unique Id which must be identical for all related
                        putflag/getflag calls and putnoise/getnoise calls
  --attack-info ATTACK_INFO
                        The attack info returned by the corresponding putflag,
                        used only when running the exploit method
```

```
usage: enochecker_cli run [-h] [-m MULTIPLY] [--loop] targets [targets ...]

positional arguments:
  targets               One of: putflag, putflag-N, getflag, getflag-N,
                        putnoise, putnoise-N, getnoise, getnoise-N, havoc,
                        havoc-N, exploit, exploit-N, all

options:
  -h, --help            show this help message and exit
  -m MULTIPLY, --multiply MULTIPLY
                        Number of chain copies to run concurrently
  --loop                Run continuously
```

```
usage: enochecker_cli sim [-h] [--exploiters EXPLOITERS] [-m FACTOR]
                          [--rounds ROUNDS] [--statistics PATH]

options:
  -h, --help            show this help message and exit
  --exploiters EXPLOITERS
                        The number of exploiters to simulate
  -m FACTOR, --multiply FACTOR
                        Multiplier for non-exploit traffic
  --rounds ROUNDS       The number of rounds to simulate
  --statistics PATH     Collect statistics into this file
```

## Installation

`pip3 install git+ssh://git@github.com/attacking-lab/enochecker-cli`
