# Enochecker CLI


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
                        address on which checker is listening
  -p {1..65535}, --checker-port {1..65535}
                        port on which the checker is listening
  -A SERVICE_ADDRESS, --service-address SERVICE_ADDRESS
                        address at which service is reachable by checker
  --flag-regex FLAG_REGEX
  --timeout TIMEOUT     number of seconds to wait until a checker task
                        completes (default: 60, sim: 15 like the gameserver)

Commands:
  {raw,run,sim}
    raw                 build and dispatch a single raw checker task
    run                 run checker task chains
    sim                 simulate checker load
```

```
usage: enochecker_cli raw [-h] [--task-id TASK_ID] [--team-id TEAM_ID]
                          [--team-name TEAM_NAME]
                          [--current-round-id CURRENT_ROUND_ID]
                          [--related-round-id RELATED_ROUND_ID] [--flag FLAG]
                          [--variant-id VARIANT_ID]
                          [--round-length ROUND_LENGTH]
                          [--task-chain-id TASK_CHAIN_ID] [--seed SEED]
                          [--attack-info ATTACK_INFO]
                          {putflag,getflag,putnoise,getnoise,havoc,exploit,test}

positional arguments:
  {putflag,getflag,putnoise,getnoise,havoc,exploit,test}
                        one of: putflag, getflag, putnoise, getnoise, havoc,
                        exploit, test

options:
  -h, --help            show this help message and exit
  --task-id TASK_ID     unique id for task
  --team-id TEAM_ID     id of the target team
  --team-name TEAM_NAME
                        name of the target team
  --current-round-id CURRENT_ROUND_ID
                        id of the current round
  --related-round-id RELATED_ROUND_ID
                        id of the round in which database info was stored
  --flag FLAG           flag for putflag/getflag or flag to find in exploit
                        mode
  --variant-id VARIANT_ID
                        variantId for the method being called
  --round-length ROUND_LENGTH
                        round length in milliseconds (default 300 000)
  --task-chain-id TASK_CHAIN_ID
                        unique id which must be identical for all related
                        putflag/getflag calls and putnoise/getnoise calls
  --seed SEED           seed the checker should use for random behaviour
  --attack-info ATTACK_INFO
                        attack info returned by the corresponding putflag,
                        used only when running the exploit method
```

```
usage: enochecker_cli run [-h] [-m MULTIPLY] [--loop] targets [targets ...]

positional arguments:
  targets               one of: putflag, putflag-N, getflag, getflag-N,
                        putnoise, putnoise-N, getnoise, getnoise-N, havoc,
                        havoc-N, exploit, exploit-N, test, test-N, all

options:
  -h, --help            show this help message and exit
  -m MULTIPLY, --multiply MULTIPLY
                        number of chain copies to run concurrently
  --loop                run continuously
```

```
usage: enochecker_cli sim [-h] [-t TEAMS] [--rounds ROUNDS]
                          [--round-time SECONDS] [--check-past-rounds N]
                          [--checker-hold SECONDS] [--concurrency C]
                          [--concurrency-factor F] [--pool-size POOL_SIZE]
                          [--exploiters EXPLOITERS] [--statistics PATH]
                          [-s SEED]

options:
  -h, --help            show this help message and exit
  -t, --teams, -m, --multiply TEAMS
                        number of teams the gameserver checks each round; each
                        runs its own schedule draw (default: 1)
  --rounds ROUNDS       number of rounds to simulate (default: run until
                        interrupted)
  --round-time SECONDS  round length (default: 60)
  --check-past-rounds N
                        rounds after the one it was stored in that a flag
                        keeps being checked with getflag; match the game's
                        flag validity (default: 10)
  --checker-hold SECONDS
                        seconds at the end of each round in which no task runs
                        (default: 5)
  --concurrency C       max concurrent checker requests per team (default:
                        --concurrency-factor times the minimum the round
                        needs)
  --concurrency-factor F
                        headroom over the minimum per-team concurrency when
                        --concurrency is unset (default: 2)
  --pool-size POOL_SIZE
                        number of precomputed schedules each draw picks from
                        (default: 64)
  --exploiters EXPLOITERS
                        additionally run every exploit variant this many times
                        per round; not gameserver traffic (default: 0)
  --statistics PATH     write one CSV row per task into this file
  -s, --seed SEED       seed for task ids and schedules
```

`sim` replays the load atklab/gameserver's eno
runner puts on a checker. Each round, every team gets its own draw from the
gameserver's flat star scheduler (vendored into `enochecker_cli.scheduler`),
built from the same task set the gameserver dispatches: per flag variant a
putflag, its getflag, and one getflag for each of the last
`--check-past-rounds` rounds; per noise variant a putnoise and its getnoise;
per havoc variant a havoc. Tasks run within the first `--round-time` minus
`--checker-hold` seconds. Each getflag/getnoise starts at least `--timeout`
+ 1 seconds after its put, and no team has more than `C` tasks in flight.
The run fails up front with the minimum feasible round length if the task
set does not fit the round. Failed and timed-out tasks are recorded, not
fatal, so `--statistics` shows how the checker degrades under load.

## Installation

`pip install git+https://github.com/attacking-lab/enochecker-cli`
