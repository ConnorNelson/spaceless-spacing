# Spaceless Spacing

This challenge is based off of [Timeless Timing Attacks: Exploiting Concurrency to Leak Secrets over Remote Connections](https://www.usenix.org/system/files/sec20-van_goethem.pdf).

The exploit is also based off of the repo associated with this paper: [DistriNet/timeless-timing-attacks](https://github.com/DistriNet/timeless-timing-attacks).

# Abstract
To perform successful remote timing attacks, an adversary typically collects a series of network timing measurements and subsequently performs statistical analysis to reveal a difference in execution time.
The number of measurements that must be obtained largely depends on the amount of jitter thatthe requests and responses are subjected to.
In remote timing attacks, a significant source of jitter is the network path between the adversary and the targeted server, making it practically infeasible to successfully exploit timing side-channels that exhibit only a small difference in execution time.

In this paper, we introduce a conceptually novel type of timing attack that leverages the coalescing of packets by network protocols and concurrent handling of requests by applications.
These concurrency-based timing attacks infer a relative timing difference by analyzing the order in which responses are returned, and thus do not rely on any absolute timing information.
We show how these attacks result in a 100-fold improvement over typical timing attacks performed over the Internet, and can accurately detect timing differences as small as 100ns, similar to attacks launched on a local system.
We describe how these timing attacks can be successfully deployed against HTTP/2 webservers, Tor onion services, and EAP-pwd, a popular Wi-Fi authentication method.

# Build and Running

## Challenge

```sh
docker build -t spaceless-spacing .
docker run -it --rm -p 4242:80 -e SECRET='flag{test}' spaceless-spacing
```

The enviornment variable `SECRET` can be changed to whatever, so long as it does not contain spaces.

Environment variables `NGINX_WORKER_PROCESSES`, `UWSGI_CHEAPER`, and `UWSGI_PROCESSES` should theoretically be able to scale the challenge up, but these have not been extensively tested.

## Exploit

```sh
docker build -t spaceless-spacing-exploit -f Dockerfile.exploit .
docker run -it --rm --network=host -e TARGET='http://localhost:4242' spaceless-spacing-exploit
```

The environment variable `TARGET` controls what endpoint to launch the exploit against.

The exploit assumes that the character set of the SECRET is `abcdefghijklmnopqrstuvwxyz{}`.
This can be altered by modifying `SECRET_CHARSET` inside [exploit/exploit.py](exploit/exploit.py).

The exploit also assumes a character outside of the character set of the SECRET is `*`.
This can be altered by modifying `COMPARISON_CHAR` inside [exploit/exploit.py](exploit/exploit.py).

The exploit has tuning parameters `TIMING_ITERATIONS = 1` and `NUM_REQUEST_PAIRS = 10` inside [exploit/exploit.py](exploit/exploit.py).
These tuning parameters control how many times to attempt to test a particular character guess for the secret.
The current values have worked for me, but you may wish to increase them if the exploit isn't working.

The flag `--network=host` is necessary if the challenge is running locally.
