
# Suricata Bench

Suricata Bench is a small Docker-based web app for testing Suricata rules against PCAP files.

It is meant to make rule testing easier for beginners:

- upload a PCAP in a browser
- test it against the common free Suricata rules
- or turn those off and test only your own custom rule
- paste a rule directly into the UI
- see what alerted
- see the exact rule text that matched
- review basic diagnostics if something fails to parse

The web UI runs on port **7007**.

---

# What this project is for

Suricata Bench is useful when you want to answer questions like:

- "Will this PCAP fire any common free Suricata rules?"
- "Does my custom rule parse correctly?"
- "Did my rule actually fire, or did something else alert?"
- "What exact rule matched this traffic?"

This is especially helpful when you are writing or testing rules for:

- phishing delivery
- suspicious payload downloads
- malware staging
- odd HTTP/TLS/DNS behavior
- synthetic or hand-built PCAPs

---

# What this project is not

Suricata Bench is **not**:

- a live IDS/IPS deployment
- a sensor for monitoring real network traffic continuously
- a full Suricata management platform
- a replacement for a production Suricata installation

This project is for **offline PCAP replay and rule testing**.

---

# Features

- Web UI on **port 7007**
- Upload `.pcap` and `.pcapng` files
- Toggle the common free Suricata ruleset on or off
- Paste a custom Suricata rule directly into the UI
- Run a PCAP against:
  - the free rules only
  - your custom rule only
  - both together
- View:
  - alerts
  - source and destination IP/port
  - SID
  - matched rule text
  - diagnostics and parse errors
- Theme presets for the UI
- Manual color editing for the theme

---

# Project layout

```
suricata-bench/
├── app/
│   ├── requirements.txt
│   ├── server.py
│   ├── static/
│   └── templates/
│       └── index.html
├── data/
│   ├── output/
│   ├── rules/
│   └── uploads/
├── docker-compose.yml
├── Dockerfile
├── entrypoint.sh
└── README.md
```

---

# Requirements

You need:

* Docker
* Docker Compose

On many systems, Docker Compose is available as:

```
docker compose
```

If that command works, you are fine.

---

# Beginner installation steps

## 1. Put the project somewhere on your system

Example:

```
/home/youruser/suricata-bench
```

## 2. Open a terminal in the project directory

Example:

```
cd /home/youruser/suricata-bench
```

## 3. Build and start the container

```
docker compose up --build
```

The first build may take a little while because Docker has to:

* download the base image
* install Suricata
* install Python packages
* set up the app

## 4. Open the web UI

In your browser, go to:

```
http://localhost:7007
```

If you are running this on another machine or VM, replace `localhost` with that system's IP address.

Example:

```
http://192.168.1.50:7007
```

---

# How to stop the app

If it is running in the foreground, press:

```
Ctrl+C
```

To stop and remove the running container in the background:

```
docker compose down
```

---

# How to start it again later

From the project directory:

```
docker compose up
```

If you changed code or configuration and want Docker to rebuild:

```
docker compose up --build
```

---

# First-use workflow

1. Start the container.
2. Open the UI on port 7007.
3. Choose a PCAP file.
4. Decide whether to leave the free ruleset enabled.
5. Paste a custom rule if you want to test one.
6. Click **Run PCAP**.
7. Review alerts and matched rules.
8. Open **Diagnostics** if something did not work as expected.

---

# Using the free ruleset

The checkbox:

```
Include free ruleset (ET Open / common free rules)
```

controls whether the default free rules are included in the run.

## When enabled

The PCAP is tested against:

* the saved free rules
* plus your pasted custom rule, if you provided one

## When disabled

The PCAP is tested only against:

* your pasted custom rule

This is very useful when you want to isolate your own rule and make sure a different ruleset is not producing the alert.

---

# Using a custom rule

Paste your Suricata rule into the **Custom rule draft box**.

Example:

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"LOCAL suspicious URI payload extension"; flow:to_server,established; http.uri; content:".wsf"; nocase; classtype:trojan-activity; sid:9000100; rev:1;)
```

Then click **Run PCAP**.

If the rule parses correctly and matches traffic, you should see:

* an alert card on the right
* the SID
* the alert message
* the exact matched rule text

---

# Recommended beginner testing method

If you are writing a new rule, start simple.

## Good approach

1. Start with a very small rule that uses `content`
2. Confirm it parses
3. Confirm it alerts
4. Then add more logic such as:

   * `http.host`
   * `http.uri`
   * `flow`
   * `pcre`
   * references
   * more conditions

## Why this matters

If you write a large rule immediately and it fails, it is harder to tell whether the problem is:

* rule syntax
* a bad PCRE
* the wrong buffer
* the PCAP contents
* or logic that is too strict

---

# Understanding the results

## Alerts and matched rules

The right-side panel shows each alert that fired.

For each alert, the UI shows:

* alert name
* timestamp
* source IP and port
* destination IP and port
* SID
* category
* severity
* matched rule text

This helps you confirm whether:

* your own rule fired
* or some other rule fired

## Runner output

The runner output gives a short summary such as:

* how many alerts fired
* how many rules were enabled
* whether diagnostics found any problems

## Diagnostics

Open the **Diagnostics** section if something looks wrong.

This is especially useful for:

* signature parse errors
* invalid PCRE syntax
* undefined Suricata variables
* other Suricata stderr messages

---

# How to tell whether your rule actually fired

If your rule truly fired, you should usually see:

* your message text
* your SID
* your exact rule text in the matched rule panel

If instead you see things like:

* `SID 0`
* `Rule text not found in active ruleset`

then your custom rule may not have been the thing that fired.

That usually means either:

* a built-in engine alert fired
* or your custom rule failed to load and something else alerted

In that case, check **Diagnostics**.

---

# HOME_NET and EXTERNAL_NET behavior

This project is set up for a simple lab-style model.

`HOME_NET` is treated as RFC1918 space:

* `10.0.0.0/8`
* `172.16.0.0/12`
* `192.168.0.0/16`

`EXTERNAL_NET` is treated as:

```
!$HOME_NET
```

That works well for synthetic or lab-built PCAPs where internal traffic uses private addressing and public or test-public addresses are treated as external.

---

# Supported traffic and rule style

Suricata Bench works best for PCAP testing involving things like:

* HTTP
* TLS
* DNS

It is especially convenient for rule writing around:

* `http.host`
* `http.uri`
* `content`
* `pcre`
* flow direction
* delivery or staging patterns

---

# Theme presets

The UI includes a compact theme preset area.

You can:

* preview a preset
* save the current theme
* open manual colors if you want to customize each color directly

The custom rule box also disables browser spellcheck behavior so rules are not covered in red zigzag underlines.

---

# Persisted data

The `./data` directory is mounted into the container and stores:

* uploaded temp files
* saved ET Open rules
* last custom rules text
* run outputs
* saved palette settings

---

# Common troubleshooting

## The page does not open

Make sure the container is running:

```
docker compose up
```

Then open:

```
http://localhost:7007
```

If you are on another machine, use that machine's IP instead of `localhost`.

## Docker says the port is already in use

Something else is already using port 7007.

You can either:

* stop the other program
* or change the port mapping in `docker-compose.yml`

Example:

```
ports:
  - "7010:7007"
```

Then open:

```
http://localhost:7010
```

## My rule does not fire

Check these things in order:

1. Does the rule parse with zero signature parse errors?
2. Does the PCAP actually contain the traffic you expect?
3. Are you matching the right buffer, such as `http.host` or `http.uri`?
4. Is your logic too strict?
5. Are you testing with the free rules disabled so only your custom rule is in play?

## I get parse errors

This usually means a syntax problem in the rule.

Common causes:

* malformed `pcre`
* missing semicolon
* bad quoting
* invalid rule option order
* using the wrong sticky buffer syntax

Start with a smaller rule, make sure it parses, then add complexity.

## I expected my custom alert, but I got something else

That often means:

* your custom rule did not load
* a built-in or different rule alerted instead

Check the alert SID and matched rule text, then open Diagnostics.

## The free rules seem noisy

That is normal for broad community rulesets.

To test only your own rule:

* uncheck the free ruleset checkbox
* paste only your custom rule
* rerun the PCAP

---

# Suggested beginner usage examples

## Example 1: test only a custom rule

1. Open the UI
2. Choose a PCAP
3. Uncheck the free ruleset box
4. Paste your custom rule
5. Click **Run PCAP**
6. Confirm that your SID and matched rule appear

## Example 2: see whether community rules alert on a PCAP

1. Open the UI
2. Choose a PCAP
3. Leave the free ruleset enabled
4. Leave the custom rule box empty
5. Click **Run PCAP**
6. Review what fired

## Example 3: compare custom rule vs full ruleset

1. Run with only your custom rule
2. Note the results
3. Enable the free ruleset
4. Run again
5. Compare what changed

---

# Important limitations

* This is for offline PCAP replay, not live inline IPS.
* Some rules depend on variables or datasets not included in a minimal test harness.
* Rules that rely on external files, reputation data, or special config may need extra wiring.
* The default config here is intentionally lightweight so you can iterate quickly.

---

# Good future upgrades

* rule file upload in addition to pasted text
* syntax linting before run
* show grouped results by SID
* side-by-side compare: ET Open only vs custom only vs both
* download button for EVE JSON
* saved test history in SQLite
* selected ruleset families toggle instead of all-or-nothing

---

# License and use

Use this project for testing, learning, and rule development in environments where you are authorized to analyze the traffic in the PCAPs you provide.



