# Suricata Bench

Suricata Bench is a Docker-based web app for replaying PCAPs through Suricata and quickly testing rule behavior.

It is aimed at practical rule-development work:

- test a PCAP against cached ET Open / common free rules with the option to update the rules to current
- paste a custom rule directly into the UI
- isolate your custom rule from the default ruleset when needed
- run an optional disabled-rule coverage pass for submission prep
- inspect exactly what alerted, including matched rule text
- review parsing and runtime diagnostics without leaving the browser

The web UI runs on **port 7007**.

## What this project is for

Suricata Bench is useful when you want to answer questions like:

- Will this PCAP fire any current ET Open / common free rules?
- Does my custom rule parse correctly?
- Did my custom rule fire, or did something else alert first?
- Is there already dormant or generic coverage in disabled rules?
- What exact rule text matched this traffic?


---

## What this project is not

Suricata Bench is **not**:

- a live IDS/IPS deployment
- a continuous monitoring sensor
- a full Suricata management platform
- a replacement for a production Suricata installation

This project is for **offline PCAP replay and rule testing**.

---

## Features

- Web UI on **port 7007**
- Upload `.pcap` or `.pcapng` files
- Toggle the default ET Open / common free ruleset on or off
- Paste a custom Suricata rule directly into the UI
- Run a PCAP against:
  - the default ruleset only
  - your custom rule only
  - both together
- Optional **Coverage Review Mode** to test disabled `#alert` / `#drop` / `#reject` / `#pass` rules in a separate pass
- Manual **Refresh ET Open rules** action using `suricata-update`
- Ruleset status display showing:
  - whether cached rules are present
  - last refresh time
  - refresh status
  - cached ruleset size
- Alert cards showing:
  - timestamp
  - source and destination IP/port
  - SID
  - message/category/severity
  - exact matched rule text
  - uncommented disabled-rule test form when applicable
- Diagnostics for both:
  - the active/default run
  - the disabled-rule coverage run
- Theme presets plus manual color editing


---

## Current ruleset behavior

Suricata Bench caches ET Open rules locally under `/data/rules/et-open.rules`.

That means:

- the first startup pulls rules if the cached rules file is missing
- later startups reuse the cached rules
- rules are **not** refreshed automatically on every run
- use the **Refresh ET Open rules** button when you want the latest available rules

Refresh metadata is stored in:

- `/data/rules/et-open.meta.json`

This is intentional: it gives you a stable local ruleset by default while still making refresh status visible.

## Lua support

Lua support is now treated as an always-on bench capability.

What that means in practice:

- the generated Suricata config explicitly enables Lua rules
- the bench runtime creates a persistent Lua script directory at `/data/rules/lua`
- any `.lua` files found under that directory are copied into each temporary run directory before Suricata executes
- the UI now includes a collapsed optional Lua script panel for per-run inline scripts

### UI workflow

By default, the Lua editor stays collapsed so the interface does not look busier than necessary.

When needed, you can:

1. expand **Optional Lua support script**
2. check **Use Lua script for this run** or just start typing in the Lua editor
3. optionally expand **Filename options** to override the default `custom.lua`
4. reference that filename from your Suricata rule with `lua:lua/<name>.lua`

If you leave the filename field blank, `custom.lua` is used.

Filename normalization rules:

- `sample` becomes `sample.lua`
- `Sample.LUA` becomes `sample.lua`
- only letters, numbers, `_`, and `-` are allowed in the base name

### Persistent script directory workflow

If you want reusable scripts outside the inline editor, place them under `/data/rules/lua/` and reference them from your rule with a path relative to the rules directory.

Example rule reference:

```suricata
alert http any any -> any any (msg:"LOCAL Lua HTTP test"; flow:established,to_server; lua:lua/http-test.lua; sid:9000001; rev:1;)
```

In that example, the script should exist here inside the container volume:

```text
/data/rules/lua/http-test.lua
```

There is still no separate global on/off Lua toggle. The current design keeps Lua available by default while making the actual script entry area optional and collapsed until needed.

---

## Coverage Review Mode

Coverage Review Mode exists for one specific question:

> Does ET already have active or disabled coverage for this behavior?

When enabled, Suricata Bench performs a second Suricata pass using uncommented disabled rules.

This is useful for:

- checking dormant GPL / ET coverage before writing a new rule
- validating whether a candidate is already covered generically
- reviewing disabled rules during ET Open submission prep

### Important behavior

Coverage Review Mode is **separate** from the normal active/default ruleset run.

That means you get:

- active/default coverage results
- disabled-rule coverage results

instead of one noisy combined run. If you want the noisey combined single run, go ahead it won't break anything.

### Internal suppression of known-unloadable disabled rules

Some disabled rules are not realistically testable in a lightweight bench run because they depend on:

- unsupported app-layer parsers in the current Suricata build
- stale app-layer event names
- demo/example hash-list dependencies

Suricata Bench suppresses those internally during the disabled-rule pass so they do not pollute coverage diagnostics unnecessarily.

This suppression is dynamic for app-layer parser support and checks the running Suricata binary with:

```bash
suricata --list-app-layer-protos
```

So if you later swap to a Suricata build that supports more parsers, those disabled rules can become testable automatically.

---

## Suricata build notes

The container now uses **Ubuntu 22.04** with the **OISF stable PPA** so Suricata Bench can run a newer Suricata build than older distro-default packages.

A practical packaging note:

- the newer Suricata package already provides `suricata-update`
- so the Dockerfile installs `suricata` directly and does **not** install a separate `suricata-update` package

If you want to inspect the app-layer parsers supported by the running container:

```bash
docker compose exec suricata-bench suricata --list-app-layer-protos
```

If you want to inspect rule keyword families:

```bash
docker compose exec suricata-bench suricata --list-keywords=all
```

Important distinction:

- `--list-app-layer-protos` tells you what the current Suricata binary can actually parse at the app layer
- `--list-keywords=all` can show keyword families that do **not** guarantee parser availability

For parser-dependent disabled-rule coverage, `--list-app-layer-protos` is the source of truth.

---

## Project layout

```text
suricata-bench/
├── addons/
├── app/
│   ├── requirements.txt
│   ├── server.py
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

`data/` is bind-mounted into the container and is intentionally used to persist:

- cached ET Open rules
- refresh metadata
- uploaded temp files
- run outputs
- saved UI palette choices

`addons/` is also mounted read-only into the container at `/addons` so example rule packs can carry helper assets such as Lua scripts.

---

## Requirements

You need:

- Docker
- Docker Compose

On many systems, Docker Compose is available as:

```bash
docker compose
```

---

## Quick start

### 1. Clone or place the project somewhere on your system

Example:

```bash
cd /home/youruser
```

```bash
git clone https://github.com/Pb-22/Suricata-Bench.git
```

### 2. Enter the project directory

```bash
cd /home/youruser/Suricata-Bench
```

### 3. Build and start the app

```bash
docker compose up --build
```

Then open:

```text
http://localhost:7007
```

If you are running this on another machine or VM, replace `localhost` with that host’s IP.

Example:

```text
http://192.168.1.50:7007
```

---

## Stop / restart

Stop the foreground app:

```bash
Ctrl+C
```

Stop and remove the running container:

```bash
docker compose down
```

Start it again later:

```bash
docker compose up
```

Rebuild after changing code or container configuration:

```bash
docker compose up --build
```

### Important note

Use:

```bash
docker compose up
```

for the web app service.

If you use `docker compose run`, Docker may show only the internal container IP and you may think the app is on the wrong interface even though the published service is fine.

---

## First-use workflow

1. Start the container.
2. Open the UI on port 7007.
3. Optionally click **Refresh ET Open rules** if you want the newest rules instead of the cached copy.
4. Choose a PCAP file.
5. Decide whether to leave the free/default ruleset enabled.
6. Optionally enable **Coverage review: test disabled #alert rules**.
7. Paste a custom rule if you want to test one.
8. Click **Run PCAP**.
9. Review:
   - active/default alerts
   - disabled-rule coverage alerts
   - diagnostics
   - matched rule text

---

## Using the default ruleset

The checkbox:

```text
Include free ruleset (ET Open / common free rules)
```

controls whether the cached default ruleset is included.

### When enabled

The PCAP is tested against:

- the cached default ruleset
- plus your pasted custom rule, if you provided one

### When disabled

The PCAP is tested only against:

- your pasted custom rule

This is useful when you want to isolate your own rule and make sure a default ruleset is not also producing an alert for the same behavior.

---

## Using a custom rule

Paste your Suricata rule into the **Custom rule draft box**.

Example:

```text
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"LOCAL suspicious URI payload extension"; flow:to_server,established; http.uri; content:".wsf"; nocase; classtype:trojan-activity; sid:9000100; rev:1;)
```

Then click **Run PCAP**.

If the rule parses correctly and matches traffic, you should see:

- an alert card
- the SID
- the alert message
- the exact matched rule text

If there is a problem with the rule, you will see the error In the output.
---

## Recommended rule-testing workflow

If you are writing a new rule, start simple.

### Good approach

1. Run the PCAP against the default ruleset first.
2. If nothing useful fires, test a very small custom rule.
3. Start with a simple proof rule using one sticky buffer or one cheap anchor.
4. Confirm the proof rule matches.
5. Add narrower conditions after you know the base detection works.
6. Use Coverage Review Mode when you want to know whether disabled rules already cover the behavior.

This usually makes debugging much faster than jumping straight into a complex final rule.

---

## Example use cases

### 1. Check whether a detectection idea is already covered with a known PCAP file

- leave the default ruleset enabled
- do not paste a custom rule yet
- run the PCAP
- inspect alerts

### 2. Test only your custom rule

- disable the default ruleset
- paste your rule
- run the PCAP

### 3. Compare active coverage vs disabled coverage

- enable the default ruleset
- enable Coverage Review Mode
- optionally paste a candidate rule
- run the PCAP
- compare the active/default results with the disabled-rule results

### 4. Refresh stale rules before testing

- click **Refresh ET Open rules**
- confirm the updated timestamp in **Ruleset status**
- run the PCAP again

---

