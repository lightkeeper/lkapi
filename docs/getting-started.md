<!--
  MAINTAINER NOTE: This file is paired with docs/getting-started-artifact.html (the styled,
  browser-facing version). The two are a pair — every content change (steps, examples, IDs,
  troubleshooting rows) must be made in BOTH files so a reader gets the same information
  whichever format they open.
-->
# Getting started with lkapi

A step-by-step guide for pulling your Lightkeeper portfolio data using the LK API repository.

## What this is

`lkapi` is a small Python tool that lets you pull your firm's Lightkeeper portfolio data straight into a table you can filter, sort, chart, save as a CSV, etc. The data is sourced from saved Grid views in the user interface. You reference one of these saved views when making a request, and the data comes back as a "DataFrame" — a table you can inspect and manipulate with a Python library called Pandas. You don't need an extensive programming background; this guide will get you started with finding, installing, and running the LK API tool.

This guide, and the `lkapi` package itself, are Python-specific, but the underlying Lightkeeper Web API isn't tied to any one programming language. It's a standard web API, so it works the same way from Python, R, C#, JavaScript, or anything else that can make an HTTPS request. If your team already works in a different language, see [Prefer a different language?](#prefer-a-different-language) near the end of this guide.

## Before you start

You need two things from Lightkeeper before any of this will work:

1. **A `client_id` and `client_secret`.** These are like a username and password for the API. There's no self-service way to get these. Reach out to your Lightkeeper contact or [Lightkeeper support](https://lightkeeper.com/) and ask for API access.
2. **The web address (URL) of the data grid you want.** You'll copy this from the Lightkeeper UI in Step 4 below. You don't need it yet.

## Step 1: Install Python (only if you don't already have it)

This tool needs Python version 3.10 or newer. **Many computers already have Python, so check what you have before installing anything.**

Open the **Command Prompt** (Windows: search for it in the Start menu) or the **Terminal** (Mac: press Cmd+Space, type "Terminal"), then run:
```
python --version
```
> On Mac, use `python3 --version` instead.

- If it prints `3.10` or higher (for example `Python 3.12.4`), you already have what you need — **skip to Step 2.**
- If it prints an older version, an error like `command not found`, or nothing at all, install Python using the steps below.

### If you need to install it

**Windows:**
1. Go to [python.org/downloads](https://www.python.org/downloads/) and download the latest installer.
2. Run it. On the very first screen, **check the box that says "Add python.exe to PATH"** before clicking Install. This step is easy to miss and causes problems later if skipped.
3. Open the **Command Prompt** (search for it in the Start menu) and type:
   ```
   python --version
   ```
   You should see something like `Python 3.12.4`. If you see an error instead, close and reopen Command Prompt and try again.

> **If `python` or `pip` says "not recognized" (Windows):** this almost always means the "Add python.exe to PATH" box in step 2 was missed. Two fixes:
> - **Quick, no reinstall:** use `py` instead of `python` — it works even without PATH. Try `py --version`, and use `py -m pip install ...` and `py -m jupyter notebook` wherever this guide says `pip` / `jupyter notebook`.
> - **Proper fix:** re-run the installer and tick **"Add python.exe to PATH"** (or, if it opens to a "Modify" screen, choose Modify → Advanced Options → **"Add Python to environment variables"**). Then **close every Command Prompt window and open a new one** — PATH changes only apply to windows opened afterward.

**Mac:**
1. Go to [python.org/downloads](https://www.python.org/downloads/) and download the latest macOS installer.
2. Run it and follow the prompts.
3. Open the **Terminal** app (search for it with Spotlight, Cmd+Space) and type:
   ```
   python3 --version
   ```
   You should see something like `Python 3.12.4`.

> On Mac, use `python3` and `pip3` everywhere this guide says `python`/`pip`.

## Step 2: Install lkapi and Jupyter

In the same Command Prompt / Terminal window, type:
```bash
pip install lkapi jupyter
```

This installs two things:
- **lkapi**: the tool that talks to Lightkeeper.
- **Jupyter Notebook**: a tool you can use to actually run your code (explained below).

### Already use `uv`, conda, or another environment manager?

If you already manage isolated Python environments (with [uv](https://docs.astral.sh/uv/), conda, `venv`, etc.), you don't need the global `pip install` above, and you can even skip Step 1: `lkapi` is a normal package that installs into any environment. Two rules matter:

1. Install **Jupyter into the same environment** as `lkapi`. If they land in different environments, the notebook won't find `lkapi` (the `ModuleNotFoundError` in Step 6).
2. **Launch Jupyter from that same environment.**

With `uv` you don't even have to install Python 3.10+ yourself — uv downloads a compatible version automatically:
```bash
uv init lk-data && cd lk-data
uv add lkapi jupyter      # uv fetches a compatible Python if you don't have one
uv run jupyter notebook   # then pick up at Step 3
```

With conda:
```bash
conda create -n lk python=3.12
conda activate lk
pip install lkapi jupyter
jupyter notebook          # then pick up at Step 3
```

If none of this is familiar, ignore it and use the `pip install` command above — it's the simplest path.

### What is Jupyter Notebook?

Jupyter Notebook is a free, widely-used tool that opens as a page in your web browser. Instead of writing one big program, you write small pieces of Python code in boxes called **cells** and run them one at a time. Each cell's result (a number, a table, a chart) appears right underneath it. It's a bit like a spreadsheet where each formula shows its own answer immediately below, rather than in a separate cell. This makes it a popular way for people without a software engineering background to explore data with Python.

**Jupyter is just one way to run this code, not the only one.** This guide uses it because it's the easiest starting point if you've never run Python before, but `lkapi` is a normal Python package, so anyone on your team who already codes can use whatever tool they're comfortable with instead:
- **A terminal**: save the same code in a plain text file ending in `.py` (e.g. `my_query.py`) and run it with `python my_query.py`. You won't see each step's output automatically like in a notebook, so you'd add a `print(...)` line wherever you want to see a result.
- **An IDE like [VS Code](https://code.visualstudio.com/)**: a full code editor with error-checking, autocomplete, and (via its Python/Jupyter extensions) the ability to run either plain scripts or notebook-style cells directly in the editor. Common among people who write Python regularly.

Everything you need to know for this guide is: cells, running a cell with **Shift+Enter**, and saving your work, covered in Step 3 below. If you want to explore further on your own:
- [Try Jupyter](https://jupyter.org/try): run a notebook in your browser with no installation, to get a feel for it.
- [Jupyter Documentation](https://docs.jupyter.org/en/latest/): the official docs, including a beginner-friendly walkthrough of the interface.

## Step 3: Launch Jupyter and open a new notebook

1. In the same terminal window, type:
   ```bash
   jupyter notebook
   ```
2. A browser tab will open showing a file browser (the address bar will say something like `localhost:8888/tree`).
3. Click the **New** dropdown near the top right, then choose **Python 3 (ipykernel)** from the list.
   > Make sure you pick **Python 3 (ipykernel)**, not **Text File** or **Python File**. Those create a plain `.py` file that just displays your code; there's no way to run it and no output will appear. A notebook file ends in `.ipynb` and its address bar will say `localhost:8888/notebooks/...`, not `localhost:8888/edit/...`.
4. This opens a new notebook with one empty, ready-to-use cell.

## Step 4: Get your grid URL

1. In the Lightkeeper UI, open the grid (data view) you want data from.
2. Click the **API** button.
3. Copy the URL shown there. It will look something like this:
   ```
   https://YOUR-ENVIRONMENT.lightkeeperhq.com/lightstation/api/reports/query/layout/YOUR_LAYOUT_ID/v2?focus=LKP_YOUR_PORTFOLIO__PORT&rollup=ISSUER&bd=20250101&ed=20250131
   ```
   If what you copied looks roughly like that (starts with `https://`, contains `lightkeeperhq.com`, and has a `focus=` and `bd=`/`ed=` in it), you copied the right thing.

## Step 5: Your first request

> **Terminal commands vs. Python code:** commands like `pip install` and `jupyter notebook` are typed straight into your Command Prompt/Terminal window. The code below is different — it's Python, meant to go in a notebook cell as described here, not typed directly into the terminal. If you ever want to run Python code without Jupyter, first type `python` (or `ipython`, if installed) into your terminal to start an interactive session — the prompt changes to `>>>` (or `In [1]:` for ipython) — enter your Python code there, then type `exit()` when you're done.
> **If you use `ipython`:** pasting multi-line code can break because of its auto-indent behavior. If that happens, run `%paste` first, then paste your code again.

Click into the first empty cell of your notebook and paste this, replacing the three placeholder values with your real URL, client ID, and client secret:

```python
import lkapi

frames = lkapi.get_grid_data(
    url="PASTE_YOUR_GRID_URL_HERE",
    username="YOUR_CLIENT_ID",
    password="YOUR_CLIENT_SECRET",
)

frames['rollup']
```

Press **Shift+Enter** to run the cell. After a moment, you should see a table appear below the cell. That's your portfolio data.

The `lkapi.get_grid_data` function returns a dictionary containing a few different tables, depending on what you need. In this example with the get_grid_data() function set to frames, you can access the following data:
- `frames['rollup']`: one row per rollup (e.g. per issuer, per sector), summarized for the whole date range you requested.
- `frames['time']`: one row per time period (e.g. per day), summarized across the portfolio.
- `frames['total']`: the overall totals.
- `frames['portfolio']`: details about the portfolio itself (available dates, last update time).
- `frames['request']`: details about the request you made (useful mainly for troubleshooting).

### A speed tip: `viewby`

Your grid URL can include an optional `viewby=rollup` or `viewby=time` parameter (if it's missing, `time` is used). This controls how much day-by-day detail the server computes, and for a wide date range it makes a real difference:

- **`viewby=time`**: computes the full day-by-day breakdown, so `frames['time']` has one row per period. For a short date range this is fine, but for a multi-year pull it can take a long time and return a very large amount of data.
- **`viewby=rollup`**: skips the day-by-day breakdown. `frames['rollup']` is unaffected, but `frames['time']` will come back with just an overall total instead of one row per date. In exchange, the request can be dramatically faster.

If you only need rollup-level numbers (e.g. by issuer or sector) and not a day-by-day time series, make sure  `&viewby=rollup` is included in the URL you are using for a much faster response. This isn't a bug: an empty-looking `frames['time']` when you've set `viewby=rollup` is expected.

### Date ranges and "date snap" views

Some saved grid views have a **date snap**: a rule like "Year to Date" (YTD) or "Quarter to Date" (QTD) applied automatically, configured when the view was built in the Lightkeeper UI. Whether a view has a date snap changes how the `bd` (begin date) and `ed` (end date) parts of your URL behave:

- **A view saved with a date snap (e.g. "YTD"):** the end date (`ed`, or `end_date` if building a request from components, see Step 7) is respected. Move it to see the same snap "as of" a different day. But the begin date (`bd` / `begin_date`) is *not* respected; it's always recalculated from the snap. For a "YTD" view, that means the begin date is always January 1st of whatever year your end date falls in, no matter what begin date you pass.
- **A view saved with no date snap:** both the begin date and end date fully control the range, exactly as you'd expect. Change either one and the results shift accordingly.

If you set a custom begin date and the results don't seem to reflect it, this is the most likely reason: check whether the grid was saved with a date snap. If you want full control over dates via variables, save your grid views without date snaps. 

## Step 6: Common problems and what they mean

| What you see | What it means | What to do |
|---|---|---|
| `'python' is not recognized...` or `'pip' is not recognized...` (Windows), or `command not found` (Mac) | Python isn't on your PATH, so the terminal can't find it — usually the "Add python.exe to PATH" box was unchecked when Python was installed. | **Quick fix:** use the `py` launcher, which works without PATH — `py -m pip install ...` and `py -m jupyter notebook`. **Proper fix:** re-run the Python installer with "Add python.exe to PATH" ticked (or Modify → Advanced Options → "Add Python to environment variables"), then **close and reopen** Command Prompt. On Mac, use `python3` / `pip3`. |
| `pip : The term 'pip' is not recognized...` (Windows), but `python --version` works fine | Python itself is on PATH, but its `Scripts` folder (where `pip.exe` lives) isn't. | Check `python --version` first to confirm this is the case, then run `python -m pip install ...` instead of `pip install ...` — it uses Python's own module runner and doesn't need `Scripts` on PATH. |
| `ERROR: Could not find a version that satisfies the requirement lkapi` (often alongside `Requires-Python >=3.10`), when running `pip install` | Your Python is older than 3.10, so `pip` refuses to install `lkapi`. | Install Python 3.10 or newer (Step 1), or use an environment manager like `uv` that provides one (see the note in Step 2). Then run `pip install lkapi jupyter` again. |
| `PermissionError: Invalid client credentials provided.` | Your client ID or client secret is wrong. | Double-check what Lightkeeper gave you; watch for extra spaces or a swapped ID/secret. |
| `RuntimeError: ... forwarded to the signin screen` | The URL or credentials point at the wrong Lightkeeper environment. | Re-copy the URL from Step 4, making sure it's from the same environment your credentials belong to. |
| `ModuleNotFoundError: No module named 'lkapi'` | lkapi isn't installed in the Python that Jupyter is actually using. | Close Jupyter, run `pip install lkapi` again from the same terminal window you'll use to launch `jupyter notebook`, then relaunch. |
| `frames['time']` comes back almost empty | Your URL has `viewby=rollup`, which intentionally skips the day-by-day breakdown to make the request much faster (see the speed tip above). | If you need the daily breakdown, change (or add) `viewby=time` to your URL or remove the viewby parameter from the url entirely. Expect it to take longer for wide date ranges. |
| Changing the begin date (`bd` / `begin_date`) has no effect | Your saved view has a date snap (like "YTD"), which always recalculates the begin date automatically (see "Date ranges and 'date snap' views" above). | This is expected for a snapped view; only the end date can move. Ask whoever built the grid whether a non-snapped version exists if you need full control over both dates. |

If you hit something not listed here, reach out to [Lightkeeper support](https://lightkeeper.com/) with the full error message.

## Step 7 (optional): Stored credentials — don't want to paste your secret every time?

Once you're comfortable with the basics, you can store your credentials once instead of pasting them into every notebook:

```python
import lkapi

# a long-lived credential manager which stores to the keyring if available or environment variables otherwise
credential_manager = lkapi.get_credential_manager(url="https://YOUR-ENVIRONMENT.lightkeeperhq.com")
credential_manager.set_secret('YOUR_CLIENT_ID', 'YOUR_CLIENT_SECRET')
```
In a longer term development or production environment, store credentials once in secure credential storage via the [keyring](https://pypi.org/project/keyring/) python module if installed or environment variables, rather than passing them in code. By default, this only remembers your credentials for your current terminal session, so run it again each time you start a new session.
```bash
pip install keyring
```

With credentials stored, you can build requests from simple pieces instead of a full copied URL:

```python
import lkapi

frames = lkapi.get_grid_data(
    grid="YOUR_LAYOUT_ID",
    environment="YOUR-ENVIRONMENT",
    portfolio="LKP_YOUR_PORTFOLIO__PORT",
    rollup="ISSUER",
    begin_date="20250101",
    end_date="20250131",
)
```

**Where do these values come from?** The properties for the get_grid_data function can be found in the API url or in each Grid view by clicking on the Lightkeeper API icon:

```
https://YOUR-ENVIRONMENT.lightkeeperhq.com/lightstation/api/reports/query/layout/YOUR_LAYOUT_ID/v2?focus=LKP_YOUR_PORTFOLIO__PORT&rollup=ISSUER&bd=20250101&ed=20250131
```

| Argument | Where it is in the URL |
|---|---|
| `environment` | the part between `https://` and `.lightkeeperhq.com` |
| `grid` | the segment right after `/layout/` |
| `portfolio` | the `focus=` value |
| `rollup` | the `rollup=` value |
| `begin_date` / `end_date` | the `bd=` / `ed=` values |

Your real portfolio and layout IDs are long, system-generated strings (like the `LKP_YOUR_PORTFOLIO__PORT` portfolio and layout ID shown here), not short friendly names — that's expected; just copy them exactly as they appear in the URL. (`rollup` is the exception: it's a grouping name like `ISSUER` or `SECTOR`.)

> Use the **same** environment here that you stored your credentials under in the `set_secret` step above. If they don't match, `lkapi` won't find the credentials it just saved.

## Prefer a different language?

Everything above is Python because `lkapi` is a Python package, but Lightkeeper's Web API itself works the same way regardless of what programming language you or your team use. Under the hood, `lkapi` is just doing two things that any language can do:

1. **Exchange your `client_id`/`client_secret` for a temporary access token**: a one-time login that's valid for one hour.
2. **Use that token to request your grid data** from the same URL you copied in Step 4.

This is what those two steps look like using [curl](https://curl.se/) (a common command-line tool for making web requests), for illustration:

```bash
# 1) Exchange client credentials for a bearer token (valid for one hour)
curl -s -X POST "https://api.auth.YOUR-ENVIRONMENT.lightkeeperhq.com/oauth2/token" \
  -d grant_type=client_credentials \
  -d client_id="YOUR_CLIENT_ID" \
  -d client_secret="YOUR_CLIENT_SECRET"
# -> {"token_type": "Bearer", "access_token": "eyJ...", "expires_in": 3600}

# 2) Request grid data (the same URL you copied in Step 4)
curl -s "https://YOUR-ENVIRONMENT.lightkeeperhq.com/lightstation/api/reports/query/layout/YOUR_LAYOUT_ID/v2?focus=LKP_YOUR_PORTFOLIO__PORT&rollup=ISSUER&bd=20250101&ed=20250131" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

The response is plain JSON, so any language that can make an HTTPS request and parse JSON can use it directly: no `lkapi` package required.

If your team wants a ready-made client in another language, an [OpenAPI](https://www.openapis.org/) specification for this API is available in the `lkapi` repository (`openapi/lkapi.yaml`), which the [openapi-generator](https://openapi-generator.tech/) tool can turn into a client for C#, JavaScript, Java, and many other languages. This is a developer-facing option, best handed to your engineering or IT team rather than done yourself.

## Where to get help

For anything related to getting API access, credentials, or general questions, reach out to [Lightkeeper support](https://lightkeeper.com/).
