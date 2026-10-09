---
id: sqlitexferauth01ax
name: 'SQLite INSERT SELECT xfer skips source READ'
kind: 0-day
cve: '-'
cveRisk: high
summary: >-
  SQLite 3.53.4 xferOptimization copies INSERT SELECT as raw B-tree records.
  sqlite3AuthCheck is INSERT on dest only. SELECT on src is denied. The copy
  still lands the witness. Vendor treated 3.54 d1cdb817 as a new feature.
  Labbed on 3.53.4. No CVE yet.
disclosureStatus: public
vendor: SQLite (Hwaci)
affected: >-
  SQLite 3.53.4 (b09c88c, SOURCE_ID 2026-07-24 19:02:57 bf7c7f3003...).
  Local. Needs an embedder sqlite3_set_authorizer. 3.54 xfer authorizer
  treated as a new feature, not a 3.53 bugfix. 3.54.0 is still draft.
tags:
  - 0-day
  - sqlite
  - authorizer
  - xfer
  - privilege-leftover
  - cwe-863
publishedAt: '2026-10-09T12:25:00.000Z'
updatedAt: '2026-10-09T12:25:00.000Z'
createdAt: '2026-10-09T12:25:00.000Z'
state: published
---

## SELECT was denied. The table still moved.

I am [@abraxas_null](https://x.com/abraxas_null). The proof of concept is on GitHub: **[abraxas/sqlite-xfer-auth](https://github.com/abraxas/sqlite-xfer-auth)** ([loopback client](https://github.com/abraxas/sqlite-xfer-auth/blob/main/sqlite-xfer-auth-Abraxas-Labs.py)). The lab stack is [`lab/`](https://github.com/abraxas/sqlite-xfer-auth/tree/main/lab): [Dockerfile](https://github.com/abraxas/sqlite-xfer-auth/blob/main/lab/Dockerfile), [docker-compose.yml](https://github.com/abraxas/sqlite-xfer-auth/blob/main/lab/docker-compose.yml), [run.sh](https://github.com/abraxas/sqlite-xfer-auth/blob/main/lab/run.sh), [poc.py](https://github.com/abraxas/sqlite-xfer-auth/blob/main/lab/poc.py), [xfer_auth.c](https://github.com/abraxas/sqlite-xfer-auth/blob/main/lab/xfer_auth.c). Authorized lab only. It talks to loopback.

This is **[SQLite](https://sqlite.org/src) [3.53.4](https://github.com/sqlite/sqlite/tree/version-3.53.4)** (`b09c88c14082339b66c7b7158d609a771e64ca69`). Fossil SOURCE_ID `2026-07-24 19:02:57 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc`. No CVE yet. [CWE-863](https://cwe.mitre.org/data/definitions/863.html). [7.5 High](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N) (`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`). Local. Embedder authorizer. Privilege leftover.

`sqlite3_set_authorizer` is the documented gate for untrusted SQL. DENY `SQLITE_SELECT` / `SQLITE_READ` on `src`. Allow `SQLITE_INSERT` on a schema-compatible `dest`. `SELECT * FROM src` is `SQLITE_AUTH`. `INSERT INTO dest SELECT * FROM src` is not. The witness that lived in `src` is now in `dest`. The authorizer log for the copy is one event: `INSERT:dest`.

That path has a name. `xferOptimization`. It exists so VACUUM can move whole B-trees without compiling a SELECT. On 3.53.4 it still does that when an authorizer is installed. The vendor already wrote the check. They put it on trunk as a 3.54 feature and left latest GA without it.

## Why SQLite, why this pin

I wanted a library people actually embed. Not a SaaS admin panel. Not a plugin. SQLite is public domain, ships in phones and browsers and language runtimes, and still has a C authorizer that applications treat as a column ACL. Chrome/WebSQL-style embedders, PHP `SQLite3::setAuthorizer`, anything that prepares attacker SQL against a shared file and then trusts the callback. The security model is honest: untrusted SQL and untrusted `.db` (plus a sibling `-wal`) are first-class inputs. [sqlite.org/security.html](https://sqlite.org/security.html) says so. Memory corruption, crash, or a skipped READ on those inputs is High. Local is in-scope.

Canonical tree is Fossil at [sqlite.org/src](https://sqlite.org/src). GitHub [sqlite/sqlite](https://github.com/sqlite/sqlite) is a mirror. I do not open public GitHub issues on that mirror.

Latest GA on the day of the hunt was 3.53.4, 2026-07-24. Git `b09c88c14082339b66c7b7158d609a771e64ca69`. SOURCE_ID in the amalgamation matches the Fossil string above. 3.54.0 was still a draft, planned 2026-10-15. Pinning a draft because trunk looks cleaner is how you lab a future and then tell operators they were never affected. They were. They are still on 3.53.4.

3.53.4 itself is a maintenance patch for (mostly) AI-discovered bugs in 3.53.0-3.53.3. If a leftover of later trunk still fires here, it is not a stale minor.

Default library: `load_extension` off. `TRUSTED_SCHEMA` on (compat). Typical amalgamation extras are FTS5, JSON, rtree. CLI, `sqlite3_rsync`, session, official WASM are extra surfaces. `sqlite3_set_authorizer` is NULL until the embedder installs a callback. Authorization is compiled in. `SQLITE_OMIT_AUTHORIZATION` is not a default Makefile flag. Neither is `SQLITE_OMIT_XFER_OPT`.

I only wanted Critical or High. Medium stays on the floor unless it chains. A finding on this hunt needed a leftover of a named 3.54 / branch-3.53 guard, a crash or heap write on untrusted SQL or an untrusted DB, or an authorizer skip that still returns real column data after SQLITE_DENY.

## The skip list is half the hunt

Before you look for leftovers, you write down what is already public so you do not "discover" a CVE with a press release. SQLite's table lives at [sqlite.org/cves.html](https://sqlite.org/cves.html). On 3.53.4 the interesting ones were already closed:

- [CVE-2026-11822](https://www.cve.org/CVERecord?id=CVE-2026-11822) / [CVE-2026-11824](https://www.cve.org/CVERecord?id=CVE-2026-11824) FTS5 `szLeaf<4` heap overflow. Duplicate CVEs. Fixed 3.53.2. `fts5LeafRead` on this pin rejects `szLeaf<4`.
- [CVE-2026-50812](https://www.cve.org/CVERecord?id=CVE-2026-50812) session NPD on a malformed changeset. Optional `-DSQLITE_ENABLE_SESSION`.
- concat_ws / LOOKASIDE / FTS5-index / zipfile CLI CVEs from 3.49-3.52. Closed years or months before this GA.
- JSON [CVE-2024-0232](https://www.cve.org/CVERecord?id=CVE-2024-0232) class. Closed.
- Ada Logics `sqlite3_rsync` stack smash (`readPow2` `x>16`). In tree on this pin.
- WAL-reset corruption. Closed 3.51.3 / 3.53.0.

The [JFrog "critical CVE" wave](https://research.jfrog.com/post/sqlite-critical-cves-or-llm-slops/) (CVE-2026-51296 family) is unreproducible. SQLite and JFrog treat it as LLM slop. I left it.

Public forum leftovers of later trunk versus this GA are a different list. WAL page-size mismatch. FTS5 secure-delete. rtree `last_insert_rowid` 0. FULL JOIN USING authorizer. xferOptimization authorizer. Those are not CVEs. They are check-ins on trunk or branch-3.53 after 2026-07-24. Hunt whether they still fire here. This post is one of them.

## Twenty surfaces, one authorizer skip I am writing up

I split the tree. Parser and VDBE. Btree and pager. WAL. FTS3. FTS5. JSON. vtab / ATTACH / pragma. trusted_schema / authorizer. Shell and zipfile. `sqlite3_rsync`. Session and RBU. deserialize / memdb. Triggers, views, windows. rtree / geopoly. WASM. 3.54 patch siblings. `load_extension` / VFS. C API. recover and misc extras. Schema side effects.

Most of that is SQLite doing what 3.53.4 said it would do.

Tokenizer length is `i64`. Parser stack is `SQLITE_LIMIT_PARSER_DEPTH`. VDBE op array caps at `SQLITE_LIMIT_VDBE_OP`. `load_extension` needs `SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION` and it defaults off. `fts3_tokenizer` is DIRECTONLY. JSON UAF class is closed. Envelope-style "unauth SQL on a default open" is the product: a process that opens a DB and prepares whatever string you hand it. I am not filing that.

Authorizer default-off is also the product. The leftover is not "authorizer is NULL." The leftover is: when an embedder installs the callback the docs told them to install, `INSERT INTO dest SELECT * FROM src` still copies a table that callback just denied.

There is a sibling on the same pin. FULL JOIN USING rewrites the column to `coalesce(...)` (`TK_FUNCTION`). `sqlite3AuthRead` runs only for `TK_COLUMN` / `TK_TRIGGER`. Denied data comes back through the join. Same C API, different statement shape, smaller blast radius (a column, not a whole table). That is a different leftover. This post is the copy.

## The fast path that does not compile a SELECT

INSERT auth is dest-table only. [`insert.c`](https://github.com/sqlite/sqlite/blob/b09c88c14082339b66c7b7158d609a771e64ca69/src/insert.c) on this pin:

```c
if( sqlite3AuthCheck(pParse, SQLITE_INSERT, pTab->zName, 0,
                     db->aDb[iDb].zDbSName) ){
  goto insert_cleanup;
}
```

That is the only `sqlite3AuthCheck` in the file. Then, before the SELECT compiler runs:

```c
#ifndef SQLITE_OMIT_XFER_OPT
  /* If the statement is of the form
  **
  **       INSERT INTO <table1> SELECT * FROM <table2>;
  **
  ** Then special optimizations can be applied that make the transfer
  ** very fast and which reduce fragmentation of indices.
  */
  if( pColumn==0
   && pSelect!=0
   && pTrigger==0
   && xferOptimization(pParse, pTab, pSelect, onError, iDb)
  ){
    assert( !pTrigger );
    assert( pList==0 );
    goto insert_end;
  }
#endif /* SQLITE_OMIT_XFER_OPT */
```

`goto insert_end`. No `sqlite3Select()`. The SELECT compiler is where `SQLITE_SELECT` fires (`select.c`, `sqlite3AuthCheck(pParse, SQLITE_SELECT, 0, 0, 0)`) and where empty-column `SQLITE_READ` fires (`sqlite3AuthCheck(pParse, SQLITE_READ, pItem->zName, "", zDb)`). Per-column `sqlite3AuthRead` lives in name resolution. None of that runs if xfer takes the statement.

`xferOptimization` itself is picky, which is why people miss it. One FROM term. No subquery. No WHERE, ORDER BY, GROUP BY, LIMIT, DISTINCT, WITH, compound. Result set must be `*`. Source and dest must be ordinary tables, same column count, same INTEGER PRIMARY KEY, same affinity and collation, compatible indexes. Virtual tables and views are out. Foreign keys on dest, if enabled, are out. `PRAGMA count_changes` is out. VACUUM is the original customer. The comment in the source says so.

Picky is not the same as rare. `INSERT INTO dest SELECT * FROM src` is also the statement you write when you want a table in a place you are allowed to read. Schema-compatible dest plus INSERT allowed is a realistic authorizer policy: a staging table, an export table, a per-user scratch table. The source is the thing you DENY. The fast path copies it anyway, as raw B-tree records, no SQL types, no per-column callbacks.

Grep of `insert.c` on 3.53.4: one `sqlite3AuthCheck`, no `sqlite3AuthRead`. The optimization is compiled in. `-DSQLITE_OMIT_XFER_OPT` exists for people who already knew.

## The vendor called 3.54 a feature

This is not a private find. [Forum 2026-05-21T03:31:22Z](https://sqlite.org/bugs/info/2026-05-21T03:31:22Z), yuelinwang / yiwei dai: xfer bypasses `SQLITE_SELECT` and `SQLITE_READ` on the source. Status: Resolved.

DRH, 2026-05-21:

> Fixed by check-in d1cdb817cafd03a4.
>
> This is not going onto branch-3.53 as I consider this a new feature rather than a bug fix. The new authorizer capabilities will appear in the 3.54.0 release.

[Check-in d1cdb817cafd03a4](https://www.sqlite.org/src/info/d1cdb817cafd03a4): "Enhance the xfer-optimization to verify access to the source table using the authorizer, if an authorizer is registered." Trunk only. Not cherry-picked to branch-3.53. Comment on the check-in is the same sentence as the forum reply, dressed as a feature.

I will give the naming this much: adding an authorizer check to a twenty-year-old VACUUM fast path is, strictly, new code. Calling it a feature is how you avoid a 3.53 patch and a CVE. The documented authorizer already promised that untrusted SQL would not read tables you DENY. On latest GA that promise is still false for one statement shape. A skipped READ of real column data is a leftover of that promise, whether or not the check-in message says "enhance."

3.54.0 is still draft. Operators on 3.53.4 do not have the enhance. They have the copy.

One of my own hunts almost buried this for the same reason. Parser/VDBE wrote it down as "below bar as vendor-declared feature, not a leftover bug of this pin." That is the vendor's classification. It is not the authorizer's. The authorizer hunt kept it as High. The lab is what settles the argument.

## The lab

I did not paste the forum C file into a laptop and call it 3.53.4. The pin has to be the amalgamation SQLite ships. Dockerfile curls `sqlite-src-3530400.zip` from sqlite.org, `./configure && make sqlite3.c`, then links a small HTTP oracle, `xfer_auth.c`, against that `sqlite3.c`. `--once` at build time proves the binary before the image is copied. Runtime listens on 18850.

Compose project `sqlite-xfer-auth`. Bind `127.0.0.1:18850:18850`. Loopback only. No network client except the PoC on the same host.

The oracle opens `:memory:`, creates `src(a)` and `dest(a)`, seeds `src` with `SQLITE-XFER-AUTH-WITNESS`, then installs an authorizer that:

- DENY `SQLITE_SELECT`
- DENY `SQLITE_READ` when the table is `src`
- allow `SQLITE_INSERT` on `dest`
- DENY any other INSERT

Then it prepares `SELECT * FROM src` (expect `SQLITE_AUTH` 23, "not authorized") and `INSERT INTO dest SELECT * FROM src` (expect prepare OK, step DONE). Authorizer is cleared. `SELECT a FROM dest` must return the witness. The JSON body includes the action log. SUCCESS requires `insert_n_select == 0` and `insert_n_read_src == 0`. If the source callbacks fired, the leftover is gone and the lab FAILs.

`poc.py` is a loopback GET. It checks `libversion == 3.53.4` and the full SOURCE_ID so a "latest sqlite" image cannot lie. Then the four booleans. Last line from the SUCCESS run:

```
SUCCESS sqlite-xfer-auth how=xfer-opt-skip-src-read select-src=denied insert-select=ok dest-has-witness=yes SQLITE-XFER-AUTH-WITNESS
```

Oracle JSON, trimmed to the parts that matter: `select_src_denied: true`, `select_src_rc: 23`, `select_actions: ["SELECT:."]`, `insert_select_ok: true`, `insert_actions: ["INSERT:dest."]`, `insert_n_select: 0`, `insert_n_read_src: 0`, `dest_value: SQLITE-XFER-AUTH-WITNESS`. `SELECT:.` is the documented SELECT callback: table name NULL. The DENY on SELECT is enough to stop a normal read. The INSERT SELECT never asked.

Replay:

```bash
cd lab && ./run.sh
```

Or from a fresh clone:

```bash
git clone https://github.com/abraxas/sqlite-xfer-auth
cd sqlite-xfer-auth/lab
./run.sh
```

Bind it to loopback. The [loopback client](https://github.com/abraxas/sqlite-xfer-auth/blob/main/sqlite-xfer-auth-Abraxas-Labs.py) is `lab/run.sh` with a banner on it. I am not going to print a one-liner you can paste at someone else's process. If you own the embedder, run the proof against loopback.

## Wrong turns, in the order I made them

**Pinning 3.54.0 because the check-in is there.** 3.54.0 is a draft. Latest GA is 3.53.4. The leftover is the GA, not the draft.

**Treating "DRH said feature" as "not High."** The forum is resolved. The code on 3.53.4 still copies. Classification is not a patch. Parser/VDBE hunt dropped it for that reason. Authorizer hunt did not. Lab agrees with the second hunt.

**Re-filing the forum PoC as a 3.53.4 result without pinning the amalgamation.** A laptop `libsqlite3` is whoever Apple or Debian shipped. SOURCE_ID in the JSON is the oracle. If it is not `bf7c7f3003...`, you labbed a different library.

**Assuming `SQLITE_OMIT_XFER_OPT` is default.** It is a compile flag for people who already knew. Default amalgamation includes the optimization. VACUUM wants it. So does `INSERT INTO dest SELECT * FROM src`.

**Expecting `sqlite3Select` to still run "somewhere."** `goto insert_end` means it does not. The INSERT SELECT action log is the proof. Zero `SELECT`, zero `READ src`. One `INSERT dest`.

**Denying only `SQLITE_READ` on table name `src` and forgetting `SQLITE_SELECT`.** SELECT's first argument is NULL. A callback that keys only on `a3=="src"` will miss the SELECT event and still deny per-column READ on a normal SELECT. The xfer path never sends those READ events. The lab DENYs both so the control is the documented one, not a callback bug.

**Adding WHERE, LIMIT, or a column list so the SQL "looks like a real query."** That is how you disable xfer and accidentally prove the slow path authorizes. The leftover is the `SELECT *` form. Picky is the point.

**Using Python `sqlite3` as the oracle.** CPython links whatever SQLite the OS has. The lab compiles 3.53.4 from the zip SQLite publishes and talks to it over loopback HTTP. Python is the client. The engine is C.

**Calling default-open SQL this bug.** Opening a DB and running `SELECT` with no authorizer is the product. This leftover needs the embedder that installed the gate.

**Inflating it to RCE.** It is a copy of bytes the authorizer already said you cannot read. No `load_extension`. No shell. No heap write. Privilege leftover, C:H I:N A:N, local, PR:L because you already needed to prepare SQL against that connection.

**A reverse shell.** Theatre. The oracle is a witness string in dest.

## What an attacker can do

Hold the ability to prepare SQL on a connection whose embedder installed `sqlite3_set_authorizer` as the untrusted-SQL / column ACL. The callback DENYs READ and SELECT on a table. It allows INSERT on another table with a compatible schema.

`SELECT * FROM src` fails. `INSERT INTO dest SELECT * FROM src` copies every row, as raw B-tree records, into dest. Then `SELECT` dest, which the policy allows, and read what src held.

That is the whole leftover. Staging tables, export tables, per-user scratch tables, anything schema-compatible that the authorizer treats as writable. The source never gets a READ callback. The destination does not need SELECT on the source. VACUUM's fast path is the gadget.

Default library, no authorizer: not this bug. `load_extension` still off. Not RCE. Not a crash. Not a file write outside the DB. Confidentiality of a table the embedder already tried to hide, through SQL the embedder already agreed to prepare.

WebSQL-style hosts, PHP `SQLite3::setAuthorizer`, any application that lets a principal prepare SQL and then trusts the callback to enforce per-table READ, are the victim model. An application that never installs an authorizer is outside it.

## The fix

Do what [d1cdb817cafd03a4](https://www.sqlite.org/src/info/d1cdb817cafd03a4) does on trunk: if an authorizer is registered, `xferOptimization` must verify access to the source table, or refuse the fast path and fall through to `sqlite3Select` so `SQLITE_SELECT` and `sqlite3AuthRead` run. Cherry-pick that to branch-3.53, or ship it in a 3.53.5, instead of waiting for a 3.54 "feature" operators do not have yet.

Until then, embedders that DENY READ on a table still have to DENY INSERT into any compatible destination, or compile with `-DSQLITE_OMIT_XFER_OPT`. Trusting the authorizer callback alone is the 3.53.4 leftover.

I am not going to print a SQL snippet aimed at someone else's process. If you own the embedder, run [the proof of concept](https://github.com/abraxas/sqlite-xfer-auth) against loopback.

## References

- Proof of concept: [abraxas/sqlite-xfer-auth](https://github.com/abraxas/sqlite-xfer-auth) · [sqlite-xfer-auth-Abraxas-Labs.py](https://github.com/abraxas/sqlite-xfer-auth/blob/main/sqlite-xfer-auth-Abraxas-Labs.py)
- Lab: [`lab/`](https://github.com/abraxas/sqlite-xfer-auth/tree/main/lab) · [Dockerfile](https://github.com/abraxas/sqlite-xfer-auth/blob/main/lab/Dockerfile) · [docker-compose.yml](https://github.com/abraxas/sqlite-xfer-auth/blob/main/lab/docker-compose.yml) · [run.sh](https://github.com/abraxas/sqlite-xfer-auth/blob/main/lab/run.sh) · [poc.py](https://github.com/abraxas/sqlite-xfer-auth/blob/main/lab/poc.py) · [xfer_auth.c](https://github.com/abraxas/sqlite-xfer-auth/blob/main/lab/xfer_auth.c)
- [@abraxas_null](https://x.com/abraxas_null) · [github.com/abraxas](https://github.com/abraxas) · [abraxaslabs.tech](https://abraxaslabs.tech) · [abraxas.null@proton.me](mailto:abraxas.null@proton.me)
- [CWE-863](https://cwe.mitre.org/data/definitions/863.html) · [7.5 High](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
- Tree: [sqlite.org/src](https://sqlite.org/src) tag [version-3.53.4](https://github.com/sqlite/sqlite/tree/version-3.53.4) (`b09c88c14082339b66c7b7158d609a771e64ca69`) · SOURCE_ID `2026-07-24 19:02:57 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc`
- [`insert.c` INSERT auth](https://github.com/sqlite/sqlite/blob/b09c88c14082339b66c7b7158d609a771e64ca69/src/insert.c) · `xferOptimization` · [`sqlite3_set_authorizer`](https://www.sqlite.org/c3ref/set_authorizer.html)
- Forum [2026-05-21T03:31:22Z](https://sqlite.org/bugs/info/2026-05-21T03:31:22Z) · check-in [d1cdb817cafd03a4](https://www.sqlite.org/src/info/d1cdb817cafd03a4)
- CVE table: [sqlite.org/cves.html](https://sqlite.org/cves.html) · security model: [sqlite.org/security.html](https://sqlite.org/security.html)
