# PHP + nginx container hardening playbook

A repeatable procedure for hardening a PHP-FPM behind nginx stack in containers. Each
section is a small loop: measure, change one thing, measure again, write down what you
learned. Runtime first, code second, then the edge, exposure, and the plumbing.

## 1. Upgrading the PHP runtime in containers

The image tag is a request, not a fact. Rebuild, then ask the running process what it
is before you resolve a single dependency against it.

- Pin the base image by digest (or at minimum by an immutable tag) so a rebuild is
  reproducible and a rollback is a tag change, not an archaeology project.
- Keep the previous image reference around until the new one has served traffic.
- Rebuild rather than restart: a restart reuses the old layers and proves nothing.
- Verify version and extension set from inside the running container.

```bash
docker compose build <service>
docker compose up -d <service>
docker exec <container> php -v
docker exec <container> php -m
```

- Confirm the pool's effective configuration, not just the file on disk: a dry-run
  dump of the FPM configuration shows what the workers actually received.
- Only after version and extensions are confirmed should you touch dependency
  resolution, platform pins, or lint baselines: all of it is measured against this runtime.

## 2. Driving deprecations to zero

Deprecations are cheap to fix while the list is short and expensive once it is noise.
Measure the whole tree, not just the code you own.

- Sweep every PHP file — application, vendor, and any dormant copies — with full
  error reporting and lint-only execution.
- Run the sweep on both the old and new runtime, then diff the outputs: the delta is
  the work the upgrade created, the intersection is debt you can clear in the same pass.
- Classify by cause, not file: removed operator, non-canonical cast, invalid syntax
  form, implicit nullable now written out, optional parameter before a required one.
- Fixes in vendored code are debt with an expiry date. Record package, file, and why;
  re-check after every dependency update and delete the patch when upstream adopts the
  behaviour. Re-applying a superseded patch is a regression.
- Look for shadowed duplicates: two files declaring the same class, differing in
  filename case or directory. Retire the stale one only after proving every include
  site resolves to the survivor. A non-executable suffix still allows download, so
  removal is hygiene, not a closed leak.
- Done means the same sweep returns no deprecations, no fatals, no parse errors.

## 3. Triage of nginx warnings

Three different questions get confused: is the config syntactically valid, what does
the config on disk say, and what did the running workers load?

- A config test answers the first, a config dump the second; neither answers the third.
- On-disk configuration is not proof of what is loaded. Compare the container's start
  time against configuration mtimes before trusting a dump: a file edited after start
  is not live.
- Certificate stapling: if the chain carries no OCSP responder URL the directive can
  never succeed, and it warns once per server block pulling in the shared TLS snippet.
  Disable it in the snippet, not per vhost.
- A warning repeated N times usually means one shared include pulled into N server
  blocks. Find the include before editing N files.
- Duplicate server blocks: diff them. If they are identical, one is already ignored;
  delete exactly that one and keep the survivor.
- A duplicate `server_name` is only a conflict on the same listen socket. The same
  name on two ports is legitimate; the warning is about the pairing, not the name.
- Reload races are not configuration faults. A request issued in the same instant as
  a reload can fail while old workers retire. Retry once before investigating.
- Verify with a request that traverses the real path (TLS, SNI, and the port the block
  listens on). A check that silently falls back to another port or to DNS tells you
  nothing, and a client-side error may be the server deliberately closing the stream.

```bash
docker exec <container> nginx -t
docker exec <container> nginx -T
docker exec <container> nginx -s reload
```

## 4. Exposure inside the document root

Whatever sits under the document root is public unless something denies it. Execution
is not the same control as disclosure.

- Inventory the docroot for backups, disabled copies, editor artefacts, dumps,
  archives, and dotfiles: a suffix that stops PHP executing still serves the body.
- Deny at the path that holds non-public material, returning the same status a missing
  file would return, so the rule does not confirm existence:

```nginx
location ^~ /<private-dir>/ {
    deny all;
    return 404;
}
```

- Where possible, move the data out of the document root rather than deny it. A deny
  rule is a promise someone has to keep; a path outside the root is a fact.
- Check the rule through the real entry path, not a local shortcut, and confirm both
  directions: the private path is gone and the site root still answers.
- Accepted risks must be written down as accepted, with the reason and the owner's
  decision. A risk that is only "not fixed yet" is rediscovered every quarter.

## 5. Where to place a mitigation

Choose the layer by asking what an attacker controls and what the layer can see.

- Prefer a kill switch at the runtime layer, disabling the vulnerable feature for the
  pool, over request-shape filtering at the edge. Body encoding, chunking, cookie
  absence, and parameter placement are attacker-controlled; a filter that enumerates
  them is a bypass checklist waiting to be written.
- Make the switch immutable where the platform allows it, so code running after a
  compromise cannot re-enable the feature.
- Do not ship a drafted edge rule that was never applied. Either apply and verify it,
  or delete it; a rule in a file nobody loaded is false coverage.
- Verify on the layer that enforces the mitigation, and re-verify after any container
  recreation: a rebuilt container is a new process tree with a new configuration read.
- Record the verification command next to the mitigation so the next person repeats
  the check instead of the assumption.

## 6. Mount hardening

Read-only by default, with a short explicit list of paths that must stay writable.

- Apply read-only to the whole tree, then carve out only what needs writes: state,
  uploads, caches, runtime sockets.
- Read-only beats ownership for the runtime write path but does not replace it. Files
  owned by the service user are writable at the host level regardless of the mount
  flag, so chown them to a non-service owner as well.
- Directory ownership matters too: rename and unlink are directory writes, so a
  root-owned file inside a service-user-writable directory is still replaceable.
- Do not "normalize" intentional ownership. Some paths are owned by a specific user or
  group on purpose, and a blanket recursive chown destroys that intent.
- Stage mount changes in the compose definition, then recreate. An unapplied change is
  not a control; verify writability from inside the container after recreation:

```bash
docker exec <container> sh -c 'touch /path/to/<dir>/.probe 2>/dev/null && echo RW || echo RO'
```

## 7. Redis over a unix socket

A socket-only datastore removes a network surface but adds a permission surface that
is easy to misread.

- With TCP disabled (`port 0`), the socket is the only channel. A failed TCP probe is
  expected and is not an outage; do not diagnose it as one.
- Socket ownership can be inherited from the mount directory rather than the serving
  process: a setgid directory passes its group to files created inside it, so the socket
  may belong to neither the process's primary group nor what a name-resolving `ls` shows.
- A permission test run as root proves nothing: root bypasses file permission checks.
  Test as the user the application actually runs as.

```bash
docker exec -u <service-user> <container> <client> -s /path/to/<socket> ping
```

- Wait for the health signal before probing: a datastore accepts connections while it
  is still loading its dataset and answers with an error that is a timing artefact.
- Tightening socket permissions usually means setting the group at creation time in
  the entrypoint, not editing a directive, and validating it as the service user.
- If the deployment accepts permissive socket modes because the socket is reachable
  only from containers that mount it, write that reasoning down as an accepted risk.

## 8. Dependency updates

Run the dependency tool in an environment that matches production, and prove the
baseline before and after.

- Use a container built on the same PHP runtime as production. A host toolchain on a
  different minor version resolves a different dependency set.
- Check the manifest's platform pin. A stale pin resolves packages against a version
  that is not running; correct it and confirm the change moves no packages.
- Audit before the update and again after. Note how many advisories come from
  transitive packages that no manifest constraint could have caught.
- Back up the installed code, not only the lock file: the lock does not capture what
  is on disk, and restoring from it alone needs a network round trip.
- Prefer a constrained update first: record how many installs, updates, and removals
  happened, and refuse the step if the plan includes an unintended major bump.
- After the update, re-check every manual vendor patch: some are now upstream
  behaviour, some have no target file left. The usual correct action is removal.
- If the tool ran privileged, restore ownership of the vendor tree to the service
  user, then reload gracefully so OPcache clears and in-flight requests finish.

## 9. Verification discipline

Most of the expensive mistakes in this kind of work are measurement mistakes.

- Dry run first when the tool supports it, and read the plan before accepting it.
- Change one reversible thing at a time, and keep the command that undoes it.
- Save an artifact before deleting it, and verify the backup is readable; a backup
  overwritten by a later copy of the edited file is not a backup.
- Prefer measured evidence over inference: running version, loaded configuration,
  post-change file count, status code on the real path.
- Guard pattern-based edits with a uniqueness check. An edit matching zero lines (or
  many) fails silently; confirm the target count is exactly one, then re-read the file.
- Record what was retracted and why. A conclusion that was wrong once is a trap for
  whoever reads the notes next.
- Keep unresolved items as explicit open questions with the evidence needed to close
  them, instead of leaving them implicit in a summary that reads as finished.
