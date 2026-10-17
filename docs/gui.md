# Graphical interface

[Home](../README.md) · [Installation](installation.md) · [CLI guide](cli-guide.md) · [Analysis](analysis.md) · [Reference](reference.md) · [GUI](gui.md) · [Security model](security-model.md) · [Troubleshooting](troubleshooting.md) · [Development](development.md) · [Releasing](releasing.md)


```bash
secure-repo gui
```

The GUI is a local web application. Secure Repo starts a server on `127.0.0.1`, prints the URL and opens your
browser. Close it with `Ctrl+C` in the terminal.

1. **Select target** - *This repository* (auto-detected), *Remote Git URL* or *Local folder*.
2. **Discover branches** - the same branch recon as the CLI; pick one from the list.
3. **Engagement options** - online intelligence, optional compliance audit (choose frameworks), test files, learning
   from triage, minimum confidence, analysis engine, max file size, auditor name, and the authorization
   confirmation.
4. **Initiate scan** - watch the pipeline, the live log and the **live structure map**: boxes light up as files are
   analyzed and turn orange/red when findings appear.
5. **Results** - overview, neural map, structure boxes, findings, libraries, compliance and export.
6. **Triage** - open any finding and mark it as false positive, accepted risk or confirmed; the score, the lists
   and the report folder are updated instantly and the decision is remembered for the next scans.

| | |
|---|---|
| <img src="images/gui-overview.png" alt="Overview" width="440"> | <img src="images/gui-neural-map.png" alt="Neural map" width="440"> |
| **Overview** - score, severity distribution, OWASP Top 10, hygiene, most exposed files and top weaknesses. | **Neural map** - files → weaknesses → OWASP categories → severity, with animated signal pulses. |
| <img src="images/gui-neural-highlight.png" alt="Highlighted activation path" width="440"> | <img src="images/gui-explanation.png" alt="Explanation drawer" width="440"> |
| **Activation paths** - search or click a node to light up everything connected to it. | **Explanations** - why it is insecure, how to fix it, evidence and references. |
| <img src="images/gui-structure-boxes.png" alt="Structure boxes" width="440"> | <img src="images/gui-compliance.png" alt="Compliance" width="440"> |
| **Structure** - nested boxes sized by bytes or lines and colored by risk. Click a folder to zoom in. | **Compliance** - per-framework score and every control with its evidence. |
| <img src="images/gui-data-flow.png" alt="Data-flow trace" width="440"> | <img src="images/gui-triage.png" alt="Triage panel" width="440"> |
| **Data flow** - the path of untrusted data from its source to the dangerous sink, with confidence reasons. | **Triage** - teach Secure Repo: false positive, accepted risk or confirmed, with reason and scope. |
| <img src="images/gui-libraries.png" alt="Libraries" width="440"> | |
| **Libraries** - every library, how its version was resolved (lockfile, manifest, environment, registry, graph) and its advisories. | |

Neural map controls: click a node for its explanation · scroll to zoom · drag to pan · double-click to fit ·
switch between *Neural layers* and *Organic* (force-directed) layouts · filter by severity · toggle pulses.

**Downloads**: HTML report, full evidence ZIP, JSON, SARIF, Markdown summary, CycloneDX SBOM, CSV files, lockfile
guide, virtual lockfile and analysis-quality report, plus *Print / Save as PDF*. You can also re-open any `report.json` with **Load report**.

**GUI security model**: listens on `127.0.0.1` only · random per-session token (sent in the URL fragment, never
logged) · `Host` header validation against DNS rebinding · strict Content-Security-Policy with zero third-party
resources · the downloadable HTML report blocks all network access.
