# Report source - Assignment 5.1

Author: Kumar Waibhav Akshat (RA2212704010027)

`content.js` is the source of
`docs/Assignment_5.1_Agent_Authentication_Host_Integrity_Report.docx` / `.pdf`. It is written in the content
DSL of the shared **CipherMesh report kit** (`dsl.js`, `build_report.js`, `make_report.sh`, `render_diagrams.js`,
`chart_style.py`, SRM and CipherMesh logos). The kit is shared by all CipherMesh unit reports and is **not included
in this submission**. `content.js` stops with a clear error if the kit cannot be found; point `REPORTKIT_DSL` at the
kit's `dsl.js` if it is not at `../../../reportkit/`.

## Build commands (from the deliverable root, `KIT` = path to the report kit)

```bash
# 1. diagrams (Figures 3.1, 3.2, 3.3, 5.2) from docs/figures/diagrams.html (needs Node + Playwright)
NODE_PATH=$(npm root -g) node $KIT/render_diagrams.js docs/figures/diagrams.html docs/figures arch pipe seq integ

# 2. charts (Figures 5.1, 5.3, 5.4) from the real logs in logs/ (needs matplotlib)
python3 docs/figures/make_charts.py $KIT/chart_style.py

# 3. report: two LibreOffice passes so the TOC / list of figures / list of tables page numbers are exact
REPORTKIT_DSL=$KIT/dsl.js bash $KIT/make_report.sh docs/report_src/content.js docs \
    Assignment_5.1_Agent_Authentication_Host_Integrity_Report

# 4. set the docx author properties (dc:creator, cp:lastModifiedBy)
python3 docs/report_src/finalize_docx.py docs/Assignment_5.1_Agent_Authentication_Host_Integrity_Report.docx

# 5. layout check: lists pages with very few lines
python3 $KIT/sparse.py docs/Assignment_5.1_Agent_Authentication_Host_Integrity_Report.pdf
```

Every number quoted in the report comes from the files in `logs/`, produced by `bash demo/run_all.sh`.
