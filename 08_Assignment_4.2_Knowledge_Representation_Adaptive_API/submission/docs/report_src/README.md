# Report source - Assignment 4.2

Author: Kumar Waibhav Akshat (RA2212704010027)

`content.js` is the source of
`docs/Assignment_4.2_Knowledge_Representation_Adaptive_API_Report.docx` / `.pdf`. Every number, table row and
log excerpt in the report is read at build time from the real files in `../../logs/`, the code in
`../../ciphermesh/` and the figures in `../figures/`.

The PDF and DOCX in `docs/` are the built outputs. They are produced with the shared course report kit
(`dsl.js`, `build_report.js`, `render_diagrams.js`, `make_report.sh`, `chart_style.py`). The kit is shared by
several assignments and is **not** included in this folder.

To rebuild with the kit:

```bash
export REPORTKIT=/path/to/reportkit
python3 docs/figures/make_charts.py "$REPORTKIT"            # charts (needs matplotlib)
python3 docs/figures/make_diagrams.py                        # writes docs/figures/diagrams.html
NODE_PATH=$(npm root -g) node "$REPORTKIT/render_diagrams.js" docs/figures/diagrams.html docs/figures \
    fig_ontology fig_pipeline fig_graph_live fig_graph_replay
bash "$REPORTKIT/make_report.sh" docs/report_src/content.js docs \
    Assignment_4.2_Knowledge_Representation_Adaptive_API_Report   # two-pass build (TOC page numbers)
```

After the build, `docProps/core.xml` of the DOCX is post-processed so that `cp:lastModifiedBy` reads "Kumar Waibhav Akshat" (LibreOffice writes "Un-named").
