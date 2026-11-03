"""Post-build step for the Assignment 5.1 report: set docx core properties to the author.

Author: Kumar Waibhav Akshat (RA2212704010027).
Usage: python3 docs/report_src/finalize_docx.py docs/Assignment_5.1_Agent_Authentication_Host_Integrity_Report.docx
Rewrites docProps/core.xml so that dc:creator and cp:lastModifiedBy both name the author.
"""
import re
import shutil
import sys
import tempfile
import zipfile

AUTHOR = "Kumar Waibhav Akshat"


def finalize(path: str) -> None:
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".docx").name
    with zipfile.ZipFile(path) as src, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as dst:
        for item in src.infolist():
            data = src.read(item.filename)
            if item.filename == "docProps/core.xml":
                xml = data.decode("utf-8")
                xml = re.sub(r"<dc:creator>.*?</dc:creator>", f"<dc:creator>{AUTHOR}</dc:creator>", xml, flags=re.S)
                if "<cp:lastModifiedBy" in xml:
                    xml = re.sub(r"<cp:lastModifiedBy>.*?</cp:lastModifiedBy>|<cp:lastModifiedBy/>",
                                 f"<cp:lastModifiedBy>{AUTHOR}</cp:lastModifiedBy>", xml, flags=re.S)
                else:
                    xml = xml.replace("</cp:coreProperties>",
                                      f"<cp:lastModifiedBy>{AUTHOR}</cp:lastModifiedBy></cp:coreProperties>")
                data = xml.encode("utf-8")
            dst.writestr(item, data)
    shutil.move(tmp, path)


if __name__ == "__main__":
    finalize(sys.argv[1])
