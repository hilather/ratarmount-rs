# Common Crawl WARC records

ratarmount indexes WARC records as files, so a text extraction pipeline can
open a record directly through the Session/Python API instead of downloading a
whole crawl segment. Use `ratarmount_rs.open(warc_source)` for a local path or
supported remote source, iterate indexed record paths, and read selected
records. WARC response entries contain the HTTP entity body, so application
text extraction can operate on selected bytes directly:

```python
import ratarmount_rs
from html.parser import HTMLParser

class Text(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
    def handle_data(self, data):
        if data.strip():
            self.parts.append(data.strip())

def extract_text(html):
    parser = Text()
    parser.feed(html)
    return " ".join(parser.parts)

with ratarmount_rs.open("hf://datasets/example/crawl@main/segment.warc.gz") as warc:
    for entry in warc.iter(order="name"):
        if entry.path.endswith("/article.html"):
            html = warc.read(entry.path).decode("utf-8", errors="replace")
            print(entry.path, extract_text(html))
```

For Common Crawl, stream only the needed WARC source from the public S3 bucket
or a Hub mirror. The application's `extract_text` function can apply
site-specific parsing; ratarmount serves indexed WARC record bodies and is not
an HTML boilerplate extractor.

The smoke script builds a tiny local WARC response and indexes it without
FUSE. Set `WARC_URL` to a remote or local crawl segment to additionally check
the mount path; that part skips if `/dev/fuse` is missing.

```sh
docs/recipes/scripts/common-crawl-warc.sh
```
