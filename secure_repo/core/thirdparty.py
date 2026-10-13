"""Recognise third-party libraries that were copied into a repository (and are therefore not the project's own code).

``node_modules/`` and ``vendor/`` are skipped by the walker, but a library dropped into ``static/js/`` is still just
a library. Its findings are reported (the code does ship) at low confidence and flagged as third-party so that
nobody edits the bundled copy by hand: the fix is to update it.
"""

from __future__ import annotations

import os
import re
from typing import Optional

LIBRARIES = (
    "jquery", "jquery-ui", "jquery.ui", "bootstrap", "angular", "angularjs", "lodash", "underscore", "moment",
    "materialize", "popper", "d3", "chart", "backbone", "handlebars", "modernizr", "highcharts", "select2",
    "datatables", "leaflet", "three", "socket.io", "react", "react-dom", "vue", "axios", "prism", "highlight",
    "ckeditor", "tinymce", "fontawesome", "font-awesome", "zepto", "requirejs", "swagger-ui", "ace", "codemirror",
    "knockout", "ember", "mootools", "prototype", "dojo", "extjs", "polyfill", "core-js", "fullcalendar", "toastr",
    "sweetalert", "swiper", "slick", "owl.carousel", "bluebird", "rxjs", "jszip", "pdf", "mathjax", "tether",
)
_NAME = "|".join(re.escape(name) for name in sorted(LIBRARIES, key=len, reverse=True))
_FILENAME = re.compile(rf"(?i)^({_NAME})([.\-_@]v?\d[\w.\-]*|[.\-_](min|bundle|slim|full|all|latest|dist|umd|esm))*\.(js|css|mjs)$")
_HEADER_NAME = "|".join(re.escape(name) for name in (
    "jQuery", "jQuery UI", "Bootstrap", "AngularJS", "Angular", "Lodash", "Underscore.js", "Moment.js", "Materialize",
    "Popper.js", "D3", "Chart.js", "Backbone.js", "Handlebars", "Modernizr", "Highcharts", "Select2", "DataTables",
    "Leaflet", "Three.js", "Socket.IO", "Vue.js", "React", "Axios", "Prism", "CKEditor", "TinyMCE", "Font Awesome",
    "Zepto", "RequireJS", "CodeMirror", "Knockout"))
# A banner line starts with the library name ("/*! jQuery v3.6.0", " * Materialize v1.0.0"), which a project's own
# comment such as "uses React 16" does not.
_HEADER = re.compile(rf"(?im)^[ \t]*(?:/\*!?|\*|//!?)[ \t]*({_HEADER_NAME})\b[^\n]{{0,60}}?\bv?\d+\.\d+")
_LIB_DIRS = re.compile(r"(?i)(^|/)(third[_-]?party|thirdparty|vendors?|externals?|bower_components|assets/vendor|"
                       r"static/(?:js/)?lib|public/(?:js/)?lib|www/lib)/")
_ASSET_EXT = (".js", ".mjs", ".css")


def detect(rel_path: str, language: str, text: str) -> Optional[str]:
    """Why this file is considered a bundled third-party library, or None."""
    lowered = rel_path.lower()
    if not lowered.endswith(_ASSET_EXT):
        return None
    name = os.path.basename(lowered)
    if _FILENAME.match(name):
        return f"file name '{name}'"
    header = _HEADER.search(text[:1200])
    if header:
        return f"header names {header.group(1)}"
    if _LIB_DIRS.search(lowered):
        return "located in a third-party/vendor folder"
    return None
