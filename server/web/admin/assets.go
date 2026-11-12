package adminweb

import _ "embed"

//go:embed index.html
var HTML string

//go:embed admin.css
var CSS string

//go:embed admin.js
var JS string
