# Sourcemaps (symbolication)

## Upload
`POST /sourcemaps`

Headers:
- `x-ember-project`
- `x-ember-key`

JSON body:
```
{
  "release": "1.0.0",
  "minified_url": "https://cdn/app.min.js",
  "map_text": "<.map content>"
}
```

## Usage
During ingestion, if `context.release` is present and a sourcemap matches `minified_url`, frames are symbolicated.

### Enriched code context
When source contents are embedded in the sourcemap, EMBER attaches:
- `pre_context`
- `context_line`
- `post_context`
- `source_language` (inferred from filename extension)
